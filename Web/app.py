#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import uuid
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from werkzeug.utils import secure_filename
import pandas as pd

# Configuración
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import Config

# Módulos de RulesAudit
from modules.analyzer import FirewallRuleAnalyzer
from modules.utils import validar_archivo_excel, sanitizar_nombre_archivo
from modules.excel_reporter import generar_reporte_excel
from modules.html_reporter import generar_reporte_html

app = Flask(__name__)
app.config.from_object(Config)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Debe iniciar sesión para acceder.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/admin/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == app.config['ADMIN_USERNAME'] and password == app.config['ADMIN_PASSWORD']:
            session['logged_in'] = True
            session['username'] = username
            session['login_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            flash('Acceso concedido. Bienvenido al sistema RulesAudit.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Credenciales incorrectas. Acceso denegado.', 'error')
    
    return render_template('admin/login.html')

@app.route('/admin/logout')
def logout():
    session.clear()
    flash('Sesión cerrada correctamente.', 'success')
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
@login_required
def dashboard():
    reports = []
    if os.path.exists(app.config['REPORTS_FOLDER']):
        for f in os.listdir(app.config['REPORTS_FOLDER']):
            if f.endswith(('.html', '.xlsx')):
                filepath = os.path.join(app.config['REPORTS_FOLDER'], f)
                stat = os.stat(filepath)
                reports.append({
                    'name': f,
                    'size': f"{stat.st_size / 1024:.1f} KB",
                    'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                    'type': 'HTML' if f.endswith('.html') else 'Excel'
                })
    
    reports.sort(key=lambda x: x['modified'], reverse=True)
    
    return render_template('admin/dashboard.html', 
                         username=session.get('username'),
                         login_time=session.get('login_time'),
                         reports=reports[:20])

@app.route('/admin/analyze', methods=['POST'])
@login_required
def analyze():
    if 'file' not in request.files:
        flash('No se seleccionó ningún archivo.', 'error')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    cliente = request.form.get('cliente', '').strip()
    
    if file.filename == '':
        flash('No se seleccionó ningún archivo.', 'error')
        return redirect(url_for('dashboard'))
    
    if not cliente:
        flash('Debe ingresar el nombre del cliente.', 'error')
        return redirect(url_for('dashboard'))
    
    if not allowed_file(file.filename):
        flash('Formato de archivo no permitido. Use .xlsx o .xls', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        filename = secure_filename(file.filename)
        upload_id = str(uuid.uuid4())[:8]
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{upload_id}_{filename}")
        file.save(temp_path)
        
        cliente_sanitized = sanitizar_nombre_archivo(cliente)
        
        flash('Archivo cargado correctamente. Iniciando análisis...', 'info')
        
        df = pd.read_excel(temp_path, sheet_name=0, header=0)
        
        vulns_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'modules', 'vulns.json')
        
        analizador = FirewallRuleAnalyzer(df, vulns_path)
        vulnerabilidades = analizador.analizar()
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        report_excel = f"{cliente_sanitized}_{timestamp}.xlsx"
        report_html = f"{cliente_sanitized}_{timestamp}.html"
        
        excel_path = os.path.join(app.config['REPORTS_FOLDER'], report_excel)
        html_path = os.path.join(app.config['REPORTS_FOLDER'], report_html)
        
        if vulnerabilidades:
            generar_reporte_excel(vulnerabilidades, excel_path)
            generar_reporte_html(
                vulnerabilidades,
                filename,
                html_path,
                cliente
            )
            
            stats = {
                'total': len(vulnerabilidades),
                'critica': sum(1 for v in vulnerabilidades if v['Severidad'] == 'CRÍTICA'),
                'alta': sum(1 for v in vulnerabilidades if v['Severidad'] == 'ALTA'),
                'media': sum(1 for v in vulnerabilidades if v['Severidad'] == 'MEDIA'),
                'baja': sum(1 for v in vulnerabilidades if v['Severidad'] == 'BAJA'),
                'informativa': sum(1 for v in vulnerabilidades if v['Severidad'] == 'INFORMATIVA')
            }
            
            flash(f'Análisis completado. {stats["total"]} vulnerabilidades encontradas.', 'success')
            
            return render_template('admin/report.html',
                                 vulnerabilidades=vulnerabilidades,
                                 stats=stats,
                                 cliente=cliente,
                                 filename=filename,
                                 report_excel=report_excel,
                                 report_html=report_html,
                                 timestamp=timestamp)
        else:
            flash('No se encontraron vulnerabilidades en el archivo.', 'warning')
            return redirect(url_for('dashboard'))
            
    except Exception as e:
        flash(f'Error durante el análisis: {str(e)}', 'error')
        return redirect(url_for('dashboard'))
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

@app.route('/admin/download/<filename>')
@login_required
def download_report(filename):
    filepath = os.path.join(app.config['REPORTS_FOLDER'], filename)
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    else:
        flash('Archivo no encontrado.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/admin/view/<filename>')
@login_required
def view_report(filename):
    filepath = os.path.join(app.config['REPORTS_FOLDER'], filename)
    if os.path.exists(filepath) and filename.endswith('.html'):
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        return content
    else:
        flash('Archivo no encontrado o no es un HTML.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/admin/delete/<filename>')
@login_required
def delete_report(filename):
    filepath = os.path.join(app.config['REPORTS_FOLDER'], filename)
    
    try:
        if os.path.exists(filepath):
            os.remove(filepath)
            flash('Reporte eliminado correctamente.', 'success')
        else:
            flash('Archivo no encontrado.', 'error')
    except Exception as e:
        flash(f'Error al eliminar: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/admin/clear-all')
@login_required
def clear_all():
    try:
        count = 0
        for folder in [app.config['UPLOAD_FOLDER'], app.config['REPORTS_FOLDER']]:
            for filename in os.listdir(folder):
                filepath = os.path.join(folder, filename)
                try:
                    if os.path.isfile(filepath):
                        os.unlink(filepath)
                        count += 1
                except Exception as e:
                    print(f"Error deleting {filepath}: {e}")
        flash(f'Se eliminaron {count} archivos temporales y reportes.', 'success')
    except Exception as e:
        flash(f'Error al limpiar: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)