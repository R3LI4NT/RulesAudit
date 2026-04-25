import os
import time
from datetime import datetime
from collections import defaultdict

import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify, abort
from werkzeug.utils import secure_filename

import config
from modules import (
    FirewallRuleAnalyzer,
    PuntuadorRiesgo,
    GestorHistorial,
    generar_reporte_excel,
    generar_reporte_html,
    exportar_json,
    exportar_csv,
    sanitizar_nombre_archivo,
    calcular_hash_archivo
)


app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config['UPLOAD_FOLDER'] = config.UPLOAD_FOLDER
app.config['REPORTS_FOLDER'] = config.REPORTS_FOLDER
app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH
app.config['SESSION_COOKIE_HTTPONLY'] = config.SESSION_COOKIE_HTTPONLY
app.config['SESSION_COOKIE_SAMESITE'] = config.SESSION_COOKIE_SAMESITE
app.config['PERMANENT_SESSION_LIFETIME'] = config.PERMANENT_SESSION_LIFETIME

gestor_historial = GestorHistorial(config.HISTORY_FOLDER)

intentos_login = defaultdict(list)


def extension_permitida(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in config.ALLOWED_EXTENSIONS


def requiere_login(f):
    from functools import wraps

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario' not in session:
            flash('Debes iniciar sesion primero', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def verificar_rate_limit(ip):
    ahora = time.time()
    intentos_login[ip] = [t for t in intentos_login[ip] if ahora - t < config.RATE_LIMIT_WINDOW]
    return len(intentos_login[ip]) < config.RATE_LIMIT_LOGIN


def registrar_intento_login(ip):
    intentos_login[ip].append(time.time())


@app.route('/')
def index():
    if 'usuario' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/admin/login', methods=['GET', 'POST'])
def login():
    if 'usuario' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        ip = request.remote_addr or 'unknown'
        if not verificar_rate_limit(ip):
            flash('Demasiados intentos fallidos. Intenta en unos minutos.', 'error')
            return render_template('admin/login.html'), 429

        usuario = request.form.get('username', '').strip() or request.form.get('usuario', '').strip()
        password = request.form.get('password', '').strip()

        if usuario in config.ADMIN_CREDENCIALES and config.ADMIN_CREDENCIALES[usuario] == password:
            session.permanent = True
            session['usuario'] = usuario
            session['login_time'] = datetime.now().isoformat()
            intentos_login.pop(ip, None)
            flash(f'Bienvenido {usuario}', 'success')
            return redirect(url_for('dashboard'))

        registrar_intento_login(ip)
        flash('Credenciales invalidas', 'error')

    return render_template('admin/login.html')


@app.route('/admin/logout')
def logout():
    session.clear()
    flash('Sesion cerrada correctamente', 'success')
    return redirect(url_for('login'))


def listar_reports_carpeta():
    reports = []
    if not os.path.exists(app.config['REPORTS_FOLDER']):
        return reports
    for archivo in sorted(os.listdir(app.config['REPORTS_FOLDER']), reverse=True):
        ruta = os.path.join(app.config['REPORTS_FOLDER'], archivo)
        if not os.path.isfile(ruta):
            continue
        ext = archivo.rsplit('.', 1)[-1].lower()
        tipo_map = {
            'html': 'HTML', 'xlsx': 'Excel', 'xls': 'Excel',
            'json': 'JSON', 'csv': 'CSV'
        }
        if ext not in tipo_map:
            continue
        size_bytes = os.path.getsize(ruta)
        if size_bytes < 1024:
            size_str = f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            size_str = f"{size_bytes / 1024:.1f} KB"
        else:
            size_str = f"{size_bytes / (1024 * 1024):.1f} MB"
        modified_ts = datetime.fromtimestamp(os.path.getmtime(ruta))
        reports.append({
            'name': archivo,
            'modified': modified_ts.strftime('%Y-%m-%d %H:%M:%S'),
            'size': size_str,
            'type': tipo_map[ext]
        })
    return reports


@app.route('/admin/dashboard')
@requiere_login
def dashboard():
    historial = gestor_historial.listar_historial(limite=20)
    reports = listar_reports_carpeta()
    total_reglas = sum(h.get('total_reglas', 0) for h in historial)
    login_time = session.get('login_time', '')
    if login_time:
        try:
            login_time = datetime.fromisoformat(login_time).strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            pass
    return render_template(
        'admin/dashboard.html',
        usuario=session['usuario'],
        username=session['usuario'],
        historial=historial,
        reports=reports,
        total_reglas=total_reglas,
        login_time=login_time
    )


@app.route('/admin/analyze', methods=['POST'])
@requiere_login
def analyze():
    archivo = request.files.get('archivo') or request.files.get('file')
    if archivo is None:
        flash('No se selecciono ningun archivo', 'error')
        return redirect(url_for('dashboard'))

    nombre_cliente = (
        request.form.get('nombre_cliente', '').strip()
        or request.form.get('cliente', '').strip()
        or 'Cliente'
    )

    if archivo.filename == '':
        flash('Nombre de archivo vacio', 'error')
        return redirect(url_for('dashboard'))

    if not extension_permitida(archivo.filename):
        flash('Tipo de archivo no permitido. Usa .xlsx o .xls', 'error')
        return redirect(url_for('dashboard'))

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    nombre_seguro = secure_filename(archivo.filename)
    nombre_archivo = f"{timestamp}_{nombre_seguro}"
    ruta_archivo = os.path.join(app.config['UPLOAD_FOLDER'], nombre_archivo)
    archivo.save(ruta_archivo)

    hash_archivo = calcular_hash_archivo(ruta_archivo)

    try:
        df = pd.read_excel(ruta_archivo)

        analyzer = FirewallRuleAnalyzer(df)
        vulnerabilidades = analyzer.analizar()
        resumen = analyzer.obtener_resumen()
        compliance = analyzer.obtener_compliance()
        headers_archivo = analyzer.headers

        scorer = PuntuadorRiesgo(vulnerabilidades, resumen.get('total_reglas', 0))
        score = scorer.calcular_score_global()

        cliente_limpio = sanitizar_nombre_archivo(nombre_cliente)
        nombre_base = f"{cliente_limpio}_{timestamp}"

        ruta_excel = os.path.join(app.config['REPORTS_FOLDER'], f"{nombre_base}.xlsx")
        generar_reporte_excel(vulnerabilidades, ruta_excel, resumen=resumen, score=score, compliance=compliance)

        ruta_html = os.path.join(app.config['REPORTS_FOLDER'], f"{nombre_base}.html")
        generar_reporte_html(
            vulnerabilidades,
            archivo.filename,
            ruta_html,
            nombre_cliente,
            resumen=resumen,
            score=score,
            compliance=compliance,
            headers_archivo=headers_archivo
        )

        ruta_json = os.path.join(app.config['REPORTS_FOLDER'], f"{nombre_base}.json")
        exportar_json(vulnerabilidades, resumen, score, compliance, ruta_json, nombre_cliente, archivo.filename)

        ruta_csv = os.path.join(app.config['REPORTS_FOLDER'], f"{nombre_base}.csv")
        exportar_csv(vulnerabilidades, ruta_csv)

        entrada_id = gestor_historial.registrar_analisis(
            cliente=nombre_cliente,
            archivo_original=archivo.filename,
            vulnerabilidades=vulnerabilidades,
            resumen=resumen,
            score=score
        )

        session['ultimo_analisis'] = {
            'id': entrada_id,
            'cliente': nombre_cliente,
            'archivo': archivo.filename,
            'nombre_base': nombre_base,
            'hash': hash_archivo,
            'timestamp': timestamp,
            'total_vulnerabilidades': len(vulnerabilidades)
        }

        flash(f'Analisis completado: {len(vulnerabilidades)} hallazgos detectados', 'success')
        return redirect(url_for('ver_reporte', entrada_id=entrada_id))

    except Exception as e:
        flash(f'Error al analizar el archivo: {str(e)}', 'error')
        return redirect(url_for('dashboard'))
    finally:
        try:
            if os.path.exists(ruta_archivo):
                os.remove(ruta_archivo)
        except Exception:
            pass


@app.route('/admin/reporte/<entrada_id>')
@requiere_login
def ver_reporte(entrada_id):
    analisis = gestor_historial.obtener_analisis(entrada_id)
    if not analisis:
        flash('Analisis no encontrado', 'error')
        return redirect(url_for('dashboard'))

    vulnerabilidades = analisis.get('vulnerabilidades', [])
    stats_severidad = {
        'critica': sum(1 for v in vulnerabilidades if v.get('Severidad') == 'CRÍTICA'),
        'alta': sum(1 for v in vulnerabilidades if v.get('Severidad') == 'ALTA'),
        'media': sum(1 for v in vulnerabilidades if v.get('Severidad') == 'MEDIA'),
        'baja': sum(1 for v in vulnerabilidades if v.get('Severidad') == 'BAJA'),
        'informativa': sum(1 for v in vulnerabilidades if v.get('Severidad') == 'INFORMATIVA')
    }

    cliente = analisis.get('cliente', '')
    fecha_iso = analisis.get('fecha', '')
    try:
        timestamp_str = datetime.fromisoformat(fecha_iso).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        timestamp_str = fecha_iso[:19].replace('T', ' ')

    cliente_limpio = sanitizar_nombre_archivo(cliente)
    fecha_compact = fecha_iso.replace(':', '').replace('-', '').replace('T', '_')[:15]
    nombre_base = f"{cliente_limpio}_{fecha_compact}"

    report_html = f"{nombre_base}.html"
    report_excel = f"{nombre_base}.xlsx"
    report_json = f"{nombre_base}.json"
    report_csv = f"{nombre_base}.csv"

    return render_template(
        'admin/report.html',
        usuario=session['usuario'],
        username=session['usuario'],
        analisis=analisis,
        entrada_id=entrada_id,
        cliente=cliente,
        timestamp=timestamp_str,
        stats=stats_severidad,
        vulnerabilidades=vulnerabilidades,
        score=analisis.get('score', {}),
        resumen=analisis.get('resumen', {}),
        report_html=report_html,
        report_excel=report_excel,
        report_json=report_json,
        report_csv=report_csv
    )


@app.route('/admin/historial')
@requiere_login
def historial():
    cliente_filtro = request.args.get('cliente', '').strip()
    if cliente_filtro:
        lista = gestor_historial.listar_historial(cliente=cliente_filtro)
        stats = gestor_historial.estadisticas_cliente(cliente_filtro)
    else:
        lista = gestor_historial.listar_historial()
        stats = None
    return render_template(
        'admin/dashboard.html',
        usuario=session['usuario'],
        historial=lista,
        cliente_filtro=cliente_filtro,
        stats_cliente=stats,
        vista='historial'
    )


@app.route('/admin/comparar/<id_anterior>/<id_actual>')
@requiere_login
def comparar(id_anterior, id_actual):
    resultado = gestor_historial.comparar_analisis(id_anterior, id_actual)
    if not resultado:
        flash('No se pudieron comparar los analisis', 'error')
        return redirect(url_for('dashboard'))
    return render_template(
        'admin/report.html',
        usuario=session['usuario'],
        comparacion=resultado,
        vista='comparacion'
    )


@app.route('/admin/download/<entrada_id>/<formato>')
@requiere_login
def descargar(entrada_id, formato):
    analisis = gestor_historial.obtener_analisis(entrada_id)
    if not analisis:
        abort(404)

    cliente = analisis.get('cliente', 'cliente')
    fecha = analisis.get('fecha', '').replace(':', '').replace('-', '').replace('T', '_')[:15]
    cliente_limpio = sanitizar_nombre_archivo(cliente)
    nombre_base = f"{cliente_limpio}_{fecha}"

    rutas_posibles = {
        'html': os.path.join(app.config['REPORTS_FOLDER'], f"{nombre_base}.html"),
        'excel': os.path.join(app.config['REPORTS_FOLDER'], f"{nombre_base}.xlsx"),
        'xlsx': os.path.join(app.config['REPORTS_FOLDER'], f"{nombre_base}.xlsx"),
        'json': os.path.join(app.config['REPORTS_FOLDER'], f"{nombre_base}.json"),
        'csv': os.path.join(app.config['REPORTS_FOLDER'], f"{nombre_base}.csv")
    }

    ruta = rutas_posibles.get(formato.lower())
    if not ruta or not os.path.exists(ruta):
        for archivo in os.listdir(app.config['REPORTS_FOLDER']):
            if archivo.startswith(cliente_limpio) and archivo.endswith(f'.{formato.lower()}'):
                ruta = os.path.join(app.config['REPORTS_FOLDER'], archivo)
                break
        else:
            flash(f'Reporte en formato {formato} no disponible. Regenera el analisis.', 'error')
            return redirect(url_for('ver_reporte', entrada_id=entrada_id))

    como_adjunto = request.args.get('inline', '0') != '1'
    return send_file(ruta, as_attachment=como_adjunto)


@app.route('/admin/inline/<entrada_id>/<formato>')
@requiere_login
def ver_inline(entrada_id, formato):
    analisis = gestor_historial.obtener_analisis(entrada_id)
    if not analisis:
        abort(404)

    cliente = analisis.get('cliente', 'cliente')
    fecha = analisis.get('fecha', '').replace(':', '').replace('-', '').replace('T', '_')[:15]
    cliente_limpio = sanitizar_nombre_archivo(cliente)
    nombre_base = f"{cliente_limpio}_{fecha}"

    extensiones = {'html': '.html', 'json': '.json', 'csv': '.csv'}
    ext = extensiones.get(formato.lower())
    if not ext:
        abort(404)

    ruta = os.path.join(app.config['REPORTS_FOLDER'], f"{nombre_base}{ext}")
    if not os.path.exists(ruta):
        for archivo in os.listdir(app.config['REPORTS_FOLDER']):
            if archivo.startswith(cliente_limpio) and archivo.endswith(ext):
                ruta = os.path.join(app.config['REPORTS_FOLDER'], archivo)
                break
        else:
            abort(404)

    return send_file(ruta, as_attachment=False)


@app.route('/admin/api/historial')
@requiere_login
def api_historial():
    cliente = request.args.get('cliente', '').strip()
    limite = int(request.args.get('limite', 50))
    historial_data = gestor_historial.listar_historial(cliente=cliente if cliente else None, limite=limite)
    return jsonify({'success': True, 'total': len(historial_data), 'items': historial_data})


@app.route('/admin/api/eliminar/<entrada_id>', methods=['POST'])
@requiere_login
def api_eliminar(entrada_id):
    resultado = gestor_historial.eliminar_analisis(entrada_id)
    return jsonify({'success': resultado})


@app.route('/admin/view_report/<filename>')
@requiere_login
def view_report(filename):
    nombre_seguro = secure_filename(filename)
    ruta = os.path.join(app.config['REPORTS_FOLDER'], nombre_seguro)
    if not os.path.exists(ruta):
        abort(404)
    return send_file(ruta, as_attachment=False)


@app.route('/admin/download_report/<filename>')
@requiere_login
def download_report(filename):
    nombre_seguro = secure_filename(filename)
    ruta = os.path.join(app.config['REPORTS_FOLDER'], nombre_seguro)
    if not os.path.exists(ruta):
        abort(404)
    return send_file(ruta, as_attachment=True)


@app.route('/admin/delete_report/<filename>', methods=['GET', 'POST'])
@requiere_login
def delete_report(filename):
    nombre_seguro = secure_filename(filename)
    ruta = os.path.join(app.config['REPORTS_FOLDER'], nombre_seguro)
    if os.path.exists(ruta):
        try:
            os.remove(ruta)
            base = os.path.splitext(nombre_seguro)[0]
            for ext in ('.html', '.xlsx', '.json', '.csv'):
                ruta_extra = os.path.join(app.config['REPORTS_FOLDER'], base + ext)
                if os.path.exists(ruta_extra):
                    os.remove(ruta_extra)
            historial_lista = gestor_historial.listar_historial(limite=200)
            for entrada in historial_lista:
                fecha = entrada.get('fecha', '').replace(':', '').replace('-', '').replace('T', '_')[:15]
                cliente_limpio = sanitizar_nombre_archivo(entrada.get('cliente', ''))
                if base.startswith(cliente_limpio) and fecha[:8] in base:
                    gestor_historial.eliminar_analisis(entrada['id'])
                    break
            flash('Reporte eliminado correctamente', 'success')
        except Exception as e:
            flash(f'Error al eliminar: {str(e)}', 'error')
    return redirect(url_for('dashboard'))


@app.route('/admin/clear_all', methods=['GET', 'POST'])
@requiere_login
def clear_all():
    try:
        for archivo in os.listdir(app.config['REPORTS_FOLDER']):
            ruta = os.path.join(app.config['REPORTS_FOLDER'], archivo)
            if os.path.isfile(ruta):
                os.remove(ruta)
        gestor_historial.limpiar_historial()
        flash('Todos los reportes han sido eliminados', 'success')
    except Exception as e:
        flash(f'Error al limpiar: {str(e)}', 'error')
    return redirect(url_for('dashboard'))


@app.errorhandler(404)
def not_found(e):
    return render_template('admin/login.html', error='Pagina no encontrada'), 404


@app.errorhandler(413)
def too_large(e):
    flash('Archivo demasiado grande. Maximo 50 MB', 'error')
    return redirect(url_for('dashboard'))


@app.errorhandler(500)
def server_error(e):
    flash('Error interno del servidor', 'error')
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    print("=" * 60)
    print("  RulesAudit v2.1 :: Motor de Auditoria de Firewall")
    print("=" * 60)
    print(f"  Servidor iniciado en: http://127.0.0.1:5000")
    print(f"  Credenciales por defecto: admin / rulesaudit")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=False)
