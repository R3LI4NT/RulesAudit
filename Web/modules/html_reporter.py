import pandas as pd
from datetime import datetime
import os
import json


def generar_reporte_html(vulnerabilidades, nombre_archivo_original, ruta_salida, nombre_cliente):
    if not vulnerabilidades:
        print("\n[!] No hay vulnerabilidades para generar reporte HTML")
        return None
    
    df = pd.DataFrame(vulnerabilidades)
    
    # Estadísticas
    stats = {
        'total': len(vulnerabilidades),
        'critica': sum(1 for v in vulnerabilidades if v['Severidad'] == 'CRÍTICA'),
        'alta': sum(1 for v in vulnerabilidades if v['Severidad'] == 'ALTA'),
        'media': sum(1 for v in vulnerabilidades if v['Severidad'] == 'MEDIA'),
        'baja': sum(1 for v in vulnerabilidades if v['Severidad'] == 'BAJA'),
        'informativa': sum(1 for v in vulnerabilidades if v['Severidad'] == 'INFORMATIVA')
    }
    
    # Top vulnerabilidades por tipo
    top_tipos = df['Descripción'].value_counts().head(10).to_dict()
    
    # Vulnerabilidades por sección
    secciones = df['Sección'].value_counts().head(10).to_dict()
    
    # Fecha y hora del reporte
    fecha_reporte = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Generar HTML
    html_content = generar_template_html(
        stats=stats,
        vulnerabilidades=vulnerabilidades,
        top_tipos=top_tipos,
        secciones=secciones,
        nombre_archivo=nombre_archivo_original,
        fecha_reporte=fecha_reporte,
        timestamp=timestamp,
        nombre_cliente=nombre_cliente
    )
    
    with open(ruta_salida, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"\n[+] Reporte HTML generado: {ruta_salida}")
    return ruta_salida


def generar_template_html(stats, vulnerabilidades, top_tipos, secciones, nombre_archivo, fecha_reporte, timestamp, nombre_cliente):
    # Generar filas de la tabla de vulnerabilidades
    tabla_vulnerabilidades = ""
    for i, v in enumerate(vulnerabilidades, 1):
        # Determinar clase CSS según severidad
        severidad_class = {
            'CRÍTICA': 'critica',
            'ALTA': 'alta',
            'MEDIA': 'media',
            'BAJA': 'baja',
            'INFORMATIVA': 'informativa'
        }.get(v['Severidad'], '')
        
        icono = {
            'CRÍTICA': '💀',
            'ALTA': '🔴',
            'MEDIA': '🟠',
            'BAJA': '🟢',
            'INFORMATIVA': '🔵'
        }.get(v['Severidad'], '')
        
        descripcion = v['Descripción'].replace('<', '&lt;').replace('>', '&gt;')
        recomendacion = v['Recomendación'].replace('<', '&lt;').replace('>', '&gt;')
        
        row_id = f"vuln_{i}"
        
        tabla_vulnerabilidades += f"""
        <tr class="severidad-{severidad_class} scan-line" id="{row_id}" onclick="inspeccionarVulnerabilidad({i})">
            <td><span class="glitch-number">{i:03d}</span></td>
            <td><span class="badge badge-{severidad_class}">{icono} {v['Severidad']}</span></td>
            <td>{v['Tipo']}</td>
            <td class="matrix-text">{v['Sección']}</td>
            <td class="matrix-text">{v['Regla']}</td>
            <td class="matrix-text">{descripcion}</td>
            <td class="matrix-text">{recomendacion}</td>
        </tr>
        """
    
    top_items = ""
    for i, (desc, count) in enumerate(list(top_tipos.items())[:10], 1):
        porcentaje = (count / stats['total']) * 100
        top_items += f"""
        <div class="top-item glitch-hover" data-text="{desc}">
            <div class="top-number">#{i:02d}</div>
            <div class="top-content">
                <div class="top-title glitch-text">{desc}</div>
                <div class="top-stats">
                    <span class="top-count"><i class="fas fa-bug"></i> {count} ocurrencias</span>
                    <span class="top-percent">{porcentaje:.1f}%</span>
                </div>
                <div class="progress-bar terminal-progress">
                    <div class="progress-fill" style="width: {porcentaje}%; background: linear-gradient(90deg, #00ff00, #ff0000);"></div>
                </div>
            </div>
        </div>
        """
    
    secciones_items = ""
    for seccion, count in list(secciones.items())[:10]:
        secciones_items += f"""
        <div class="section-chip terminal-chip" onclick="filtrarSeccion('{seccion}')">
            <span class="section-name"><i class="fas fa-folder"></i> {seccion}</span>
            <span class="section-count">{count}</span>
        </div>
        """

    vuln_data = []
    for v in vulnerabilidades:
        vuln_data.append({
            'severidad': v['Severidad'],
            'tipo': v['Tipo'],
            'seccion': v['Sección'],
            'regla': v['Regla'],
            'descripcion': v['Descripción'],
            'recomendacion': v['Recomendación']
        })
    
    vuln_json = json.dumps(vuln_data, ensure_ascii=False)
    
    bar_data = [
        {'severidad': 'CRÍTICA', 'valor': stats['critica'], 'color': '#8B0000', 'icono': '💀'},
        {'severidad': 'ALTA', 'valor': stats['alta'], 'color': '#FF0000', 'icono': '🔴'},
        {'severidad': 'MEDIA', 'valor': stats['media'], 'color': '#FFA500', 'icono': '🟠'},
        {'severidad': 'BAJA', 'valor': stats['baja'], 'color': '#00FF00', 'icono': '🟢'},
        {'severidad': 'INFORMATIVA', 'valor': stats['informativa'], 'color': '#0088FF', 'icono': '🔵'}
    ]
    
    bar_data.sort(key=lambda x: x['valor'], reverse=True)
    
    max_valor = max([d['valor'] for d in bar_data]) if bar_data else 1
    
    barras_html = ""
    for item in bar_data:
        porcentaje = (item['valor'] / stats['total'] * 100) if stats['total'] > 0 else 0
        ancho_barra = (item['valor'] / max_valor * 100) if max_valor > 0 else 0
        
        barras_html += f"""
        <div class="bar-item" onclick="seleccionarSeveridad('{item['severidad']}')">
            <div class="bar-label">
                <span class="bar-icon">{item['icono']}</span>
                <span class="bar-name">{item['severidad']}</span>
                <span class="bar-value">{item['valor']}</span>
                <span class="bar-percent">({porcentaje:.1f}%)</span>
            </div>
            <div class="bar-container">
                <div class="bar-fill" style="width: {ancho_barra}%; background-color: {item['color']}; box-shadow: 0 0 15px {item['color']};"></div>
            </div>
        </div>
        """
    
    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RulesAudit :: {nombre_cliente} :: Reporte</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="icon" type="image/x-icon" href="https://raw.githubusercontent.com/R3LI4NT/RulesAudit/refs/heads/main/img/favicon.ico">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Space+Grotesk:wght@300;400;500;600;700&display=swap');
        
        /* RESET Y VARIABLES */
        :root {{
            --bg-primary: #0a0c0f;
            --bg-secondary: #15181e;
            --bg-tertiary: #1e232b;
            --text-primary: #e0e0e0;
            --text-secondary: #8b949e;
            --accent-cyan: #00ffff;
            --accent-green: #00ff00;
            --accent-red: #ff0000;
            --accent-orange: #ff7700;
            --accent-yellow: #ffff00;
            --accent-blue: #0088ff;
            --border-color: #2d333b;
            --glitch-offset: 2px;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Space Grotesk', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            padding: 20px;
            position: relative;
            min-height: 100vh;
        }}
        
        /* EFECTO MATRIZ DE FONDO */
        body::before {{
            content: "";
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: repeating-linear-gradient(
                0deg,
                rgba(0, 255, 0, 0.03) 0px,
                rgba(0, 0, 0, 0.5) 1px,
                transparent 2px
            );
            pointer-events: none;
            z-index: 0;
            animation: scan 8s linear infinite;
        }}
        
        @keyframes scan {{
            0% {{ transform: translateY(0); }}
            100% {{ transform: translateY(100vh); }}
        }}
        
        .container {{
            max-width: 1600px;
            margin: 0 auto;
            position: relative;
            z-index: 1;
        }}
        
        /* MODAL DE INSPECCIÓN */
        .modal {{
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.9);
            backdrop-filter: blur(5px);
            animation: modalFadeIn 0.3s;
            overflow-y: auto;
            padding: 20px;
        }}
        
        @keyframes modalFadeIn {{
            from {{ opacity: 0; }}
            to {{ opacity: 1; }}
        }}
        
        .modal-content {{
            position: relative;
            background: var(--bg-secondary);
            margin: 20px auto;
            padding: 0;
            width: 90%;
            max-width: 700px;
            border: 2px solid var(--accent-cyan);
            box-shadow: 0 0 50px rgba(0, 255, 255, 0.5);
            animation: modalSlideIn 0.3s;
        }}
        
        @keyframes modalSlideIn {{
            from {{ transform: translateY(-100px); opacity: 0; }}
            to {{ transform: translateY(0); opacity: 1; }}
        }}
        
        .modal-header {{
            padding: 15px 20px;
            background: linear-gradient(135deg, #000000, #1a1f2e);
            border-bottom: 2px solid var(--accent-cyan);
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 10;
        }}
        
        .modal-header h2 {{
            font-family: 'Share Tech Mono', monospace;
            color: var(--accent-cyan);
            font-size: 1.3em;
        }}
        
        .modal-header h2 i {{
            margin-right: 10px;
            color: var(--accent-green);
        }}
        
        .close-modal {{
            color: var(--text-secondary);
            font-size: 2em;
            cursor: pointer;
            transition: all 0.3s;
            line-height: 0.8;
        }}
        
        .close-modal:hover {{
            color: var(--accent-red);
            transform: scale(1.1);
        }}
        
        .modal-body {{
            padding: 20px;
            max-height: 70vh;
            overflow-y: auto;
        }}
        
        .modal-body::-webkit-scrollbar {{
            width: 5px;
        }}
        
        .modal-body::-webkit-scrollbar-track {{
            background: var(--bg-tertiary);
        }}
        
        .modal-body::-webkit-scrollbar-thumb {{
            background: var(--accent-cyan);
            box-shadow: 0 0 10px var(--accent-cyan);
        }}
        
        .evidence-section {{
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            padding: 15px;
            margin-bottom: 15px;
        }}
        
        .evidence-title {{
            font-family: 'Share Tech Mono', monospace;
            color: var(--accent-green);
            margin-bottom: 10px;
            font-size: 1em;
        }}
        
        .evidence-title i {{
            margin-right: 8px;
        }}
        
        .evidence-content {{
            background: #000;
            padding: 12px;
            border: 1px solid var(--border-color);
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.9em;
            line-height: 1.5;
            overflow-x: auto;
            word-break: break-word;
        }}
        
        .evidence-line {{
            color: var(--accent-cyan);
        }}
        
        .evidence-line strong {{
            color: var(--accent-green);
            margin-right: 5px;
        }}
        
        /* NUEVO ESTILO PARA EL FOOTER DEL MODAL */
        .modal-footer {{
            padding: 15px 20px;
            border-top: 1px solid var(--border-color);
            background: var(--bg-tertiary);
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.85em;
            color: var(--text-secondary);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .nav-buttons {{
            display: flex;
            gap: 10px;
        }}
        
        .nav-button {{
            background: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 5px 15px;
            cursor: pointer;
            font-family: 'Share Tech Mono', monospace;
            transition: all 0.3s;
            display: inline-flex;
            align-items: center;
            gap: 5px;
        }}
        
        .nav-button:hover:not(:disabled) {{
            border-color: var(--accent-cyan);
            color: var(--accent-cyan);
            box-shadow: 0 0 10px var(--accent-cyan);
        }}
        
        .nav-button:disabled {{
            opacity: 0.3;
            cursor: not-allowed;
        }}
        
        .help-text {{
            color: var(--text-secondary);
        }}
        
        .help-text i {{
            margin: 0 3px;
            color: var(--accent-green);
        }}
        
        /* HEADER HACKER */
        .header {{
            background: linear-gradient(135deg, #000000, #1a1f2e);
            border: 2px solid var(--accent-cyan);
            border-radius: 0;
            padding: 30px;
            margin-bottom: 25px;
            color: var(--text-primary);
            box-shadow: 0 0 30px rgba(0, 255, 255, 0.3),
                        inset 0 0 20px rgba(0, 255, 255, 0.1);
            position: relative;
            overflow: hidden;
        }}
        
        .header::before {{
            content: "AUDITORÍA DE FIREWALL - REGLAS";
            position: absolute;
            top: 10px;
            right: 20px;
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.8em;
            color: var(--accent-cyan);
            opacity: 0.3;
            letter-spacing: 4px;
        }}
        
        .header::after {{
            content: "";
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(0, 255, 255, 0.1), transparent);
            animation: scanline 3s linear infinite;
        }}
        
        @keyframes scanline {{
            0% {{ left: -100%; }}
            100% {{ left: 200%; }}
        }}
        
        .header h1 {{
            font-size: 3em;
            font-weight: 700;
            margin-bottom: 10px;
            font-family: 'Share Tech Mono', monospace;
            text-shadow: 0 0 10px var(--accent-cyan),
                         2px 2px 0 rgba(255, 0, 0, 0.5),
                         -2px -2px 0 rgba(0, 0, 255, 0.5);
            animation: glitch 3s infinite;
        }}
        
        @keyframes glitch {{
            2%, 64% {{ transform: translate(2px, 0) skew(0deg); }}
            4%, 60% {{ transform: translate(-2px, 0) skew(0deg); }}
            62% {{ transform: translate(0, 0) skew(5deg); }}
        }}
        
        .header h1 i {{
            margin-right: 10px;
            color: var(--accent-green);
        }}
        
        .header .subtitle {{
            font-size: 1.1em;
            opacity: 0.8;
            font-family: 'Share Tech Mono', monospace;
            border-left: 3px solid var(--accent-green);
            padding-left: 15px;
        }}
        
        .cliente-badge {{
            background: rgba(0, 255, 255, 0.1);
            display: inline-block;
            padding: 8px 20px;
            margin: 15px 0;
            font-size: 1.1em;
            border: 1px solid var(--accent-cyan);
            box-shadow: 0 0 15px rgba(0, 255, 255, 0.3);
            font-family: 'Share Tech Mono', monospace;
        }}
        
        .cliente-badge i {{
            margin-right: 8px;
            color: var(--accent-green);
        }}
        
        .cliente-badge strong {{
            color: var(--accent-cyan);
            font-weight: 600;
        }}
        
        .header .meta-info {{
            display: flex;
            gap: 30px;
            font-size: 0.95em;
            flex-wrap: wrap;
            border-top: 1px solid var(--border-color);
            padding-top: 15px;
            margin-top: 15px;
        }}
        
        .header .meta-info span {{
            background: rgba(0, 0, 0, 0.5);
            padding: 5px 15px;
            border: 1px solid var(--border-color);
        }}
        
        .header .meta-info i {{
            margin-right: 5px;
            color: var(--accent-green);
        }}
        
        /* KPI CARDS - ESTILO TERMINAL */
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 20px;
            margin-bottom: 25px;
        }}
        
        .kpi-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            padding: 20px;
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
        }}
        
        .kpi-card::before {{
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 2px;
            background: linear-gradient(90deg, transparent, var(--accent-cyan), transparent);
            transform: translateX(-100%);
            transition: transform 0.5s;
        }}
        
        .kpi-card:hover::before {{
            transform: translateX(100%);
        }}
        
        .kpi-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 0 30px rgba(0, 255, 255, 0.2);
            border-color: var(--accent-cyan);
        }}
        
        .kpi-card.critica {{ border-left: 4px solid #8B0000; }}
        .kpi-card.alta {{ border-left: 4px solid #FF0000; }}
        .kpi-card.media {{ border-left: 4px solid #FFA500; }}
        .kpi-card.baja {{ border-left: 4px solid #00FF00; }}
        .kpi-card.informativa {{ border-left: 4px solid #0088FF; }}
        
        .kpi-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        
        .kpi-title {{
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 2px;
            color: var(--text-secondary);
            font-family: 'Share Tech Mono', monospace;
        }}
        
        .kpi-icon {{
            font-size: 1.5em;
            filter: drop-shadow(0 0 5px currentColor);
        }}
        
        .kpi-value {{
            font-size: 2.5em;
            font-weight: 700;
            margin-bottom: 5px;
            font-family: 'Share Tech Mono', monospace;
        }}
        
        .kpi-percent {{
            font-size: 0.9em;
            color: var(--text-secondary);
        }}
        
        .kpi-percent i {{
            margin-right: 3px;
            color: var(--accent-green);
        }}
        
        /* CHARTS CARDS */
        .charts-row {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 25px;
            margin-bottom: 25px;
        }}
        
        .chart-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            padding: 25px;
            transition: all 0.3s;
        }}
        
        .chart-card:hover {{
            border-color: var(--accent-cyan);
            box-shadow: 0 0 30px rgba(0, 255, 255, 0.1);
        }}
        
        .chart-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
        }}
        
        .chart-header h3 {{
            font-size: 1.2em;
            color: var(--accent-cyan);
            font-family: 'Share Tech Mono', monospace;
        }}
        
        .chart-header i {{
            color: var(--accent-green);
        }}
        
        /* GRÁFICO DE BARRAS */
        .bar-chart-container {{
            padding: 10px;
        }}
        
        .bar-item {{
            margin-bottom: 20px;
            cursor: pointer;
            transition: transform 0.2s;
            padding: 8px;
            border-radius: 4px;
        }}
        
        .bar-item:hover {{
            transform: translateX(5px);
            background: rgba(0, 255, 255, 0.1);
        }}
        
        .bar-item.selected {{
            background: rgba(0, 255, 255, 0.15);
            border-left: 3px solid var(--accent-cyan);
            padding-left: 12px;
        }}
        
        .bar-label {{
            display: flex;
            align-items: center;
            margin-bottom: 8px;
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.95em;
        }}
        
        .bar-icon {{
            margin-right: 10px;
            font-size: 1.2em;
            width: 30px;
        }}
        
        .bar-name {{
            flex: 1;
            font-weight: 600;
            letter-spacing: 1px;
        }}
        
        .bar-value {{
            font-weight: 700;
            color: var(--accent-green);
            margin-right: 10px;
        }}
        
        .bar-percent {{
            color: var(--text-secondary);
            font-size: 0.85em;
            min-width: 70px;
            text-align: right;
        }}
        
        .bar-container {{
            width: 100%;
            height: 24px;
            background: #000;
            border: 1px solid var(--border-color);
            overflow: hidden;
            position: relative;
        }}
        
        .bar-fill {{
            height: 100%;
            transition: width 0.5s, box-shadow 0.3s;
            position: relative;
            overflow: hidden;
        }}
        
        .bar-fill::after {{
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
            animation: barScan 2s linear infinite;
        }}
        
        @keyframes barScan {{
            0% {{ transform: translateX(-100%); }}
            100% {{ transform: translateX(100%); }}
        }}
        
        /* TOP VULNERABILIDADES */
        .top-list {{
            max-height: 400px;
            overflow-y: auto;
            padding-right: 10px;
        }}
        
        .top-list::-webkit-scrollbar {{
            width: 5px;
        }}
        
        .top-list::-webkit-scrollbar-track {{
            background: var(--bg-tertiary);
        }}
        
        .top-list::-webkit-scrollbar-thumb {{
            background: var(--accent-cyan);
            box-shadow: 0 0 10px var(--accent-cyan);
        }}
        
        .top-item {{
            display: flex;
            align-items: flex-start;
            margin-bottom: 15px;
            padding: 15px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            transition: all 0.3s;
            cursor: help;
            position: relative;
        }}
        
        .top-item:hover {{
            border-color: var(--accent-cyan);
            transform: translateX(5px) scale(1.02);
            background: #1e2f3f;
        }}
        
        .glitch-hover:hover .glitch-text {{
            animation: textGlitch 0.3s infinite;
        }}
        
        @keyframes textGlitch {{
            0% {{ transform: translate(0); }}
            20% {{ transform: translate(-2px, 2px); }}
            40% {{ transform: translate(-2px, -2px); }}
            60% {{ transform: translate(2px, 2px); }}
            80% {{ transform: translate(2px, -2px); }}
            100% {{ transform: translate(0); }}
        }}
        
        .top-number {{
            width: 40px;
            height: 40px;
            background: #000;
            color: var(--accent-cyan);
            border: 1px solid var(--accent-cyan);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            margin-right: 15px;
            flex-shrink: 0;
            font-family: 'Share Tech Mono', monospace;
            box-shadow: 0 0 10px var(--accent-cyan);
        }}
        
        .top-content {{
            flex: 1;
            min-width: 0;
        }}
        
        .top-title {{
            font-weight: 500;
            margin-bottom: 8px;
            word-wrap: break-word;
            line-height: 1.4;
            color: var(--text-primary);
        }}
        
        .top-stats {{
            display: flex;
            justify-content: space-between;
            font-size: 0.85em;
            margin-bottom: 8px;
        }}
        
        .top-count {{
            color: var(--accent-green);
        }}
        
        .top-count i {{
            margin-right: 5px;
        }}
        
        .top-percent {{
            font-weight: 600;
            color: var(--accent-cyan);
        }}
        
        .terminal-progress {{
            height: 4px;
            background: #000;
            border: 1px solid var(--border-color);
            overflow: hidden;
        }}
        
        .progress-fill {{
            height: 100%;
            transition: width 0.3s;
            box-shadow: 0 0 10px currentColor;
        }}
        
        /* SECTIONS GRID */
        .sections-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 15px;
            max-height: 400px;
            overflow-y: auto;
            padding-right: 10px;
        }}
        
        .sections-grid::-webkit-scrollbar {{
            width: 5px;
        }}
        
        .sections-grid::-webkit-scrollbar-track {{
            background: var(--bg-tertiary);
        }}
        
        .sections-grid::-webkit-scrollbar-thumb {{
            background: var(--accent-green);
            box-shadow: 0 0 10px var(--accent-green);
        }}
        
        .terminal-chip {{
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            padding: 12px 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: all 0.3s;
            cursor: pointer;
            word-break: break-word;
        }}
        
        .terminal-chip:hover {{
            border-color: var(--accent-green);
            background: #1a2a1a;
            transform: translateY(-2px);
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.2);
        }}
        
        .terminal-chip i {{
            margin-right: 8px;
            color: var(--accent-green);
        }}
        
        .section-name {{
            font-size: 0.9em;
            font-weight: 500;
            margin-right: 10px;
            word-break: break-word;
        }}
        
        .section-count {{
            background: #000;
            padding: 4px 12px;
            font-size: 0.8em;
            font-weight: 600;
            border: 1px solid var(--border-color);
            font-family: 'Share Tech Mono', monospace;
        }}
        
        /* STATS SUMMARY */
        .stats-summary {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 2px solid var(--border-color);
        }}
        
        .stat-block {{
            text-align: center;
            padding: 15px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            transition: all 0.3s;
        }}
        
        .stat-block:hover {{
            border-color: var(--accent-cyan);
            transform: scale(1.05);
        }}
        
        .stat-label {{
            font-size: 0.85em;
            color: var(--text-secondary);
            margin-bottom: 5px;
            font-family: 'Share Tech Mono', monospace;
        }}
        
        .stat-number {{
            font-size: 1.8em;
            font-weight: 700;
            color: var(--accent-green);
            font-family: 'Share Tech Mono', monospace;
            text-shadow: 0 0 10px var(--accent-green);
        }}
        
        /* FILTERS */
        .filters-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            padding: 20px;
            margin-bottom: 25px;
        }}
        
        .filters-grid {{
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }}
        
        .filter-group {{
            flex: 1;
            min-width: 200px;
        }}
        
        .filter-group label {{
            display: block;
            font-size: 0.85em;
            color: var(--accent-cyan);
            margin-bottom: 5px;
            font-family: 'Share Tech Mono', monospace;
            letter-spacing: 1px;
        }}
        
        .filter-select, .filter-input {{
            width: 100%;
            padding: 12px 15px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            font-family: 'Share Tech Mono', monospace;
            transition: all 0.3s;
        }}
        
        .filter-select:focus, .filter-input:focus {{
            outline: none;
            border-color: var(--accent-cyan);
            box-shadow: 0 0 20px rgba(0, 255, 255, 0.2);
        }}
        
        .filter-actions {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}
        
        .btn {{
            padding: 12px 24px;
            border: 1px solid var(--border-color);
            background: transparent;
            color: var(--text-primary);
            font-size: 0.95em;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            font-family: 'Share Tech Mono', monospace;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .btn-primary {{
            border-color: var(--accent-cyan);
            color: var(--accent-cyan);
        }}
        
        .btn-primary:hover {{
            background: var(--accent-cyan);
            color: #000;
            box-shadow: 0 0 30px var(--accent-cyan);
        }}
        
        .btn-secondary {{
            border-color: var(--accent-green);
            color: var(--accent-green);
        }}
        
        .btn-secondary:hover {{
            background: var(--accent-green);
            color: #000;
            box-shadow: 0 0 30px var(--accent-green);
        }}
        
        /* TABLE */
        .table-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            padding: 20px;
            overflow-x: auto;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            min-width: 1200px;
            font-size: 0.9em;
        }}
        
        th {{
            text-align: left;
            padding: 15px;
            background: #000;
            color: var(--accent-cyan);
            font-weight: 600;
            font-size: 0.9em;
            position: sticky;
            top: 0;
            z-index: 10;
            border-bottom: 2px solid var(--accent-cyan);
            font-family: 'Share Tech Mono', monospace;
            letter-spacing: 1px;
        }}
        
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid var(--border-color);
            color: var(--text-primary);
            cursor: pointer;
        }}
        
        .scan-line {{
            transition: all 0.3s;
        }}
        
        .scan-line:hover {{
            background: rgba(0, 255, 255, 0.1) !important;
            border-left: 3px solid var(--accent-cyan);
            transform: scale(1.01);
            box-shadow: 0 0 20px rgba(0, 255, 255, 0.3);
        }}
        
        .glitch-number {{
            font-family: 'Share Tech Mono', monospace;
            color: var(--accent-green);
        }}
        
        .matrix-text {{
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.95em;
        }}
        
        .badge {{
            display: inline-block;
            padding: 6px 12px;
            font-size: 0.8em;
            font-weight: 600;
            text-align: center;
            white-space: nowrap;
            font-family: 'Share Tech Mono', monospace;
            border: 1px solid transparent;
        }}
        
        .badge-critica {{ 
            background: #8B0000; 
            color: #fff;
            border-color: #ff0000;
            box-shadow: 0 0 10px #ff0000;
        }}
        .badge-alta {{ 
            background: #FF0000; 
            color: #fff;
            border-color: #ff6666;
            box-shadow: 0 0 10px #ff0000;
        }}
        .badge-media {{ 
            background: #FFA500; 
            color: #000;
            border-color: #ffd700;
            box-shadow: 0 0 10px #ffa500;
        }}
        .badge-baja {{ 
            background: #00FF00; 
            color: #000;
            border-color: #90ff90;
            box-shadow: 0 0 10px #00ff00;
        }}
        .badge-informativa {{ 
            background: #0088FF; 
            color: #fff;
            border-color: #66aaff;
            box-shadow: 0 0 10px #0088ff;
        }}
        
        .severidad-critica {{ background: rgba(139, 0, 0, 0.2); }}
        .severidad-alta {{ background: rgba(255, 0, 0, 0.2); }}
        .severidad-media {{ background: rgba(255, 165, 0, 0.2); }}
        .severidad-baja {{ background: rgba(0, 255, 0, 0.1); }}
        .severidad-informativa {{ background: rgba(0, 136, 255, 0.1); }}
        
        /* FOOTER */
        .footer {{
            text-align: center;
            margin-top: 25px;
            padding: 20px;
            color: var(--text-secondary);
            font-size: 0.9em;
            border-top: 1px solid var(--border-color);
            font-family: 'Share Tech Mono', monospace;
        }}
        
        .footer i {{
            color: var(--accent-green);
        }}
        
        .footer a {{
            color: var(--accent-cyan);
            text-decoration: none;
        }}
        
        .footer a:hover {{
            text-decoration: underline;
        }}
        
        /* RESPONSIVE */
        @media (max-width: 1200px) {{
            .kpi-grid {{
                grid-template-columns: repeat(3, 1fr);
            }}
        }}
        
        @media (max-width: 768px) {{
            .kpi-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
            
            .charts-row {{
                grid-template-columns: 1fr;
            }}
            
            .filters-grid {{
                flex-direction: column;
            }}
            
            .filter-group {{
                width: 100%;
            }}
            
            .modal-footer {{
                flex-direction: column;
                gap: 10px;
                text-align: center;
            }}
        }}
    </style>
</head>
<body>
    <!-- MODAL DE INSPECCIÓN CON BOTONES ANTERIOR/SIGUIENTE A LA IZQUIERDA -->
    <div id="inspectModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2><i class="fas fa-search"></i> INSPECCIÓN DE VULNERABILIDAD</h2>
                <span class="close-modal" onclick="cerrarModal()">&times;</span>
            </div>
            <div class="modal-body">
                <div class="evidence-section">
                    <div class="evidence-title"><i class="fas fa-tag"></i> SEVERIDAD</div>
                    <div class="evidence-content">
                        <div class="evidence-line" id="modalSeveridad"></div>
                    </div>
                </div>
                
                <div class="evidence-section">
                    <div class="evidence-title"><i class="fas fa-code-branch"></i> TIPO</div>
                    <div class="evidence-content">
                        <div class="evidence-line" id="modalTipo"></div>
                    </div>
                </div>
                
                <div class="evidence-section">
                    <div class="evidence-title"><i class="fas fa-folder"></i> SECCIÓN</div>
                    <div class="evidence-content">
                        <div class="evidence-line" id="modalSeccion"></div>
                    </div>
                </div>
                
                <div class="evidence-section">
                    <div class="evidence-title"><i class="fas fa-shield-alt"></i> REGLA</div>
                    <div class="evidence-content">
                        <div class="evidence-line" id="modalRegla"></div>
                    </div>
                </div>
                
                <div class="evidence-section">
                    <div class="evidence-title"><i class="fas fa-exclamation-triangle"></i> DESCRIPCIÓN</div>
                    <div class="evidence-content">
                        <div class="evidence-line" id="modalDescripcion"></div>
                    </div>
                </div>
                
                <div class="evidence-section">
                    <div class="evidence-title"><i class="fas fa-tools"></i> RECOMENDACIÓN</div>
                    <div class="evidence-content">
                        <div class="evidence-line" id="modalRecomendacion"></div>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <div class="nav-buttons">
                    <button class="nav-button" onclick="navegarVulnerabilidad(-1)" id="prevBtn" disabled>
                        <i class="fas fa-chevron-left"></i> ANTERIOR
                    </button>
                    <button class="nav-button" onclick="navegarVulnerabilidad(1)" id="nextBtn">
                        SIGUIENTE <i class="fas fa-chevron-right"></i>
                    </button>
                </div>
                <div class="help-text">
                    <i class="fas fa-mouse-pointer"></i> Click fuera para cerrar
                </div>
            </div>
        </div>
    </div>

    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>
                <i class="fa-solid fa-fire"></i>
                RulesAudit
            </h1>
            <div class="subtitle">[REGLAS DE FIREWALL] :: EVALUACIÓN DE VULNERABILIDADES</div>
            <div class="cliente-badge">
                <i class="fas fa-user-secret"></i> CLIENTE: <strong>{nombre_cliente}</strong>
            </div>
            <div class="meta-info">
                <span><i class="fas fa-file-code"></i> ARCHIVO: {nombre_archivo}</span>
                <span><i class="fas fa-clock"></i> FECHA: {fecha_reporte}</span>
                <span><i class="fas fa-bug"></i> VULNERABILIDADES: {stats['total']}</span>
                <span><i class="fas fa-shield-halved"></i> NIVEL DE RIESGO: {((stats['critica']*5 + stats['alta']*4 + stats['media']*3 + stats['baja']*2 + stats['informativa']*1) / max(stats['total'],1) * 20):.1f}%</span>
            </div>
        </div>
        
        <!-- KPI Cards -->
        <div class="kpi-grid">
            <div class="kpi-card critica">
                <div class="kpi-header">
                    <span class="kpi-title">CRÍTICA</span>
                    <span class="kpi-icon">💀</span>
                </div>
                <div class="kpi-value">{stats['critica']}</div>
                <div class="kpi-percent">
                    <i class="fas fa-chart-line"></i>
                    {stats['critica']/stats['total']*100:.1f}%
                </div>
            </div>
            
            <div class="kpi-card alta">
                <div class="kpi-header">
                    <span class="kpi-title">ALTA</span>
                    <span class="kpi-icon">🔴</span>
                </div>
                <div class="kpi-value">{stats['alta']}</div>
                <div class="kpi-percent">
                    <i class="fas fa-chart-line"></i>
                    {stats['alta']/stats['total']*100:.1f}%
                </div>
            </div>
            
            <div class="kpi-card media">
                <div class="kpi-header">
                    <span class="kpi-title">MEDIA</span>
                    <span class="kpi-icon">🟠</span>
                </div>
                <div class="kpi-value">{stats['media']}</div>
                <div class="kpi-percent">
                    <i class="fas fa-chart-line"></i>
                    {stats['media']/stats['total']*100:.1f}%
                </div>
            </div>
            
            <div class="kpi-card baja">
                <div class="kpi-header">
                    <span class="kpi-title">BAJA</span>
                    <span class="kpi-icon">🟢</span>
                </div>
                <div class="kpi-value">{stats['baja']}</div>
                <div class="kpi-percent">
                    <i class="fas fa-chart-line"></i>
                    {stats['baja']/stats['total']*100:.1f}%
                </div>
            </div>
            
            <div class="kpi-card informativa">
                <div class="kpi-header">
                    <span class="kpi-title">INFORMATIVA</span>
                    <span class="kpi-icon">🔵</span>
                </div>
                <div class="kpi-value">{stats['informativa']}</div>
                <div class="kpi-percent">
                    <i class="fas fa-chart-line"></i>
                    {stats['informativa']/stats['total']*100:.1f}%
                </div>
            </div>
        </div>
        
        <!-- Charts Row -->
        <div class="charts-row">
            <!-- Gráfico de Barras -->
            <div class="chart-card">
                <div class="chart-header">
                    <h3><i class="fas fa-chart-bar"></i> DISTRIBUCIÓN POR SEVERIDAD</h3>
                    <i class="fas fa-info-circle" title="Barras ordenadas de mayor a menor impacto. Click para filtrar"></i>
                </div>
                <div class="bar-chart-container" id="barChart">
                    {barras_html}
                </div>
            </div>
            
            <!-- Top Vulnerabilidades -->
            <div class="chart-card">
                <div class="chart-header">
                    <h3><i class="fas fa-list"></i> TOP VULNERABILIDADES</h3>
                    <i class="fas fa-info-circle" title="Las 10 vulnerabilidades más frecuentes"></i>
                </div>
                <div class="top-list">
                    {top_items}
                </div>
            </div>
        </div>
        
        <!-- Secciones y Resumen -->
        <div class="charts-row">
            <div class="chart-card">
                <div class="chart-header">
                    <h3><i class="fas fa-layer-group"></i> SECCIONES AFECTADAS</h3>
                    <i class="fas fa-info-circle" title="Distribución de vulnerabilidades por sección"></i>
                </div>
                <div class="sections-grid">
                    {secciones_items}
                </div>
            </div>
            
            <div class="chart-card">
                <div class="chart-header">
                    <h3><i class="fas fa-chart-bar"></i> RESUMEN EJECUTIVO</h3>
                    <i class="fas fa-info-circle" title="Estadísticas generales del análisis"></i>
                </div>
                <div class="stats-summary">
                    <div class="stat-block">
                        <div class="stat-label">TOTAL VULNS</div>
                        <div class="stat-number">{stats['total']}</div>
                    </div>
                    <div class="stat-block">
                        <div class="stat-label">RIESGO PREDOMINANTE</div>
                        <div class="stat-number">
                            {max([(k,v) for k,v in stats.items() if k != 'total'], key=lambda x: x[1])[0].capitalize()}
                        </div>
                    </div>
                    <div class="stat-block">
                        <div class="stat-label">ÍNDICE DE RIESGO</div>
                        <div class="stat-number">
                            {((stats['critica']*5 + stats['alta']*4 + stats['media']*3 + stats['baja']*2 + stats['informativa']*1) / max(stats['total'],1) * 20):.1f}%
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Filters -->
        <div class="filters-card">
            <div class="filters-grid">
                <div class="filter-group">
                    <label><i class="fas fa-filter"></i> FILTRAR POR SEVERIDAD</label>
                    <select id="severidadFilter" class="filter-select" onchange="filtrarTabla()">
                        <option value="TODAS">[TODAS LAS SEVERIDADES]</option>
                        <option value="CRÍTICA">💀 CRÍTICA</option>
                        <option value="ALTA">🔴 ALTA</option>
                        <option value="MEDIA">🟠 MEDIA</option>
                        <option value="BAJA">🟢 BAJA</option>
                        <option value="INFORMATIVA">🔵 INFORMATIVA</option>
                    </select>
                </div>
                
                <div class="filter-group">
                    <label><i class="fas fa-search"></i> BUSCAR</label>
                    <input type="text" id="searchInput" class="filter-input" placeholder="> 'patrón' _" onkeyup="filtrarTabla()">
                </div>
                
                <div class="filter-actions">
                    <button class="btn btn-primary" onclick="exportarCSV()">
                        <i class="fas fa-file-csv"></i> EXPORTAR CSV
                    </button>
                    <button class="btn btn-secondary" onclick="exportarHTML()">
                        <i class="fas fa-file-code"></i> EXPORTAR HTML
                    </button>
                    <button class="btn btn-secondary" onclick="resetFiltros()">
                        <i class="fas fa-undo"></i> REINICIAR
                    </button>
                </div>
            </div>
        </div>
        
        <!-- Table -->
        <div class="table-card">
            <table id="vulnerabilidadesTable">
                <thead>
                    <tr>
                        <th>#ID</th>
                        <th>SEVERIDAD</th>
                        <th>TIPO</th>
                        <th>SECCIÓN</th>
                        <th>REGLA</th>
                        <th>DESCRIPCIÓN</th>
                        <th>RECOMENDACIÓN</th>
                    </tr>
                </thead>
                <tbody id="tablaBody">
                    {tabla_vulnerabilidades}
                </tbody>
            </table>
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p>
                <i class="fas fa-copyright"></i> RulesAudit v1.0 - [<a href="https://github.com/R3LI4NT/RulesAudit" target="_blank">GITHUB</a>] :: 
                | <i class="fas fa-user-secret"></i> {nombre_cliente} | <i class="fas fa-clock"></i> {fecha_reporte}
            </p>
        </div>
    </div>
    
    <script>
        // Datos de vulnerabilidades para inspección
        const vulnerabilidadesData = {vuln_json};
        
        // Variable para tracking de la vulnerabilidad actual
        let currentVulnIndex = -1;
        let selectedSeveridad = null;
        
        // Función para inspeccionar vulnerabilidad
        function inspeccionarVulnerabilidad(index) {{
            currentVulnIndex = index - 1; // Ajustar a índice 0-based
            const vuln = vulnerabilidadesData[currentVulnIndex];
            
            // Actualizar modal con los datos
            document.getElementById('modalSeveridad').innerHTML = getSeveridadHTML(vuln.severidad);
            document.getElementById('modalTipo').innerHTML = `<span class="evidence-line"><strong>></strong> ${{vuln.tipo}}</span>`;
            document.getElementById('modalSeccion').innerHTML = `<span class="evidence-line"><strong>></strong> ${{vuln.seccion}}</span>`;
            document.getElementById('modalRegla').innerHTML = `<span class="evidence-line"><strong>></strong> ${{vuln.regla}}</span>`;
            document.getElementById('modalDescripcion').innerHTML = `<span class="evidence-line"><strong>></strong> ${{vuln.descripcion}}</span>`;
            document.getElementById('modalRecomendacion').innerHTML = `<span class="evidence-line"><strong>></strong> ${{vuln.recomendacion}}</span>`;
            
            // Actualizar estado de botones de navegación
            document.getElementById('prevBtn').disabled = currentVulnIndex === 0;
            document.getElementById('nextBtn').disabled = currentVulnIndex === vulnerabilidadesData.length - 1;
            
            // Mostrar modal
            document.getElementById('inspectModal').style.display = 'block';
            
            // Prevenir scroll del body
            document.body.style.overflow = 'hidden';
        }}
        
        // Función para navegar entre vulnerabilidades
        function navegarVulnerabilidad(direccion) {{
            const nuevoIndex = currentVulnIndex + direccion;
            if (nuevoIndex >= 0 && nuevoIndex < vulnerabilidadesData.length) {{
                // Actualizar el índice y mostrar la nueva vulnerabilidad
                currentVulnIndex = nuevoIndex;
                const vuln = vulnerabilidadesData[currentVulnIndex];
                
                document.getElementById('modalSeveridad').innerHTML = getSeveridadHTML(vuln.severidad);
                document.getElementById('modalTipo').innerHTML = `<span class="evidence-line"><strong>></strong> ${{vuln.tipo}}</span>`;
                document.getElementById('modalSeccion').innerHTML = `<span class="evidence-line"><strong>></strong> ${{vuln.seccion}}</span>`;
                document.getElementById('modalRegla').innerHTML = `<span class="evidence-line"><strong>></strong> ${{vuln.regla}}</span>`;
                document.getElementById('modalDescripcion').innerHTML = `<span class="evidence-line"><strong>></strong> ${{vuln.descripcion}}</span>`;
                document.getElementById('modalRecomendacion').innerHTML = `<span class="evidence-line"><strong>></strong> ${{vuln.recomendacion}}</span>`;
                
                // Actualizar botones
                document.getElementById('prevBtn').disabled = currentVulnIndex === 0;
                document.getElementById('nextBtn').disabled = currentVulnIndex === vulnerabilidadesData.length - 1;
            }}
        }}
        
        // Función para obtener HTML de severidad con color
        function getSeveridadHTML(severidad) {{
            const colores = {{
                'CRÍTICA': '#8B0000',
                'ALTA': '#FF0000',
                'MEDIA': '#FFA500',
                'BAJA': '#00FF00',
                'INFORMATIVA': '#0088FF'
            }};
            const iconos = {{
                'CRÍTICA': '💀',
                'ALTA': '🔴',
                'MEDIA': '🟠',
                'BAJA': '🟢',
                'INFORMATIVA': '🔵'
            }};
            const color = colores[severidad] || '#ffffff';
            const icono = iconos[severidad] || '';
            
            return `<span style="color: ${{color}}; font-weight: bold; text-shadow: 0 0 10px ${{color}};">${{icono}} ${{severidad}}</span>`;
        }}
        
        // Función para seleccionar severidad en el gráfico
        function seleccionarSeveridad(severidad) {{
            selectedSeveridad = severidad;
            
            // Actualizar clases en las barras
            const barras = document.querySelectorAll('.bar-item');
            barras.forEach(barra => {{
                if (severidad === null) {{
                    barra.classList.remove('selected');
                }} else {{
                    const barraSeveridad = barra.querySelector('.bar-name').innerText.trim();
                    if (barraSeveridad === severidad) {{
                        barra.classList.add('selected');
                    }} else {{
                        barra.classList.remove('selected');
                    }}
                }}
            }});
            
            // Actualizar el filtro de la tabla
            const filterSelect = document.getElementById('severidadFilter');
            if (severidad === null) {{
                filterSelect.value = 'TODAS';
            }} else {{
                filterSelect.value = severidad;
            }}
            filtrarTabla();
        }}
        
        // Función para cerrar modal
        function cerrarModal() {{
            document.getElementById('inspectModal').style.display = 'none';
            document.body.style.overflow = 'auto';
        }}
        
        // Cerrar modal al hacer click fuera
        window.onclick = function(event) {{
            const modal = document.getElementById('inspectModal');
            if (event.target == modal) {{
                cerrarModal();
            }}
        }}
        
        // Cerrar modal con tecla ESC y navegar con flechas
        document.addEventListener('keydown', function(event) {{
            const modal = document.getElementById('inspectModal');
            if (modal.style.display === 'block') {{
                if (event.key === 'Escape') {{
                    cerrarModal();
                }} else if (event.key === 'ArrowLeft') {{
                    navegarVulnerabilidad(-1);
                }} else if (event.key === 'ArrowRight') {{
                    navegarVulnerabilidad(1);
                }}
            }}
        }});
        
        function filtrarTabla() {{
            var severidad = document.getElementById('severidadFilter').value;
            var busqueda = document.getElementById('searchInput').value.toLowerCase();
            var tabla = document.getElementById('tablaBody');
            var filas = tabla.getElementsByTagName('tr');
            var totalVisibles = 0;
            
            for (var i = 0; i < filas.length; i++) {{
                var fila = filas[i];
                var celdas = fila.getElementsByTagName('td');
                var mostrar = true;
                
                // Filtrar por severidad
                if (severidad !== 'TODAS') {{
                    var badge = celdas[1].querySelector('.badge');
                    if (badge) {{
                        var severidadCelda = badge.innerText.replace(/[💀🔴🟠🟢🔵]/g, '').trim();
                        if (severidadCelda !== severidad) {{
                            mostrar = false;
                        }}
                    }}
                }}
                
                // Filtrar por búsqueda
                if (busqueda !== '') {{
                    var textoFila = fila.innerText.toLowerCase();
                    if (!textoFila.includes(busqueda)) {{
                        mostrar = false;
                    }}
                }}
                
                fila.style.display = mostrar ? '' : 'none';
                if (mostrar) totalVisibles++;
            }}
            
            console.log(`[FILTRO] Mostrando ${{totalVisibles}} de ${{filas.length}} vulnerabilidades`);
        }}
        
        function filtrarPorSeveridad(severidad) {{
            var select = document.getElementById('severidadFilter');
            select.value = severidad;
            filtrarTabla();
            seleccionarSeveridad(severidad === 'TODAS' ? null : severidad);
        }}
        
        function filtrarSeccion(seccion) {{
            var input = document.getElementById('searchInput');
            input.value = seccion;
            filtrarTabla();
        }}
        
        function resetFiltros() {{
            document.getElementById('severidadFilter').value = 'TODAS';
            document.getElementById('searchInput').value = '';
            filtrarTabla();
            seleccionarSeveridad(null);
        }}
        
        function exportarCSV() {{
            var csv = [];
            var filas = document.querySelectorAll('#vulnerabilidadesTable tr');
            
            for (var i = 0; i < filas.length; i++) {{
                var fila = filas[i];
                if (i === 0 || fila.style.display !== 'none') {{
                    var celdas = fila.querySelectorAll('td, th');
                    var filaCsv = [];
                    for (var j = 0; j < celdas.length; j++) {{
                        var texto = celdas[j].innerText.replace(/"/g, '""').replace(/[💀🔴🟠🟢🔵]/g, '').trim();
                        filaCsv.push('"' + texto + '"');
                    }}
                    csv.push(filaCsv.join(','));
                }}
            }}
            
            var blob = new Blob([csv.join('\\n')], {{ type: 'text/csv' }});
            var url = window.URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = 'RulesAudit_{nombre_cliente}_{timestamp}.csv';
            a.click();
        }}
        
        function exportarHTML() {{
            var contenido = document.documentElement.outerHTML;
            var blob = new Blob([contenido], {{ type: 'text/html' }});
            var url = window.URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = 'RulesAudit_{nombre_cliente}_{timestamp}.html';
            a.click();
        }}
        
    </script>
</body>
</html>
"""
    
    return html


def generar_donut_chart(stats):
    return ""
