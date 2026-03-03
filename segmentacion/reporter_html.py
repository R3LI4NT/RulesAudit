import pandas as pd
from datetime import datetime
import json
import os

def generar_reporte_html(resultados, modo_actual, stats, cde_prefixes, cnto_prefixes, nopci_prefixes, nombre_archivo_original, ruta_salida, nombre_cliente="CLIENTE"):
    if not resultados:
        print("\n[!] No hay resultados para generar reporte HTML")
        return None
    
    df = pd.DataFrame(resultados)
    
    stats.update({
        'total': len(resultados),
        'modo': modo_actual
    })
    
    if modo_actual == "CDE → CNTO":
        titulo_modo1 = "REDES CNTO CARGADAS (MODO 1)"
        titulo_modo2 = "REDES CDE CARGADAS (MODO 1)"
        datos_modo1 = {ip: 1 for ip in cnto_prefixes}
        datos_modo2 = {ip: 1 for ip in cde_prefixes}
    elif modo_actual == "CNTO → CDE":
        titulo_modo1 = "REDES CDE CARGADAS (MODO 2)"
        titulo_modo2 = "REDES CNTO CARGADAS (MODO 2)"
        datos_modo1 = {ip: 1 for ip in cde_prefixes}
        datos_modo2 = {ip: 1 for ip in cnto_prefixes}
    else:
        titulo_modo1 = "REDES CDE/CNTO CARGADAS (MODO 3)"
        titulo_modo2 = "REDES NO-PCI CARGADAS (MODO 3)"
        combined = cde_prefixes + cnto_prefixes
        datos_modo1 = {ip: 1 for ip in combined}
        datos_modo2 = {ip: 1 for ip in nopci_prefixes}
    
    fecha_reporte = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    html_content = generar_template_html(
        resultados=resultados,
        stats=stats,
        datos_modo1=datos_modo1,
        datos_modo2=datos_modo2,
        titulo_modo1=titulo_modo1,
        titulo_modo2=titulo_modo2,
        modo_actual=modo_actual,
        nombre_archivo=nombre_archivo_original,
        fecha_reporte=fecha_reporte,
        timestamp=timestamp,
        nombre_cliente=nombre_cliente
    )
    
    with open(ruta_salida, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"\n[+] Reporte HTML generado: {ruta_salida}")
    return ruta_salida

def generar_template_html(resultados, stats, datos_modo1, datos_modo2, titulo_modo1, titulo_modo2, modo_actual, nombre_archivo, fecha_reporte, timestamp, nombre_cliente):
    tabla_resultados = ""
    for i, r in enumerate(resultados, 1):
        icono = "🟢"
        
        tipo_con_padding = r['Type'].replace('<', '&lt;').replace('>', '&gt;')
        source_con_tooltip = r['Source'].replace('<', '&lt;').replace('>', '&gt;')
        dest_con_tooltip = r['Destination'].replace('<', '&lt;').replace('>', '&gt;')
        services_con_tooltip = r['Services'].replace('<', '&lt;').replace('>', '&gt;')
        actions_con_tooltip = r['Actions'].replace('<', '&lt;').replace('>', '&gt;')
        
        row_id = f"rule_{i}"
        
        tabla_resultados += f"""
        <tr class="scan-line" id="{row_id}" onclick="inspeccionarRegla({i})">
            <td><span class="glitch-number">{i:03d}</span></td>
            <td><span class="badge badge-ok" style="padding: 6px 12px; white-space: nowrap; display: inline-block; width: auto; max-width: 100%; overflow: visible;">{icono} {tipo_con_padding}</span></td>
            <td class="matrix-text" style="padding: 12px 15px; max-width: 250px; white-space: normal; word-wrap: break-word; overflow-wrap: break-word; hyphens: auto;" title="{source_con_tooltip}">{r['Source']}</td>
            <td class="matrix-text" style="padding: 12px 15px; max-width: 250px; white-space: normal; word-wrap: break-word; overflow-wrap: break-word; hyphens: auto;" title="{dest_con_tooltip}">{r['Destination']}</td>
            <td class="matrix-text" style="padding: 12px 15px; max-width: 200px; white-space: normal; word-wrap: break-word; overflow-wrap: break-word; hyphens: auto;" title="{services_con_tooltip}">{r['Services']}</td>
            <td class="matrix-text" style="padding: 12px 15px; max-width: 150px; white-space: normal; word-wrap: break-word; overflow-wrap: break-word; hyphens: auto;" title="{actions_con_tooltip}">{r['Actions']}</td>
        </tr>
        """
    
    modo1_items = ""
    total_modo1 = len(datos_modo1)
    for i, (ip, count) in enumerate(list(datos_modo1.items())[:20], 1):
        ip_escapado = ip.replace('<', '&lt;').replace('>', '&gt;')
        modo1_items += f"""
        <div class="top-item glitch-hover" data-text="{ip_escapado}" title="{ip_escapado}">
            <div class="top-number">#{i:02d}</div>
            <div class="top-content">
                <div class="top-title glitch-text" style="white-space: normal; word-wrap: break-word; overflow-wrap: break-word;">{ip_escapado}</div>
                <div class="top-stats">
                    <span class="top-count"><i class="fas fa-network-wired"></i> Red cargada</span>
                </div>
            </div>
        </div>
        """
    
    modo2_items = ""
    total_modo2 = len(datos_modo2)
    for i, (ip, count) in enumerate(list(datos_modo2.items())[:20], 1):
        ip_escapado = ip.replace('<', '&lt;').replace('>', '&gt;')
        modo2_items += f"""
        <div class="top-item glitch-hover" data-text="{ip_escapado}" title="{ip_escapado}">
            <div class="top-number">#{i:02d}</div>
            <div class="top-content">
                <div class="top-title glitch-text" style="white-space: normal; word-wrap: break-word; overflow-wrap: break-word;">{ip_escapado}</div>
                <div class="top-stats">
                    <span class="top-count"><i class="fas fa-shield"></i> Red cargada</span>
                </div>
            </div>
        </div>
        """
    
    if not modo1_items:
        modo1_items = """
        <div class="top-item">
            <div class="top-content">
                <div class="top-title">No hay redes cargadas</div>
            </div>
        </div>
        """
    
    if not modo2_items:
        modo2_items = """
        <div class="top-item">
            <div class="top-content">
                <div class="top-title">No hay redes cargadas</div>
            </div>
        </div>
        """
    
    reglas_data = []
    for r in resultados:
        reglas_data.append({
            'type': r['Type'],
            'source': r['Source'],
            'destination': r['Destination'],
            'services': r['Services'],
            'actions': r['Actions']
        })
    
    reglas_json = json.dumps(reglas_data, ensure_ascii=False)
    
    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RulesAudit :: {nombre_cliente} :: Reporte Segmentación</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Space+Grotesk:wght@300;400;500;600;700&display=swap');
        
        :root {{
            --bg-primary: #0a0c0f;
            --bg-secondary: #15181e;
            --bg-tertiary: #1e232b;
            --text-primary: #e0e0e0;
            --text-secondary: #8b949e;
            --accent-cyan: #00ffff;
            --accent-green: #00ff9d;
            --accent-red: #ff0066;
            --accent-orange: #ffb86b;
            --accent-blue: #5fa4e6;
            --border-color: #2d333b;
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
        
        body::before {{
            content: "";
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: repeating-linear-gradient(
                0deg,
                rgba(0, 255, 157, 0.03) 0px,
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
            border: 2px solid var(--accent-green);
            box-shadow: 0 0 50px rgba(0, 255, 157, 0.3);
        }}
        
        .modal-header {{
            padding: 15px 20px;
            background: linear-gradient(135deg, #000000, #1a1f2e);
            border-bottom: 2px solid var(--accent-green);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .modal-header h2 {{
            font-family: 'Share Tech Mono', monospace;
            color: var(--accent-green);
            font-size: 1.3em;
        }}
        
        .modal-header h2 i {{
            margin-right: 10px;
            color: var(--accent-cyan);
        }}
        
        .close-modal {{
            color: var(--text-secondary);
            font-size: 2em;
            cursor: pointer;
            transition: all 0.3s;
        }}
        
        .close-modal:hover {{
            color: var(--accent-red);
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
            background: var(--accent-green);
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
        
        .modal-footer {{
            padding: 15px 20px;
            border-top: 1px solid var(--border-color);
            background: var(--bg-tertiary);
            font-family: 'Share Tech Mono', monospace;
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
            border-color: var(--accent-green);
            color: var(--accent-green);
            box-shadow: 0 0 10px var(--accent-green);
        }}
        
        .nav-button:disabled {{
            opacity: 0.3;
            cursor: not-allowed;
        }}
        
        .header {{
            background: linear-gradient(135deg, #000000, #1a1f2e);
            border: 2px solid var(--accent-green);
            padding: 30px;
            margin-bottom: 25px;
            box-shadow: 0 0 30px rgba(0, 255, 157, 0.2);
            position: relative;
            overflow: hidden;
        }}
        
        .header::before {{
            content: "TEST DE SEGMENTACIÓN - REGLAS";
            position: absolute;
            top: 10px;
            right: 20px;
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.8em;
            color: var(--accent-green);
            opacity: 0.3;
            letter-spacing: 4px;
        }}
        
        .header h1 {{
            font-size: 3em;
            font-weight: 700;
            margin-bottom: 10px;
            font-family: 'Share Tech Mono', monospace;
            text-shadow: 0 0 10px var(--accent-green);
        }}
        
        .header h1 i {{
            margin-right: 10px;
            color: var(--accent-cyan);
        }}
        
        .header .subtitle {{
            font-size: 1.1em;
            opacity: 0.8;
            font-family: 'Share Tech Mono', monospace;
            border-left: 3px solid var(--accent-green);
            padding-left: 15px;
        }}
        
        .cliente-badge {{
            background: rgba(0, 255, 157, 0.1);
            display: inline-block;
            padding: 8px 20px;
            margin: 15px 0;
            border: 1px solid var(--accent-green);
            box-shadow: 0 0 15px rgba(0, 255, 157, 0.3);
            font-family: 'Share Tech Mono', monospace;
        }}
        
        .modo-badge {{
            background: rgba(255, 182, 107, 0.1);
            display: inline-block;
            padding: 8px 20px;
            margin: 15px 0;
            border: 1px solid var(--accent-orange);
            color: var(--accent-orange);
            font-family: 'Share Tech Mono', monospace;
        }}
        
        .meta-info {{
            display: flex;
            gap: 30px;
            font-size: 0.95em;
            flex-wrap: wrap;
            border-top: 1px solid var(--border-color);
            padding-top: 15px;
            margin-top: 15px;
        }}
        
        .meta-info span {{
            background: rgba(0, 0, 0, 0.5);
            padding: 5px 15px;
            border: 1px solid var(--border-color);
        }}
        
        .meta-info i {{
            margin-right: 5px;
            color: var(--accent-green);
        }}
        
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
        
        .kpi-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 0 30px rgba(0, 255, 157, 0.2);
            border-color: var(--accent-green);
        }}
        
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
            border-color: var(--accent-green);
            box-shadow: 0 0 30px rgba(0, 255, 157, 0.1);
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
            color: var(--accent-green);
            font-family: 'Share Tech Mono', monospace;
        }}
        
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
            background: var(--accent-green);
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
        }}
        
        .top-item:hover {{
            border-color: var(--accent-green);
            transform: translateX(5px);
            background: #1e2f3f;
        }}
        
        .top-number {{
            width: 40px;
            height: 40px;
            background: #000;
            color: var(--accent-green);
            border: 1px solid var(--accent-green);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            margin-right: 15px;
            flex-shrink: 0;
            font-family: 'Share Tech Mono', monospace;
        }}
        
        .top-content {{
            flex: 1;
            min-width: 0;
        }}
        
        .top-title {{
            font-weight: 500;
            margin-bottom: 8px;
            word-wrap: break-word;
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
        }}
        
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
            color: var(--accent-green);
            margin-bottom: 5px;
            font-family: 'Share Tech Mono', monospace;
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
            border-color: var(--accent-green);
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
            cursor: pointer;
            transition: all 0.3s;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            font-family: 'Share Tech Mono', monospace;
        }}
        
        .btn-primary {{
            border-color: var(--accent-green);
            color: var(--accent-green);
        }}
        
        .btn-primary:hover {{
            background: var(--accent-green);
            color: #000;
            box-shadow: 0 0 30px var(--accent-green);
        }}
        
        .btn-secondary {{
            border-color: var(--accent-orange);
            color: var(--accent-orange);
        }}
        
        .btn-secondary:hover {{
            background: var(--accent-orange);
            color: #000;
            box-shadow: 0 0 30px var(--accent-orange);
        }}
        
        .table-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            padding: 20px;
            overflow-x: auto;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            min-width: 1000px;
            font-size: 0.9em;
            table-layout: fixed;
        }}
        
        th {{
            text-align: left;
            padding: 15px;
            background: #000;
            color: var(--accent-green);
            font-weight: 600;
            font-size: 0.9em;
            position: sticky;
            top: 0;
            border-bottom: 2px solid var(--accent-green);
            font-family: 'Share Tech Mono', monospace;
        }}
        
        th:nth-child(1) {{ width: 5%; }}
        th:nth-child(2) {{ width: 15%; }}
        th:nth-child(3) {{ width: 25%; }}
        th:nth-child(4) {{ width: 25%; }}
        th:nth-child(5) {{ width: 20%; }}
        th:nth-child(6) {{ width: 10%; }}
        
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid var(--border-color);
            color: var(--text-primary);
            cursor: pointer;
            vertical-align: top;
        }}
        
        .scan-line {{
            transition: all 0.3s;
        }}
        
        .scan-line:hover {{
            background: rgba(0, 255, 157, 0.1) !important;
            border-left: 3px solid var(--accent-green);
        }}
        
        .badge-ok {{
            background: #1a3b2e;
            color: var(--accent-green);
            border: 1px solid var(--accent-green);
            font-family: 'Share Tech Mono', monospace;
            display: inline-block;
            padding: 6px 12px;
            white-space: nowrap;
            border-radius: 4px;
            font-size: 0.9em;
            letter-spacing: 0.5px;
        }}
        
        .footer {{
            text-align: center;
            margin-top: 25px;
            padding: 20px;
            color: var(--text-secondary);
            border-top: 1px solid var(--border-color);
            font-family: 'Share Tech Mono', monospace;
        }}
        
        .footer a {{
            color: var(--accent-green);
            text-decoration: none;
        }}
        
        @media (max-width: 1200px) {{
            .kpi-grid {{
                grid-template-columns: repeat(3, 1fr);
            }}
            
            .charts-row {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div id="inspectModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2><i class="fas fa-search"></i> INSPECCIÓN DE REGLA</h2>
                <span class="close-modal" onclick="cerrarModal()">&times;</span>
            </div>
            <div class="modal-body">
                <div class="evidence-section">
                    <div class="evidence-title"><i class="fas fa-tag"></i> TIPO</div>
                    <div class="evidence-content">
                        <div class="evidence-line" id="modalType"></div>
                    </div>
                </div>
                
                <div class="evidence-section">
                    <div class="evidence-title"><i class="fas fa-network-wired"></i> SOURCE</div>
                    <div class="evidence-content">
                        <div class="evidence-line" id="modalSource"></div>
                    </div>
                </div>
                
                <div class="evidence-section">
                    <div class="evidence-title"><i class="fas fa-bullseye"></i> DESTINATION</div>
                    <div class="evidence-content">
                        <div class="evidence-line" id="modalDestination"></div>
                    </div>
                </div>
                
                <div class="evidence-section">
                    <div class="evidence-title"><i class="fas fa-cogs"></i> SERVICES</div>
                    <div class="evidence-content">
                        <div class="evidence-line" id="modalServices"></div>
                    </div>
                </div>
                
                <div class="evidence-section">
                    <div class="evidence-title"><i class="fas fa-shield-alt"></i> ACTION</div>
                    <div class="evidence-content">
                        <div class="evidence-line" id="modalActions"></div>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <div class="nav-buttons">
                    <button class="nav-button" onclick="navegarRegla(-1)" id="prevBtn" disabled>
                        <i class="fas fa-chevron-left"></i> ANTERIOR
                    </button>
                    <button class="nav-button" onclick="navegarRegla(1)" id="nextBtn">
                        SIGUIENTE <i class="fas fa-chevron-right"></i>
                    </button>
                </div>
                <div class="help-text">
                    <i class="fas fa-arrow-left"></i> <i class="fas fa-arrow-right"></i> Navegar
                </div>
            </div>
        </div>
    </div>

    <div class="container">
        <div class="header">
            <h1>
                <i class="fa-solid fa-fire"></i>
                RulesAudit
            </h1>
            <div class="subtitle">[TEST DE SEGMENTACIÓN] :: REPORTE DE REGLAS</div>
            <div class="cliente-badge">
                <i class="fas fa-user-secret"></i> CLIENTE: <strong>{nombre_cliente}</strong>
            </div>
            <div class="modo-badge">
                <i class="fas fa-arrows-left-right"></i> MODO: <strong>{modo_actual}</strong>
            </div>
            <div class="meta-info">
                <span><i class="fas fa-file-code"></i> ARCHIVO: {nombre_archivo}</span>
                <span><i class="fas fa-clock"></i> FECHA: {fecha_reporte}</span>
                <span><i class="fas fa-shield"></i> REGLAS: {stats['total']}</span>
                <span><i class="fas fa-network-wired"></i> CDE: {stats.get('cde', 0)} redes</span>
                <span><i class="fas fa-network-wired"></i> CNTO: {stats.get('cnto', 0)} redes</span>
                <span><i class="fas fa-network-wired"></i> NO-PCI: {stats.get('nopci', 0)} redes</span>
            </div>
        </div>
        
        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-header">
                    <span class="kpi-title">REGLAS ENCONTRADAS</span>
                    <span class="kpi-icon">🔍</span>
                </div>
                <div class="kpi-value">{stats['total']}</div>
            </div>
            
            <div class="kpi-card">
                <div class="kpi-header">
                    <span class="kpi-title">MODO ANÁLISIS</span>
                    <span class="kpi-icon">↹</span>
                </div>
                <div class="kpi-value" style="font-size: 1.5em;">{modo_actual}</div>
            </div>
            
            <div class="kpi-card">
                <div class="kpi-header">
                    <span class="kpi-title">REDES CDE</span>
                    <span class="kpi-icon">📡</span>
                </div>
                <div class="kpi-value">{stats.get('cde', 0)}</div>
            </div>
            
            <div class="kpi-card">
                <div class="kpi-header">
                    <span class="kpi-title">REDES CNTO</span>
                    <span class="kpi-icon">📡</span>
                </div>
                <div class="kpi-value">{stats.get('cnto', 0)}</div>
            </div>

            <div class="kpi-card">
                <div class="kpi-header">
                    <span class="kpi-title">REDES NO-PCI</span>
                    <span class="kpi-icon">📡</span>
                </div>
                <div class="kpi-value">{stats.get('nopci', 0)}</div>
            </div>
        </div>
        
        <div class="charts-row">
            <div class="chart-card">
                <div class="chart-header">
                    <h3><i class="fas fa-bullseye"></i> {titulo_modo1}</h3>
                </div>
                <div class="top-list">
                    {modo1_items}
                </div>
            </div>
            
            <div class="chart-card">
                <div class="chart-header">
                    <h3><i class="fas fa-network-wired"></i> {titulo_modo2}</h3>
                </div>
                <div class="top-list">
                    {modo2_items}
                </div>
            </div>
        </div>
        
        <div class="filters-card">
            <div class="filters-grid">
                <div class="filter-group">
                    <label><i class="fas fa-search"></i> BUSCAR</label>
                    <input type="text" id="searchInput" class="filter-input" placeholder="IP, servicio, acción..." onkeyup="filtrarTabla()">
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
        
        <div class="table-card">
            <table id="reglasTable">
                <thead>
                    <tr>
                        <th>#ID</th>
                        <th>TIPO</th>
                        <th>SOURCE</th>
                        <th>DESTINATION</th>
                        <th>SERVICES</th>
                        <th>ACTIONS</th>
                    </tr>
                </thead>
                <tbody id="tablaBody">
                    {tabla_resultados}
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>
                <i class="fas fa-copyright"></i> RulesAudit v1.0 - [SEGMENTATION ANALYZER] :: 
                | <i class="fas fa-user-secret"></i> {nombre_cliente} | <i class="fas fa-clock"></i> {fecha_reporte}
            </p>
        </div>
    </div>
    
    <script>
        const reglasData = {reglas_json};
        let currentRuleIndex = -1;
        
        function inspeccionarRegla(index) {{
            currentRuleIndex = index - 1;
            const rule = reglasData[currentRuleIndex];
            
            document.getElementById('modalType').innerHTML = `<span class="evidence-line"><strong>></strong> ${{rule.type}}</span>`;
            document.getElementById('modalSource').innerHTML = `<span class="evidence-line"><strong>></strong> ${{rule.source}}</span>`;
            document.getElementById('modalDestination').innerHTML = `<span class="evidence-line"><strong>></strong> ${{rule.destination}}</span>`;
            document.getElementById('modalServices').innerHTML = `<span class="evidence-line"><strong>></strong> ${{rule.services}}</span>`;
            document.getElementById('modalActions').innerHTML = `<span class="evidence-line"><strong>></strong> ${{rule.actions}}</span>`;
            
            document.getElementById('prevBtn').disabled = currentRuleIndex === 0;
            document.getElementById('nextBtn').disabled = currentRuleIndex === reglasData.length - 1;
            
            document.getElementById('inspectModal').style.display = 'block';
            document.body.style.overflow = 'hidden';
        }}
        
        function navegarRegla(direccion) {{
            const nuevoIndex = currentRuleIndex + direccion;
            if (nuevoIndex >= 0 && nuevoIndex < reglasData.length) {{
                currentRuleIndex = nuevoIndex;
                const rule = reglasData[currentRuleIndex];
                
                document.getElementById('modalType').innerHTML = `<span class="evidence-line"><strong>></strong> ${{rule.type}}</span>`;
                document.getElementById('modalSource').innerHTML = `<span class="evidence-line"><strong>></strong> ${{rule.source}}</span>`;
                document.getElementById('modalDestination').innerHTML = `<span class="evidence-line"><strong>></strong> ${{rule.destination}}</span>`;
                document.getElementById('modalServices').innerHTML = `<span class="evidence-line"><strong>></strong> ${{rule.services}}</span>`;
                document.getElementById('modalActions').innerHTML = `<span class="evidence-line"><strong>></strong> ${{rule.actions}}</span>`;
                
                document.getElementById('prevBtn').disabled = currentRuleIndex === 0;
                document.getElementById('nextBtn').disabled = currentRuleIndex === reglasData.length - 1;
            }}
        }}
        
        function cerrarModal() {{
            document.getElementById('inspectModal').style.display = 'none';
            document.body.style.overflow = 'auto';
        }}
        
        window.onclick = function(event) {{
            const modal = document.getElementById('inspectModal');
            if (event.target == modal) {{
                cerrarModal();
            }}
        }}
        
        document.addEventListener('keydown', function(event) {{
            const modal = document.getElementById('inspectModal');
            if (modal.style.display === 'block') {{
                if (event.key === 'Escape') {{
                    cerrarModal();
                }} else if (event.key === 'ArrowLeft') {{
                    navegarRegla(-1);
                }} else if (event.key === 'ArrowRight') {{
                    navegarRegla(1);
                }}
            }}
        }});
        
        function filtrarTabla() {{
            var busqueda = document.getElementById('searchInput').value.toLowerCase();
            var tabla = document.getElementById('tablaBody');
            var filas = tabla.getElementsByTagName('tr');
            var totalVisibles = 0;
            
            for (var i = 0; i < filas.length; i++) {{
                var fila = filas[i];
                var textoFila = fila.innerText.toLowerCase();
                var mostrar = busqueda === '' || textoFila.includes(busqueda);
                
                fila.style.display = mostrar ? '' : 'none';
                if (mostrar) totalVisibles++;
            }}
        }}
        
        function resetFiltros() {{
            document.getElementById('searchInput').value = '';
            filtrarTabla();
        }}
        
        function exportarCSV() {{
            var csv = [];
            var filas = document.querySelectorAll('#reglasTable tr');
            
            for (var i = 0; i < filas.length; i++) {{
                var fila = filas[i];
                if (i === 0 || fila.style.display !== 'none') {{
                    var celdas = fila.querySelectorAll('td, th');
                    var filaCsv = [];
                    for (var j = 0; j < celdas.length; j++) {{
                        var texto = celdas[j].innerText.replace(/"/g, '""').trim();
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
</html>"""
    
    return html