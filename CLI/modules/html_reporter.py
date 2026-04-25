import json
from datetime import datetime
from .utils import escapar_html


def generar_reporte_html(vulnerabilidades, nombre_archivo_original, ruta_salida, nombre_cliente,
                          resumen=None, score=None, compliance=None, headers_archivo=None):
    if not vulnerabilidades:
        return None

    stats = {
        'total': len(vulnerabilidades),
        'critica': sum(1 for v in vulnerabilidades if v['Severidad'] == 'CRÍTICA'),
        'alta': sum(1 for v in vulnerabilidades if v['Severidad'] == 'ALTA'),
        'media': sum(1 for v in vulnerabilidades if v['Severidad'] == 'MEDIA'),
        'baja': sum(1 for v in vulnerabilidades if v['Severidad'] == 'BAJA'),
        'informativa': sum(1 for v in vulnerabilidades if v['Severidad'] == 'INFORMATIVA')
    }

    top_tipos = {}
    for v in vulnerabilidades:
        desc = v.get('Descripción', '')[:80]
        top_tipos[desc] = top_tipos.get(desc, 0) + 1
    top_tipos = dict(sorted(top_tipos.items(), key=lambda x: x[1], reverse=True)[:10])

    secciones = {}
    for v in vulnerabilidades:
        seccion = v.get('Sección', 'General')
        secciones[seccion] = secciones.get(seccion, 0) + 1
    secciones = dict(sorted(secciones.items(), key=lambda x: x[1], reverse=True)[:10])

    categorias = {}
    for v in vulnerabilidades:
        cat = v.get('Categoria', 'otros')
        categorias[cat] = categorias.get(cat, 0) + 1

    fecha_reporte = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    html_content = _generar_template(
        stats=stats,
        vulnerabilidades=vulnerabilidades,
        top_tipos=top_tipos,
        secciones=secciones,
        categorias=categorias,
        nombre_archivo=nombre_archivo_original,
        fecha_reporte=fecha_reporte,
        timestamp=timestamp,
        nombre_cliente=nombre_cliente,
        resumen=resumen or {},
        score=score or {},
        compliance=compliance or [],
        headers_archivo=headers_archivo or []
    )

    with open(ruta_salida, 'w', encoding='utf-8') as f:
        f.write(html_content)
    return ruta_salida


def _generar_filas_tabla(vulnerabilidades):
    filas = ""
    for i, v in enumerate(vulnerabilidades, 1):
        sev_class = {
            'CRÍTICA': 'critica', 'ALTA': 'alta', 'MEDIA': 'media',
            'BAJA': 'baja', 'INFORMATIVA': 'informativa'
        }.get(v['Severidad'], '')
        icono = {
            'CRÍTICA': '💀', 'ALTA': '🔴', 'MEDIA': '🟠',
            'BAJA': '🟢', 'INFORMATIVA': '🔵'
        }.get(v['Severidad'], '')
        descripcion = escapar_html(v.get('Descripción', ''))[:120]
        filas += f"""
        <tr class="severidad-{sev_class} scan-line" id="vuln_{i}" onclick="inspeccionarVulnerabilidad({i})" data-severidad="{v['Severidad']}" data-categoria="{v.get('Categoria', 'otros')}">
            <td><span class="glitch-number">{i:03d}</span></td>
            <td><span class="vuln-id">{escapar_html(v.get('ID', 'N/A'))}</span></td>
            <td><span class="badge badge-{sev_class}">{icono} {v['Severidad']}</span></td>
            <td><span class="cvss-score cvss-{sev_class}">{v.get('CVSS', 0)}</span></td>
            <td class="matrix-text">{escapar_html(v.get('Categoria', ''))}</td>
            <td class="matrix-text">{escapar_html(v.get('Sección', ''))}</td>
            <td class="matrix-text">{escapar_html(v.get('Regla', ''))}</td>
            <td class="matrix-text">{descripcion}</td>
        </tr>
        """
    return filas


def _generar_top_items(top_tipos, total):
    html = ""
    for i, (desc, count) in enumerate(top_tipos.items(), 1):
        porcentaje = (count / total) * 100 if total > 0 else 0
        html += f"""
        <div class="top-item">
            <div class="top-number">#{i:02d}</div>
            <div class="top-content">
                <div class="top-title">{escapar_html(desc)}</div>
                <div class="top-stats">
                    <span class="top-count"><i class="fas fa-bug"></i> {count} ocurrencias</span>
                    <span class="top-percent">{porcentaje:.1f}%</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {porcentaje}%;"></div>
                </div>
            </div>
        </div>
        """
    return html


def _generar_secciones_items(secciones):
    html = ""
    for seccion, count in secciones.items():
        html += f"""
        <div class="section-chip" onclick="filtrarSeccion('{escapar_html(seccion)}')">
            <span class="section-name"><i class="fas fa-folder"></i> {escapar_html(seccion)}</span>
            <span class="section-count">{count}</span>
        </div>
        """
    return html


def _generar_barras_severidad(stats):
    bar_data = [
        {'severidad': 'CRÍTICA', 'valor': stats['critica'], 'color': '#8B0000', 'icono': '💀'},
        {'severidad': 'ALTA', 'valor': stats['alta'], 'color': '#FF0000', 'icono': '🔴'},
        {'severidad': 'MEDIA', 'valor': stats['media'], 'color': '#FFA500', 'icono': '🟠'},
        {'severidad': 'BAJA', 'valor': stats['baja'], 'color': '#00FF00', 'icono': '🟢'},
        {'severidad': 'INFORMATIVA', 'valor': stats['informativa'], 'color': '#0088FF', 'icono': '🔵'}
    ]
    bar_data.sort(key=lambda x: x['valor'], reverse=True)
    max_valor = max([d['valor'] for d in bar_data]) if bar_data else 1

    html = ""
    for item in bar_data:
        porcentaje = (item['valor'] / stats['total'] * 100) if stats['total'] > 0 else 0
        ancho = (item['valor'] / max_valor * 100) if max_valor > 0 else 0
        html += f"""
        <div class="bar-item" onclick="seleccionarSeveridad('{item['severidad']}')">
            <div class="bar-label">
                <span class="bar-icon">{item['icono']}</span>
                <span class="bar-name">{item['severidad']}</span>
                <span class="bar-value">{item['valor']}</span>
                <span class="bar-percent">({porcentaje:.1f}%)</span>
            </div>
            <div class="bar-container">
                <div class="bar-fill" style="width: {ancho}%; background-color: {item['color']}; box-shadow: 0 0 15px {item['color']};"></div>
            </div>
        </div>
        """
    return html


def _generar_categorias_html(categorias, total):
    iconos = {
        'exposicion': 'fa-globe',
        'cifrado': 'fa-unlock',
        'gestion': 'fa-server',
        'base_datos': 'fa-database',
        'higiene': 'fa-broom',
        'observabilidad': 'fa-eye',
        'segmentacion': 'fa-network-wired',
        'egreso': 'fa-arrow-right-from-bracket',
        'malware': 'fa-biohazard',
        'compliance': 'fa-clipboard-check',
        'otros': 'fa-circle-info'
    }
    html = ""
    for cat, count in sorted(categorias.items(), key=lambda x: x[1], reverse=True):
        porcentaje = (count / total * 100) if total > 0 else 0
        icono = iconos.get(cat, 'fa-circle-info')
        html += f"""
        <div class="cat-item">
            <div class="cat-icon"><i class="fas {icono}"></i></div>
            <div class="cat-info">
                <div class="cat-name">{cat.replace('_', ' ').title()}</div>
                <div class="cat-count">{count} <small>({porcentaje:.1f}%)</small></div>
            </div>
        </div>
        """
    return html


def _generar_compliance_html(compliance):
    if not compliance:
        return '<div class="compliance-ok"><i class="fas fa-check-circle"></i> No se detectaron incumplimientos directos en los marcos evaluados</div>'
    html = ""
    for marco in compliance:
        controles = marco.get('controles_incumplidos', [])
        html += f"""
        <div class="compliance-item">
            <div class="compliance-marco">
                <i class="fas fa-clipboard-check"></i> {escapar_html(marco.get('marco', ''))}
            </div>
            <div class="compliance-desc">{escapar_html(marco.get('descripcion', ''))}</div>
            <div class="compliance-controles">
                {''.join(f'<span class="control-badge">{escapar_html(c)}</span>' for c in controles)}
            </div>
        </div>
        """
    return html


def _generar_score_html(score):
    if not score:
        return ''
    grado = score.get('grado', 'A')
    nivel = score.get('nivel', 'BAJO')
    color = score.get('color', '#00FF00')
    valor = score.get('score', 0)
    desc = score.get('descripcion', '')
    return f"""
    <div class="score-card" style="border-color: {color}; box-shadow: 0 0 30px {color}33;">
        <div class="score-grado" style="color: {color}; text-shadow: 0 0 20px {color};">{grado}</div>
        <div class="score-body">
            <div class="score-valor">{valor}<span class="score-max">/100</span></div>
            <div class="score-nivel" style="color: {color};">{nivel}</div>
            <div class="score-desc">{escapar_html(desc)}</div>
        </div>
    </div>
    """


def _generar_template(stats, vulnerabilidades, top_tipos, secciones, categorias,
                       nombre_archivo, fecha_reporte, timestamp, nombre_cliente,
                       resumen, score, compliance, headers_archivo):

    tabla_vulnerabilidades = _generar_filas_tabla(vulnerabilidades)
    top_items = _generar_top_items(top_tipos, stats['total'])
    secciones_items = _generar_secciones_items(secciones)
    barras_html = _generar_barras_severidad(stats)
    categorias_html = _generar_categorias_html(categorias, stats['total'])
    compliance_html = _generar_compliance_html(compliance)
    score_html = _generar_score_html(score)

    vuln_data = []
    for v in vulnerabilidades:
        vuln_data.append({
            'id': v.get('ID', 'N/A'),
            'severidad': v['Severidad'],
            'cvss': v.get('CVSS', 0),
            'tipo': v.get('Tipo', ''),
            'categoria': v.get('Categoria', ''),
            'seccion': v.get('Sección', ''),
            'regla': v.get('Regla', ''),
            'descripcion': v.get('Descripción', ''),
            'recomendacion': v.get('Recomendación', ''),
            'referencias': v.get('Referencias', []),
            'evidencia': v.get('Evidencia', {})
        })
    vuln_json = json.dumps(vuln_data, ensure_ascii=False)
    headers_json = json.dumps(headers_archivo, ensure_ascii=False)

    total_reglas = resumen.get('total_reglas', 0)
    reglas_afectadas = resumen.get('reglas_afectadas', 0)
    cvss_prom = resumen.get('cvss_promedio', 0)
    formato_det = resumen.get('formato_detectado', 'N/A')

    return _CSS_Y_HTML.format(
        nombre_cliente=escapar_html(nombre_cliente),
        nombre_archivo=escapar_html(nombre_archivo),
        fecha_reporte=fecha_reporte,
        timestamp=timestamp,
        total=stats['total'],
        critica=stats['critica'],
        alta=stats['alta'],
        media=stats['media'],
        baja=stats['baja'],
        informativa=stats['informativa'],
        total_reglas=total_reglas,
        reglas_afectadas=reglas_afectadas,
        cvss_prom=cvss_prom,
        formato_det=escapar_html(formato_det),
        tabla_vulnerabilidades=tabla_vulnerabilidades,
        top_items=top_items,
        secciones_items=secciones_items,
        barras_html=barras_html,
        categorias_html=categorias_html,
        compliance_html=compliance_html,
        score_html=score_html,
        vuln_json=vuln_json,
        headers_json=headers_json
    )


_CSS_Y_HTML = r"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RulesAudit v2.1 :: {nombre_cliente} :: Reporte</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="icon" type="image/x-icon" href="https://raw.githubusercontent.com/R3LI4NT/RulesAudit/refs/heads/main/img/favicon.ico">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Space+Grotesk:wght@300;400;500;600;700&display=swap');

        :root {{
            --bg-primary: #0a0c0f;
            --bg-secondary: #15181e;
            --bg-tertiary: #1e232b;
            --bg-evidence: #0d1117;
            --text-primary: #e0e0e0;
            --text-secondary: #8b949e;
            --accent-cyan: #00ffff;
            --accent-green: #00ff00;
            --accent-red: #ff0000;
            --accent-orange: #ff7700;
            --accent-yellow: #ffff00;
            --accent-blue: #0088ff;
            --accent-purple: #bd00ff;
            --border-color: #2d333b;
        }}

        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

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
            top: 0; left: 0;
            width: 100%; height: 100%;
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

        .header {{
            background: linear-gradient(135deg, #000000, #0a1f2e);
            border: 2px solid var(--accent-cyan);
            padding: 30px;
            margin-bottom: 25px;
            position: relative;
            overflow: hidden;
        }}

        .header::before {{
            content: "";
            position: absolute;
            top: 0; left: 0;
            width: 4px;
            height: 100%;
            background: linear-gradient(180deg, var(--accent-cyan), var(--accent-green));
            box-shadow: 0 0 20px var(--accent-cyan);
        }}

        .header h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
            color: var(--accent-cyan);
            font-family: 'Share Tech Mono', monospace;
            text-shadow: 0 0 15px var(--accent-cyan);
        }}

        .header-meta {{
            display: flex;
            gap: 30px;
            flex-wrap: wrap;
            margin-top: 15px;
            color: var(--text-secondary);
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.95rem;
        }}

        .header-meta span {{ display: flex; align-items: center; gap: 8px; }}
        .header-meta i {{ color: var(--accent-green); }}

        .dashboard-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 25px;
        }}

        .panel {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            padding: 20px;
            position: relative;
        }}

        .panel-title {{
            font-size: 1.1rem;
            color: var(--accent-cyan);
            margin-bottom: 15px;
            font-family: 'Share Tech Mono', monospace;
            text-transform: uppercase;
            letter-spacing: 2px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
        }}

        .panel-title i {{ margin-right: 10px; }}

        .score-card {{
            display: flex;
            align-items: center;
            gap: 30px;
            padding: 25px;
            background: var(--bg-secondary);
            border: 3px solid;
            margin-bottom: 25px;
        }}

        .score-grado {{
            font-size: 6rem;
            font-weight: 900;
            font-family: 'Share Tech Mono', monospace;
            line-height: 1;
        }}

        .score-body {{ flex: 1; }}
        .score-valor {{
            font-size: 3rem;
            font-weight: 700;
            font-family: 'Share Tech Mono', monospace;
            color: var(--text-primary);
        }}
        .score-max {{ font-size: 1.2rem; color: var(--text-secondary); }}
        .score-nivel {{
            font-size: 1.3rem;
            font-weight: 700;
            margin-top: 5px;
            font-family: 'Share Tech Mono', monospace;
            text-transform: uppercase;
        }}
        .score-desc {{ color: var(--text-secondary); margin-top: 10px; }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}

        .stat-box {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-left: 4px solid var(--accent-cyan);
            padding: 20px;
            transition: transform 0.2s;
        }}

        .stat-box:hover {{ transform: translateY(-2px); }}
        .stat-box.critica {{ border-left-color: #8B0000; }}
        .stat-box.alta {{ border-left-color: #FF0000; }}
        .stat-box.media {{ border-left-color: #FFA500; }}
        .stat-box.baja {{ border-left-color: #00FF00; }}
        .stat-box.info {{ border-left-color: #0088FF; }}

        .stat-value {{
            font-size: 2.2rem;
            font-weight: 700;
            font-family: 'Share Tech Mono', monospace;
            color: var(--text-primary);
        }}

        .stat-label {{
            font-size: 0.85rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 5px;
        }}

        .bar-item {{
            margin-bottom: 12px;
            cursor: pointer;
            transition: transform 0.2s;
        }}
        .bar-item:hover {{ transform: translateX(5px); }}

        .bar-label {{
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 0.9rem;
            margin-bottom: 5px;
            font-family: 'Share Tech Mono', monospace;
        }}
        .bar-icon {{ font-size: 1.1rem; }}
        .bar-name {{ flex: 1; font-weight: 600; }}
        .bar-value {{ font-weight: 700; color: var(--accent-cyan); }}
        .bar-percent {{ color: var(--text-secondary); font-size: 0.85rem; }}

        .bar-container {{
            background: var(--bg-tertiary);
            height: 10px;
            border-radius: 2px;
            overflow: hidden;
        }}
        .bar-fill {{
            height: 100%;
            transition: width 0.8s ease;
        }}

        .categorias-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
        }}

        .cat-item {{
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            padding: 15px;
            display: flex;
            gap: 12px;
            align-items: center;
            transition: all 0.2s;
        }}
        .cat-item:hover {{
            border-color: var(--accent-cyan);
            box-shadow: 0 0 15px rgba(0, 255, 255, 0.2);
        }}
        .cat-icon {{
            font-size: 1.8rem;
            color: var(--accent-cyan);
            width: 40px;
            text-align: center;
        }}
        .cat-name {{
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.9rem;
            color: var(--text-primary);
        }}
        .cat-count {{
            font-size: 1.3rem;
            font-weight: 700;
            color: var(--accent-green);
        }}
        .cat-count small {{
            font-size: 0.75rem;
            color: var(--text-secondary);
            font-weight: normal;
        }}

        .top-item {{
            background: var(--bg-tertiary);
            border-left: 3px solid var(--accent-cyan);
            padding: 12px 15px;
            margin-bottom: 10px;
            display: flex;
            gap: 15px;
        }}
        .top-number {{
            font-family: 'Share Tech Mono', monospace;
            font-size: 1.2rem;
            color: var(--accent-green);
            font-weight: 700;
        }}
        .top-content {{ flex: 1; }}
        .top-title {{
            font-size: 0.9rem;
            margin-bottom: 8px;
            color: var(--text-primary);
        }}
        .top-stats {{
            display: flex;
            justify-content: space-between;
            font-size: 0.8rem;
            color: var(--text-secondary);
            margin-bottom: 6px;
        }}
        .top-count {{ font-family: 'Share Tech Mono', monospace; }}
        .progress-bar {{
            background: var(--bg-primary);
            height: 4px;
            border-radius: 2px;
            overflow: hidden;
        }}
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, var(--accent-green), var(--accent-red));
            transition: width 0.8s;
        }}

        .section-chip {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            padding: 8px 14px;
            margin: 4px;
            cursor: pointer;
            transition: all 0.2s;
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.85rem;
        }}
        .section-chip:hover {{
            border-color: var(--accent-cyan);
            box-shadow: 0 0 10px rgba(0, 255, 255, 0.3);
        }}
        .section-name i {{ color: var(--accent-green); }}
        .section-count {{
            background: var(--accent-cyan);
            color: var(--bg-primary);
            padding: 2px 8px;
            font-weight: 700;
            border-radius: 2px;
        }}

        .filters-bar {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            padding: 15px 20px;
            margin-bottom: 15px;
            display: flex;
            gap: 15px;
            align-items: center;
            flex-wrap: wrap;
        }}

        .filter-input {{
            flex: 1;
            min-width: 250px;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 10px 14px;
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.9rem;
        }}
        .filter-input:focus {{
            outline: none;
            border-color: var(--accent-cyan);
            box-shadow: 0 0 10px rgba(0, 255, 255, 0.3);
        }}

        .filter-select {{
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 10px 14px;
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.9rem;
            cursor: pointer;
        }}

        .filter-count {{
            color: var(--accent-green);
            font-family: 'Share Tech Mono', monospace;
            font-weight: 700;
        }}

        .btn-reset {{
            background: transparent;
            border: 1px solid var(--accent-orange);
            color: var(--accent-orange);
            padding: 8px 16px;
            cursor: pointer;
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.85rem;
            transition: all 0.2s;
        }}
        .btn-reset:hover {{
            background: var(--accent-orange);
            color: var(--bg-primary);
        }}

        .table-wrapper {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            overflow-x: auto;
        }}

        .vuln-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }}

        .vuln-table thead {{
            background: linear-gradient(135deg, #000000, #0a1f2e);
            position: sticky;
            top: 0;
            z-index: 10;
        }}

        .vuln-table th {{
            padding: 14px 12px;
            text-align: left;
            color: var(--accent-cyan);
            font-family: 'Share Tech Mono', monospace;
            text-transform: uppercase;
            letter-spacing: 1px;
            border-bottom: 2px solid var(--accent-cyan);
            font-size: 0.85rem;
        }}

        .vuln-table tbody tr {{
            border-bottom: 1px solid var(--border-color);
            cursor: pointer;
            transition: background 0.15s;
        }}

        .vuln-table tbody tr:hover {{
            background: rgba(0, 255, 255, 0.05);
        }}

        .vuln-table td {{
            padding: 12px;
            color: var(--text-primary);
            vertical-align: top;
        }}

        .glitch-number {{
            font-family: 'Share Tech Mono', monospace;
            color: var(--accent-green);
            font-weight: 700;
        }}

        .vuln-id {{
            font-family: 'Share Tech Mono', monospace;
            color: var(--accent-purple);
            font-size: 0.82rem;
            background: rgba(189, 0, 255, 0.1);
            padding: 2px 6px;
            border: 1px solid rgba(189, 0, 255, 0.3);
        }}

        .cvss-score {{
            display: inline-block;
            min-width: 40px;
            text-align: center;
            padding: 3px 8px;
            font-family: 'Share Tech Mono', monospace;
            font-weight: 700;
            font-size: 0.9rem;
            border-radius: 2px;
        }}
        .cvss-critica {{ background: #8B0000; color: white; }}
        .cvss-alta {{ background: #FF0000; color: white; }}
        .cvss-media {{ background: #FFA500; color: black; }}
        .cvss-baja {{ background: #90EE90; color: black; }}
        .cvss-informativa {{ background: #87CEEB; color: black; }}

        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 2px;
            font-weight: 700;
            font-size: 0.82rem;
            font-family: 'Share Tech Mono', monospace;
            letter-spacing: 1px;
        }}
        .badge-critica {{ background: #8B0000; color: white; box-shadow: 0 0 10px rgba(139, 0, 0, 0.6); }}
        .badge-alta {{ background: #FF0000; color: white; box-shadow: 0 0 10px rgba(255, 0, 0, 0.6); }}
        .badge-media {{ background: #FFA500; color: black; }}
        .badge-baja {{ background: #00FF00; color: black; }}
        .badge-informativa {{ background: #0088FF; color: white; }}

        .matrix-text {{
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.85rem;
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
        }}

        .modal {{
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0; top: 0;
            width: 100%; height: 100%;
            background-color: rgba(0, 0, 0, 0.92);
            backdrop-filter: blur(6px);
            overflow-y: auto;
            padding: 20px;
        }}

        .modal.show {{
            display: block;
            animation: modalFadeIn 0.25s;
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
            width: 95%;
            max-width: 1000px;
            border: 2px solid var(--accent-cyan);
            box-shadow: 0 0 60px rgba(0, 255, 255, 0.4);
        }}

        .modal-header {{
            padding: 20px 25px;
            background: linear-gradient(135deg, #000000, #0a1f2e);
            border-bottom: 2px solid var(--accent-cyan);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .modal-header h2 {{
            color: var(--accent-cyan);
            font-family: 'Share Tech Mono', monospace;
            font-size: 1.3rem;
            text-shadow: 0 0 10px var(--accent-cyan);
        }}

        .close-modal {{
            color: var(--accent-red);
            font-size: 2rem;
            cursor: pointer;
            transition: transform 0.2s;
            font-weight: 700;
            line-height: 1;
        }}
        .close-modal:hover {{ transform: rotate(90deg); text-shadow: 0 0 10px var(--accent-red); }}

        .modal-body {{
            padding: 25px;
            max-height: calc(100vh - 220px);
            overflow-y: auto;
        }}

        .modal-body::-webkit-scrollbar {{ width: 8px; }}
        .modal-body::-webkit-scrollbar-track {{ background: var(--bg-primary); }}
        .modal-body::-webkit-scrollbar-thumb {{ background: var(--accent-cyan); border-radius: 4px; }}

        .modal-nav-info {{
            display: flex;
            justify-content: space-between;
            background: var(--bg-tertiary);
            padding: 10px 20px;
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.9rem;
            color: var(--text-secondary);
            border-bottom: 1px solid var(--border-color);
        }}

        .evidence-section {{
            background: var(--bg-evidence);
            border: 1px solid var(--border-color);
            border-left: 3px solid var(--accent-cyan);
            margin-bottom: 18px;
            padding: 14px 16px;
        }}

        .evidence-title {{
            color: var(--accent-cyan);
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .evidence-title i {{ color: var(--accent-green); }}

        .evidence-line {{
            color: var(--text-primary);
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.95rem;
            padding: 6px 0;
            word-break: break-word;
        }}

        .evidence-line strong {{
            color: var(--accent-green);
            margin-right: 8px;
        }}

        .rule-evidence-box {{
            background: #000000;
            border: 2px solid var(--accent-green);
            padding: 20px;
            position: relative;
            margin-top: 10px;
            box-shadow: inset 0 0 20px rgba(0, 255, 0, 0.1);
        }}

        .rule-evidence-box::before {{
            content: "RULE EVIDENCE";
            position: absolute;
            top: -12px;
            left: 15px;
            background: var(--bg-primary);
            padding: 0 10px;
            color: var(--accent-green);
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.75rem;
            letter-spacing: 2px;
        }}

        .rule-fields-table {{
            width: 100%;
            border-collapse: collapse;
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.9rem;
        }}

        .rule-fields-table tr {{
            border-bottom: 1px dashed rgba(0, 255, 0, 0.15);
        }}

        .rule-fields-table tr:last-child {{
            border-bottom: none;
        }}

        .rule-fields-table td {{
            padding: 10px 8px;
            vertical-align: top;
        }}

        .rule-field-name {{
            color: var(--accent-green);
            font-weight: 700;
            width: 28%;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-size: 0.82rem;
        }}

        .rule-field-name::before {{
            content: "> ";
            color: var(--accent-cyan);
        }}

        .rule-field-value {{
            color: var(--text-primary);
            word-break: break-word;
            padding-left: 15px;
        }}

        .rule-field-value.empty {{
            color: var(--text-secondary);
            font-style: italic;
            opacity: 0.6;
        }}

        .rule-field-value.highlight {{
            color: var(--accent-red);
            font-weight: 700;
            text-shadow: 0 0 5px var(--accent-red);
        }}

        .rule-field-value.accept {{
            color: var(--accent-green);
            font-weight: 700;
        }}

        .rule-field-value.deny {{
            color: var(--accent-red);
            font-weight: 700;
        }}

        .copy-btn {{
            position: absolute;
            top: 10px;
            right: 10px;
            background: transparent;
            border: 1px solid var(--accent-cyan);
            color: var(--accent-cyan);
            padding: 4px 10px;
            cursor: pointer;
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.75rem;
            transition: all 0.2s;
        }}
        .copy-btn:hover {{
            background: var(--accent-cyan);
            color: var(--bg-primary);
        }}

        .ref-badges {{
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            margin-top: 8px;
        }}

        .ref-badge {{
            background: rgba(189, 0, 255, 0.1);
            border: 1px solid var(--accent-purple);
            color: var(--accent-purple);
            padding: 3px 10px;
            font-size: 0.78rem;
            font-family: 'Share Tech Mono', monospace;
        }}

        .modal-footer {{
            padding: 15px 25px;
            background: var(--bg-tertiary);
            border-top: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }}

        .nav-buttons {{ display: flex; gap: 10px; }}

        .nav-button {{
            background: transparent;
            border: 1px solid var(--accent-cyan);
            color: var(--accent-cyan);
            padding: 8px 18px;
            cursor: pointer;
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            transition: all 0.2s;
        }}

        .nav-button:hover:not(:disabled) {{
            background: var(--accent-cyan);
            color: var(--bg-primary);
            box-shadow: 0 0 15px var(--accent-cyan);
        }}

        .nav-button:disabled {{
            opacity: 0.3;
            cursor: not-allowed;
        }}

        .help-text {{
            color: var(--text-secondary);
            font-size: 0.8rem;
            font-family: 'Share Tech Mono', monospace;
        }}

        .compliance-item {{
            background: var(--bg-tertiary);
            border-left: 3px solid var(--accent-yellow);
            padding: 12px 16px;
            margin-bottom: 12px;
        }}

        .compliance-marco {{
            color: var(--accent-yellow);
            font-family: 'Share Tech Mono', monospace;
            font-weight: 700;
            margin-bottom: 6px;
        }}

        .compliance-desc {{
            color: var(--text-secondary);
            font-size: 0.85rem;
            margin-bottom: 8px;
        }}

        .compliance-controles {{
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }}

        .control-badge {{
            background: rgba(255, 255, 0, 0.1);
            border: 1px solid var(--accent-yellow);
            color: var(--accent-yellow);
            padding: 3px 10px;
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.78rem;
        }}

        .compliance-ok {{
            color: var(--accent-green);
            padding: 15px;
            background: rgba(0, 255, 0, 0.08);
            border: 1px solid var(--accent-green);
            font-family: 'Share Tech Mono', monospace;
        }}

        .footer {{
            text-align: center;
            padding: 30px;
            margin-top: 30px;
            border-top: 1px solid var(--border-color);
            color: var(--text-secondary);
            font-family: 'Share Tech Mono', monospace;
        }}

        .footer-logo {{
            color: var(--accent-cyan);
            font-size: 1.3rem;
            margin-bottom: 10px;
            font-weight: 700;
        }}

        .severidad-critica {{ background: rgba(139, 0, 0, 0.08); }}
        .severidad-alta {{ background: rgba(255, 0, 0, 0.06); }}
        .severidad-media {{ background: rgba(255, 165, 0, 0.05); }}
        .severidad-baja {{ background: rgba(0, 255, 0, 0.04); }}
        .severidad-informativa {{ background: rgba(0, 136, 255, 0.04); }}

        @media (max-width: 900px) {{
            .dashboard-grid {{ grid-template-columns: 1fr; }}
            .header h1 {{ font-size: 1.8rem; }}
            .score-card {{ flex-direction: column; text-align: center; }}
            .score-grado {{ font-size: 4rem; }}
            .rule-field-name {{ width: 40%; }}
        }}
    </style>
</head>
<body>
    <div class="modal" id="inspectModal">
        <div class="modal-content">
            <div class="modal-header">
                <h2><i class="fas fa-search"></i> INSPECCION DE VULNERABILIDAD</h2>
                <span class="close-modal" onclick="cerrarModal()">&times;</span>
            </div>
            <div class="modal-nav-info">
                <span id="modalVulnIdDisplay"></span>
                <span id="modalCounter"></span>
            </div>
            <div class="modal-body">
                <div class="evidence-section">
                    <div class="evidence-title"><i class="fas fa-fingerprint"></i> IDENTIFICADOR</div>
                    <div id="modalId" class="evidence-line"></div>
                </div>

                <div class="evidence-section">
                    <div class="evidence-title"><i class="fas fa-tag"></i> SEVERIDAD Y SCORE</div>
                    <div id="modalSeveridad" class="evidence-line"></div>
                </div>

                <div class="evidence-section">
                    <div class="evidence-title"><i class="fas fa-code-branch"></i> TIPO Y CATEGORIA</div>
                    <div id="modalTipo" class="evidence-line"></div>
                </div>

                <div class="evidence-section">
                    <div class="evidence-title"><i class="fas fa-folder"></i> SECCION / REGLA</div>
                    <div id="modalSeccionRegla" class="evidence-line"></div>
                </div>

                <div class="evidence-section">
                    <div class="evidence-title"><i class="fas fa-exclamation-triangle"></i> DESCRIPCION</div>
                    <div id="modalDescripcion" class="evidence-line"></div>
                </div>

                <div class="evidence-section">
                    <div class="evidence-title"><i class="fas fa-tools"></i> RECOMENDACION</div>
                    <div id="modalRecomendacion" class="evidence-line"></div>
                </div>

                <div class="evidence-section" id="modalReferenciasSection" style="display:none;">
                    <div class="evidence-title"><i class="fas fa-link"></i> REFERENCIAS</div>
                    <div id="modalReferencias" class="ref-badges"></div>
                </div>

                <div class="evidence-section">
                    <div class="evidence-title"><i class="fas fa-file-code"></i> REGLA COMPLETA DEL ARCHIVO (EVIDENCIA)</div>
                    <div class="rule-evidence-box">
                        <button class="copy-btn" onclick="copiarEvidencia()"><i class="fas fa-copy"></i> COPIAR</button>
                        <table class="rule-fields-table" id="modalEvidenciaTabla"></table>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <div class="nav-buttons">
                    <button class="nav-button" onclick="navegarVulnerabilidad(-1)" id="prevBtn">
                        <i class="fas fa-chevron-left"></i> ANTERIOR
                    </button>
                    <button class="nav-button" onclick="navegarVulnerabilidad(1)" id="nextBtn">
                        SIGUIENTE <i class="fas fa-chevron-right"></i>
                    </button>
                </div>
                <div class="help-text">
                    <i class="fas fa-keyboard"></i> ESC para cerrar | &larr; &rarr; navegar
                </div>
            </div>
        </div>
    </div>

    <div class="container">
        <div class="header">
            <h1><i class="fa-solid fa-fire"></i> RulesAudit :: v2.1</h1>
            <div class="header-meta">
                <span><i class="fas fa-user-shield"></i> Cliente: <strong>{nombre_cliente}</strong></span>
                <span><i class="fas fa-file"></i> Archivo: {nombre_archivo}</span>
                <span><i class="fas fa-clock"></i> {fecha_reporte}</span>
                <span><i class="fas fa-fingerprint"></i> {timestamp}</span>
                <span><i class="fas fa-table"></i> Formato: {formato_det}</span>
            </div>
        </div>

        {score_html}

        <div class="stats-grid">
            <div class="stat-box critica">
                <div class="stat-value">{critica}</div>
                <div class="stat-label">Criticas</div>
            </div>
            <div class="stat-box alta">
                <div class="stat-value">{alta}</div>
                <div class="stat-label">Altas</div>
            </div>
            <div class="stat-box media">
                <div class="stat-value">{media}</div>
                <div class="stat-label">Medias</div>
            </div>
            <div class="stat-box baja">
                <div class="stat-value">{baja}</div>
                <div class="stat-label">Bajas</div>
            </div>
            <div class="stat-box info">
                <div class="stat-value">{informativa}</div>
                <div class="stat-label">Informativas</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{total}</div>
                <div class="stat-label">Total Hallazgos</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{total_reglas}</div>
                <div class="stat-label">Reglas Totales</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{reglas_afectadas}</div>
                <div class="stat-label">Reglas Afectadas</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{cvss_prom}</div>
                <div class="stat-label">CVSS Promedio</div>
            </div>
        </div>

        <div class="dashboard-grid">
            <div class="panel">
                <div class="panel-title"><i class="fas fa-chart-bar"></i> Distribucion por Severidad</div>
                {barras_html}
            </div>
            <div class="panel">
                <div class="panel-title"><i class="fas fa-sitemap"></i> Distribucion por Categoria</div>
                <div class="categorias-grid">{categorias_html}</div>
            </div>
        </div>

        <div class="dashboard-grid">
            <div class="panel">
                <div class="panel-title"><i class="fas fa-trophy"></i> Top 10 Vulnerabilidades</div>
                {top_items}
            </div>
            <div class="panel">
                <div class="panel-title"><i class="fas fa-folder-tree"></i> Secciones Afectadas</div>
                <div>{secciones_items}</div>
            </div>
        </div>

        <div class="filters-bar">
            <input type="text" id="filterText" class="filter-input" placeholder="Buscar en vulnerabilidades..." oninput="aplicarFiltros()">
            <select id="filterSeveridad" class="filter-select" onchange="aplicarFiltros()">
                <option value="">Todas las severidades</option>
                <option value="CRÍTICA">Criticas</option>
                <option value="ALTA">Altas</option>
                <option value="MEDIA">Medias</option>
                <option value="BAJA">Bajas</option>
                <option value="INFORMATIVA">Informativas</option>
            </select>
            <select id="filterCategoria" class="filter-select" onchange="aplicarFiltros()">
                <option value="">Todas las categorias</option>
                <option value="exposicion">Exposicion</option>
                <option value="cifrado">Cifrado</option>
                <option value="gestion">Gestion</option>
                <option value="base_datos">Bases de Datos</option>
                <option value="higiene">Higiene</option>
                <option value="observabilidad">Observabilidad</option>
                <option value="segmentacion">Segmentacion</option>
                <option value="egreso">Egreso</option>
                <option value="malware">Malware</option>
            </select>
            <span class="filter-count" id="filterCount">{total} visibles</span>
            <button class="btn-reset" onclick="resetFiltros()"><i class="fas fa-times"></i> RESET</button>
        </div>

        <div class="table-wrapper">
            <table class="vuln-table" id="vulnTable">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>ID</th>
                        <th>Severidad</th>
                        <th>CVSS</th>
                        <th>Categoria</th>
                        <th>Seccion</th>
                        <th>Regla</th>
                        <th>Descripcion</th>
                    </tr>
                </thead>
                <tbody>
                    {tabla_vulnerabilidades}
                </tbody>
            </table>
        </div>

        <div class="footer">
            <div class="footer-logo"><i class="fa-solid fa-fire"></i> RulesAudit v2.1</div>
            <p>Reporte generado por el motor de analisis de vulnerabilidades de firewall</p>
            <p style="margin-top:10px; opacity:0.6;">Inspeccion profunda | Evidencia granular | CVSS scoring</p>
        </div>
    </div>

    <script>
        const vulnData = {vuln_json};
        const headersArchivo = {headers_json};
        let currentIndex = -1;
        let filteredIndices = vulnData.map((_, i) => i);

        function inspeccionarVulnerabilidad(numeroFila) {{
            currentIndex = numeroFila - 1;
            renderizarModal();
            document.getElementById('inspectModal').classList.add('show');
            document.body.style.overflow = 'hidden';
        }}

        function renderizarModal() {{
            const v = vulnData[currentIndex];
            if (!v) return;

            const colores = {{
                'CRÍTICA': '#8B0000', 'ALTA': '#FF0000', 'MEDIA': '#FFA500',
                'BAJA': '#00FF00', 'INFORMATIVA': '#0088FF'
            }};
            const iconos = {{
                'CRÍTICA': '💀', 'ALTA': '🔴', 'MEDIA': '🟠',
                'BAJA': '🟢', 'INFORMATIVA': '🔵'
            }};
            const color = colores[v.severidad] || '#ffffff';
            const icono = iconos[v.severidad] || '';

            document.getElementById('modalVulnIdDisplay').textContent = 'VULN-' + String(currentIndex + 1).padStart(3, '0');
            document.getElementById('modalCounter').textContent = (currentIndex + 1) + ' / ' + vulnData.length;

            document.getElementById('modalId').innerHTML = '<strong>&gt;</strong> ' + escaparHTML(v.id);
            document.getElementById('modalSeveridad').innerHTML =
                '<span style="color:' + color + ';font-weight:700;text-shadow:0 0 10px ' + color + ';">' +
                icono + ' ' + v.severidad + '</span>' +
                ' <span style="margin-left:20px;color:var(--accent-cyan);">CVSS: <strong>' + v.cvss + '</strong></span>';
            document.getElementById('modalTipo').innerHTML = '<strong>&gt;</strong> ' + escaparHTML(v.tipo) +
                ' <span style="color:var(--text-secondary);margin-left:15px;">(' + escaparHTML(v.categoria) + ')</span>';
            document.getElementById('modalSeccionRegla').innerHTML = '<strong>&gt;</strong> Seccion: ' + escaparHTML(v.seccion) +
                '<br><strong>&gt;</strong> Regla: ' + escaparHTML(v.regla);
            document.getElementById('modalDescripcion').innerHTML = '<strong>&gt;</strong> ' + escaparHTML(v.descripcion);
            document.getElementById('modalRecomendacion').innerHTML = '<strong>&gt;</strong> ' + escaparHTML(v.recomendacion);

            const refSection = document.getElementById('modalReferenciasSection');
            const refContainer = document.getElementById('modalReferencias');
            if (v.referencias && v.referencias.length > 0) {{
                refContainer.innerHTML = v.referencias.map(r =>
                    '<span class="ref-badge">' + escaparHTML(r) + '</span>'
                ).join('');
                refSection.style.display = 'block';
            }} else {{
                refSection.style.display = 'none';
            }}

            renderizarEvidencia(v.evidencia);

            document.getElementById('prevBtn').disabled = currentIndex === 0;
            document.getElementById('nextBtn').disabled = currentIndex === vulnData.length - 1;
        }}

        function renderizarEvidencia(evidencia) {{
            const tabla = document.getElementById('modalEvidenciaTabla');
            tabla.innerHTML = '';
            if (!evidencia || Object.keys(evidencia).length === 0) {{
                tabla.innerHTML = '<tr><td colspan="2" style="color:var(--text-secondary);padding:20px;text-align:center;">Sin datos de evidencia disponibles</td></tr>';
                return;
            }}

            const orden = headersArchivo.length > 0 ? headersArchivo : Object.keys(evidencia);
            for (const campo of orden) {{
                if (!(campo in evidencia)) continue;
                const valor = evidencia[campo];
                const tr = document.createElement('tr');

                const tdNombre = document.createElement('td');
                tdNombre.className = 'rule-field-name';
                tdNombre.textContent = campo;

                const tdValor = document.createElement('td');
                tdValor.className = 'rule-field-value';

                if (!valor || valor === 'nan' || valor === 'None') {{
                    tdValor.classList.add('empty');
                    tdValor.textContent = '(vacio)';
                }} else {{
                    tdValor.textContent = valor;
                    const valorLower = String(valor).toLowerCase();
                    const campoLower = String(campo).toLowerCase();
                    if (campoLower.includes('action') || campoLower.includes('accion')) {{
                        if (['accept','allow','permit','pass'].includes(valorLower)) {{
                            tdValor.classList.add('accept');
                        }} else if (['deny','drop','reject','block'].includes(valorLower)) {{
                            tdValor.classList.add('deny');
                        }}
                    }}
                    if (['any','all','*','0.0.0.0/0'].includes(valorLower)) {{
                        tdValor.classList.add('highlight');
                    }}
                }}

                tr.appendChild(tdNombre);
                tr.appendChild(tdValor);
                tabla.appendChild(tr);
            }}
        }}

        function escaparHTML(texto) {{
            if (texto === null || texto === undefined) return '';
            const div = document.createElement('div');
            div.textContent = String(texto);
            return div.innerHTML;
        }}

        function navegarVulnerabilidad(direccion) {{
            const nuevo = currentIndex + direccion;
            if (nuevo >= 0 && nuevo < vulnData.length) {{
                currentIndex = nuevo;
                renderizarModal();
            }}
        }}

        function cerrarModal() {{
            document.getElementById('inspectModal').classList.remove('show');
            document.body.style.overflow = 'auto';
        }}

        function copiarEvidencia() {{
            const v = vulnData[currentIndex];
            if (!v) return;
            let texto = '=== EVIDENCIA - REGLA COMPLETA ===\n';
            texto += 'Vulnerabilidad: ' + v.id + ' - ' + v.descripcion + '\n';
            texto += 'Severidad: ' + v.severidad + ' (CVSS ' + v.cvss + ')\n';
            texto += '----------------------------------------\n';
            const orden = headersArchivo.length > 0 ? headersArchivo : Object.keys(v.evidencia);
            for (const campo of orden) {{
                if (campo in v.evidencia) {{
                    texto += campo + ': ' + (v.evidencia[campo] || '(vacio)') + '\n';
                }}
            }}
            navigator.clipboard.writeText(texto).then(() => {{
                const btn = event.target.closest('.copy-btn');
                const textoOriginal = btn.innerHTML;
                btn.innerHTML = '<i class="fas fa-check"></i> COPIADO';
                setTimeout(() => {{ btn.innerHTML = textoOriginal; }}, 1500);
            }});
        }}

        function aplicarFiltros() {{
            const texto = document.getElementById('filterText').value.toLowerCase();
            const severidad = document.getElementById('filterSeveridad').value;
            const categoria = document.getElementById('filterCategoria').value;

            const filas = document.querySelectorAll('#vulnTable tbody tr');
            let visibles = 0;

            filas.forEach(fila => {{
                const textoFila = fila.textContent.toLowerCase();
                const sevFila = fila.dataset.severidad || '';
                const catFila = fila.dataset.categoria || '';

                const pasaTexto = !texto || textoFila.includes(texto);
                const pasaSev = !severidad || sevFila === severidad;
                const pasaCat = !categoria || catFila === categoria;

                if (pasaTexto && pasaSev && pasaCat) {{
                    fila.style.display = '';
                    visibles++;
                }} else {{
                    fila.style.display = 'none';
                }}
            }});

            document.getElementById('filterCount').textContent = visibles + ' visibles';
        }}

        function filtrarSeccion(seccion) {{
            document.getElementById('filterText').value = seccion;
            aplicarFiltros();
            document.querySelector('.table-wrapper').scrollIntoView({{ behavior: 'smooth' }});
        }}

        function seleccionarSeveridad(severidad) {{
            document.getElementById('filterSeveridad').value = severidad;
            aplicarFiltros();
            document.querySelector('.table-wrapper').scrollIntoView({{ behavior: 'smooth' }});
        }}

        function resetFiltros() {{
            document.getElementById('filterText').value = '';
            document.getElementById('filterSeveridad').value = '';
            document.getElementById('filterCategoria').value = '';
            aplicarFiltros();
        }}

        document.addEventListener('keydown', (e) => {{
            const modal = document.getElementById('inspectModal');
            if (!modal.classList.contains('show')) return;
            if (e.key === 'Escape') cerrarModal();
            else if (e.key === 'ArrowLeft') navegarVulnerabilidad(-1);
            else if (e.key === 'ArrowRight') navegarVulnerabilidad(1);
        }});

        document.getElementById('inspectModal').addEventListener('click', (e) => {{
            if (e.target.id === 'inspectModal') cerrarModal();
        }});
    </script>
</body>
</html>
"""
