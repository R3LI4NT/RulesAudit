import json
import csv
from datetime import datetime


def exportar_json(vulnerabilidades, resumen, score, compliance, ruta_salida, cliente='', archivo=''):
    data = {
        'metadata': {
            'cliente': cliente,
            'archivo_analizado': archivo,
            'fecha_generacion': datetime.now().isoformat(),
            'generador': 'RulesAudit v2.1',
            'formato': 'JSON'
        },
        'resumen': resumen,
        'score': score,
        'compliance': compliance,
        'vulnerabilidades': vulnerabilidades
    }
    with open(ruta_salida, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2, default=str)
    return ruta_salida


def exportar_csv(vulnerabilidades, ruta_salida):
    if not vulnerabilidades:
        return None
    headers_evidencia = set()
    for v in vulnerabilidades:
        evidencia = v.get('Evidencia', {})
        for clave in evidencia.keys():
            headers_evidencia.add(clave)
    headers_evidencia = sorted(headers_evidencia)
    columnas_base = ['ID', 'Severidad', 'CVSS', 'Tipo', 'Categoria', 'Sección', 'Regla', 'Descripción', 'Recomendación']
    columnas_evidencia = [f"Ev_{h}" for h in headers_evidencia]
    columnas = columnas_base + columnas_evidencia
    with open(ruta_salida, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f, delimiter=';', quoting=csv.QUOTE_ALL)
        writer.writerow(columnas)
        for v in vulnerabilidades:
            fila = []
            for col in columnas_base:
                fila.append(str(v.get(col, '')))
            evidencia = v.get('Evidencia', {})
            for h in headers_evidencia:
                fila.append(str(evidencia.get(h, '')))
            writer.writerow(fila)
    return ruta_salida


def exportar_markdown(vulnerabilidades, resumen, score, ruta_salida, cliente=''):
    lineas = []
    lineas.append(f"# Reporte RulesAudit v2.1")
    lineas.append(f"")
    lineas.append(f"**Cliente:** {cliente}")
    lineas.append(f"**Fecha:** {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    lineas.append(f"**Formato detectado:** {resumen.get('formato_detectado', 'N/A')}")
    lineas.append(f"**Total reglas analizadas:** {resumen.get('total_reglas', 0)}")
    lineas.append(f"")
    lineas.append(f"## Resumen Ejecutivo")
    lineas.append(f"")
    lineas.append(f"- **Score de riesgo:** {score.get('score', 0)}/100 ({score.get('nivel', 'N/A')})")
    lineas.append(f"- **Grado:** {score.get('grado', 'N/A')}")
    lineas.append(f"- **Total vulnerabilidades:** {len(vulnerabilidades)}")
    lineas.append(f"- **Reglas afectadas:** {resumen.get('reglas_afectadas', 0)}")
    lineas.append(f"- **CVSS promedio:** {resumen.get('cvss_promedio', 0)}")
    lineas.append(f"")
    por_sev = resumen.get('por_severidad', {})
    lineas.append(f"### Distribucion por Severidad")
    lineas.append(f"")
    lineas.append(f"| Severidad | Cantidad |")
    lineas.append(f"|-----------|----------|")
    for sev in ['CRÍTICA', 'ALTA', 'MEDIA', 'BAJA', 'INFORMATIVA']:
        lineas.append(f"| {sev} | {por_sev.get(sev, 0)} |")
    lineas.append(f"")
    lineas.append(f"## Vulnerabilidades Detectadas")
    lineas.append(f"")
    for i, v in enumerate(vulnerabilidades, 1):
        lineas.append(f"### {i}. [{v.get('Severidad', 'N/A')}] {v.get('Descripción', '')}")
        lineas.append(f"")
        lineas.append(f"- **ID:** {v.get('ID', 'N/A')}")
        lineas.append(f"- **CVSS:** {v.get('CVSS', 0)}")
        lineas.append(f"- **Categoria:** {v.get('Categoria', 'N/A')}")
        lineas.append(f"- **Seccion:** {v.get('Sección', 'N/A')}")
        lineas.append(f"- **Regla:** {v.get('Regla', 'N/A')}")
        lineas.append(f"- **Recomendacion:** {v.get('Recomendación', '')}")
        evidencia = v.get('Evidencia', {})
        if evidencia:
            lineas.append(f"")
            lineas.append(f"**Evidencia (regla completa del archivo):**")
            lineas.append(f"")
            lineas.append(f"| Campo | Valor |")
            lineas.append(f"|-------|-------|")
            for campo, valor in evidencia.items():
                valor_seguro = str(valor).replace('|', '\\|').replace('\n', ' ')[:200]
                lineas.append(f"| {campo} | {valor_seguro} |")
        lineas.append(f"")
        lineas.append(f"---")
        lineas.append(f"")
    contenido = '\n'.join(lineas)
    with open(ruta_salida, 'w', encoding='utf-8') as f:
        f.write(contenido)
    return ruta_salida
