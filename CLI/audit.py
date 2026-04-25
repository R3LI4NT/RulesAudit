#!/usr/bin/env python3

import sys
import os

# Colores
RED = '\033[1;31m'
GREEN = '\033[1;32m'
YELLOW = '\033[1;33m'
CYAN = '\033[1;36m'
END = '\033[0m'

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.file_selector import seleccionar_archivo_excel
from modules.analyzer import FirewallRuleAnalyzer
from modules.scorer import PuntuadorRiesgo
from modules.excel_reporter import generar_reporte_excel
from modules.html_reporter import generar_reporte_html
from modules.exporters import exportar_json, exportar_csv, exportar_markdown
from modules.utils import print_banner, validar_archivo_excel, sanitizar_nombre_archivo

import pandas as pd
from datetime import datetime


def solicitar_nombre_cliente():
    print("\n" + "=" * 60)
    print(f"{GREEN}[+]{END} INFORMACIÓN DEL CLIENTE")
    print("=" * 60)

    while True:
        nombre_cliente = input("\nIngrese el nombre del cliente: ").strip()

        if not nombre_cliente:
            print(f"{YELLOW}[!]{END} El nombre no puede estar vacío. Intente nuevamente.")
            continue

        print(f"\n{GREEN}[+]{END} Nombre ingresado: {nombre_cliente}")
        confirmar = input("¿Es correcto? (s/n): ").strip().lower()

        if confirmar in ['s', 'si', 'sí', 'y', 'yes']:
            return sanitizar_nombre_archivo(nombre_cliente)
        else:
            print(f"{YELLOW}[!]{END} Por favor, ingrese el nombre nuevamente.")


def solicitar_archivo_vulns():
    print("\n" + "=" * 60)
    print(" CONFIGURACIÓN DE VULNERABILIDADES")
    print("=" * 60)
    print("1 - Usar archivo vulns.json por defecto (si existe)")
    print("2 - Especificar archivo personalizado")

    opcion = input("\nOpción (1 o 2) [default: 1]: ").strip() or "1"

    if opcion == "2":
        from modules.file_selector import seleccionar_archivo_json
        return seleccionar_archivo_json()
    elif opcion == "0":
        exit(0)
    else:
        # Buscar vulns.json
        posibles = ['vulns.json', os.path.join('modules', 'vulns.json')]
        for ruta in posibles:
            if os.path.exists(ruta):
                print(f"[+] Usando: {ruta}")
                return ruta
        print(f"{YELLOW}[!]{END} No se encontró {RED}vulns.json{END}, usando configuración por defecto")
        return None


def solicitar_formatos():
    print("\n" + "=" * 60)
    print(f"{GREEN}[+]{END} FORMATOS DE EXPORTACIÓN")
    print("=" * 60)
    print("1 - HTML")
    print("2 - Excel (.xlsx)")
    print("3 - JSON")
    print("4 - CSV")
    print()
    print("Ingrese los números separados por coma (ej: 1,2,3,4)")
    print("ENTER = todos los formatos del Web (HTML + Excel + JSON + CSV)")

    seleccion = input("\nFormatos: ").strip()

    if not seleccion:
        return {'html', 'xlsx', 'json', 'csv'}

    mapa = {'1': 'html', '2': 'xlsx', '3': 'json', '4': 'csv', '5': 'md'}
    formatos = set()
    for token in seleccion.split(','):
        token = token.strip()
        if token in mapa:
            formatos.add(mapa[token])
        elif token:
            print(f"{YELLOW}[!]{END} Opción ignorada: {token}")

    if not formatos:
        print(f"{YELLOW}[!]{END} Selección vacía o inválida, usando default (HTML+Excel+JSON+CSV)")
        return {'html', 'xlsx', 'json', 'csv'}
    return formatos


def generar_nombre_reporte(nombre_cliente, timestamp, extension):
    return f"{nombre_cliente}_{timestamp}.{extension}"


def main():
    print_banner()

    nombre_cliente = solicitar_nombre_cliente()

    # Preguntar por archivo de vulnerabilidades
    archivo_vulns = solicitar_archivo_vulns()

    # Seleccionar archivo Excel
    ruta_excel = seleccionar_archivo_excel()
    if not ruta_excel:
        print(f"\n{YELLOW}[!]{END} No se seleccionó ningún archivo")
        return

    print(f"\n{GREEN}[+]{END} Analizando: {os.path.basename(ruta_excel)}")

    # Validar archivo
    if not validar_archivo_excel(ruta_excel):
        print(f"\n{YELLOW}[!]{END} El archivo no es válido o no se puede leer")
        return

    try:
        # Cargar datos
        print(f"{GREEN}[+]{END} Cargando reglas de firewall...")
        df = pd.read_excel(ruta_excel, sheet_name=0, header=0)
        print(f"   {GREEN}[+]{END} {len(df)} reglas cargadas correctamente")

        print(f"\n{GREEN}[+]{END} Iniciando análisis de vulnerabilidades...")
        print("-" * 60)

        analizador = FirewallRuleAnalyzer(df, archivo_vulns)
        vulnerabilidades = analizador.analizar()
        resumen = analizador.obtener_resumen()
        compliance = analizador.obtener_compliance()
        headers_archivo = getattr(analizador, 'headers', None)

        scorer = PuntuadorRiesgo(vulnerabilidades, resumen.get('total_reglas', 0))
        score = scorer.calcular_score_global()

        # Generar timestamp para los archivos
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Preguntar por carpeta de destino
        print("\n" + "=" * 60)
        print(f"{GREEN}[+]{END} CARPETA DE DESTINO")
        print("=" * 60)
        print("1 - Usar la misma carpeta del archivo analizado")
        print("2 - Seleccionar otra carpeta")

        opcion_carpeta = input("\nOpción (1 o 2) [default: 1]: ").strip() or "1"

        if opcion_carpeta == "2":
            from modules.file_selector import seleccionar_carpeta_destino
            carpeta_destino = seleccionar_carpeta_destino()
            if not carpeta_destino:
                print(f"{YELLOW}[!]{END} Usando carpeta del archivo original...")
                carpeta_destino = os.path.dirname(ruta_excel)
        else:
            carpeta_destino = os.path.dirname(ruta_excel)

        # Preguntar formatos a exportar
        formatos = solicitar_formatos()

        # Rutas completas
        nombre_base = f"{nombre_cliente}_{timestamp}"
        archivos_generados = []

        print(f"\n{GREEN}[+]{END} Generando reportes...")

        # Excel
        if 'xlsx' in formatos:
            ruta = os.path.join(carpeta_destino, f"{nombre_base}.xlsx")
            generar_reporte_excel(
                vulnerabilidades, ruta,
                resumen=resumen, score=score, compliance=compliance,
            )
            archivos_generados.append(('Excel', ruta))
            print(f"   {GREEN}[+]{END} Excel:    {os.path.basename(ruta)}")

        # HTML
        if 'html' in formatos:
            ruta = os.path.join(carpeta_destino, f"{nombre_base}.html")
            generar_reporte_html(
                vulnerabilidades,
                os.path.basename(ruta_excel),
                ruta,
                nombre_cliente,
                resumen=resumen,
                score=score,
                compliance=compliance,
                headers_archivo=headers_archivo,
            )
            archivos_generados.append(('HTML', ruta))
            print(f"   {GREEN}[+]{END} HTML:     {os.path.basename(ruta)}")

        # JSON
        if 'json' in formatos:
            ruta = os.path.join(carpeta_destino, f"{nombre_base}.json")
            exportar_json(
                vulnerabilidades, resumen, score, compliance, ruta,
                cliente=nombre_cliente,
                archivo=os.path.basename(ruta_excel),
            )
            archivos_generados.append(('JSON', ruta))
            print(f"   {GREEN}[+]{END} JSON:     {os.path.basename(ruta)}")

        # CSV
        if 'csv' in formatos:
            ruta = os.path.join(carpeta_destino, f"{nombre_base}.csv")
            res = exportar_csv(vulnerabilidades, ruta)
            if res:
                archivos_generados.append(('CSV', ruta))
                print(f"   {GREEN}[+]{END} CSV:      {os.path.basename(ruta)}")
            else:
                print(f"   {YELLOW}[!]{END} CSV no generado (sin vulnerabilidades)")

        # Mostrar resumen
        print("\n" + "=" * 60)
        print(f"{GREEN}[+]{END} RESUMEN DEL ANÁLISIS")
        print("=" * 60)

        if vulnerabilidades:
            print(f"\n{GREEN}[+]{END} Cliente: {nombre_cliente}")
            print(f"   • Total reglas analizadas: {resumen.get('total_reglas', 0)}")
            print(f"   • Total vulnerabilidades:  {len(vulnerabilidades)}")
            print(f"   • Reglas afectadas:        {resumen.get('reglas_afectadas', 0)}")
            print(f"   • CVSS promedio:           {resumen.get('cvss_promedio', 0)}")
            print(f"   • Score de riesgo:         {score.get('score', 0)}/100  "
                  f"({score.get('nivel', 'N/A')} — Grado {score.get('grado', 'N/A')})")

            por_sev = resumen.get('por_severidad', {})
            print(f"\n{GREEN}[+]{END} Distribución por severidad:")
            for sev in ['CRÍTICA', 'ALTA', 'MEDIA', 'BAJA', 'INFORMATIVA']:
                cantidad = por_sev.get(sev, 0)
                if cantidad:
                    print(f"   • {sev:<12} {cantidad}")

            print(f"\n{GREEN}[+]{END} Archivos generados en: {carpeta_destino}")
            for tipo, ruta in archivos_generados:
                print(f"   • {tipo:<9} {os.path.basename(ruta)}")
        else:
            print(f"\n{GREEN}[+]{END} No se encontraron vulnerabilidades")

        print(f"\n{GREEN}[+]{END} Análisis completado exitosamente")

    except Exception as e:
        print(f"\n{YELLOW}[!]{END} Error durante el análisis: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
