#!/usr/bin/env python3

import sys
import os

#Colores
RED = '\033[1;31m'
GREEN = '\033[1;32m'
YELLOW = '\033[1;33m'
END = '\033[0m'

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.file_selector import seleccionar_archivo_excel
from modules.analyzer import FirewallRuleAnalyzer
from modules.excel_reporter import generar_reporte_excel
from modules.html_reporter import generar_reporte_html
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
        
        # Analizar vulnerabilidades con el motor
        print(f"\n{GREEN}[+]{END} Iniciando análisis de vulnerabilidades...")
        print("-" * 60)
        
        analizador = FirewallRuleAnalyzer(df, archivo_vulns)
        vulnerabilidades = analizador.analizar()
        
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
        
        # Generar nombres de archivo con formato cliente_fecha
        nombre_excel = generar_nombre_reporte(nombre_cliente, timestamp, 'xlsx')
        nombre_html = generar_nombre_reporte(nombre_cliente, timestamp, 'html')
        
        # Rutas completas
        ruta_excel_reporte = os.path.join(carpeta_destino, nombre_excel)
        ruta_html_reporte = os.path.join(carpeta_destino, nombre_html)
        
        # Generar reporte Excel
        generar_reporte_excel(vulnerabilidades, ruta_excel_reporte)
        
        # Generar reporte HTML
        generar_reporte_html(
            vulnerabilidades, 
            os.path.basename(ruta_excel),
            ruta_html_reporte,
            nombre_cliente
        )
        
        # Mostrar resumen
        print("\n" + "=" * 60)
        print(f"{GREEN}[+]{END} RESUMEN DEL ANÁLISIS")
        print("=" * 60)
        
        if vulnerabilidades:
            # Calcular estadísticas por severidad
            stats_severidad = {
                'CRÍTICA': sum(1 for v in vulnerabilidades if v['Severidad'] == 'CRÍTICA'),
                'ALTA': sum(1 for v in vulnerabilidades if v['Severidad'] == 'ALTA'),
                'MEDIA': sum(1 for v in vulnerabilidades if v['Severidad'] == 'MEDIA'),
                'BAJA': sum(1 for v in vulnerabilidades if v['Severidad'] == 'BAJA'),
                'INFORMATIVA': sum(1 for v in vulnerabilidades if v['Severidad'] == 'INFORMATIVA')
            }
            
            print(f"\n{GREEN}[+]{END} Reportes generados para: {nombre_cliente}")
            print(f"   • Excel: {nombre_excel}")
            print(f"   • HTML: {nombre_html}")
            print(f"   • Carpeta: {carpeta_destino}")
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
