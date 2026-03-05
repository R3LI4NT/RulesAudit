import os
import re
import unicodedata

#Colores
RED = '\033[1;31m'
BLUE = '\033[1;34m'
GREEN = '\033[1;32m'
YELLOW = '\033[1;33m'
MAGENTA = '\033[1;35m'
WHITE = '\033[1;37m'
CYAN = '\033[1;36m'
END = '\033[0m'

def validar_archivo_excel(ruta):
    if not ruta or not os.path.exists(ruta):
        return False
    
    if not ruta.lower().endswith(('.xlsx', '.xls')):
        return False
    
    return True


def sanitizar_nombre_archivo(nombre):
    nombre = unicodedata.normalize('NFKD', nombre).encode('ASCII', 'ignore').decode('ASCII')
    
    nombre = re.sub(r'[^\w\-_\. ]', '', nombre)
    nombre = re.sub(r'[ \-]+', '_', nombre)
    
    nombre = nombre.strip('_')
    
    return nombre


def convertir_bytes(bytes_str):
    if not bytes_str or bytes_str == '0 B':
        return 0
    
    match = re.match(r'([\d.]+)\s*([GMK]?B?)', bytes_str.strip())
    if not match:
        return 0
    
    valor, unidad = match.groups()
    valor = float(valor)
    
    if 'GB' in unidad:
        return valor * 1024**3
    elif 'MB' in unidad:
        return valor * 1024**2
    elif 'kB' in unidad or 'KB' in unidad:
        return valor * 1024
    else:
        return valor


def print_banner():
    banner = f"""
{BLUE}    ╔══════════════════════════════════════════════════════════╗{END}
{BLUE}    ║     {WHITE}🛡️  AUDITOR DE REGLAS DE FIREWALL v1.0 🛡️{BLUE}            ║{END}
{BLUE}    ║           {WHITE}Análisis de Reglas de Firewall{BLUE}                 ║{END}
{BLUE}    ║                                                          ║{END}
{BLUE}    ╚══════════════════════════════════════════════════════════╝{END}
    """
    print(banner)


def formatear_tiempo(segundos):
    if segundos < 60:
        return f"{segundos:.1f} segundos"
    elif segundos < 3600:
        minutos = segundos / 60
        return f"{minutos:.1f} minutos"
    else:
        horas = segundos / 3600
        return f"{horas:.1f} horas"