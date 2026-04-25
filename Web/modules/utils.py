import os
import re
import unicodedata
import hashlib
import secrets


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
    return nombre or 'reporte'


def convertir_bytes(bytes_str):
    if not bytes_str or bytes_str == '0 B':
        return 0
    match = re.match(r'([\d.]+)\s*([GMK]?B?)', bytes_str.strip())
    if not match:
        return 0
    valor, unidad = match.groups()
    try:
        valor = float(valor)
    except ValueError:
        return 0
    if 'GB' in unidad:
        return valor * 1024**3
    elif 'MB' in unidad:
        return valor * 1024**2
    elif 'kB' in unidad or 'KB' in unidad:
        return valor * 1024
    return valor


def calcular_hash_archivo(ruta):
    hasher = hashlib.sha256()
    try:
        with open(ruta, 'rb') as f:
            for bloque in iter(lambda: f.read(8192), b''):
                hasher.update(bloque)
        return hasher.hexdigest()
    except Exception:
        return None


def generar_token():
    return secrets.token_urlsafe(32)


def escapar_html(texto):
    if texto is None:
        return ''
    return (
        str(texto)
        .replace('&', '&amp;')
        .replace('<', '&lt;')
        .replace('>', '&gt;')
        .replace('"', '&quot;')
        .replace("'", '&#39;')
    )


def formatear_tiempo(segundos):
    if segundos < 60:
        return f"{segundos:.1f} segundos"
    elif segundos < 3600:
        return f"{segundos / 60:.1f} minutos"
    return f"{segundos / 3600:.1f} horas"
