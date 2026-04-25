import os
import secrets

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

ADMIN_CREDENCIALES = {
    'admin': 'rulesaudit'
}

UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
REPORTS_FOLDER = os.path.join(BASE_DIR, 'reports')
HISTORY_FOLDER = os.path.join(BASE_DIR, 'history')

ALLOWED_EXTENSIONS = {'xlsx', 'xls'}
MAX_CONTENT_LENGTH = 50 * 1024 * 1024

SECRET_KEY_FILE = os.path.join(BASE_DIR, '.secret_key')

def obtener_secret_key():
    if os.path.exists(SECRET_KEY_FILE):
        try:
            with open(SECRET_KEY_FILE, 'r') as f:
                clave = f.read().strip()
                if clave:
                    return clave
        except Exception:
            pass
    clave = secrets.token_hex(32)
    try:
        with open(SECRET_KEY_FILE, 'w') as f:
            f.write(clave)
        os.chmod(SECRET_KEY_FILE, 0o600)
    except Exception:
        pass
    return clave

SECRET_KEY = obtener_secret_key()

SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
PERMANENT_SESSION_LIFETIME = 3600

RATE_LIMIT_LOGIN = 5
RATE_LIMIT_WINDOW = 300

for folder in [UPLOAD_FOLDER, REPORTS_FOLDER, HISTORY_FOLDER]:
    os.makedirs(folder, exist_ok=True)
