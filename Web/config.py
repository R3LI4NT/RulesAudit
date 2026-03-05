import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'rules-audit-secret-key-2026'
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    REPORTS_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024 
    ALLOWED_EXTENSIONS = {'xlsx', 'xls'}
    
    # Credenciales de admin
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME') or 'admin'
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD') or 'rulesaudit'
    
    # Crear carpetas si no existen
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(REPORTS_FOLDER, exist_ok=True)