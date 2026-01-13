from datetime import timedelta
import os
from dotenv import load_dotenv

# Load .env from parent directory
basedir = os.path.abspath(os.path.dirname(__file__))
# Check if we are in backend/
if os.path.basename(basedir) == 'backend':
    env_path = os.path.join(os.path.dirname(basedir), '.env')
else:
    env_path = os.path.join(basedir, '.env')

load_dotenv(env_path)

# File Paths
GROUPS_FILE = 'groups.json'
USERS_FILE = 'users.json'
SETTINGS_FILE = 'settings.json'
LOG_FILE = 'search_logs.json'
AUDIT_LOG_FILE = 'audit.log'
IP_BANS_FILE = 'ip_bans.json'

# Robust Database Selection (Instance vs Root)
instance_db = os.path.join(basedir, 'instance', 'app.db')
if os.path.exists(instance_db):
    db_path = instance_db
else:
    db_path = os.path.join(basedir, 'app.db')
    
SQLALCHEMY_DATABASE_URI = f'sqlite:///{db_path}'

# Security Config
PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
SECRET_KEY = os.getenv('SECRET_KEY', 'default_secret_key_change_me')
ADMIN_PASSWORD_ENV = os.getenv("ADMIN_PASSWORD")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# App Config
MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2MB
OPENAI_API_URL = "https://api.openai.com/v1/threads/{}/messages"

# Validation
ADMIN_PASSWORDS = [p.strip() for p in (ADMIN_PASSWORD_ENV or "").split(',') if p.strip()]

if not ADMIN_PASSWORDS:
    # We raise error here to fail fast if config is invalid, similar to original app.py
    raise ValueError("CRITICAL SECURITY ERROR: ADMIN_PASSWORD must contain at least one valid password.")
