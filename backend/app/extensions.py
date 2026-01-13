from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from huey import SqliteHuey

db = SQLAlchemy()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")

# Huey Configuration (Sqlite Backend)
# filename='huey.db' will be created in the application root (or active directory)
huey = SqliteHuey(filename='huey.db')
