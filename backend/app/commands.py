from .extensions import db
from .models import User
from werkzeug.security import generate_password_hash
import config
from datetime import datetime

def ensure_admin_exists():
    """
    Checks if the default Administrator account exists.
    If not, creates it using the first password in ADDMIN_PASSWORDS config.
    """
    try:
        user = User.query.filter_by(username='Administrator').first()
        if not user:
            print("security: initializing default administrator account...")
            if not config.ADMIN_PASSWORDS:
                print("security warning: no ADMIN_PASSWORDS set, cannot create admin.")
                return

            pwd = config.ADMIN_PASSWORDS[0]
            
            user = User(
                id='admin',
                username='Administrator',
                password_hash=generate_password_hash(pwd),
                password_hint="Initialized from Config",
                is_admin=True,
                created_at=int(datetime.now().timestamp())
            )
            db.session.add(user)
            db.session.commit()
            print("security: administrator account created.")
        else:
            # Account exists. We do NOT overwrite password here to prevent accidental reset.
            pass
    except Exception as e:
        print(f"security init error: {e}")
