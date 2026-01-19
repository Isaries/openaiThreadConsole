from app import create_app
from app.extensions import db
from app.models import User
from werkzeug.security import generate_password_hash
import config

app = create_app()

def reset_password():
    with app.app_context():
        if not config.ADMIN_PASSWORDS:
            print("Error: No ADMIN_PASSWORDS found in config.")
            return

        new_password = config.ADMIN_PASSWORDS[0]
        
        user = User.query.filter_by(username='Administrator').first()
        if user:
            print(f"Found Administrator. Updating password...")
            user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            print("Password updated successfully.")
        else:
            print("Administrator account not found. Creating it...")
            # Fallback creation if somehow missing
            from datetime import datetime
            user = User(
                id='admin',
                username='Administrator',
                password_hash=generate_password_hash(new_password),
                password_hint="Forced Reset",
                is_admin=True,
                created_at=int(datetime.now().timestamp())
            )
            db.session.add(user)
            db.session.commit()
            print("Administrator created.")

if __name__ == '__main__':
    reset_password()
