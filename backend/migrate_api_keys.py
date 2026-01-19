from app import create_app
from app.extensions import db
from app.models import Project
from sqlalchemy import text
import security

app = create_app()

def add_column_if_missing():
    with app.app_context():
        try:
            # Check if column exists
            db.session.execute(text('SELECT api_key_hash FROM projects LIMIT 1'))
            print("Column api_key_hash already exists.")
        except Exception:
            print("Column api_key_hash missing. Adding...")
            try:
                # SQLite specific
                with db.engine.connect() as conn:
                    conn.execute(text('ALTER TABLE projects ADD COLUMN api_key_hash VARCHAR(64)'))
                    # Explicit commit if needed usually handled by context in some versions, but explicit is safe
                    conn.commit() 
                print("Column added successfully.")
            except Exception as e:
                print(f"Failed to add column: {e}")

def migrate():
    with app.app_context():
        add_column_if_missing()
        
        print("Starting API Key Migration...")
        projects = Project.query.all()
        count = 0
        
        for p in projects:
            if not p.api_key: continue
            
            # Check if already hashed to avoid work? No, re-hash is safe.
            
            # Decrypt
            decrypted = security.get_decrypted_key(p.api_key)
            if not decrypted or decrypted == "INVALID_KEY_RESET_REQUIRED":
                print(f"Skipping Project {p.name} (Invalid/Legacy Key)")
                continue
                
            # Hash
            p.api_key_hash = security.hash_api_key(decrypted)
            count += 1
            
        try:
            db.session.commit()
            print(f"Migration Complete. Updated {count} projects.")
        except Exception as e:
            print(f"Migration Failed: {e}")
            db.session.rollback()

if __name__ == '__main__':
    migrate()
