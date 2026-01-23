from app import create_app
from app.extensions import db
from app.models import User, Thread
from sqlalchemy import text

app = create_app()

def migrate():
    with app.app_context():
        print("Starting Thread Bookmarks Migration...")
        
        try:
            # Check if table exists
            db.session.execute(text('SELECT 1 FROM user_bookmarks LIMIT 1'))
            print("Table 'user_bookmarks' already exists.")
        except Exception:
            print("Table 'user_bookmarks' missing. Creating...")
            try:
                # db.create_all() will create any missing tables defined in models
                # Since we added user_bookmarks to models, this is sufficient and safe.
                db.create_all()
                print("Table 'user_bookmarks' created successfully.")
            except Exception as e:
                print(f"Failed to create table: {e}")
                exit(1)
        
        print("Migration Check Complete.")

if __name__ == '__main__':
    migrate()
