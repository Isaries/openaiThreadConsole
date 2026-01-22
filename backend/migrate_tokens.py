
import sqlite3
import os

def migrate():
    print("Migrating database schema...")
    base_dir = os.path.abspath(os.path.dirname(__file__))
    
    # Check instance folder first
    db_path = os.path.join(base_dir, 'instance', 'app.db')
    if not os.path.exists(db_path):
        db_path = os.path.join(base_dir, 'app.db')
        
    print(f"Target DB: {db_path}")
    
    if not os.path.exists(db_path):
        print("Database not found. Skipping migration (will be created fresh).")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # 1. Thread: total_tokens
    try:
        cursor.execute("ALTER TABLE threads ADD COLUMN total_tokens INTEGER DEFAULT 0")
        print("Added 'total_tokens' to 'threads' table.")
    except sqlite3.OperationalError as e:
        if 'duplicate column' in str(e):
            print("'total_tokens' already exists in 'threads'.")
        else:
            print(f"Error migrating 'threads': {e}")

    # 2. SystemMetric: total_managed_tokens
    try:
        cursor.execute("ALTER TABLE sys_metrics ADD COLUMN total_managed_tokens INTEGER DEFAULT 0")
        print("Added 'total_managed_tokens' to 'sys_metrics' table.")
    except sqlite3.OperationalError as e:
        if 'duplicate column' in str(e):
            print("'total_managed_tokens' already exists in 'sys_metrics'.")
        else:
            print(f"Error migrating 'sys_metrics': {e}")

    conn.commit()
    conn.close()
    print("Migration complete.")

if __name__ == "__main__":
    migrate()
