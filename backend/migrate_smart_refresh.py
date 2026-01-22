
import sqlite3
import os

def migrate():
    print("Migrating database schema for smart refresh...")
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
    
    # 1. Thread: last_message_timestamp
    try:
        cursor.execute("ALTER TABLE threads ADD COLUMN last_message_timestamp INTEGER")
        print("Added 'last_message_timestamp' to 'threads' table.")
    except sqlite3.OperationalError as e:
        if 'duplicate column' in str(e):
            print("'last_message_timestamp' already exists in 'threads'.")
        else:
            print(f"Error migrating 'threads': {e}")

    # 2. Thread: stale_refresh_count
    try:
        cursor.execute("ALTER TABLE threads ADD COLUMN stale_refresh_count INTEGER DEFAULT 0")
        print("Added 'stale_refresh_count' to 'threads' table.")
    except sqlite3.OperationalError as e:
        if 'duplicate column' in str(e):
            print("'stale_refresh_count' already exists in 'threads'.")
        else:
            print(f"Error migrating 'threads': {e}")

    # 3. Thread: refresh_priority
    try:
        cursor.execute("ALTER TABLE threads ADD COLUMN refresh_priority VARCHAR(20) DEFAULT 'normal'")
        print("Added 'refresh_priority' to 'threads' table.")
    except sqlite3.OperationalError as e:
        if 'duplicate column' in str(e):
            print("'refresh_priority' already exists in 'threads'.")
        else:
            print(f"Error migrating 'threads': {e}")

    conn.commit()
    conn.close()
    print("Migration complete.")

if __name__ == "__main__":
    migrate()
