# Database Migration Instructions

## Required Migration: Add progress_data Column

### Background
The dynamic timeout feature requires a new `progress_data` column in the `search_result_chunks` table to store real-time progress information.

### Migration Steps

#### Option 1: Using Docker (Recommended)

```bash
# 1. Access the web container
docker-compose exec web bash

# 2. Open Python shell
python

# 3. Run migration
from app import create_app
from app.extensions import db
app = create_app()
with app.app_context():
    db.engine.execute("ALTER TABLE search_result_chunks ADD COLUMN progress_data TEXT")
    print("Migration completed successfully!")
exit()

# 4. Exit container
exit

# 5. Restart containers
docker-compose restart
```

#### Option 2: Direct SQL (If you have direct database access)

```bash
# 1. Access your SQLite database
sqlite3 /path/to/your/database.db

# 2. Run the migration
ALTER TABLE search_result_chunks ADD COLUMN progress_data TEXT;

# 3. Verify
.schema search_result_chunks

# 4. Exit
.quit

# 5. Restart application
docker-compose restart
```

#### Option 3: Using Migration Script

```bash
# From the backend directory
docker-compose exec web bash
cd /app
sqlite3 instance/app.db < migrations/add_progress_data_column.sql
exit
docker-compose restart
```

### Verification

After migration, verify the column exists:

```python
from app import create_app
from app.models import SearchResultChunk
app = create_app()
with app.app_context():
    # This should not raise an error
    chunk = SearchResultChunk.query.first()
    print("Migration successful!" if hasattr(chunk, 'progress_data') else "Migration failed!")
```

### Rollback (If Needed)

If you need to rollback:

```sql
-- SQLite doesn't support DROP COLUMN directly
-- You'll need to recreate the table without the column
-- Backup your data first!
```

## Notes

- This migration is **required** for the progress indicator feature to work
- The column is nullable, so existing records will have NULL values
- No data migration is needed as this is a new feature
