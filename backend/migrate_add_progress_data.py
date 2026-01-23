#!/usr/bin/env python
"""Database migration script to add progress_data column"""

from app import create_app
from app.extensions import db
from sqlalchemy import text

def run_migration():
    app = create_app()
    with app.app_context():
        try:
            # Add the new column using SQLAlchemy 2.0 syntax
            with db.engine.connect() as conn:
                conn.execute(text('ALTER TABLE search_result_chunks ADD COLUMN progress_data TEXT'))
                conn.commit()
            print('✅ Migration completed successfully!')
            print('   Added progress_data column to search_result_chunks table')
        except Exception as e:
            if 'duplicate column name' in str(e).lower():
                print('⚠️  Column already exists, migration skipped')
            else:
                print(f'❌ Migration failed: {e}')
                raise

if __name__ == '__main__':
    run_migration()
