#!/usr/bin/env python3
"""
Migration script to recalculate thread tokens.

This script updates all threads in the database to use the new token calculation method.
Old method: Tracked Assistant run execution tokens (conversation usage)
New method: Tracks message reading tokens (API call cost for retrieving messages)

Usage:
    python3 recalculate_tokens.py
"""

import sys
import os

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app, logic
from app.extensions import db
from app.models import Thread, Message
from sqlalchemy import func
import time

def recalculate_all_tokens():
    """Recalculate tokens for all threads in the database."""
    app = create_app()
    
    with app.app_context():
        print("=" * 80)
        print("Token Recalculation Migration")
        print("=" * 80)
        
        # Get statistics before migration
        total_threads = Thread.query.count()
        old_total_tokens = db.session.query(func.sum(Thread.total_tokens)).scalar() or 0
        
        print(f"\n📊 Current Statistics:")
        print(f"   Total Threads: {total_threads}")
        print(f"   Old Total Tokens: {old_total_tokens:,}")
        print(f"   Old Average: {old_total_tokens / total_threads if total_threads > 0 else 0:,.2f} tokens/thread")
        
        # Confirm before proceeding
        print(f"\n⚠️  This will recalculate tokens for all {total_threads} threads.")
        print("   Old token values (run execution tokens) will be replaced with new values (message reading tokens).")
        
        response = input("\nProceed with migration? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("❌ Migration cancelled.")
            return
        
        print("\n🔄 Starting migration...\n")
        
        # Process all threads
        threads = Thread.query.all()
        updated_count = 0
        error_count = 0
        new_total_tokens = 0
        
        for i, thread in enumerate(threads, 1):
            try:
                # Get messages for this thread
                messages = Message.query.filter_by(thread_id=thread.id).all()
                
                # Convert to API format for token calculation
                messages_data = []
                for msg in messages:
                    messages_data.append({
                        'role': msg.role,
                        'content': [
                            {
                                'type': 'text',
                                'text': {'value': msg.content or ''}
                            }
                        ]
                    })
                
                # Calculate new token count
                new_tokens = logic.calculate_messages_tokens(messages_data)
                
                if new_tokens is not None:
                    thread.total_tokens = new_tokens
                    new_total_tokens += new_tokens
                    updated_count += 1
                    
                    # Progress indicator
                    if i % 50 == 0:
                        print(f"   Processed {i}/{total_threads} threads... (Latest: {thread.thread_id[:20]}... = {new_tokens:,} tokens)")
                else:
                    error_count += 1
                    print(f"   ⚠️  Error calculating tokens for {thread.thread_id}")
                
            except Exception as e:
                error_count += 1
                print(f"   ❌ Error processing {thread.thread_id}: {e}")
        
        # Commit all changes
        try:
            db.session.commit()
            print(f"\n✅ Migration completed successfully!")
        except Exception as e:
            db.session.rollback()
            print(f"\n❌ Error committing changes: {e}")
            return
        
        # Final statistics
        print("\n" + "=" * 80)
        print("📊 Migration Results:")
        print("=" * 80)
        print(f"   Threads Updated: {updated_count}")
        print(f"   Errors: {error_count}")
        print(f"\n   Old Total Tokens: {old_total_tokens:,}")
        print(f"   New Total Tokens: {new_total_tokens:,}")
        print(f"   Difference: {old_total_tokens - new_total_tokens:,} ({((old_total_tokens - new_total_tokens) / old_total_tokens * 100) if old_total_tokens > 0 else 0:.1f}% reduction)")
        print(f"\n   New Average: {new_total_tokens / updated_count if updated_count > 0 else 0:,.2f} tokens/thread")
        print("=" * 80)

if __name__ == "__main__":
    recalculate_all_tokens()
