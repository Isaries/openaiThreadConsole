from .extensions import huey
from . import logic
import logging
import time
import os
from huey import crontab # For periodic tasks

# Ensure logger is configured for the worker
logger = logging.getLogger('huey')

@huey.task()
def search_task(project_id, target_name, start_date, end_date, api_key, group_id, group_name, mode='quick'):
    """
    Background task to process search request.
    mode: 'quick' (DB only) or 'fresh' (Sync API then DB)
    """
    logger.info(f"Starting {mode} search task for project: {group_name}")
    
    from .models import Project
    from . import create_app
    app = create_app()
    
    results = []
    
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return {'error': 'Project not found'}
            
        threads = project.threads
        debug_log = []
        startTime = time.time()
        
        if mode == 'fresh':
            # 1. Sync Phase (Iterate all threads in project to update cache)
            # This is slow but required for "Fresh".
            for t in threads:
                try:
                     logic.sync_thread_to_db(t.thread_id, api_key, project_id)
                except Exception as e:
                     logger.error(f"Sync failed for {t.thread_id}: {e}")

        # 2. Search Phase (SQL Optimized)
        # Instead of iterating all threads in Python, we ask DB for matches.
        matching_threads = logic.search_threads_sql(project_id, target_name, start_date, end_date)
        
        # 3. Format/Snippet Generation Phase
        for t in matching_threads:
            # Re-use existing logic to generate snippets/highlighting
            res = logic.process_thread_from_db(t, target_name, start_date, end_date)
            
            # Collect debug info
            debug_log.append(res)
            
            if res.get('keep'):
                res['data']['group_name'] = group_name
                results.append(res['data'])

        endTime = time.time()
        duration = endTime - startTime
        
        # Sort results
        results.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Save Search History Log
        from datetime import datetime, timezone, timedelta
        utc8 = timezone(timedelta(hours=8))
        log_time = datetime.now(utc8)
        
        date_range_str = None
        if start_date or end_date:
            d_start = start_date if start_date else 'Any'
            d_end = end_date if end_date else 'Any'
            date_range_str = f"{d_start} ~ {d_end}"
            
        log_entry = {
             'timestamp': int(log_time.timestamp()),
             'time': log_time.strftime('%Y-%m-%d %H:%M:%S'),
             'group': group_name,
             'target': target_name,
             'date_range': date_range_str,
             'matches': len(results),
             'total': len(threads),
             'api_results': debug_log 
        }
        import database
        database.save_log(log_entry)

    return {
        'results': results,
        'debug_log': debug_log,
        'duration': duration,
        'count': len(results),
        'target_name': target_name,
        'date_range': date_range_str
    }

# --- Scheduled Tasks ---

@huey.periodic_task(crontab(minute=0, hour=18)) # UTC 18:00 = UTC+8 02:00
def scheduled_refresh_task():
    logger.info("Starting Scheduled Cache Refresh (Every 3 days check)")
    
    from .models import Project
    from . import create_app
    app = create_app()
    
    with app.app_context():
        projects = Project.query.all()
        now = int(time.time())
        day_seconds = 86400
        interval = 3 * day_seconds # 3 Days
        
        count = 0
        
        for p in projects:
            # Need API Key for project
            # Logic mostly inside logic.py but we need key here
            # Fetch Key via logic.get_headers or similar? 
            # logic.get_headers handles decryption. 
            # We can use project.api_key but it might be encrypted.
            # logic.sync_thread_to_db expects DECRYPTED or Raw key?
            # It expects whatever logic.get_headers accepts. 
            # logic.get_headers handles decryption IF passed.
            
            # Let's pass p.api_key directly. logic.sync -> fetch -> get_headers(api_key).
            # If api_key is None, get_headers checks Global Settings.
            
            for t in p.threads:
                last_sync = t.last_synced_at or 0
                
                if (now - last_sync) > interval:
                    logger.info(f"Refeshing stale cache: {t.thread_id}")
                    s, m = logic.sync_thread_to_db(t.thread_id, p.api_key, p.id)
                    if s: count += 1
                    else: logger.warning(f"Failed to refresh {t.thread_id}: {m}")
                    time.sleep(0.5) # Rate Limit Protection
                    

@huey.task()
def refresh_specific_threads(project_id, thread_ids, group_name=""):
    """
    Manual refresh triggered by Admin.
    """
    logger.info(f"Manual Refresh for {project_id} - {len(thread_ids)} threads")
    from .models import Project
    from . import create_app
    app = create_app()
    
    success_count = 0
    
    with app.app_context():
        project = Project.query.get(project_id)
        if not project: return
        
        api_key = project.api_key # logic handles decryption if needed? No, logic needs decrypted or handles it.
        # Check logic.sync_thread_to_db: calls logic.fetch_thread_messages -> logic.get_headers.
        # logic.get_headers: if api_key passed, use it. If it's encrypted string, it tries to decrypt it?
        # logic.py Line 43: security.get_decrypted_key(api_key).
        # So passing encrypted key is fine!
        
        for tid in thread_ids:
            s, m = logic.sync_thread_to_db(tid, project.api_key, project_id)
            if s: success_count += 1
            # Gentle rate limit
            time.sleep(0.5)
            
    logger.info(f"Manual Refresh Complete: {success_count}/{len(thread_ids)}")

@huey.periodic_task(crontab(minute=0, hour=18, day='*/3')) # UTC 18:00 = UTC+8 02:00
def cleanup_temp_files_task():
    logger.info("Starting Temp File Cleanup")
    import glob
    from app.services.pdf_service import TEMP_PDF_IMG_DIR
    
    if not os.path.exists(TEMP_PDF_IMG_DIR):
        return

    now = time.time()
    cutoff = now - 3600 # 1 Hour
    
    files = glob.glob(os.path.join(TEMP_PDF_IMG_DIR, "*"))
    count = 0
    for f in files:
        try:
            if os.path.isfile(f):
                mtime = os.path.getmtime(f)
                if mtime < cutoff:
                    os.remove(f)
                    count += 1
        except Exception as e:
            logger.warning(f"Failed to delete {f}: {e}")
            
    logger.info(f"Cleanup Complete. Deleted {count} files.")

