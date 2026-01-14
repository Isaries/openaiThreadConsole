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

@huey.periodic_task(crontab(minute=0)) # Check every hour
def scheduled_refresh_task():
    logger.info("Starting Scheduled Refresh Check (Hourly)")
    
    # 1. Load Settings & Check Conditions
    import database
    from dateutil import parser
    from datetime import datetime
    from . import utils
    
    settings = database.load_settings()
    config_data = settings.get('auto_refresh', {})
    
    # Defaults: Enabled=True, Frequency=3 days, Hour=2 (02:00 AM)
    # The default behavior matches the original hardcoded logic: 3 days interval.
    # But original start time was 18:00 UTC (02:00 UTC+8).
    
    is_enabled = config_data.get('enabled', True)
    frequency_days = int(config_data.get('frequency_days', 3))
    target_hour = int(config_data.get('hour', 2)) # 0-23 Local Time (UTC+8)
    
    if not is_enabled:
        logger.info("Auto-refresh is DISABLED in settings. Skipping.")
        return

    # Get Current Time (UTC+8)
    # database.utc8_converter() returns a struct_time, let's use utils or datetime directly
    from datetime import timezone, timedelta
    utc8 = timezone(timedelta(hours=8))
    now = datetime.now(utc8)
    
    if now.hour != target_hour:
        # Not the right hour
        return
        
    logger.info(f"Time match ({now.hour}:00). Checking frequency...")
    
    # Frequency Check (Last Run)
    last_run_str = config_data.get('last_run')
    if last_run_str:
        try:
            last_run = parser.parse(last_run_str)
            # Ensure last_run is offset-aware
            if last_run.tzinfo is None:
                last_run = last_run.replace(tzinfo=utc8)
                
            days_diff = (now - last_run).days
            if days_diff < frequency_days:
                logger.info(f"Skipping: Last run was {days_diff} days ago (Frequency: {frequency_days} days).")
                return
        except Exception as e:
            logger.warning(f"Error parsing last_run time: {e}. Executing anyway.")
            pass
            
    logger.info("Conditions met. Executing Refresh Logic...")

    from .models import Project
    from . import create_app
    app = create_app()
    
    with app.app_context():
        projects = Project.query.all()
        current_ts = int(time.time())
        day_seconds = 86400
        interval = frequency_days * day_seconds 
        
        count = 0
        
        for p in projects:
            for t in p.threads:
                last_sync = t.last_synced_at or 0
                
                # Double check against individual thread latency
                # Even if task runs, we only update stale threads
                if (current_ts - last_sync) > interval:
                    logger.info(f"Refeshing stale cache: {t.thread_id}")
                    s, m = logic.sync_thread_to_db(t.thread_id, p.api_key, p.id)
                    if s: count += 1
                    else: logger.warning(f"Failed to refresh {t.thread_id}: {m}")
                    time.sleep(0.5) # Rate Limit Protection
                    
    # Update Last Run Time
    config_data['last_run'] = now.isoformat()
    settings['auto_refresh'] = config_data
    database.save_settings(settings)
    logger.info("Scheduled Refresh Completed.")
                    

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

