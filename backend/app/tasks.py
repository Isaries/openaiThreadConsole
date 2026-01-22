from .extensions import huey, db
from . import logic
import logging
import time
import os
import glob
import json
import database
from huey import crontab # For periodic tasks
from datetime import datetime, timezone, timedelta
from dateutil import parser
try:
    import psutil
except ImportError:
    psutil = None

# Ensure logger is configured for the worker
logger = logging.getLogger('huey')

@huey.task(context=True)
def search_task(project_id, target_name, start_date, end_date, api_key, group_id, group_name, mode='quick', bypass_priority_filter=False, task=None):
    """
    Background task to process search request.
    mode: 'quick' (DB only) or 'fresh' (Sync API then DB)
    bypass_priority_filter: If True, ignore refresh_priority (for admin manual refresh)
    """
    logger.info(f"Starting {mode} search task for project: {group_name}. Task ID: {task.id if task else 'Unknown'}")
    
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
        
        # Smart Refresh Statistics
        skipped_frozen = 0
        skipped_low = 0
        refreshed_count = 0
        
        if mode == 'fresh':
            # 1. Sync Phase (Iterate all threads in project to update cache)
            # This is slow but required for "Fresh".
            import random
            for t in threads:
                try:
                    # Smart Refresh: Check priority unless bypassed
                    if not bypass_priority_filter:
                        if t.refresh_priority == 'frozen':
                            skipped_frozen += 1
                            logger.info(f"Skipped frozen thread: {t.thread_id}")
                            continue
                        elif t.refresh_priority == 'low':
                            # 80% chance to skip
                            if random.random() < 0.8:
                                skipped_low += 1
                                logger.info(f"Skipped low priority thread: {t.thread_id}")
                                continue
                    
                    logic.sync_thread_to_db(t.thread_id, api_key, project_id)
                    refreshed_count += 1
                except Exception as e:
                     logger.error(f"Sync failed for {t.thread_id}: {e}")

        # Chunking Logic
        BATCH_SIZE = 10
        current_batch = []
        page_index = 0
        total_count = 0
        
        from .models import SearchResultChunk
        
        # 2. Search Phase
        matching_threads = logic.search_threads_sql(project_id, target_name, start_date, end_date)
        
        # 3. Processing & Chunk Writing
        for t in matching_threads:
            # Re-use existing logic
            res = logic.process_thread_from_db(t, target_name, start_date, end_date)
            
            # Collect debug info (Careful with memory here too, keep it small?)
            # debug_log.append(res) # If thousands, this is huge. Let's limit debug log.
            if len(debug_log) < 100:
                 debug_log.append(res)
            
            if res.get('keep'):
                res['data']['group_name'] = group_name
                current_batch.append(res['data'])
                total_count += 1
                
                # Flush Batch
                if len(current_batch) >= BATCH_SIZE:
                    chunk = SearchResultChunk(
                        task_id=task.id, # Accessing Huey task ID from context
                        page_index=page_index,
                        data_json=json.dumps(current_batch)
                    )
                    db.session.add(chunk)
                    db.session.commit()
                    
                    current_batch = []
                    page_index += 1
                    time.sleep(0.2) # Throttling
    
        # Flush Final Batch
        if current_batch:
            chunk = SearchResultChunk(
                task_id=task.id,
                page_index=page_index,
                data_json=json.dumps(current_batch)
            )
            db.session.add(chunk)
            db.session.commit()
        
        endTime = time.time()
        duration = endTime - startTime
        
        # Save Search History Log (simplified)
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
                'matches': total_count,
                'total': len(matching_threads),
                'api_results': debug_log
        }
        database.save_log(log_entry)
    
        result = {
            'status': 'done',
            'count': total_count,
            'total_pages': page_index + (1 if current_batch else 0),
            'debug_log': debug_log,
            'duration': duration,
            'target_name': target_name,
            'date_range': date_range_str
        }
        
        # Add smart refresh stats only if fresh mode was used
        if mode == 'fresh':
            result.update({
                'refreshed_count': refreshed_count,
                'skipped_frozen': skipped_frozen,
                'skipped_low': skipped_low,
                'total_skipped': skipped_frozen + skipped_low
            })
        
        return result

# --- Scheduled Tasks ---

@huey.periodic_task(crontab(minute=0)) # Check every hour
def scheduled_refresh_task():
    logger.info("Starting Scheduled Refresh Check (Hourly)")
    
    # 1. Load Settings & Check Conditions
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

    logger.info("Conditions met. Executing Refresh Logic...")

    from .models import Project, RefreshHistory
    from . import create_app
    app = create_app()
    
    start_ts = time.time()
    total_scanned = 0
    updated_count = 0
    error_count = 0
    error_logs = []
    
    try:
        with app.app_context():
            projects = Project.query.all()
            current_ts = int(time.time())
            day_seconds = 86400
            interval = frequency_days * day_seconds 
            
            # Batch Commit Counter
            pending_updates = 0

            for p in projects:
                for t in p.threads:
                    total_scanned += 1
                    
                    last_sync = t.last_synced_at or 0
                    
                    # Double check against individual thread latency
                    # Even if task runs, we only update stale threads
                    if (current_ts - last_sync) > interval:
                        logger.info(f"Refeshing stale cache: {t.thread_id}")
                        s, m = logic.sync_thread_to_db(t.thread_id, p.api_key, p.id)
                        if s: 
                            updated_count += 1
                            pending_updates += 1
                        else: 
                            error_count += 1
                            logger.warning(f"Failed to refresh {t.thread_id}: {m}")
                            if len(error_logs) < 10: # Limit log size
                                error_logs.append(f"{t.thread_id}: {m}")
                        
                        # Batch Commit (Every 50 updates) to prevent long transactions
                        if pending_updates >= 50:
                            db.session.commit()
                            pending_updates = 0
                                
                        time.sleep(0.5) # Rate Limit Protection
            
            # Final Commit for remaining
            if pending_updates > 0:
                db.session.commit()
            
            # --- Save History ---
            duration = time.time() - start_ts
            status = 'Success'
            if error_count > 0:
                status = 'Partial' if updated_count > 0 else 'Failed'
                
            history = RefreshHistory(
                timestamp=int(start_ts),
                duration=round(duration, 2),
                result_status=status,
                total_scanned=total_scanned,
                updated_count=updated_count,
                error_count=error_count,
                log_json=json.dumps(error_logs, ensure_ascii=False)
            )
            db.session.add(history)
            
            # --- Cleanup Old History (> 30 Days) ---
            cutoff_ts = int(start_ts) - (30 * 86400)
            RefreshHistory.query.filter(RefreshHistory.timestamp < cutoff_ts).delete()
            
            db.session.commit()
                        
        # Update Last Run Time
        # Update Last Run Time (Re-load to prevent Race Condition with Admin UI)
        current_settings = database.load_settings()
        current_config = current_settings.get('auto_refresh', {})
        
        # Update only the timestamp, keeping other admin-set values (enabled, hour, freq)
        current_config['last_run'] = now.isoformat()
        current_settings['auto_refresh'] = current_config
        
        database.save_settings(current_settings)
        logger.info(f"Scheduled Refresh Completed. Updated: {updated_count}, Errors: {error_count}")

    except Exception as e:
        logger.error(f"Scheduled Refresh CRITICAL FAILURE: {e}")
        # Try to log failure to DB even if unexpected error
        try:
            with app.app_context():
                duration = time.time() - start_ts
                history = RefreshHistory(
                    timestamp=int(start_ts),
                    duration=round(duration, 2),
                    result_status='Critical Failed',
                    total_scanned=total_scanned,
                    updated_count=updated_count,
                    error_count=error_count + 1,
                    log_json=json.dumps([f"System Error: {str(e)}"], ensure_ascii=False)
                )
                db.session.add(history)
                db.session.commit()
        except:
            pass
                    

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
    import config
    TEMP_PDF_IMG_DIR = config.TEMP_PDF_IMG_DIR
    
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

# --- System Monitoring ---
@huey.periodic_task(crontab(minute=0))  # Every hour at :00
def collect_system_metrics_task():
    logger.info("Starting System Metric Collection")
    try:
        if not psutil:
             raise ImportError("psutil not installed")

        from .models import SystemMetric
        from . import create_app
        import time
        
        # 1. Collect Metrics
        # cpu_percent with interval blocks for 1 sec to get accurate reading
        cpu = psutil.cpu_percent(interval=1) 
        mem = psutil.virtual_memory()
        
        app = create_app()
        with app.app_context():
            # 1.5 Calculate Total Managed Tokens (must be inside app context)
            from .models import Thread
            from sqlalchemy import func
            total_tokens = db.session.query(func.sum(Thread.total_tokens)).scalar() or 0
            
            # 2. Save to DB
            new_metric = SystemMetric(
                timestamp=int(time.time()),
                cpu_percent=cpu,
                memory_percent=mem.percent,
                memory_used=round(mem.used / (1024**3), 2), # GB
                memory_total=round(mem.total / (1024**3), 2), # GB
                total_managed_tokens=total_tokens
            )
            db.session.add(new_metric)
            
            # 3. Cleanup Old Data (> 10 Days)
            # 10 days = 86400 * 10 seconds
            cutoff = int(time.time()) - (10 * 86400)
            
            # Efficient delete
            deleted = SystemMetric.query.filter(SystemMetric.timestamp < cutoff).delete()
            if deleted:
                logger.info(f"Cleaned up {deleted} old metric records.")
                
            db.session.commit()
        
        logger.info(f"Metrics Saved: CPU={cpu}%, MEM={mem.percent}%, Tokens={total_tokens}")
    except Exception as e:
        logger.error(f"System Metric Collection Failed: {e}")

