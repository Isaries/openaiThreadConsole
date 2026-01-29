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

def run_recalculation_logic():
    """
    Helper to run the recalculation logic (shared with task)
    """
    from . import create_app, logic
    from .models import Thread, Message
    
    app = create_app()
    with app.app_context():
        threads = Thread.query.all()
        updated_count = 0
        error_count = 0
        
        for t in threads:
            try:
                # Optimized: Accessing messages via relationship
                messages = t.messages 
                messages_data = []
                for msg in messages:
                    messages_data.append({
                        'role': msg.role,
                        'content': [{'type': 'text', 'text': {'value': msg.content or ''}}]
                    })
                
                token_count = logic.calculate_messages_tokens(messages_data)
                
                if token_count is not None:
                     if t.total_tokens != token_count:
                        t.total_tokens = token_count
                        updated_count += 1
                else:
                    error_count += 1
            except Exception:
                error_count += 1
                
        if updated_count > 0:
            db.session.commit()
            
        return updated_count, error_count

@huey.task()
def recalculate_tokens_task():
    logger.info("Starting Token Recalculation Task")
    try:
        updated, errors = run_recalculation_logic()
        logger.info(f"Token Recalculation Finished. Updated: {updated}, Errors: {errors}")
    except Exception as e:
        logger.error(f"Token Recalculation Failed: {e}")


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
        
        # Progress Tracking
        total_threads = len(threads)
        processed_threads = 0
        
        # 1. Cleanup & Initialization Phase
        # CLEANUP: Delete old search results for this task_id before creating new ones
        if task and task.id:
            try:
                from .models import SearchResultChunk
                deleted = SearchResultChunk.query.filter_by(task_id=task.id).delete()
                if deleted > 0:
                    logger.info(f"Cleaned up {deleted} old search result chunks for task {task.id}")
                
                # Create initial progress chunk (page_index = -1)
                initial_chunk = SearchResultChunk(
                    task_id=task.id,
                    page_index=-1,
                    data_json='[]',
                    progress_data=json.dumps({
                        'progress': {
                            'current': 0,
                            'total': total_threads,
                            'percentage': 0,
                            'phase': 'syncing' if mode == 'fresh' else 'searching'
                        }
                    })
                )
                db.session.add(initial_chunk)
                db.session.commit()
            except Exception as e:
                logger.warning(f"Failed to cleanup or initialize progress: {e}")
                db.session.rollback()

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
                            processed_threads += 1  # Count skipped threads
                            logger.info(f"Skipped frozen thread: {t.thread_id}")
                            continue
                        elif t.refresh_priority == 'low':
                            # 80% chance to skip
                            if random.random() < 0.8:
                                skipped_low += 1
                                processed_threads += 1  # Count skipped threads
                                logger.info(f"Skipped low priority thread: {t.thread_id}")
                                continue
                    
                    logic.sync_thread_to_db(t.thread_id, api_key, project_id)
                    refreshed_count += 1
                    processed_threads += 1
                    
                    # Update progress every 10 threads
                    if task and task.id and processed_threads % 10 == 0:
                        try:
                            from .models import SearchResultChunk
                            chunk = SearchResultChunk.query.filter_by(task_id=task.id, page_index=-1).first()
                            if chunk:
                                chunk.progress_data = json.dumps({
                                    'progress': {
                                        'current': processed_threads,
                                        'total': total_threads,
                                        'percentage': round((processed_threads / total_threads) * 100, 1) if total_threads > 0 else 0,
                                        'phase': 'syncing'
                                    }
                                })
                                db.session.commit()
                        except Exception as prog_err:
                            logger.debug(f"Progress update failed: {prog_err}")
                except Exception as e:
                     logger.error(f"Sync failed for {t.thread_id}: {e}")
                     processed_threads += 1

        # 2. Search Phase
        matching_threads = logic.search_threads_sql(project_id, target_name, start_date, end_date)
        
        # Update progress to "searching" phase
        if task and task.id:
            try:
                chunk = SearchResultChunk.query.filter_by(task_id=task.id, page_index=-1).first()
                if chunk:
                    chunk.progress_data = json.dumps({
                        'progress': {
                            'current': processed_threads,
                            'total': total_threads,
                            'percentage': round((processed_threads / total_threads) * 100, 1) if total_threads > 0 else 0,
                            'phase': 'searching'
                        }
                    })
                    db.session.commit()
                    logger.info(f"Task {task.id}: Progress updated to SEARCHING ({processed_threads}/{total_threads})")
            except Exception as e:
                logger.debug(f"Task {task.id}: Search phase progress update failed: {e}")
                pass
        
        # Chunking Logic
        matching_count = len(matching_threads)
        processed_matches = 0
        BATCH_SIZE = 10
        current_batch = []
        page_index = 0
        total_count = 0
        
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
                    try:
                        chunk = SearchResultChunk(
                            task_id=task.id,
                            page_index=page_index,
                            data_json=json.dumps(current_batch, ensure_ascii=False),
                            created_at=int(time.time())
                        )
                        db.session.add(chunk)
                        db.session.commit()
                        page_index += 1
                        current_batch = []
                    except Exception as e:
                        logger.error(f"Task {task.id}: Chunk write failed: {e}")
                        db.session.rollback()
            
            # Update matching progress every 10 threads
            processed_matches += 1
            if task and task.id and processed_matches % 10 == 0:
                try:
                    p_chunk = SearchResultChunk.query.filter_by(task_id=task.id, page_index=-1).first()
                    if p_chunk:
                        p_chunk.progress_data = json.dumps({
                            'progress': {
                                'current': processed_matches,
                                'total': matching_count,
                                'percentage': round((processed_matches / matching_count) * 100, 1) if matching_count > 0 else 0,
                                'phase': 'processing'
                            }
                        })
                        db.session.commit()
                except:
                    pass

        # Final Flush for any remaining results
        if current_batch and task and task.id:
            try:
                chunk = SearchResultChunk(
                    task_id=task.id,
                    page_index=page_index,
                    data_json=json.dumps(current_batch, ensure_ascii=False),
                    created_at=int(time.time())
                )
                db.session.add(chunk)
                db.session.commit()
            except Exception as e:
                logger.error(f"Task {task.id}: Final chunk write failed: {e}")
                db.session.rollback()
        
        duration = time.time() - startTime
        
        # Save Search History Log
        utc8 = timezone(timedelta(hours=8))
        log_time = datetime.now(utc8)
        date_range_str = f"{start_date} ~ {end_date}" if start_date and end_date else "All Time"
            
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
            'duration': duration,
            'target_name': target_name,
            'date_range': date_range_str,
            'refreshed_count': refreshed_count,
            'skipped_frozen': skipped_frozen,
            'skipped_low': skipped_low
        }
        
        logger.info(f"Task {task.id} finished. Matches: {total_count}. Duration: {duration:.2f}s")
        return result

# --- Scheduled Tasks ---


def run_global_refresh_logic(frequency_days=3, force_all=False):
    """
    Core logic for global refresh.
    frequency_days: Staleness threshold.
    force_all: If True, bypass staleness check (effectively frequency_days=0).
    """
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
                    
                    # Check staleness
                    # If force_all is True, we skip interval check
                    should_refresh = force_all or ((current_ts - last_sync) > interval)
                    
                    if should_refresh:
                        logger.info(f"Refeshing stale cache: {t.thread_id}")
                        try:
                            s, m = logic.sync_thread_to_db(t.thread_id, p.api_key, p.id)
                            if s: 
                                updated_count += 1
                                pending_updates += 1
                            else: 
                                error_count += 1
                                logger.warning(f"Failed to refresh {t.thread_id}: {m}")
                                if len(error_logs) < 10: # Limit log size
                                    error_logs.append(f"{t.thread_id}: {m}")
                        except Exception as sync_err:
                            error_count += 1
                            logger.error(f"CRITICAL Sync Error for {t.thread_id}: {sync_err}")
                            if len(error_logs) < 10:
                                error_logs.append(f"{t.thread_id}: CRITICAL {sync_err}")
                        
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
            
            logger.info(f"Refresh Logic Completed. Updated: {updated_count}, Errors: {error_count}")
            return updated_count, error_count

    except Exception as e:
        logger.error(f"Refresh CRITICAL FAILURE: {e}")
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
        except Exception as e:
            logger.error(f"Failed to save refresh history: {e}")
        return 0, 0 # Return 0 on failure

@huey.task()
def manual_global_refresh_task(force=False):
    """
    Manual global refresh triggered by Admin.
    If force=True, we bypass frequency check (force_all=True).
    If force=False, we respect frequency settings (standard check).
    """
    logger.info(f"Starting Manual Global Refresh Task (Force={force})")
    
    settings = database.load_settings()
    config_data = settings.get('auto_refresh', {})
    frequency_days = int(config_data.get('frequency_days', 3))
    
    # Run logic
    run_global_refresh_logic(frequency_days=frequency_days, force_all=force)


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
    
    # Run Logic
    updated, errors = run_global_refresh_logic(frequency_days=frequency_days)
    
    # Update Last Run Time ONLY for Scheduled Task
    # Update Last Run Time (Re-load to prevent Race Condition with Admin UI)
    try:
        # Need app context for database load/save? logic runs inside app context.
        # But here we are outside app context in the task wrapper.
        # database.load_settings creates context if needed? NO.
        # We need to create context or use the one inside logic?
        # logic handles context internally.
        # We should create context here for saving settings.
        
        from . import create_app
        app = create_app()
        with app.app_context():
            current_settings = database.load_settings()
            current_config = current_settings.get('auto_refresh', {})
            
            current_config['last_run'] = now.isoformat()
            current_settings['auto_refresh'] = current_config
            
            database.save_settings(current_settings)
            
    except Exception as e:
        logger.error(f"Failed to update last run time: {e}")
                    

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
            s, m = logic.sync_thread_to_db(
                tid, 
                project.api_key, 
                project_id, 
                force_active=True # Force unfreeze on manual refresh
            )
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

# --- Memory Leak Prevention: Cleanup Old Search Results ---
@huey.periodic_task(crontab(minute='*/30'))  # Every 30 minutes
def cleanup_old_search_results():
    """
    Cleanup search result chunks older than 1 hour to prevent memory leaks.
    Search results are temporary and only needed while user is viewing them.
    """
    logger.info("Starting Search Result Cleanup")
    try:
        from .models import SearchResultChunk
        from . import create_app
        
        app = create_app()
        with app.app_context():
            # Delete chunks older than 1 hour
            cutoff = int(time.time()) - 3600  # 1 hour ago
            
            deleted = SearchResultChunk.query.filter(
                SearchResultChunk.created_at < cutoff
            ).delete()
            
            if deleted > 0:
                db.session.commit()
                logger.info(f"Cleaned up {deleted} old search result chunks")
            else:
                logger.info("No old search results to cleanup")
                
    except Exception as e:
        logger.error(f"Search Result Cleanup Failed: {e}")
        try:
            db.session.rollback()
        except:
            pass

# --- Batch PDF Export Tasks ---
def _generate_single_thread_pdf(project_id, thread_id):
    """
    Helper to generate PDF for a single thread.
    Returns PDF bytes (for threads <=50 messages) or ZIP bytes (for larger threads).
    """
    from .models import Project
    from . import logic as legacy_services
    from .services import pdf_service
    from flask import render_template
    import io
    import math
    
    project = Project.query.get(project_id)
    if not project:
        raise ValueError(f"Project {project_id} not found")
    
    api_key_enc = project.api_key
    
    # Process thread data
    logger.info(f"Generating PDF for thread {thread_id} in project {project_id}")
    thread_data = legacy_services.process_thread(
        {'thread_id': thread_id}, None, None, None, api_key_enc, project_id
    )
    
    if not thread_data or not thread_data.get('data'):
        logger.error(f"Thread {thread_id} returned no data. Status: {thread_data.get('status') if thread_data else 'None'}")
        raise ValueError(f"Thread {thread_id} not found or empty")
    
    messages = thread_data['data']['messages']
    logger.info(f"Thread {thread_id}: {len(messages)} messages")
    
    # Helper for headers
    def get_headers_callback(key):
        return legacy_services.get_headers(key)
    
    CHUNK_SIZE = 50
    total_messages = len(messages)
    
    if total_messages <= CHUNK_SIZE:
        # Single PDF
        html = render_template('print_view.html', threads=[thread_data['data']])
        html, temp_files = pdf_service.preprocess_html_for_pdf(html, project_id, get_headers_callback)
        try:
            pdf_bytes = pdf_service.generate_pdf_bytes(html)
            return {'type': 'pdf', 'data': pdf_bytes}
        finally:
            pdf_service.cleanup_temp_images(temp_files)
    else:
        # Split into multiple PDFs in a mini-ZIP
        import zipfile
        chunks = math.ceil(total_messages / CHUNK_SIZE)
        zip_buffer = io.BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            for i in range(chunks):
                start = i * CHUNK_SIZE
                end = start + CHUNK_SIZE
                chunk_msgs = messages[start:end]
                
                chunk_data = thread_data['data'].copy()
                chunk_data['messages'] = chunk_msgs
                
                html = render_template('print_view.html', threads=[chunk_data])
                html, temp_files = pdf_service.preprocess_html_for_pdf(html, project_id, get_headers_callback)
                
                try:
                    pdf_bytes = pdf_service.generate_pdf_bytes(html)
                    zf.writestr(f"thread_{thread_id}_part_{i+1}.pdf", pdf_bytes)
                finally:
                    pdf_service.cleanup_temp_images(temp_files)
        
        zip_buffer.seek(0)
        return {'type': 'zip', 'data': zip_buffer.getvalue()}

def _worker_generate_pdf_wrapper(project_id, thread_id):
    """
    Worker function for ProcessPoolExecutor.
    Must be a top-level function (not nested) to be picklable.
    """
    from . import create_app
    
    app = create_app()
    with app.app_context():
        return _generate_single_thread_pdf(project_id, thread_id)


@huey.task()
def generate_batch_pdf_task(project_id, thread_ids, user_id, task_id):
    """
    Background task to generate batch PDF export.
    Creates a ZIP file containing PDFs for all selected threads.
    task_id is pre-created in the route to avoid race conditions.
    """
    logger.info(f"Starting Batch PDF Export Task {task_id} for {len(thread_ids)} threads")
    
    from . import create_app
    from .models import PDFExportTask
    import config
    
    app = create_app()
    
    with app.app_context():
        # 1. Get the pre-created task record and update status
        task_record = PDFExportTask.query.get(task_id)
        if not task_record:
            logger.error(f"Task record {task_id} not found")
            return
        
        task_record.status = 'running'
        db.session.commit()

        
        try:
            # 2. Create export directory
            export_dir = config.TEMP_PDF_EXPORT_DIR
            os.makedirs(export_dir, exist_ok=True)
            
            zip_path = os.path.join(export_dir, f"{task_id}.zip")
            
            # 3. Generate PDFs and write to ZIP (Parallel Processing)
            import zipfile
            from concurrent.futures import ProcessPoolExecutor, as_completed
            
            max_workers = int(os.getenv('PDF_EXPORT_MAX_WORKERS', '2'))
            logger.info(f"Task {task_id}: Creating ZIP at {zip_path} with {max_workers} workers")
            
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                success_count = 0
                
                # Submit all tasks to process pool
                with ProcessPoolExecutor(max_workers=max_workers) as executor:
                    future_to_thread = {
                        executor.submit(_worker_generate_pdf_wrapper, project_id, tid): tid
                        for tid in thread_ids
                    }
                    
                    # Collect results as they complete
                    completed = 0
                    for future in as_completed(future_to_thread):
                        thread_id = future_to_thread[future]
                        completed += 1
                        
                        logger.info(f"Task {task_id}: Processing thread {completed}/{len(thread_ids)}: {thread_id}")
                        
                        try:
                            result = future.result(timeout=120)  # 2-minute timeout per thread
                            
                            if result:
                                # Handle PDF or ZIP result
                                if result['type'] == 'zip':
                                    # Expand mini-ZIP into main ZIP
                                    mini_zip_buffer = io.BytesIO(result['data'])
                                    with zipfile.ZipFile(mini_zip_buffer, 'r') as mini_zip:
                                        for name in mini_zip.namelist():
                                            zf.writestr(name, mini_zip.read(name))
                                    logger.info(f"Task {task_id}: Expanded ZIP for {thread_id} ({len(result['data'])} bytes)")
                                else:
                                    # Single PDF
                                    zf.writestr(f"thread_{thread_id}.pdf", result['data'])
                                    logger.info(f"Task {task_id}: Added {thread_id} PDF ({len(result['data'])} bytes)")
                                
                                success_count += 1
                            else:
                                logger.warning(f"Task {task_id}: No result returned for {thread_id}")
                            
                        except TimeoutError:
                            logger.error(f"Task {task_id}: Timeout for thread {thread_id} (>120s)")
                        except Exception as e:
                            logger.error(f"Task {task_id}: Failed to export thread {thread_id}: {e}", exc_info=True)
                        
                        # Update progress
                        task_record.progress_current = completed
                        db.session.commit()
                
                logger.info(f"Task {task_id}: ZIP complete with {success_count}/{len(thread_ids)} files")
            
            # 4. Mark as completed
            task_record.status = 'completed'
            task_record.file_path = zip_path
            task_record.completed_at = int(time.time())
            db.session.commit()
            
            logger.info(f"Batch PDF Export Task {task_id} completed successfully")
            
        except Exception as e:
            logger.error(f"Batch PDF Export Task {task_id} failed: {e}")
            task_record.status = 'failed'
            task_record.error_message = str(e)
            db.session.commit()

@huey.periodic_task(crontab(hour='4', minute='0'))
def cleanup_pdf_exports():
    """Clean up PDF export files older than PDF_EXPORT_TTL_HOURS"""
    logger.info("Starting PDF Export Cleanup Task")
    
    from . import create_app
    from .models import PDFExportTask
    import config
    
    app = create_app()
    
    with app.app_context():
        cutoff = time.time() - (config.PDF_EXPORT_TTL_HOURS * 3600)
        
        # Clean up files
        export_dir = config.TEMP_PDF_EXPORT_DIR
        if os.path.exists(export_dir):
            files = glob.glob(os.path.join(export_dir, "*.zip"))
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
            
            logger.info(f"Deleted {count} old PDF export files")
        
        # Clean up database records
        old_tasks = PDFExportTask.query.filter(
            PDFExportTask.created_at < int(cutoff)
        ).all()
        
        for task in old_tasks:
            db.session.delete(task)
        
        db.session.commit()
        logger.info(f"Deleted {len(old_tasks)} old PDF export task records")
