from flask import Blueprint, redirect, url_for, request, session, render_template, current_app
from ..extensions import limiter
from .. import utils
from .. import logic 
import database
import security
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    # Legacy Logic Restoration
    all_groups = database.load_groups()
    # Filter for visible groups
    groups = [g for g in all_groups if g.get('is_visible', True)]
    
    # Extract all unique tags
    all_tags = sorted(list(set(t for g in groups for t in g.get('tags', []))))
    
    # Optional: Log visit (Unknown/User)
    database.log_audit(session.get('username', 'Unknown'), 'Visit', 'Home')
    
    return render_template('index.html', groups=groups, all_tags=all_tags)

@main_bp.route('/search', methods=['POST'])
@limiter.limit("20 per minute")
def search():
    # Standard Form Submission
    group_id = request.form.get('group_id')
    target_name = request.form.get('target_name', '').strip()
    date_from = request.form.get('start_date')
    date_to = request.form.get('end_date')
    
    # 1. Permission/Group Check
    group = database.get_group_by_id(group_id)
    if not group: 
        return "Group not found", 404
        
    if not group.get('is_visible', True):
        return "Group is hidden", 403

    # Audit (Basic initiation log)
    # database.log_audit(session.get('username', 'Unknown'), 'Search Init', target_name or 'All', 'Success', f"Group: {group['name']}")
    
    # Get Key
    api_key = group.get('api_key')
    if api_key:
        api_key = security.get_decrypted_key(api_key)

    # Mode Extraction (default: quick)
    mode = request.form.get('mode', 'quick')
    
    # --- Fresh Mode Rate Limiting (2 per minute) ---
    if mode == 'fresh':
        ip = utils.get_client_ip()
        from ..models import AuditLog
        from datetime import datetime, timedelta
        
        # Check last 60 seconds
        cutoff = datetime.now() - timedelta(seconds=60)
        
        recent_count = AuditLog.query.filter(
            AuditLog.ip_address == ip,
            AuditLog.action == 'Search Init Fresh',
            AuditLog.timestamp >= cutoff
        ).count()
        
        if recent_count >= 2:
            current_app.logger.warning(f"Rate Limit Hit (Fresh) for {ip}")
            return {'error': '強制刷新頻率過高 (每分鐘限 2 次)，請稍後再試。'}, 429

    # Audit (Log initiation to count later)
    action_name = 'Search Init Fresh' if mode == 'fresh' else 'Search Init Quick'
    database.log_audit(session.get('username', 'Unknown'), action_name, target_name or 'All', 'Success', f"Group: {group['name']}")
    
    # Trigger Async Task
    from .. import tasks
    task = tasks.search_task(group_id, target_name, date_from, date_to, api_key, group_id, group['name'], mode=mode)
    
    # Return Task ID for polling
    # Return Task ID for polling, and Total Threads for progress
    threads_list = group.get('threads', [])
    return {'task_id': task.id, 'total': len(threads_list)}, 202

@main_bp.route('/search/cancel/<task_id>', methods=['POST'])
def cancel_search(task_id):
    from ..extensions import huey
    # Revoke task
    huey.revoke_by_id(task_id)
    return {'status': 'cancelled'}, 200

@main_bp.route('/search/status/<task_id>')
def search_status(task_id):
    from .. import tasks
    from ..extensions import huey
    
    # result() would block. We want check existence.
    # Huey (Sqlite) stores results in db.
    
    # Check if task is finished
    # We can try to get the result with non-blocking=True logic?
    # SqliteHuey.get(key)
    
    # Standard way: task = search_task.result(task_id, blocking=False) ?
    # task instance isn't available here easily without importing the function object.
    
    task_result = tasks.search_task.result(task_id, preserve=True) 
    # preserve=True keeps it so we can read it again in /result route?
    # Actually, if we read it here, we might consume it?
    # Huey default: get() removes it.
    
    # Better approach: 
    # Just use 'get' but check for None (Pending).
    # But if we get it, it's gone from queue storage.
    # So we should only get it in the final /result route.
    
    # How to check status without consuming?
    # SqliteHuey doesn't have a specific "status" API easily exposed without Peek.
    # But we can assume if result is ready, it returns.
    
    # WORKAROUND for SqliteHuey simple polling:
    # Just poll /result? 
    # If /result returns 202, it means not ready.
    # If 200, it renders.
    # This simplifies things.
    pass 
    # Merged with result route below.
    return {'status': 'deprecated, use /search/result directly'}, 404

@main_bp.route('/search/result/<task_id>')
def search_result(task_id):
    from ..extensions import huey
    
    # Correct Way: Use huey instance to get result by ID
    # blocking=False returns None if not ready
    # preserve=True ensures we can refresh the page
    
    try:
        data = huey.result(task_id, blocking=False, preserve=True)
    except Exception as e:
        # Handle cases where huey might raise error on invalid ID format etc
        current_app.logger.error(f"Huey Result Error: {e}")
        return {'status': 'error', 'message': str(e)}, 500

    if data is None:
        # Task still running
        return {'status': 'processing'}, 202
        
    # Task Finished
    if 'error' in data:
        return f"Error: {data['error']}", 500
        
    return render_template('result.html', 
        results=data['results'], 
        target_name=data['target_name'], 
        count=data['count'],
        target_time=f"{data['duration']:.2f} 秒",
        date_range=data['date_range'],
        debug_log=data['debug_log']
    )
