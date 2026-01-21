from flask import Blueprint, redirect, url_for, request, session, render_template, current_app
from ..extensions import limiter
from .. import utils
from .. import logic 
import database
import security
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from ..services.captcha_service import CaptchaService

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

@main_bp.route('/favicon.ico')
def favicon():
    from flask import send_from_directory
    import os
    # Since we don't have a real .ico, we serve the .svg or just 404 cleanly.
    # But to stop the browser error, let's serve the svg with correct mime or just return 204.
    # Serving svg as ico might not work in all browsers but it stops the 502.
    # Better: Serve the svg if it exists.
    return send_from_directory(current_app.static_folder, 'favicon.svg', mimetype='image/svg+xml')

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
    
    # --- Fresh Mode Rate Limiting & Permission Check ---
    if mode == 'fresh':
        # Permission Check
        if not session.get('user_id'):
            return {'error': '權限不足：強制刷新功能僅限登入用戶使用'}, 403

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



        # --- Captcha Validation (Multi-Slot) ---
        user_captcha = request.form.get('captcha', '').strip()
        captcha_uid = request.form.get('captcha_uid', '').strip()
        
        captcha_store = session.get('captcha_store', {})
        correct_answer = captcha_store.get(captcha_uid)
        
        # Cleanup used answer (Prevent Replay)
        if captcha_uid in captcha_store:
            del captcha_store[captcha_uid]
            session['captcha_store'] = captcha_store
            session.modified = True
        
        if not correct_answer:
            return {'error': '驗證碼無效或已過期，請重新整理'}, 400
            
        # Case Insensitive Check
        if user_captcha.lower() != str(correct_answer).lower():
            return {'error': '驗證碼錯誤，請再試一次'}, 400

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



@main_bp.route('/search/result/<task_id>')
def search_result(task_id):
    from ..extensions import huey
    
    # 1. Check Huey Status (Metadata only)
    try:
        # We still rely on Huey for "Status" and "Metadata"
        # The task now returns a lightweight dict
        task_meta = huey.result(task_id, blocking=False, preserve=True)
    except Exception as e:
        current_app.logger.error(f"Huey Result Error: {e}")
        return {'status': 'error', 'message': str(e)}, 500

    if task_meta is None:
        return {'status': 'processing'}, 202
        
    if 'error' in task_meta:
        return f"Error: {task_meta['error']}", 500
        
    # 2. Determine Page
    page = request.args.get('page', 0, type=int)
    
    # 3. Fetch Data Chunk (Via Logic Layer)
    results = logic.get_search_result_page(task_id, page)

    # 4. Determine Response Type
    is_xhr = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    # search.js polling is XHR but expects Full HTML (no page param)
    # pagination.js (our new logic) is XHR and sends page param
    
    # Logic: If XHR and Page is explicitly set > 0? No, Page 0 can be paginated too.
    # We differentiate by assuming the polling call does NOT send ?page=...
    # But wait, request.args.get('page', 0) defaults to 0.
    # explicit_page = request.args.get('page') is not None
    
    explicit_page = 'page' in request.args
    
    if is_xhr and explicit_page:
        # Partial Render for seamless pagination
        return render_template('_thread_list.html', 
            results=results, 
            task_id=task_id,
            page_index=page,
            target_name=task_meta.get('target_name', '')
        )
    
    # Full Page Render (First load or Refresh or Polling completion)
    return render_template('result.html', 
        results=results, 
        target_name=task_meta['target_name'], 
        count=task_meta['count'],
        # Calculate target_time if not present
        target_time=f"{task_meta.get('duration', 0):.2f} 秒",
        date_range=task_meta.get('date_range'),
        debug_log=task_meta.get('debug_log', []),
        
        # Pagination Meta
        task_id=task_id,
        total_pages=task_meta.get('total_pages', 1),
        current_page=page,
        page_index=page
    )

@main_bp.route('/captcha')
@limiter.limit("60 per minute")
def get_captcha():
    mode = request.args.get('type', 'normal')
    uid = request.args.get('uid')
    
    if not uid:
        return {'error': 'Missing UID'}, 400

    data = CaptchaService.generate(mode=mode)
    
    # Store Answer in Session Store (Max 5 items to prevent cookie overflow)
    captcha_store = session.get('captcha_store', {})
    
    # Prune if too large (remove random/oldest)
    if len(captcha_store) >= 5:
        # Simple prune: remove the first key found (FIFO-ish in Python 3.7+)
        first_key = next(iter(captcha_store))
        del captcha_store[first_key]
        
    captcha_store[uid] = data['answer']
    session['captcha_store'] = captcha_store
    
    from flask import Response
    return Response(data['image'], mimetype=data['content_type'])
