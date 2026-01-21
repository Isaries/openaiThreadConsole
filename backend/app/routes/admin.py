from flask import Blueprint, render_template, request, redirect, url_for, flash, session, send_file, jsonify, current_app
import io
from ..extensions import db, limiter
from ..models import User, Project, Thread, Message, SearchHistory, AuditLog, IPBan, Tag, SystemMetric
from .. import utils
from .. import logic
import security
import database # Refactor this usage later
from datetime import datetime
import pandas as pd
import uuid
import config
import json
import psutil
from sqlalchemy.orm import subqueryload, joinedload
from sqlalchemy import func
from ..tasks import refresh_specific_threads
from .. import tasks

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.app_template_filter('pretty_json')
def pretty_json(value):
    return json.dumps(value, indent=2, ensure_ascii=False)

@admin_bp.route('/')
def index():
    if not session.get('user_id'): return redirect(url_for('auth.login'))
    
    group_id = request.args.get('group_id')
    projects = []
    
    # Permission Filter
    # Permission Filter & Eager Loading
    query = Project.query.options(
        subqueryload(Project.tags),
        subqueryload(Project.owners)
    )
    
    if session.get('role') == 'admin':
        projects = query.all()
    else:
        user_id = session.get('user_id')
        user = User.query.get(user_id)
        if user:
            # Re-query explicitly to use eager loading options for owned projects
            # (User.owned_projects is lazy, accessing it loses our options unless we query Project directly)
            projects = query.filter(Project.owners.any(id=user_id)).all()
            
    # Optimization: Aggregate Thread Counts (1 Query instead of N)
    # SELECT project_id, COUNT(id) FROM threads GROUP BY project_id
    thread_counts = dict(db.session.query(
        Thread.project_id, func.count(Thread.id)
    ).group_by(Thread.project_id).all())

    # Convert to dicts for template compatibility
    groups_data = []
    for p in projects:
        owners = [o.id for o in p.owners] # Already loaded
        tags = [tag.name for tag in p.tags] # Already loaded
        
        # Use O(1) lookup fro counts
        count = thread_counts.get(p.id, 0)
        
        groups_data.append({
            'group_id': p.id,
            'name': p.name,
            'api_key': p.api_key,
            'is_visible': p.is_visible,
            'version': p.version,
            'owners': owners,
            'tags': tags,
            'thread_count': count
        })

    # Select Active Group
    active_group = None
    if group_id:
        active_group = next((g for g in groups_data if g['group_id'] == group_id), None)
    if not active_group and groups_data:
        active_group = groups_data[0]
        
    # Group by Tag for Sidebar
    grouped_projects = {}
    for g in groups_data:
        # Use first tag or Uncategorized
        tag = g['tags'][0] if g['tags'] else '未分類'
        if tag not in grouped_projects:
            grouped_projects[tag] = []
        grouped_projects[tag].append(g)
        
    # Sort groups within tags? (Optional, maybe by name)
    # Sort tags? (Optional, maybe specific order)
        
    audit_logs = []
    audit_logs = []
    audit_logs_pagination = None
    
    if session.get('role') == 'admin':
        # Load Audit Logs from DB (Paginated)
        logs_page = request.args.get('logs_page', 1, type=int)
        audit_logs_pagination = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(page=logs_page, per_page=50, error_out=False)
        
        audit_logs = [{
            'time': utils.unix_to_utc8(l.timestamp.timestamp()),
            'user': l.user_name,
            'action': l.action,
            'target': l.target,
            'status': l.status,
            'details': l.details,
            'ip': l.ip_address,
            'created_at': int(l.timestamp.timestamp())
        } for l in audit_logs_pagination.items]
        

        
    # --- Fetch Search History (logs) ---
    search_history = SearchHistory.query.order_by(SearchHistory.timestamp.desc()).limit(10).all()
    import json
    search_logs = []
    for h in search_history:
        api_res = []
        if h.api_results_json:
            try:
                api_res = json.loads(h.api_results_json)
            except:
                pass
                
        search_logs.append({
            'time': utils.unix_to_utc8(h.timestamp),
            'group': h.project_name,
            'target': h.target_query,
            'date_range': h.date_range,
            'matches': h.match_count,
            'total': h.total_scanned,
            'api_results': api_res
        })
        
    users_list = []
    ip_activity = {}
    bans_pagination = None
    
    if session.get('role') == 'admin':
        # Load Users from DB
        users_obj = User.query.all()
        users_list = [{
            'id': u.id,
            'username': u.username,
            'email': u.email,
            'password_hint': u.password_hint,
            'created_at': u.created_at,
            'is_admin': u.is_admin,
            'owned_projects': len(u.owned_projects)
        } for u in users_obj]
        
        # Load Bans with Pagination
        page = request.args.get('page', 1, type=int)
        bans_pagination = IPBan.query.paginate(page=page, per_page=20, error_out=False)
        
        # Process IP Activity for Dashboard
        for log in audit_logs:
            ip = log['ip']
            if ip == '127.0.0.1': continue # Skip local noise if desired
            
            if ip not in ip_activity:
                # Async Load: Set placebo here, let Frontend fetch it
                ip_activity[ip] = {'logs': [], 'user': '訪客', 'last_seen': 0, 'geo': None}
            
            # Identity Refinement
            display_user = log['user']
            if display_user in ['Unknown', 'Guest', 'Guest IP']:
                display_user = '訪客'
            
            # Add log to list (audit_logs is already sorted desc)
            # Create a display copy for template
            log_display = log.copy()
            log_display['display_user'] = display_user
            ip_activity[ip]['logs'].append(log_display)
            
            # Update summary user (prioritize non-guest)
            if display_user != '訪客' and ip_activity[ip]['user'] == '訪客':
                ip_activity[ip]['user'] = display_user

    # Prepare User Map for Owners Display
    all_users = User.query.all()
    user_map = {u.id: u.username for u in all_users}

    # API Key Masking
    masked_key = "尚未設定 (使用環境變數/預設)"
    if active_group:
        decrypted = security.get_decrypted_key(active_group['api_key'])
        if decrypted == "INVALID_KEY_RESET_REQUIRED":
            masked_key = "⚠️ 金鑰失效 (需重設)"
        elif decrypted and len(decrypted) > 12:
            masked_key = f"{decrypted[:8]}...{decrypted[-4:]}"
        elif decrypted:
            masked_key = "******" # Short keys

    # Fetch all tags for autocomplete (Only showing active tags)
    all_tags = [t.name for t in Tag.query.filter(Tag.projects.any()).with_entities(Tag.name).distinct()]
    
    # --- Server-Side Pagination for Threads ---
    threads_pagination = None
    threads_list = []
    total_threads_count = 0
    
    if active_group:
        # Paginating the threads for the active project
        t_page = request.args.get('t_page', 1, type=int)
        search_query = request.args.get('q', '').strip()
        
        query = Thread.query.filter_by(project_id=active_group['group_id'])
        
        if search_query:
            # Server-Side Search: ID or Remark
            query = query.filter(
                (Thread.thread_id.ilike(f"%{search_query}%")) | 
                (Thread.remark.ilike(f"%{search_query}%"))
            )

        threads_pagination = query.paginate(page=t_page, per_page=50, error_out=False)
        threads_list = threads_pagination.items
        total_threads_count = threads_pagination.total
        
        # True Project Total (Unfiltered)
        project_total_count = Thread.query.filter_by(project_id=active_group['group_id']).count()
    else:
        search_query = ''
        project_total_count = 0

    return render_template('admin.html', 
                         groups=groups_data, 
                         grouped_projects=grouped_projects, 
                         active_group=active_group,
                         username=session.get('username'),
                         current_role=session.get('role'),
                         logs=search_logs,
                         users=users_list,
                         ip_activity=ip_activity,
                         banned_ips=bans_pagination, 
                         bans_pagination=bans_pagination,
                         audit_logs_pagination=audit_logs_pagination,
                         all_tags=all_tags, 
                         user_map=user_map,
                         masked_key=masked_key,
                         auto_refresh_settings=database.load_settings().get('auto_refresh', {}),
                         threads=threads_list, # Current Page Items
                         threads_pagination=threads_pagination, # Pagination Controls
                         total_threads_count=total_threads_count, # Filtered Count
                         project_total_count=project_total_count, # True Total
                         search_query=search_query)

@admin_bp.route('/group/create', methods=['POST'])
def create_group():
    if not session.get('user_id'): return redirect(url_for('auth.login'))
    name = request.form.get('name', '').strip()
    api_key = request.form.get('api_key', '').strip()
    
    if not name:
        flash('Project 名稱不能為空', 'error')
        return redirect(url_for('admin.index'))
        
    if not api_key:
        flash('API Key 不能為空', 'error')
        return redirect(url_for('admin.index'))
        
    if Project.query.filter_by(name=name).first():
        flash('Project 名稱已存在，請使用不同名稱', 'error')
        return redirect(url_for('admin.index'))

    new_id = f"group_{int(datetime.now().timestamp())}"
    
    if len(api_key) > 200:
         flash('API Key 過長', 'error')
         return redirect(url_for('admin.index'))
         
    encrypted_key = security.encrypt_data(api_key)
    hashed_key = security.hash_api_key(api_key)

    new_project = Project(
        id=new_id,
        name=name,
        api_key=encrypted_key,
        api_key_hash=hashed_key,
        is_visible=True,
        version=1
    )
    
    current_user_id = session.get('user_id')
    user = User.query.get(current_user_id)
    if user and session.get('role') != 'admin':
        new_project.owners.append(user)
    
    db.session.add(new_project)
    db.session.commit()
    
    # Log Audit (using db-based logging)
    log_audit('Create Group', name)
    flash(f'Project "{name}" 建立成功', 'success')
    return redirect(url_for('admin.index', group_id=new_id))

def log_audit(action, target, status="Success", details=""):
    # Helper to call database.log_audit or direct DB
    from .. import utils
    # Use database module if present or reimplement
    # Reimplementing simplified version:
    try:
        ip = utils.get_client_ip()
        new_log = AuditLog(
            user_name=session.get('username', 'Unknown'),
            action=action,
            target=target,
            status=status,
            details=details,
            ip_address=ip,
            timestamp=datetime.now()
        )
        db.session.add(new_log)
        db.session.commit()
    except Exception as e:
        print(f"Audit Log Error: {e}")

@admin_bp.route('/group/delete', methods=['POST'])
def delete_group():
    if not session.get('user_id'): return redirect(url_for('auth.login'))
    group_id = request.form.get('group_id')
    
    project = Project.query.get(group_id)
    if not project:
        flash('Project 不存在', 'error')
        return redirect(url_for('admin.index'))
        
    current_role = session.get('role')
    user_id = session.get('user_id')
    
    is_owner = any(o.id == user_id for o in project.owners)
    if current_role != 'admin' and not is_owner:
        flash('權限不足', 'error')
        return redirect(url_for('admin.index'))
    
    group_name = project.name
    
    # Track tags before deletion to check for orphans later
    affected_tags = list(project.tags)
    
    db.session.delete(project)
    db.session.commit()
    
    # Cleanup Orphan Tags
    for t in affected_tags:
        if not t.projects:
            db.session.delete(t)
    db.session.commit()
    
    return redirect(url_for('admin.index'))

@admin_bp.route('/group/update', methods=['POST'])
def update_group():
    if not session.get('user_id'): return redirect(url_for('auth.login'))
    
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    role = session.get('role')
    
    group_id = request.form.get('group_id')
    name = request.form.get('name')
    is_visible = request.form.get('is_visible') == 'on'
    api_key = request.form.get('api_key')
    client_version = request.form.get('version', type=int)
    
    project = Project.query.get(group_id)
    if not project:
         flash('Project not found', 'error')
         return redirect(url_for('admin.index'))
         
    is_owner = any(o.id == user.id for o in project.owners)
    if role != 'admin' and not is_owner:
         flash('Permission denied', 'error')
         return redirect(url_for('admin.index'))
         
    # Optimistic Locking Check
    # Ensure we are updating the version we saw
    current_version = project.version if project.version else 1
    if client_version is not None and client_version != current_version:
        flash('資料已被其他人修改，請重新整理頁面後再試 (Optimistic Lock Error)', 'error')
        return redirect(url_for('admin.index', group_id=group_id))
        
    # Update logic
    if name: project.name = name
    project.is_visible = is_visible

    if role == 'admin':
        owner_ids = request.form.getlist('owner_ids')
        new_owners = []
        for uid in owner_ids:
             u_obj = User.query.get(uid)
             if u_obj: new_owners.append(u_obj)
             
        # User Request: Admin must explicit have permission and Cannot remove themselves
        if user not in new_owners:
            new_owners.append(user)
            
        project.owners = new_owners
    
    if request.form.get('clear_key') == 'true':
        project.api_key = None
    elif api_key and api_key.strip():
        project.api_key = security.encrypt_data(api_key.strip())
        project.api_key_hash = security.hash_api_key(api_key.strip())
        
    project.version += 1
    db.session.commit()
    
    log_audit('Update Group', project.name)
    flash("Project updated", 'success')
    return redirect(url_for('admin.index', group_id=group_id))

# --- Thread Management ---
@admin_bp.route('/threads/add_one', methods=['POST'])
def add_one_thread():
    if not session.get('user_id'): return redirect(url_for('auth.login'))
    
    group_id = request.form.get('group_id')
    thread_id = request.form.get('thread_id', '').strip()
    
    # Robustness: Strict Format Check
    import re
    # Enforce exact match: starts with thread_, followed by alphanumeric, no whitespace/special chars
    if not re.fullmatch(r'thread_[A-Za-z0-9]+', thread_id):
        flash('Thread ID 格式錯誤 (必須以 thread_ 開頭，且僅包含英數字元)', 'error')
        return redirect(url_for('admin.index', group_id=group_id))
        
    project = Project.query.get(group_id)
    if not project: return redirect(url_for('admin.index'))
    
    # Permission Check
    is_owner = any(o.id == session.get('user_id') for o in project.owners)
    if session.get('role') != 'admin' and not is_owner:
        flash('權限不足', 'error')
        return redirect(url_for('admin.index', group_id=group_id))
    
    # Check duplicate
    exists = any(t.thread_id == thread_id for t in project.threads)
    if exists:
        flash('Thread ID already exists in this project', 'error')
    else:
        remark = request.form.get('remark', '').strip() or None
        new_t = Thread(thread_id=thread_id, project_id=project.id, remark=remark)
        db.session.add(new_t)
        project.version += 1
        db.session.commit()
        flash('Thread added with remark' if remark else 'Thread added', 'success')
        
    return redirect(url_for('admin.index', group_id=group_id))

@admin_bp.route('/threads/delete_multi', methods=['POST'])
def delete_multi():
    if not session.get('user_id'): return redirect(url_for('auth.login'))
    
    group_id = request.form.get('group_id')
    project = Project.query.get(group_id)
    if not project: 
        return redirect(url_for('admin.index'))
    
    # Permission Check
    is_owner = any(o.id == session.get('user_id') for o in project.owners)
    if session.get('role') != 'admin' and not is_owner:
        flash('權限不足', 'error')
        return redirect(url_for('admin.index', group_id=group_id))
    
    # Handle Select All Pages (Batch Delete)
    select_all_pages = request.form.get('select_all_pages') == 'true'
    count = 0
    
    if select_all_pages:
        # Batch Delete Logic for ALL in project
        search_q = request.form.get('search_q', '').strip()
        
        # Base Query
        base_query = db.session.query(Thread.id).filter_by(project_id=project.id)
        
        # Apply Search Filter if exists (SAFETY: Only delete what was searched)
        if search_q:
            base_query = base_query.filter(
                (Thread.thread_id.contains(search_q)) | 
                (Thread.remark.contains(search_q))
            )
            
        # 1. Delete all associated Messages first (Prevent Orphans)
        threads_subquery = base_query.subquery() # Use the filtered query
        Message.query.filter(Message.thread_id.in_(threads_subquery)).delete(synchronize_session=False)
        
        # 2. Delete the Threads
        # Re-construct query for delete or use subquery? 
        # Since we just deleted messages, we can now delete the threads using the same filter.
        # Note: Thread.query...delete() doesn't support join/subquery well in all dialects
        # But filter(Thread.id.in_(...)) works.
        count = Thread.query.filter(Thread.id.in_(threads_subquery)).delete(synchronize_session=False)
    else:
        # Standard Checkbox Selection
        thread_ids = request.form.getlist('selected_ids') # Input name from template is selected_ids
        if not thread_ids:
            # Fallback for single button press
            single_id = request.form.get('thread_id')
            if single_id: thread_ids = [single_id]
        
        if not thread_ids:
            flash('No threads selected', 'warning')
            return redirect(url_for('admin.index', group_id=group_id))
        
        for tid in thread_ids:
            t = Thread.query.filter_by(thread_id=tid, project_id=project.id).first()
            if t:
                db.session.delete(t)
                count += 1

    if count > 0:
        project.version += 1
            
    db.session.commit()
    flash(f'{count} threads deleted', 'success')
    return redirect(url_for('admin.index', group_id=group_id))

@admin_bp.route('/projects/tags/add', methods=['POST'])
def add_project_tag():
    if not session.get('user_id'): return {'status': 'error', 'message': 'Unauthorized'}, 401
    
    data = request.json
    group_id = data.get('group_id')
    tag_name = data.get('tag_name', '').strip()
    
    if not group_id or not tag_name:
        return {'status': 'error', 'message': 'Missing parameters'}, 400
        
    project = Project.query.get(group_id)
    if not project:
         return {'status': 'error', 'message': 'Project not found'}, 404
         
    # Permission Check
    is_owner = any(o.id == session.get('user_id') for o in project.owners)
    if session.get('role') != 'admin' and not is_owner:
         return {'status': 'error', 'message': 'Permission Denied'}, 403
         
    # Enforce Single Tag Limit (Replacement)
    # Clear existing tags first
    project.tags = []
        
    # Find or Create Tag
    tag = Tag.query.filter_by(name=tag_name).first()
    if not tag:
        tag = Tag(name=tag_name)
        db.session.add(tag)
        db.session.commit() # Commit to get ID
        
    if tag not in project.tags:
        project.tags.append(tag)
        db.session.commit()
        return {'status': 'success', 'tags': [t.name for t in project.tags]}
    
    return {'status': 'success', 'message': 'Tag already exists'}

@admin_bp.route('/projects/tags/remove', methods=['POST'])
def remove_project_tag():
    if not session.get('user_id'): return {'status': 'error', 'message': 'Unauthorized'}, 401
    
    data = request.json
    group_id = data.get('group_id')
    tag_name = data.get('tag_name')
    
    project = Project.query.get(group_id)
    if not project: return {'status': 'error', 'message': 'Project not found'}, 404
    
    # Permission Check
    is_owner = any(o.id == session.get('user_id') for o in project.owners)
    if session.get('role') != 'admin' and not is_owner:
         return {'status': 'error', 'message': 'Permission Denied'}, 403
         
    tag = Tag.query.filter_by(name=tag_name).first()
    if tag and tag in project.tags:
        project.tags.remove(tag)
        db.session.commit()
        
        # Cleanup Orphan Tag
        if not tag.projects:
             db.session.delete(tag)
             db.session.commit()
        
    return {'status': 'success', 'tags': [t.name for t in project.tags]}

@admin_bp.route('/threads/update_remark', methods=['POST'])
def update_thread_remark():
    if not session.get('user_id'): return {'error': 'Unauthorized'}, 401
    
    data = request.json
    thread_id = data.get('thread_id')
    group_id = data.get('group_id')
    new_remark = data.get('remark', '').strip()
    
    project = Project.query.get(group_id)
    if not project: return {'error': 'Project not found'}, 404
    
    # Permission check
    is_owner = any(o.id == session.get('user_id') for o in project.owners)
    if session.get('role') != 'admin' and not is_owner:
        return {'error': 'Permission denied'}, 403
        
    thread = Thread.query.filter_by(thread_id=thread_id, project_id=project.id).first()
    if thread:
        thread.remark = new_remark
        db.session.commit()
        return {'success': True}
    
    return {'error': 'Thread not found'}, 404

@admin_bp.route('/threads/export', methods=['POST'])
def export_excel():
    if not session.get('user_id'): return redirect(url_for('auth.login'))
    
    group_id = request.form.get('group_id')
    project = Project.query.get(group_id)
    
    if not project:
         flash('Project not found', 'error')
         return redirect(url_for('admin.index'))
         
    # Permission Check
    is_owner = any(o.id == session.get('user_id') for o in project.owners)
    if session.get('role') != 'admin' and not is_owner:
         flash('Permission Denied', 'error')
         return redirect(url_for('admin.index'))
         
    from ..services import excel_service
    try:
        # Handle Filtering Logic (Match Review/Refresh logic)
        select_all_pages = request.form.get('select_all_pages') == 'true'
        search_q = request.form.get('search_q', '').strip()
        filtered_ids = None
        
        if not select_all_pages:
             # If not selecting all pages, check for specific selections
             ids = request.form.getlist('selected_ids')
             # Fallback for single (if any)
             if not ids and request.form.get('thread_id'):
                 ids = [request.form.get('thread_id')]
             
             if ids:
                 filtered_ids = ids
        
        # If select_all_pages is True, we pass search_q to service to filter everything matching search
        # If select_all_pages is False but no IDs, it exports EVERYTHING (default behavior if nothing selected?)
        # UX Decision: If user clicks Export without selecting anything, usually implies "Export All Current View" or "Export All".
        # Current UI logic: 
        # - Top Toolbar Export: Outside of form? No, it's form="deleteMultiForm".
        # - If nothing selected, form submission sends empty selected_ids and select_all_pages=false.
        # - In that case, we should probably Export All (Project Backup behavior).
        
        # Pass filters to service
        return excel_service.generate_excel_export(
            project.id, 
            project.name, 
            filtered_ids=filtered_ids, 
            search_q=search_q if select_all_pages else None
        )
    except Exception as e:
        flash(f'Export Failed: {e}', 'error')
        return redirect(url_for('admin.index', group_id=group_id))

@admin_bp.route('/threads/view/<thread_id>')
def view_thread(thread_id):
    if not session.get('user_id'): return redirect(url_for('auth.login'))
    
    group_id = request.args.get('group_id')
    
    project = None
    if group_id:
        project = Project.query.get(group_id)
    else:
        # Fallback: Find which project this thread belongs to? 
        # Thread model DB lookup is fastest.
        t = Thread.query.filter_by(thread_id=thread_id).first()
        if t:
            project = t.project
            
    if not project:
        flash('Project not found for this thread', 'error')
        return redirect(url_for('admin.index'))
        
    # Permission Check
    is_owner = any(o.id == session.get('user_id') for o in project.owners)
    if session.get('role') != 'admin' and not is_owner:
         flash('Permission Denied', 'error')
         return redirect(url_for('admin.index'))
         
    # Fetch Data
    api_key = security.get_decrypted_key(project.api_key) if project.api_key else None
    
    # 1. Load from DB First (Cache)
    thread_obj = Thread.query.filter_by(thread_id=thread_id).first()
    
    is_syncing = False
    result = None
    
    if thread_obj:
        # CASE 1: Data Exists - Show Cache + Trigger Async Update
        # Fire-and-forget task
        try:
             tasks.refresh_specific_threads.schedule(args=(project.id, [thread_id]), delay=0)
             if not request.args.get('nomsg'): # Avoid spamming flash on auto-refresh
                 flash('正在後台更新數據，頁面顯示為快取資料。', 'info')
        except Exception as e:
             current_app.logger.warning(f"Failed to trigger async task: {e}")
        
        # Process from DB
        result = logic.process_thread_from_db(thread_obj, target_name="", start_date=None, end_date=None)
    
    else:
        # CASE 2: No Data (First Load) - Trigger Async Update + Show Loading State
        try:
             tasks.refresh_specific_threads.schedule(args=(project.id, [thread_id]), delay=0)
             is_syncing = True
             result = {'data': {'thread_id': thread_id}, 'remark': '', 'messages': []} # Empty stub
        except Exception as e:
             flash(f'無法啟動同步任務: {e}', 'error')
             return redirect(url_for('admin.index', group_id=project.id))

    return render_template('admin_thread_view.html', 
        result=result, 
        project=project,
        active_group={'group_id': project.id, 'name': project.name},
        is_syncing=is_syncing
    )

@admin_bp.route('/threads/refresh', methods=['POST'])
@limiter.limit("10 per hour")
def refresh_threads_cache():
    if not session.get('user_id'): return redirect(url_for('auth.login'))
    
    group_id = request.form.get('group_id')
    project = Project.query.get(group_id) # Load project FIRST
    if not project: 
        return redirect(url_for('admin.index'))
    
    # Permission
    is_owner = any(o.id == session.get('user_id') for o in project.owners)
    if session.get('role') != 'admin' and not is_owner:
         flash('Permission Denied', 'error')
         return redirect(url_for('admin.index', group_id=group_id))
         
    select_all_pages = request.form.get('select_all_pages') == 'true'
    search_q = request.form.get('search_q', '').strip()
    thread_ids = []
    
    if select_all_pages:
        # Fetch all IDs for project (with search filter)
        query = Thread.query.with_entities(Thread.thread_id).filter_by(project_id=project.id)
        
        if search_q:
            query = query.filter(
                (Thread.thread_id.contains(search_q)) | 
                (Thread.remark.contains(search_q))
            )
            
        all_objs = query.all()
        thread_ids = [t.thread_id for t in all_objs]
    else:
        thread_ids = request.form.getlist('selected_ids')
        if not thread_ids:
            single = request.form.get('thread_id')
            if single: thread_ids = [single]
            
    if not thread_ids:
        flash('未選擇任何 Thread', 'warning')
        return redirect(url_for('admin.index', group_id=group_id))
        
    # Enqueue Task
    refresh_specific_threads(group_id, thread_ids, group_name=project.name)
    flash(f'已排程更新 {len(thread_ids)} 筆資料的快取', 'success')
    return redirect(url_for('admin.index', group_id=group_id))



@admin_bp.route('/threads/upload', methods=['POST'])
def upload_file():
    if not session.get('user_id'): return redirect(url_for('auth.login'))
    group_id = request.form.get('group_id')
    
    file = request.files.get('file')
    if not file or not file.filename.endswith('.xlsx'):
        flash('請上傳 Excel (.xlsx) 檔案', 'error')
        return redirect(url_for('admin.index', group_id=group_id))

    project = Project.query.get(group_id)
    if not project: return redirect(url_for('admin.index'))

    # Optimistic Locking Check
    client_version = request.form.get('version', type=int)
    current_version = project.version if project.version else 1
    
    if client_version is not None and client_version != current_version:
        flash('資料已被其他人修改，請重新整理頁面後再試', 'error')
        return redirect(url_for('admin.index', group_id=group_id))

    is_owner = any(o.id == session.get('user_id') for o in project.owners)
    if session.get('role') != 'admin' and not is_owner:
         return redirect(url_for('admin.index'))

    from ..services import excel_service
    thread_data_map, error = excel_service.parse_excel_for_import(file)

    if error:
        flash(error, 'error')
        return redirect(url_for('admin.index', group_id=group_id))
        
    new_ids = list(thread_data_map.keys())
    action = request.form.get('action', 'add')
    
    try:
        # DB Transaction Logic moved to Service
        stats = excel_service.process_import_data(project.id, thread_data_map, action)
        
        if 'error' in stats:
             flash(f"處理失敗: {stats['error']}", 'error')
        else:
             if action == 'delete':
                 count = stats['deleted']
                 if count > 0:
                     flash(f'成功刪除 {count} 筆 Thread', 'success')
                     log_audit('Batch Delete Excel', f"{count} threads from {project.name}")
                 else:
                     flash('沒有刪除任何 Thread (Excel 中的 ID 在 Project 中找不到)', 'warning')
             else:
                 added = stats['added']
                 updated = stats['updated']
                 if added > 0 or updated > 0:
                     flash(f'處理完成: 新增 {added} 筆, 更新 {updated} 筆備註', 'success')
                     log_audit('Import Excel', f"{added} added, {updated} updated in {project.name}")
                 else:
                     flash('沒有處理任何資料 (Excel 可能為空或格式不符)', 'warning')

    except Exception as e:
        flash(f'檔案處理失敗: {str(e)}', 'error')
        
    return redirect(url_for('admin.index', group_id=group_id))

# --- User Management (Admin Only) ---
@admin_bp.route('/user/create', methods=['POST'])
def create_user():
    if session.get('role') != 'admin':
        return redirect(url_for('auth.login'))
        
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()
    
    if not username or not password:
        flash('欄位不完整', 'error')
        return redirect(url_for('admin.index'))
        
    if User.query.filter_by(username=username).first():
        flash('Username 已存在', 'error')
        return redirect(url_for('admin.index'))

    if email and User.query.filter_by(email=email).first():
        flash('Email 已存在', 'error')
        return redirect(url_for('admin.index'))
        
    # Validate Password
    is_valid, msg = security.validate_password_strength(password)
    if not is_valid:
        flash(msg, 'error')
        return redirect(url_for('admin.index'))

    from werkzeug.security import generate_password_hash
    new_user = User(
        id=str(uuid.uuid4()),
        username=username,
        email=email if email else None,
        password_hash=generate_password_hash(password),
        password_hint=security.generate_password_hint(password),
        is_admin=False,
        created_at=int(datetime.now().timestamp())
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    log_audit('Create User', username)
    flash(f'教師帳戶 {username} 建立成功', 'success')
    return redirect(url_for('admin.index'))

# --- API for Refresh History ---
@admin_bp.route('/api/refresh_history')
def get_refresh_history():
    if not session.get('user_id'): return {'error': 'Unauthorized'}, 401
    
    # Optional: Admin only?
    if session.get('role') != 'admin':
         return {'error': 'Permission Denied'}, 403
         
    from ..models import RefreshHistory
    from .. import utils
    
    # Get last 5
    items = RefreshHistory.query.order_by(RefreshHistory.timestamp.desc()).limit(5).all()
    
    data = []
    for item in items:
        data.append({
            'time': utils.unix_to_utc8(item.timestamp),
            'duration': f"{item.duration}s",
            'status': item.result_status,
            'total': item.total_scanned,
            'updated': item.updated_count,
            'errors': item.error_count,
            'logs': item.log_json
        })
        
    return {'data': data}

@admin_bp.route('/user/reset', methods=['POST'])
def reset_user_password():
    if not session.get('user_id') or session.get('role') != 'admin':
        return redirect(url_for('auth.login'))
        
    user_id = request.form.get('user_id')
    new_password = request.form.get('new_password', '').strip()
    
    user = User.query.get(user_id)
    if not user:
        flash('用戶不存在', 'error')
        return redirect(url_for('admin.index'))
        
    is_valid, msg = security.validate_password_strength(new_password)
    if not is_valid:
        flash(msg, 'error')
        return redirect(url_for('admin.index'))
    
    # Security: Prevent resetting Administrator password via UI (should use .env)
    if user.username == 'Administrator':
        flash('無法重設 Administrator 密碼 (請使用環境變數)', 'error')
        return redirect(url_for('admin.index'))
    
    from werkzeug.security import generate_password_hash
    user.password_hash = generate_password_hash(new_password)
    user.password_hint = security.generate_password_hint(new_password)
    
    db.session.commit()
    log_audit('Reset Password', user.username)
    flash(f'用戶 {user.username} 密碼重設成功', 'success')
    return redirect(url_for('admin.index'))

@admin_bp.route('/user/delete', methods=['POST'])
def delete_user():
    if not session.get('user_id') or session.get('role') != 'admin':
        return redirect(url_for('auth.login'))
        
    user_id = request.form.get('user_id')
    user = User.query.get(user_id)
    
    if user:
        username = user.username
        # Remove from all owned projects first (cascade handles secondary table?)
        # Association table `project_owners` doesn't strictly cascade on user delete in some configs
        # But let's assume SQLAlchemy handles it or we manually clear.
        # Actually simplest is just delete user - default relationship cleanup.
        # Orphan Project Handling: If this user is the last owner, assign to Administrator
        for project in user.owned_projects:
            # Check if user is the only one (or simply reassign to ensure safety)
            # If removing this user leaves 0 owners?
            # project.owners includes 'user'.
            if len(project.owners) <= 1:
                admin_user = User.query.filter_by(id='admin').first() or User.query.filter_by(username='Administrator').first()
                if admin_user and admin_user.id != user.id:
                    if admin_user not in project.owners:
                        project.owners.append(admin_user)
                        print(f"Reassigned project {project.name} to Admin due to orphan risk.")

        db.session.delete(user)
        db.session.commit()
        
        log_audit('Delete User', username)
        flash('用戶已刪除', 'success')
    
    return redirect(url_for('admin.index'))

@admin_bp.route('/user/update', methods=['POST'])
def update_user():
    if not session.get('user_id') or session.get('role') != 'admin':
        return redirect(url_for('auth.login'))
        
    user_id = request.form.get('user_id')
    new_username = request.form.get('username', '').strip()
    new_email = request.form.get('email', '').strip()
    
    user = User.query.get(user_id)
    if not user:
        flash('用戶不存在', 'error')
        return redirect(url_for('admin.index'))
        
    if new_username != user.username:
        if User.query.filter_by(username=new_username).first():
             flash('Username 已存在', 'error')
             return redirect(url_for('admin.index'))

    if new_email and new_email != user.email:
        if User.query.filter_by(email=new_email).first():
             flash('Email 已存在', 'error')
             return redirect(url_for('admin.index'))
             
    user.username = new_username
    user.email = new_email if new_email else None
    
    db.session.commit()
    log_audit('Update User', new_username)
    flash(f'用戶 {new_username} 資料更新成功', 'success')
    return redirect(url_for('admin.index'))

@admin_bp.route('/ip/ban', methods=['POST'])
def ban_ip_route():
    if not session.get('user_id') or session.get('role') != 'admin':
        return redirect(url_for('auth.login'))
        
    ip = request.form.get('ip')
    duration = request.form.get('duration', type=int) # seconds
    reason = request.form.get('reason', 'Admin Action')
    
    from .. import utils
    current_ip = utils.get_client_ip()
    if ip == current_ip:
        flash('⚠️ 安全警告：您不能封鎖自己的 IP！', 'error')
        return redirect(url_for('admin.index'))
    
    if ip:
        security.ban_ip(ip, duration, reason)
        log_audit('Ban IP', f"{ip} for {duration}s")
        flash(f'IP {ip} 已封鎖', 'success')
        
    return redirect(url_for('admin.index'))

@admin_bp.route('/ip/unban', methods=['POST'])
def unban_ip_route():
    if not session.get('user_id') or session.get('role') != 'admin':
        return redirect(url_for('auth.login'))
        
    ip = request.form.get('ip')
    
    if ip:
        security.unban_ip(ip)
        log_audit('Unban IP', ip)
        flash(f'IP {ip} 已解除封鎖', 'success')
        
    return redirect(url_for('admin.index'))

@admin_bp.route('/settings', methods=['POST'])
def update_settings():
    if not session.get('user_id') or session.get('role') != 'admin':
        from flask import jsonify
        return jsonify({'error': 'Unauthorized'}), 403
        
    data = request.json
    openai_key = data.get('openai_api_key')
    
    # We don't have a Settings model in SQL yet?
    # Original used database.load_settings() (JSON).
    # We should keep supporting settings.json for global config or move to DB.
    # For now, let's stick to database.load_settings (JSON) for global config
    # to avoid creating new table right now if not planned.
    # Wait, check if database.py supports load_settings.
    
    settings = database.load_settings() # Note: database.py needs to support this
    if openai_key:
        settings['openai_api_key'] = security.encrypt_data(openai_key)
        
    database.save_settings(settings)
    log_audit('Update Global Settings', 'OpenAI Key')
    from flask import jsonify
    return jsonify({'success': True})

@admin_bp.route('/settings/refresh_schedule', methods=['POST'])
def update_refresh_schedule():
    if not session.get('user_id') or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
        
    data = request.json
    enabled = data.get('enabled', False)
    try:
        frequency = int(data.get('frequency', 1))
        hour = int(data.get('hour', 2))
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid parameters'}), 400
        
    # Validation: 1-360 days
    if not (1 <= frequency <= 360):
        return jsonify({'error': 'Frequency must be between 1 and 360 days'}), 400
        
    # Validation: 0-23 hours
    if not (0 <= hour <= 23):
        return jsonify({'error': 'Hour must be between 0 and 23'}), 400
    
    settings = database.load_settings()
    current_config = settings.get('auto_refresh', {})
    
    # Preserve last_run if exists
    last_run = current_config.get('last_run')
    
    settings['auto_refresh'] = {
        'enabled': enabled,
        'frequency_days': frequency,
        'hour': hour,
        'last_run': last_run
    }
    
    database.save_settings(settings)
    
    return jsonify({'success': True})

@admin_bp.route('/performance')
def performance_dashboard():
    if not session.get('user_id'): return redirect(url_for('auth.login'))
    if session.get('role') != 'admin':
        flash('權限不足', 'error')
        return redirect(url_for('admin.index'))
        
    # 1. Fetch History
    # Limit to 10 days (80 records max roughly if 3hr interval)
    metrics_query = SystemMetric.query.order_by(SystemMetric.timestamp.asc()).all()
    
    max_history_seconds = 10 * 86400
    cutoff = datetime.now().timestamp() - max_history_seconds
    
    metrics = [m for m in metrics_query if m.timestamp >= cutoff]
    
    chart_data = [{
        'time': utils.unix_to_utc8(m.timestamp),
        'timestamp': m.timestamp,
        'cpu': m.cpu_percent,
        'mem_pct': m.memory_percent,
        'mem_gb': m.memory_used
    } for m in metrics]
    
    # 2. Real-time Snapshot (The "Now" point)
    # 2. Real-time Snapshot (The "Now" point)
    try:
        import time # Keep time, it wasn't at top yet
        
        # Fast sampling (0.5s)
        current_cpu = psutil.cpu_percent(interval=0.5)
        
        mem = psutil.virtual_memory()
        current_mem_pct = mem.percent
        current_mem_gb = round(mem.used / (1024**3), 2)
        current_mem_total = round(mem.total / (1024**3), 2)
        
        current_snapshot = {
            'time': '現在 (即時)',
            'timestamp': int(time.time()),
            'cpu': current_cpu,
            'mem_pct': current_mem_pct,
            'mem_gb': current_mem_gb
        }
        
        # Append snapshot to chart data
        chart_data.append(current_snapshot)
        
    except ImportError:
        flash('錯誤: 尚未安裝 psutil 套件，無法讀取即時數據。請執行 pip install psutil', 'error')
        current_snapshot = {'time': 'N/A', 'cpu': 0, 'mem_pct': 0, 'mem_gb': 0}
        current_mem_total = 0
    except Exception as e:
        flash(f'讀取系統數據失敗: {str(e)}', 'error')
        current_snapshot = {'time': 'Error', 'cpu': 0, 'mem_pct': 0, 'mem_gb': 0}
        current_mem_total = 0
    
    return render_template('admin/performance.html', 
                           chart_data=chart_data, 
                           current=current_snapshot,
                           mem_total=current_mem_total)


@admin_bp.route('/api/ip_geo', methods=['POST'])
@security.login_required
@limiter.limit("60 per minute")
def api_ip_geo():
    data = request.get_json()
    ips = data.get('ips', [])
    
    results = {}
    for ip in ips:
        # cache logic is in utils
        info = utils.get_ip_info(ip)
        results[ip] = info.get('desc', 'Unknown')
        
    return jsonify(results)
