from flask import render_template, session, redirect, url_for, request
from . import admin_bp
from ...models import User, Project, Thread, user_bookmarks
from ...extensions import db
from sqlalchemy.orm import subqueryload
from sqlalchemy import func

@admin_bp.route('/')
def index():
    if not session.get('user_id'): return redirect(url_for('auth.login'))
    
    group_id = request.args.get('group_id')
    projects = []
    
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
            projects = query.filter(Project.owners.any(id=user_id)).all()
            
    # Optimization: Aggregate Thread Counts
    thread_counts = dict(db.session.query(
        Thread.project_id, func.count(Thread.id)
    ).group_by(Thread.project_id).all())

    # Convert to dicts for template compatibility
    groups_data = []
    for p in projects:
        owners = [o.id for o in p.owners]
        tags = [tag.name for tag in p.tags]
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
        tag = g['tags'][0] if g['tags'] else '未分類'
        if tag not in grouped_projects:
            grouped_projects[tag] = []
        grouped_projects[tag].append(g)
        
    # User Map
    users_obj = User.query.all()
    user_map = {u.id: u.username for u in users_obj}
    
    # Placeholders for other modules to inject? 
    # For now, we import them or keep simple query logic here.
    # To avoid circular imports, simpler is to do the query here like before.
    
    # --- Threads Pagination ---
    threads_pagination = None
    threads_list = []
    total_threads_count = 0
    project_total_count = 0
    search_query = ''

    if active_group:
        t_page = request.args.get('t_page', 1, type=int)
        search_query = request.args.get('q', '').strip()
        status_filter = request.args.get('status_filter', '').strip()
        
        query = Thread.query.filter_by(project_id=active_group['group_id'])
        
        if search_query:
            query = query.filter(
                (Thread.thread_id.ilike(f"%{search_query}%")) | 
                (Thread.remark.ilike(f"%{search_query}%"))
            )
            
        if status_filter and status_filter != 'all':
            if status_filter == 'active':
                # Active is strictly defined as NOT low or frozen (matches UI logic)
                query = query.filter(Thread.refresh_priority.notin_(['low', 'frozen']))
            else:
                query = query.filter_by(refresh_priority=status_filter)

        threads_pagination = query.paginate(page=t_page, per_page=50, error_out=False)
        threads_list = threads_pagination.items
        total_threads_count = threads_pagination.total
        project_total_count = Thread.query.filter_by(project_id=active_group['group_id']).count()

    # --- Key Masking ---
    import security as core_security
    masked_key = "No Group Selected"
    if active_group:
         decrypted = core_security.get_decrypted_key(active_group['api_key'])
         if decrypted == "INVALID_KEY_RESET_REQUIRED":
              masked_key = "⚠️ 金鑰失效 (需重設)"
         elif decrypted and len(decrypted) > 12:
              masked_key = f"{decrypted[:8]}...{decrypted[-4:]}"
         elif decrypted:
              masked_key = "******"
    
    # --- Dependencies from other modules ---
    from .security import get_dashboard_security_data
    from .system import get_dashboard_system_data
    from .users import get_dashboard_user_data
    import database
    
    security_data = get_dashboard_security_data()
    system_data = get_dashboard_system_data()
    user_data = get_dashboard_user_data()

    # --- Bookmarks ---
    bookmarked_ids = set()
    my_bookmarks = []
    if session.get('user_id'):
         curr_user = User.query.get(session['user_id'])
         if curr_user:
             # Get bookmarked threads with proper field access
             bookmark_threads = curr_user.bookmarked_threads.order_by(user_bookmarks.c.created_at.desc()).all()
             bookmarked_ids = {t.thread_id for t in bookmark_threads}
             # Convert to dict for template access
             my_bookmarks = [{'thread_id': t.thread_id, 'project_id': t.project_id, 'remark': t.remark} for t in bookmark_threads]
    
    # Merge context (New context construction)
    context = {
        **security_data,
        **system_data,
        **user_data,
        'groups_data': groups_data,
        'grouped_projects': grouped_projects,
        'active_group': active_group,
        'user_map': user_map,
        'users': users_obj,  
        'threads': threads_list,
        'threads_pagination': threads_pagination,
        'total_threads_count': total_threads_count,
        'project_total_count': project_total_count,
        'search_query': search_query,
        'status_filter': status_filter if active_group else 'all', # Pass filter to template
        'masked_key': masked_key,
        'auto_refresh_settings': database.load_settings().get('auto_refresh', {}),
        'username': session.get('username'),
        'current_user_email': curr_user.email if session.get('user_id') and (curr_user := User.query.get(session['user_id'])) else None,
        'current_role': session.get('role'),
        'my_bookmarks': my_bookmarks,

        'bookmarked_ids': bookmarked_ids,
    }

    return render_template('admin.html', **context)
