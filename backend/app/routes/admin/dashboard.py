from flask import render_template, session, redirect, url_for, request
from . import admin_bp
from ...models import User, Project, Thread
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
        
        query = Thread.query.filter_by(project_id=active_group['group_id'])
        
        if search_query:
            query = query.filter(
                (Thread.thread_id.ilike(f"%{search_query}%")) | 
                (Thread.remark.ilike(f"%{search_query}%"))
            )

        threads_pagination = query.paginate(page=t_page, per_page=50, error_out=False)
        threads_list = threads_pagination.items
        total_threads_count = threads_pagination.total
        project_total_count = Thread.query.filter_by(project_id=active_group['group_id']).count()

    # --- Key Masking ---
    from ... import security as core_security
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
    from ... import database
    
    security_data = get_dashboard_security_data()
    system_data = get_dashboard_system_data()
    user_data = get_dashboard_user_data()
    
    # Merge context
    context = {
        'groups_data': groups_data,
        'grouped_projects': grouped_projects,
        'active_group': active_group,
        'user_map': user_map,
        'threads': threads_list,
        'threads_pagination': threads_pagination,
        'total_threads_count': total_threads_count,
        'project_total_count': project_total_count,
        'search_query': search_query,
        'masked_key': masked_key,
        'auto_refresh_settings': database.load_settings().get('auto_refresh', {}),
        'username': session.get('username'),
        'current_role': session.get('role'),
        'active_group_id': active_group['group_id'] if active_group else None,
        **security_data,
        **system_data, # Note: system_data might overwrite masked_key if we are not careful. System data provided global settings.
        **user_data
    }
    
    # System data returns 'masked_key' as well (from my stub earlier).
    # I should check system.py get_dashboard_system_data.
    # It returns 'masked_key': "sk-***". 
    # I should prefer the Project Masked Key.
    # So I put system_data FIRST in merge, then overwrite with local params.
    
    context = {
        **security_data,
        **system_data,
        **user_data,
        'groups_data': groups_data,
        'grouped_projects': grouped_projects,
        'active_group': active_group,
        'user_map': user_map,
        'threads': threads_list,
        'threads_pagination': threads_pagination,
        'total_threads_count': total_threads_count,
        'project_total_count': project_total_count,
        'search_query': search_query,
        'masked_key': masked_key, # Overwrites system default
        'auto_refresh_settings': database.load_settings().get('auto_refresh', {}),
         'username': session.get('username'),
        'current_role': session.get('role'),
    }

    return render_template('admin.html', **context)
