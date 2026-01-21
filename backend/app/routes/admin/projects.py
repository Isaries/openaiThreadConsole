from flask import request, redirect, url_for, flash, session
from . import admin_bp
from ...models import Project, Tag
from ...extensions import db
from .security import log_audit
from ... import security as core_security
import uuid

@admin_bp.route('/group/create', methods=['POST'])
def create_group():
    if not session.get('user_id'): return redirect(url_for('auth.login'))
    
    # 1. Gather Inputs
    name = request.form.get('name')
    api_key_input = request.form.get('api_key')
    
    # Permission Check (Standard User can only see view, Admin can create)
    # Refined Logic: Only Admin can create new projects?
    # Legacy: if user and role != admin: new_project.owners.append(user) -> imply users CAN create?
    # Legacy Line 254: only checks login.
    # Legacy Line 290: logic to add owner.
    # So Standard Users CAN create projects.
    
    # Check permissions logic in new code:
    # if current code: "if session.get('role') != 'admin': ... flash('權限不足')" -> Standard user CANNOT create.
    # Legacy code ALLOWED standard user to create (implicitly, layout might hide button, but route didn't block).
    # Admin.html line 46: Button to show form. Visible to everyone? 
    # Admin.html sidebar: No role check for button.
    # But let's check legacy again.
    # Legacy Line 252: create_group. No role check.
    # So I should ALLOW standard users to create projects, and make them owner.
    
    # New code previously blocked non-admins?
    # Lines 20-33 in projects.py blocked it.
    # I will RESTORE legacy behavior: Allow standard users to create.
    
    if not name or not api_key_input:
         flash('請填寫完整資訊', 'error')
         return redirect(url_for('admin.index'))
         
    # Check duplicate name
    if Project.query.filter_by(name=name).first():
         flash('專案名稱已存在', 'error')
         return redirect(url_for('admin.index'))
         
    user_id = session.get('user_id')
    from ...models import User
    creator = User.query.get(user_id)
    
    from datetime import datetime
         
    new_project = Project(
        id=str(uuid.uuid4()),
        name=name,
        api_key=core_security.encrypt_data(api_key_input.strip()),
        api_key_hash=core_security.hash_api_key(api_key_input.strip()),
        created_at=int(datetime.now().timestamp()), # Fix: using datetime.now() needs import
        version=1
    )
    
    # Add creator as owner
    if creator:
        new_project.owners.append(creator)
    
    # If creator is NOT admin, they are already added.
    # Logic in legacy: "if user and session.get('role') != 'admin': new_project.owners.append(user)"
    # Usually Admin also wants to be owner? Or Admin sees all?
    # Admin sees all (dashboard.py line 21).
    # So mostly important for non-admins.
    
    db.session.add(new_project)
    log_audit('Create Project', name)
    flash('專案建立成功', 'success')
    
    db.session.commit()
    return redirect(url_for('admin.index', group_id=new_project.id))

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
         
    is_owner = any(o.id == session.get('user_id') for o in project.owners)
    if session.get('role') != 'admin' and not is_owner:
         return {'status': 'error', 'message': 'Permission Denied'}, 403
         
    # Enforce Single Tag Limit (Replacement)
    project.tags = []
        
    tag = Tag.query.filter_by(name=tag_name).first()
    if not tag:
        tag = Tag(name=tag_name)
        db.session.add(tag)
        db.session.commit()
        
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
    
    is_owner = any(o.id == session.get('user_id') for o in project.owners)
    if session.get('role') != 'admin' and not is_owner:
         return {'status': 'error', 'message': 'Permission Denied'}, 403
         
    tag = Tag.query.filter_by(name=tag_name).first()
    if tag and tag in project.tags:
        project.tags.remove(tag)
        db.session.commit()
        
        if not tag.projects:
             db.session.delete(tag)
             db.session.commit()
        
    return {'status': 'success', 'tags': [t.name for t in project.tags]}

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
    user = User.query.get(user_id) # Need to import User? It is imported inside some methods in legacy but commonly at top?
    # Original 'projects.py' line 71 imports User inside create_group?
    # Let's check imports at top of projects.py. 
    # It has 'from ...models import Project, Tag'. NOT User.
    # So I need to import User properly.
    
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
         
    is_owner = any(o.id == user_id for o in project.owners)
    if role != 'admin' and not is_owner:
         flash('Permission denied', 'error')
         return redirect(url_for('admin.index'))
         
    # Optimistic Locking Check
    current_version = project.version if project.version else 1
    if client_version is not None and client_version != current_version:
        flash('資料已被其他人修改，請重新整理頁面後再試 (Optimistic Lock Error)', 'error')
        return redirect(url_for('admin.index', group_id=group_id))
        
    # Update logic
    if name: project.name = name
    project.is_visible = is_visible

    from ...models import User # Local import if not at top

    if role == 'admin':
        owner_ids = request.form.getlist('owner_ids')
        new_owners = []
        for uid in owner_ids:
             u_obj = User.query.get(uid)
             if u_obj: new_owners.append(u_obj)
             
        # User Request: Admin must explicit have permission and Cannot remove themselves if they are owner logic?
        # Legacy logic:
        # if user not in new_owners: new_owners.append(user)
        # Checking legacy implementation line 399-400
        if user not in new_owners:
            new_owners.append(user)
            
        project.owners = new_owners
    
    if request.form.get('clear_key') == 'true':
        project.api_key = None
    elif api_key and api_key.strip():
        project.api_key = core_security.encrypt_data(api_key.strip())
        project.api_key_hash = core_security.hash_api_key(api_key.strip())
        
    project.version += 1
    db.session.commit()
    
    log_audit('Update Group', project.name)
    flash("Project updated", 'success')
    return redirect(url_for('admin.index', group_id=group_id))
