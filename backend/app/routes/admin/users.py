from flask import request, render_template, redirect, url_for, flash, session
from . import admin_bp
from ...models import User
from ...extensions import db

import security as core_security
from datetime import datetime
import uuid
# We need to import log_audit from local security module
from .security import log_audit 

def get_dashboard_user_data():
    users_list = []
    if session.get('role') == 'admin':
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
    return {'users_list': users_list}

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
    is_valid, msg = core_security.validate_password_strength(password)
    if not is_valid:
        flash(msg, 'error')
        return redirect(url_for('admin.index'))

    from werkzeug.security import generate_password_hash
    new_user = User(
        id=str(uuid.uuid4()),
        username=username,
        email=email if email else None,
        password_hash=generate_password_hash(password),
        password_hint=core_security.generate_password_hint(password),
        is_admin=False,
        created_at=int(datetime.now().timestamp())
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    log_audit('Create User', username)
    flash(f'教師帳戶 {username} 建立成功', 'success')
    return redirect(url_for('admin.index'))

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
        
    is_valid, msg = core_security.validate_password_strength(new_password)
    if not is_valid:
        flash(msg, 'error')
        return redirect(url_for('admin.index'))
    
    if user.username == 'Administrator':
        flash('無法重設 Administrator 密碼 (請使用環境變數)', 'error')
        return redirect(url_for('admin.index'))
    
    from werkzeug.security import generate_password_hash
    user.password_hash = generate_password_hash(new_password)
    user.password_hint = core_security.generate_password_hint(new_password)
    
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
        # Reassign orphans check
        for project in user.owned_projects:
            if len(project.owners) <= 1:
                # Find any admin user to reassign orphaned projects
                admin_user = User.query.filter_by(is_admin=True).first()
                if admin_user and admin_user.id != user.id:
                    if admin_user not in project.owners:
                        project.owners.append(admin_user)

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
