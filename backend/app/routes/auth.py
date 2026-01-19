from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from ..extensions import db, limiter
from ..models import User
import security
from .. import utils
from .. import utils

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("60 per minute") 
def login():
    if request.method == 'POST':
        # Brute Force Protection Check
        client_ip = utils.get_client_ip()
        is_locked, time_left = security.check_lockout(client_ip)
        if is_locked:
            flash(f'嘗試次數過多，請於 {int(time_left)} 秒後再試。', 'error')
            return render_template('login.html')

        username = request.form.get('username')
        password = request.form.get('password')
        
        # Admin Bypass (from env)
        # Validate Admin Password from Config (Global Search)
        import sys
        if not 'config' in sys.modules:
             pass
        import config

        if not username or not password:
             flash('請輸入帳號與密碼', 'error')
             return render_template('login.html')

        # DB User Check
        from sqlalchemy import or_
        user = User.query.filter(or_(User.username == username, User.email == username)).first()
        if user and security.check_password(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = 'admin' if user.is_admin else 'user'
            session.permanent = True
            utils.log_access(username, "Login Success")
            security.record_login_attempt(client_ip, True) # Record Success
            return redirect(url_for('admin.index'))
            
        utils.log_access(username, "Login Failed")
        security.record_login_attempt(client_ip, False) # Record Failure
        flash('帳號或密碼錯誤', 'error')
        
    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    username = session.get('username')
    utils.log_access(username, "Logout")
    session.clear()
    flash('您已登出', 'success')
    return redirect(url_for('auth.login'))
