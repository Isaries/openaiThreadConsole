from flask import request, jsonify, session, render_template, redirect, url_for, flash
from . import admin_bp
from ...models import AuditLog, SearchHistory, IPBan
from ... import utils
from ...extensions import db, limiter
import database
import security as core_security
import json

def log_audit(action, target, details=None, status='Success'):
    try:
        user_name = session.get('username', 'Unknown')
        ip = utils.get_client_ip()
        log = AuditLog(
            user_name=user_name,
            ip_address=ip,
            action=action,
            target=target,
            status=status,
            details=details
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"Failed to write audit log: {e}")

def get_dashboard_security_data():
    audit_logs_pagination = None
    audit_logs = []
    
    if session.get('role') == 'admin':
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

    # Search History
    search_history = SearchHistory.query.order_by(SearchHistory.timestamp.desc()).limit(10).all()
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
        
    # IP Activity & Bans
    ip_activity = {}
    bans_pagination = None
    
    if session.get('role') == 'admin':
         page = request.args.get('page', 1, type=int)
         bans_pagination = IPBan.query.paginate(page=page, per_page=20, error_out=False)
         
         for log in audit_logs:
             ip = log['ip']
             if ip == '127.0.0.1': continue
             
             if ip not in ip_activity:
                 ip_activity[ip] = {'logs': [], 'user': '訪客', 'last_seen': 0, 'geo': None}
                 
             display_user = log['user']
             if display_user in ['Unknown', 'Guest', 'Guest IP']:
                 display_user = '訪客'
                 
             log_display = log.copy()
             log_display['display_user'] = display_user
             ip_activity[ip]['logs'].append(log_display)
             
             if display_user != '訪客' and ip_activity[ip]['user'] == '訪客':
                 ip_activity[ip]['user'] = display_user

    return {
        'audit_logs': audit_logs, 
        'audit_logs_pagination': audit_logs_pagination,
        'search_logs': search_logs,
        'ip_activity': ip_activity,
        'bans_pagination': bans_pagination
    }

@admin_bp.route('/ip/ban', methods=['POST'])
def ban_ip_route():
    if not session.get('user_id') or session.get('role') != 'admin':
        return redirect(url_for('auth.login'))
        
    ip = request.form.get('ip')
    duration = request.form.get('duration', type=int) # seconds
    reason = request.form.get('reason', 'Admin Action')
    
    current_ip = utils.get_client_ip()
    if ip == current_ip:
        flash('⚠️ 安全警告：您不能封鎖自己的 IP！', 'error')
        return redirect(url_for('admin.index'))
    
    if ip:
        core_security.ban_ip(ip, duration, reason)
        log_audit('Ban IP', f"{ip} for {duration}s")
        flash(f'IP {ip} 已封鎖', 'success')
        
    return redirect(url_for('admin.index'))

@admin_bp.route('/ip/unban', methods=['POST'])
def unban_ip_route():
    if not session.get('user_id') or session.get('role') != 'admin':
        return redirect(url_for('auth.login'))
        
    ip = request.form.get('ip')
    
    if ip:
        core_security.unban_ip(ip)
        log_audit('Unban IP', ip)
        flash(f'IP {ip} 已解除封鎖', 'success')
        
    return redirect(url_for('admin.index'))

@admin_bp.route('/api/refresh_history')
def get_refresh_history():
    if not session.get('user_id'): return {'error': 'Unauthorized'}, 401
    
    if session.get('role') != 'admin':
         return {'error': 'Permission Denied'}, 403
         
    from ...models import RefreshHistory
    from ... import utils
    
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

@admin_bp.route('/api/ip_geo', methods=['POST'])
@limiter.limit("60 per minute")
def api_ip_geo():
    if not session.get('user_id'):
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.get_json()
    ips = data.get('ips', [])
    
    results = {}
    for ip in ips:
        info = utils.get_ip_info(ip)
        results[ip] = info.get('desc', 'Unknown')
        
    return jsonify(results)
