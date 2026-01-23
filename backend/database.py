from app.models import db, User, Project, Thread, SearchHistory, AuditLog, IPBan, project_owners
from datetime import datetime, timezone, timedelta
from flask import request, has_request_context
import config
import logging
from sqlalchemy import or_

# --- Timezone Setup ---
def utc8_converter(*args):
    utc8 = timezone(timedelta(hours=8))
    return datetime.now(utc8).timetuple()

logging.Formatter.converter = utc8_converter

# --- Audit Logging ---
def log_audit(user, action, target, status="Success", details=""):
    try:
        ip = "Unknown"
        if has_request_context():
            from app.utils import get_client_ip
            ip = get_client_ip()

        new_log = AuditLog(
            user_name=user,
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
        logging.error(f"Failed to write audit log: {e}")

# --- Users ---
# --- Groups / Projects ---

# --- Groups / Projects ---
def load_groups():
    # Return all groups for Admin view.
    # App expects: [{'group_id':..., 'owners': [id, id], 'threads': [...]}]
    projects = Project.query.all()
    results = []
    for p in projects:
        owners = [o.id for o in p.owners]
        threads = [{'thread_id': t.thread_id, 'remark': t.remark} for t in p.threads]
        tags = [tag.name for tag in p.tags]
        results.append({
            'group_id': p.id,
            'name': p.name,
            'api_key': p.api_key,
            'is_visible': p.is_visible,
            'version': p.version,
            'owners': owners,
            'threads': threads,
            'tags': tags
        })
    return results

def get_group_by_id(group_id):
    p = Project.query.get(group_id)
    if not p: return None
    
    owners = [o.id for o in p.owners]
    # threads = [{'thread_id': t.thread_id} for t in p.threads] # Optimization: Lazy load?
    # App expects threads to be there
    threads = [{'thread_id': t.thread_id, 'remark': t.remark} for t in p.threads]
    
    return {
        'group_id': p.id,
        'name': p.name,
        'api_key': p.api_key,
        'is_visible': p.is_visible,
        'version': p.version,
        'owners': owners,
        'threads': threads
    }

# --- Logs ---
def load_logs():
    # search_history
    logs = SearchHistory.query.order_by(SearchHistory.timestamp.desc()).limit(3).all()
    return [{
        'timestamp': l.timestamp,
        'group': l.project_name,
        'target': l.target_query,
        'date_range': l.date_range,
        'matches': l.match_count,
        'total': l.total_scanned,
        'api_results': [] # simplified
    } for l in logs]

def save_log(log_entry):
    import json
    new_log = SearchHistory(
        timestamp=log_entry.get('timestamp'),
        project_name=log_entry.get('group'),
        target_query=log_entry.get('target'),
        date_range=log_entry.get('date_range'),
        match_count=log_entry.get('matches'),
        total_scanned=log_entry.get('total'),
        api_results_json=json.dumps(log_entry.get('api_results', []), ensure_ascii=False)
    )
    db.session.add(new_log)
    db.session.commit()

# --- IP Bans ---
def load_ip_bans():
    bans = IPBan.query.all()
    return {b.ip: {'reason': b.reason, 'expires_at': b.expires_at} for b in bans}

def save_ip_bans(bans_dict):
    # bans_dict: {ip: {reason:..., expires_at:...}}
    # Sync approach: Delete all, re-insert? Or Upsert?
    # Delete all is safest for full sync
    try:
        db.session.query(IPBan).delete()
        for ip, data in bans_dict.items():
            new_ban = IPBan(ip=ip, reason=data['reason'], expires_at=data['expires_at'])
            db.session.add(new_ban)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to save IP bans: {e}")

# --- Audit Analysis ---
def load_audit_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return [{
        'time': l.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'user': l.user_name,
        'action': l.action,
        'target': l.target,
        'status': l.status,
        'details': l.details,
        'ip': l.ip_address,
        'raw': f"[{l.timestamp}] {l.action} {l.target}"
    } for l in logs]


# --- Settings ---
SETTINGS_FILE = 'settings.json'

def load_settings():
    import json
    import os
    
    # Try DB First
    try:
        from app.models import SystemSetting
        # We need app context. This function is usually called within context.
        # But if not, we might fail.
        # Check has_request_context or manually push?
        # Simpler: Just try query if db is bound.
        setting = db.session.get(SystemSetting, 'auto_refresh')
        if setting and setting.value:
            return {'auto_refresh': json.loads(setting.value)}
            
    except Exception as e:
        # DB might not be ready or context missing
        # logging.warning(f"DB Settings Load Failed: {e}")
        pass

    # Fallback to File (Migration or Safety)
    if not os.path.exists(SETTINGS_FILE):
        return {}
    try:
        with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data
    except Exception as e:
        logging.warning(f"Failed to load settings from file: {e}")
        return {}

def save_settings(settings):
    import json
    
    # 1. Save to DB (Primary)
    try:
        from app.models import SystemSetting
        
        # We handle 'auto_refresh' key specifically for now as per schema design (key-value)
        # Flatten structure: key='auto_refresh', value=json_str
        if 'auto_refresh' in settings:
             # Upsert logic
             val_str = json.dumps(settings['auto_refresh'], ensure_ascii=False)
             
             # Check if exists
             existing = db.session.get(SystemSetting, 'auto_refresh')
             if existing:
                 existing.value = val_str
                 existing.updated_at = datetime.now()
             else:
                 new_setting = SystemSetting(key='auto_refresh', value=val_str)
                 db.session.add(new_setting)
                 
             db.session.commit()
    except Exception as e:
        logging.error(f"DB Settings Save Failed: {e}")
        db.session.rollback()

    # 2. Sync to File (Legacy/Backup)
    try:
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(settings, f, indent=4, ensure_ascii=False)
    except Exception as e:
        logging.warning(f"Failed to save settings to file: {e}")


