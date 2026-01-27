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

def add_ip_ban(ip, reason, expires_at):
    """
    Atomic Add/Update Ban
    """
    try:
        ban = IPBan.query.get(ip)
        if ban:
            ban.reason = reason
            ban.expires_at = expires_at
        else:
            ban = IPBan(ip=ip, reason=reason, expires_at=expires_at)
            db.session.add(ban)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to add IP ban: {e}")
        return False
    return True

def remove_ip_ban(ip):
    """
    Atomic Remove Ban
    """
    try:
        IPBan.query.filter_by(ip=ip).delete()
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to remove IP ban: {e}")
        return False
    return True

# --- Settings ---
SETTINGS_FILE = 'settings.json'

def load_settings():
    import json
    import os
    
    settings = {}
    
    # 1. Load File (Base / Legacy)
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                settings = json.load(f)
        except Exception as e:
            logging.warning(f"Failed to load settings from file: {e}")
            
    # 2. Overlay DB (Primary / Overrides)
    try:
        from app.models import SystemSetting
        # Query all settings to construct dictionary
        all_settings = SystemSetting.query.all()
        for s in all_settings:
            try:
                # Value is stored as JSON string
                settings[s.key] = json.loads(s.value)
            except:
                settings[s.key] = s.value
            
    except Exception as e:
        # DB might not be ready or context missing
        pass

    return settings

def update_setting(key, value):
    """
    Atomic Update Single Setting
    """
    import json
    try:
        from app.models import SystemSetting
        val_str = json.dumps(value, ensure_ascii=False)
        
        # Upsert
        setting = SystemSetting.query.get(key)
        if setting:
            setting.value = val_str
            setting.updated_at = datetime.now()
        else:
            setting = SystemSetting(key=key, value=val_str)
            db.session.add(setting)
            
        db.session.commit()
        return True
    except Exception as e:
        logging.error(f"DB Setting Update Failed ({key}): {e}")
        db.session.rollback()
        return False

def save_settings(settings):
    """
    Legacy Wrapper: Supports saving full dict but using atomic updates internally.
    Optimized to only update changed keys if possible, but for compatibility acts as bulk upsert.
    """
    success = True
    for k, v in settings.items():
        if not update_setting(k, v):
            success = False
            
    # Sync to File (Backup)
    try:
        import json
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(settings, f, indent=4, ensure_ascii=False)
    except Exception as e:
        logging.warning(f"Failed to save settings backup: {e}")
        
    return success


