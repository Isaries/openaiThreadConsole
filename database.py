import json
import os
import threading
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from flask import request, has_request_context
import config

# --- Concurrency Control ---
data_lock = threading.Lock()

# --- Audit Logging ---
audit_handler = RotatingFileHandler(config.AUDIT_LOG_FILE, maxBytes=1000000, backupCount=5, encoding='utf-8')
audit_handler.setFormatter(logging.Formatter('[%(asctime)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
audit_logger = logging.getLogger('audit')
audit_logger.setLevel(logging.INFO)
audit_logger.addHandler(audit_handler)

def log_audit(user, action, target, status="Success", details=""):
    ip_info = ""
    # Auto-detect IP if in request context
    if has_request_context():
        try:
            # Check if proxied (X-Forwarded-For) or direct
            ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            if ip:
                # If multiple IPs in XFF, take the first one
                ip = ip.split(',')[0].strip()
                if "IP:" not in details: # Avoid double logging if passed in details
                    ip_info = f" IP: {ip}"
        except: pass

    msg = f"[User: {user}] [Action: {action}] [Target: {target}] [Status: {status}] {details}{ip_info}"
    audit_logger.info(msg)
    # Also log to root logger for console visibility (simulating app.logger)
    logging.getLogger().info(f"AUDIT: {msg}")

# --- Users ---
def load_users():
    if not os.path.exists(config.USERS_FILE):
        return []
    try:
        with open(config.USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except: return []

def save_users(users):
    with data_lock:
        try:
            with open(config.USERS_FILE, 'w', encoding='utf-8') as f:
                json.dump(users, f, indent=2, ensure_ascii=False)
            return True
        except: return False

def get_user_by_username(username):
    users = load_users()
    for u in users:
        if u['username'] == username:
            return u
    return None

# --- Groups ---
def load_groups():
    if not os.path.exists(config.GROUPS_FILE):
        return [{"group_id": "default", "name": "Default Project", "api_key": "", "threads": []}]
    try:
        with open(config.GROUPS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        # Migration Logic
        if isinstance(data, list) and len(data) > 0 and 'thread_id' in data[0]:
            logging.getLogger().info("Migrating old threads format to new Groups format...")
            migrated_group = {
                "group_id": "default", 
                "name": "Default Project (Migrated)", 
                "api_key": "", 
                "threads": data
            }
            save_groups([migrated_group])
            return [migrated_group]
        
        if isinstance(data, list) and len(data) == 0:
             return [{"group_id": "default", "name": "Default Project", "api_key": "", "threads": [], "owners": []}]

        # Migration: 'created_by' (str) -> 'owners' (list)
        migrated = False
        for g in data:
            if 'created_by' in g:
                if 'owners' not in g:
                    g['owners'] = [g['created_by']] if g['created_by'] and g['created_by'] != 'admin' else []
                del g['created_by']
                migrated = True
            elif 'owners' not in g:
                g['owners'] = []
                migrated = True
        
        if migrated:
            save_groups(data)

        return data 
    except Exception as e:
        logging.getLogger().error(f"Failed to load groups from {config.GROUPS_FILE}: {e}")
        return [{"group_id": "default", "name": "Default Project", "api_key": "", "threads": []}]

def save_groups(groups):
    with data_lock:
        try:
            with open(config.GROUPS_FILE, 'w', encoding='utf-8') as f:
                json.dump(groups, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            logging.getLogger().error(f"Failed to save groups to {config.GROUPS_FILE}: {e}")
            return False

def get_group_by_id(group_id):
    groups = load_groups()
    for g in groups:
        if g['group_id'] == group_id:
            return g
    return None

# --- Logs ---
def load_logs():
    if not os.path.exists(config.LOG_FILE):
        return []
    try:
        with open(config.LOG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except: return []

def save_log(log_entry):
    with data_lock:
        logs = load_logs()
        logs.insert(0, log_entry) # Add to top
        logs = logs[:3] # Keep only last 3
        try:
            with open(config.LOG_FILE, 'w', encoding='utf-8') as f:
                json.dump(logs, f, indent=2, ensure_ascii=False)
        except: pass

# --- Settings ---
def load_settings():
    if not os.path.exists(config.SETTINGS_FILE):
        return {}
    try:
        with open(config.SETTINGS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except: return {}

def save_settings(data):
    try:
        with open(config.SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        return True
    except: return False

# --- IP Bans ---
def load_ip_bans():
    if not os.path.exists(config.IP_BANS_FILE):
        return {}
    try:
        with open(config.IP_BANS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except: return {}

def save_ip_bans(bans):
    with data_lock:
        try:
            with open(config.IP_BANS_FILE, 'w', encoding='utf-8') as f:
                json.dump(bans, f, indent=2, ensure_ascii=False)
            return True
        except: return False

# --- Audit Analysis ---
def load_audit_logs():
    """
    Parses the raw audit.log file into structured data.
    Returns a list of dicts: {'time', 'user', 'action', 'target', 'status', 'ip'}
    """
    if not os.path.exists(config.AUDIT_LOG_FILE):
        return []
        
    logs = []
    import re
    
    # Regex to parse format: [Time] [User: U] [Action: A] [Target: T] [Status: S] details... IP: X
    # Example: [2024-01-01 10:00:00] [User: Admin] [Action: Login] [Target: Panel] [Status: Success] IP: 127.0.0.1
    pattern = re.compile(r'\[(.*?)\] \[User: (.*?)\] \[Action: (.*?)\] \[Target: (.*?)\] \[Status: (.*?)\] (.*)')
    
    try:
        with open(config.AUDIT_LOG_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                match = pattern.match(line)
                if match:
                    details = match.group(6)
                    ip = "Unknown"
                    if "IP: " in details:
                        parts = details.split("IP: ")
                        if len(parts) > 1:
                            ip = parts[1].strip()
                            
                    logs.append({
                        'time': match.group(1),
                        'user': match.group(2),
                        'action': match.group(3),
                        'target': match.group(4),
                        'status': match.group(5),
                        'ip': ip,
                        'raw': line
                    })
    except: pass
    
    # Return reversed (newest first)
    return list(reversed(logs))
