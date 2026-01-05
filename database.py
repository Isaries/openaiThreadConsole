import json
import os
import threading
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
import config

# --- Concurrency Control ---
data_lock = threading.Lock()

# --- Audit Logging ---
audit_handler = RotatingFileHandler(config.AUDIT_LOG_FILE, maxBytes=1000000, backupCount=5)
audit_handler.setFormatter(logging.Formatter('[%(asctime)s] %(message)s'))
audit_logger = logging.getLogger('audit')
audit_logger.setLevel(logging.INFO)
audit_logger.addHandler(audit_handler)

def log_audit(user, action, target, status="Success", details=""):
    msg = f"[User: {user}] [Action: {action}] [Target: {target}] [Status: {status}] {details}"
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
    if not os.path.exists(config.THREADS_FILE):
        return [{"group_id": "default", "name": "預設群組", "api_key": "", "threads": []}]
    try:
        with open(config.THREADS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        # Migration Logic
        if isinstance(data, list) and len(data) > 0 and 'thread_id' in data[0]:
            logging.getLogger().info("Migrating old threads format to new Groups format...")
            migrated_group = {
                "group_id": "default", 
                "name": "預設群組 (Migrated)", 
                "api_key": "", 
                "threads": data
            }
            save_groups([migrated_group])
            return [migrated_group]
        
        if isinstance(data, list) and len(data) == 0:
             return [{"group_id": "default", "name": "預設群組", "api_key": "", "threads": []}]

        return data 
    except: 
        return [{"group_id": "default", "name": "預設群組", "api_key": "", "threads": []}]

def save_groups(groups):
    with data_lock:
        try:
            with open(config.THREADS_FILE, 'w', encoding='utf-8') as f:
                json.dump(groups, f, indent=2, ensure_ascii=False)
            return True
        except: return False

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
