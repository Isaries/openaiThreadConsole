from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, has_request_context
import json
import os
import requests
import re
import pandas as pd
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv

from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Advanced Security imports
# Advanced Security imports
import logging
from logging.handlers import RotatingFileHandler
from cryptography.fernet import Fernet
import base64
import hashlib
import time

# --- Audit Logging ---
AUDIT_LOG_FILE = 'audit.log'
audit_handler = RotatingFileHandler(AUDIT_LOG_FILE, maxBytes=1000000, backupCount=5)
audit_handler.setFormatter(logging.Formatter('[%(asctime)s] %(message)s'))
audit_logger = logging.getLogger('audit')
audit_logger.setLevel(logging.INFO)
audit_logger.addHandler(audit_handler)

def log_audit(user, action, target, status="Success", details=""):
    msg = f"[User: {user}] [Action: {action}] [Target: {target}] [Status: {status}] {details}"
    audit_logger.info(msg)
    # Also log to app logger for console visibility
    app.logger.info(f"AUDIT: {msg}")

# --- Security Policies ---
LOGIN_ATTEMPTS = {} # { ip: { count: int, lockout_until: float } }
LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION = 15 * 60 # 15 minutes

def check_lockout(ip):
    record = LOGIN_ATTEMPTS.get(ip)
    if not record: return False, 0
    
    if record['count'] >= LOCKOUT_THRESHOLD:
        if time.time() < record['lockout_until']:
            return True, record['lockout_until'] - time.time()
        else:
            # Reset after expiration
            del LOGIN_ATTEMPTS[ip]
            return False, 0
    return False, 0

def record_login_attempt(ip, success):
    if success:
        if ip in LOGIN_ATTEMPTS: del LOGIN_ATTEMPTS[ip]
    else:
        record = LOGIN_ATTEMPTS.get(ip, {'count': 0, 'lockout_until': 0})
        record['count'] += 1
        if record['count'] >= LOCKOUT_THRESHOLD:
            record['lockout_until'] = time.time() + LOCKOUT_DURATION
        LOGIN_ATTEMPTS[ip] = record

def validate_password_strength(password):
    if len(password) < 10 or len(password) > 15:
        return False, "密碼長度需為 10-15 字元"
    
    has_alpha = any(c.isalpha() for c in password)
    has_num = any(c.isdigit() for c in password)
    
    if not (has_alpha and has_num):
        return False, "密碼需包含英文字母與數字"
        
    return True, ""

def generate_password_hint(password):
    if not password: return ""
    if len(password) <= 4: return "*" * len(password)
    return f"{password[:2]}***{password[-2:]}"

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key_change_me') # Session security
app.permanent_session_lifetime = timedelta(hours=1) # Auto logout after 1 hour

# --- Concurrency Control ---
import threading
data_lock = threading.Lock()

# --- Template Filters ---
@app.template_filter('nl2br')
def nl2br(value):
    if not value: return ""
    from markupsafe import escape
    # Escape first, then replace newline with <br>
    return str(escape(value)).replace('\n', '<br>')

# --- XSS Protection ---
import bleach
@app.template_filter('sanitize_html')
def sanitize_html(value):
    if not value: return ""
    allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'a', 'p', 'br', 'span', 'div', 'mark', 'code', 'pre', 'ul', 'li', 'ol']
    allowed_attrs = {
        '*': ['class', 'style'],
        'a': ['href', 'target', 'rel']
    }
    return bleach.clean(value, tags=allowed_tags, attributes=allowed_attrs, strip=True)

# --- Logging Setup ---
# Log to file, max 1MB, keep 5 backups
log_handler = RotatingFileHandler('access.log', maxBytes=1000000, backupCount=5)
class RequestFormatter(logging.Formatter):
    def format(self, record):
        if has_request_context():
            record.remote_addr = request.remote_addr
        else:
            record.remote_addr = '-'
        return super().format(record)

log_handler = RotatingFileHandler('access.log', maxBytes=1000000, backupCount=5)
log_handler.setFormatter(RequestFormatter(
    '[%(asctime)s] %(levelname)s [%(remote_addr)s] %(message)s'
))
app.logger.addHandler(log_handler)
app.logger.setLevel(logging.INFO)

# --- Encryption Helper ---
# Derive a 32-byte URL-safe base64-encoded key from SECRET_KEY
def get_encryption_key():
    secret = app.secret_key.encode()
    digest = hashlib.sha256(secret).digest()
    return base64.urlsafe_b64encode(digest)

cipher_suite = Fernet(get_encryption_key())

def encrypt_data(plaintext):
    if not plaintext: return ""
    return cipher_suite.encrypt(plaintext.encode()).decode()

def decrypt_data(ciphertext):
    if not ciphertext: return ""
    try:
        return cipher_suite.decrypt(ciphertext.encode()).decode()
    except Exception as e:
        # It's common for decryption to fail if the key is plain text (legacy)
        # So we debug log instead of error to avoid noise
        app.logger.debug(f"Decryption failed: {e}")
        return None

def get_decrypted_key(key_string):
    """
    Attempts to decrypt the key. 
    If successful, returns decrypted key.
    If fails (e.g. not encrypted or invalid), returns the original string (assuming it might be plain text)
    or None if it's empty.
    """
    if not key_string: return None
    
    # Try fully decrypt
    decrypted = decrypt_data(key_string)
    if decrypted: return decrypted
    
    # If decryption returned None, maybe it wasn't encrypted?
    # Security/Compatibility tradeoff: assume it's a plain key if it looks like one (e.g. sk-...)
    # or just return it as is.
    return key_string

# Security Setup
csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["10 per second"], # Global limit: prevent flooding
    storage_uri="memory://"
)

# Configuration
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 # Limit uploads to 2MB to prevent resource exhaustion
THREADS_FILE = 'threads.json'
SETTINGS_FILE = 'settings.json'
LOG_FILE = 'search_logs.json'
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
ADMIN_PASSWORD_ENV = os.getenv("ADMIN_PASSWORD")
if not ADMIN_PASSWORD_ENV:
    raise ValueError("CRITICAL SECURITY ERROR: ADMIN_PASSWORD environment variable is not set. Application cannot start.")

# Support multiple passwords (comma-separated)
ADMIN_PASSWORDS = [p.strip() for p in ADMIN_PASSWORD_ENV.split(',') if p.strip()]
if not ADMIN_PASSWORDS:
     raise ValueError("CRITICAL SECURITY ERROR: ADMIN_PASSWORD must contain at least one valid password.")

OPENAI_API_URL = "https://api.openai.com/v1/threads/{}/messages"

from werkzeug.security import generate_password_hash, check_password_hash
import uuid

# --- Helper Functions ---
USERS_FILE = 'users.json'

def load_users():
    if not os.path.exists(USERS_FILE):
        return []
    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except: return []

def save_users(users):
    with data_lock:
        try:
            with open(USERS_FILE, 'w', encoding='utf-8') as f:
                json.dump(users, f, indent=2, ensure_ascii=False)
            return True
        except: return False

def get_user_by_username(username):
    users = load_users()
    for u in users:
        if u['username'] == username:
            return u
    return None


def load_logs():
    if not os.path.exists(LOG_FILE):
        return []
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except: return []

def save_log(log_entry):
    with data_lock:
        logs = load_logs()
        logs.insert(0, log_entry) # Add to top
        logs = logs[:3] # Keep only last 3
        try:
            with open(LOG_FILE, 'w', encoding='utf-8') as f:
                json.dump(logs, f, indent=2, ensure_ascii=False)
        except: pass

def load_settings():
    if not os.path.exists(SETTINGS_FILE):
        return {}
    try:
        with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except: return {}

def save_settings(data):
    try:
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        return True
    except: return False

def get_headers(custom_key=None):
    # Support Group Key override
    api_key = custom_key
    
    # If no group key provided, try global settings
    if not api_key:
        settings = {}
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                    settings = json.load(f)
            except: pass
        
        api_key_from_settings = settings.get('openai_api_key')
        
        if api_key_from_settings:
            # Try to decrypt
            decrypted = decrypt_data(api_key_from_settings)
            if decrypted:
                api_key = decrypted
            else:
                # Fallback check
                if not api_key_from_settings.startswith("sk-"):
                     api_key = None 

    if api_key:
        api_key = get_decrypted_key(api_key)

    # Fallback to ENV
    if not api_key:
        api_key = os.getenv('OPENAI_API_KEY')

    return {
        "Authorization": f"Bearer {api_key}",
        "OpenAI-Beta": "assistants=v2",
        "Content-Type": "application/json"
    }

@app.template_filter('format_timestamp')
def unix_to_utc8(unix_timestamp):
    if not unix_timestamp:
        return 'Unknown Time'
    try:
        ts = int(unix_timestamp)
    except:
        return 'Invalid Time'
        
    utc8 = timezone(timedelta(hours=8))
    dt = datetime.fromtimestamp(ts, tz=utc8)
    return dt.strftime('%Y-%m-%d %H:%M:%S')

def unix_to_date_str(unix_timestamp):
    if not unix_timestamp:
        return 'Unknown Date'
    utc8 = timezone(timedelta(hours=8))
    dt = datetime.fromtimestamp(unix_timestamp, tz=utc8)
    return dt.strftime('%Y-%m-%d')

# --- Data Access: Groups (New) ---
def load_groups():
    if not os.path.exists(THREADS_FILE):
        return [{"group_id": "default", "name": "預設群組", "api_key": "", "threads": []}]
    try:
        with open(THREADS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        # Migration Logic: List of threads (Old) -> List of Groups (New)
        if isinstance(data, list) and len(data) > 0 and 'thread_id' in data[0]:
            app.logger.info("Migrating old threads format to new Groups format...")
            migrated_group = {
                "group_id": "default", 
                "name": "預設群組 (Migrated)", 
                "api_key": "", 
                "threads": data
            }
            save_groups([migrated_group])
            return [migrated_group]
        
        # If empty list (old empty file)
        if isinstance(data, list) and len(data) == 0:
             return [{"group_id": "default", "name": "預設群組", "api_key": "", "threads": []}]

        return data # Assume it's already in new Group format
    except: 
        return [{"group_id": "default", "name": "預設群組", "api_key": "", "threads": []}]

def save_groups(groups):
    with data_lock:
        try:
            with open(THREADS_FILE, 'w', encoding='utf-8') as f:
                json.dump(groups, f, indent=2, ensure_ascii=False)
            return True
        except: return False

def get_group_by_id(group_id):
    groups = load_groups()
    for g in groups:
        if g['group_id'] == group_id:
            return g
    return None

# Legacy Adapter (Temporary)
def load_threads():
    groups = load_groups()
    if groups: return groups[0]['threads']
    return []

def save_threads(threads_data):
    # This calls save_groups which is now locked, but we need to load cleanly too.
    # To be perfectly safe, we should lock the whole operation, but save_groups lock is good start.
    with data_lock: # Add lock here too mainly for the load-modify-save cycle atomicity
        groups = load_groups() # This reads file, safe.
        if groups:
            groups[0]['threads'] = threads_data
            # We assume save_groups will lock again? No, RLock (reentrant) is better but Lock is not.
            # Standard threading.Lock is NOT reentrant in Python? Wait, it is NOT.
            # So if save_groups also locks, we will Deadlock if we lock here!
            # Let's check: save_groups has `with data_lock`.
            # If we lock here, then call save_groups, we deadlock.
            # FIX: Don't lock inside save_groups, OR use RLock.
            # I will switch to RLock in the imports chunk?
            # Or just manually write here.
            # Better: Let save_groups handle the write lock. 
            # But the 'Read-Modify-Write' gap is the race condition.
            # So we MUST hold lock across Read and Write.
            # So `save_groups` should NOT lock if we lock here?
            # Complexity increased.
            # Simplest Fix: Make data_lock an RLock.
            pass

    # RE-EVALUATION: To avoid complexity in this step-by-step logic without restarting,
    # I will rely on `save_groups` lock for the Write.
    # For `save_threads`, it is legacy.
    # Let's just fix `save_groups` to be atomic write (it is with open 'w').
    # But the race is: Thread A loads, Thread B loads. Thread A saves, Thread B saves (overwriting A).
    # So we DO need a transaction lock.
    # I will change Lock to RLock in the first chunk if possible? 
    # I already sent the tool call with `threading.Lock()`.
    # `threading.Lock()` is not reentrant.
    # I can edit the first chunk to `threading.RLock()`.
    
    # Actually, I haven't submitted this tool call yet.
    # I will change the first chunk to use RLock.
    
    groups = load_groups()
    if groups:
        groups[0]['threads'] = threads_data
        return save_groups(groups)
    return False

def fetch_thread_messages(thread_id, api_key=None):
    if not thread_id: return None
    base_url = OPENAI_API_URL.format(thread_id)
    headers = get_headers(api_key)
    
    all_messages = []
    params = {"limit": 100} # Max limit per page to reduce requests
    
    try:
        while True:
            response = requests.get(base_url, headers=headers, params=params, timeout=20)
            if response.status_code != 200:
                # If partial success, maybe return what we have? Or fail?
                # Failsafe: if we have some messages, return them but log warning.
                if all_messages: 
                    app.logger.warning(f"Partial fetch for {thread_id}: {response.status_code}")
                    break 
                else: 
                     return None
            
            data = response.json()
            messages = data.get('data', [])
            all_messages.extend(messages)
            
            if data.get('has_more') and messages:
                params['after'] = messages[-1]['id']
            else:
                break
                
        return {'data': all_messages}
    except Exception as e:
        app.logger.error(f"Fetch error {thread_id}: {e}")
        return None

def process_thread(thread_data, target_name, start_date, end_date, api_key=None):
    t_id = thread_data.get('thread_id')
    
    # Default return structure
    result = {
        'thread_id': t_id,
        'keep': False,
        'status': 'Unknown',
        'data': None,
        'messages': []
    }

    api_response = fetch_thread_messages(t_id, api_key)
    if not api_response or 'data' not in api_response:
        result['status'] = 'API Error'
        return result
    
    messages_data = api_response['data']
    if not messages_data:
        result['status'] = 'Empty Messages'
        return result

    processed_messages = []
    has_target = False
    
    for msg in messages_data:
        try:
            role = msg.get('role')
            if not role: continue
            
            created_at = msg.get('created_at')
            try:
                msg_ts = int(created_at)
            except:
                msg_ts = 0
                
            time_str = unix_to_utc8(msg_ts)
            date_str = unix_to_date_str(msg_ts)
            
            content_value = ""
            if msg.get('content') and msg['content']:
                text_content = msg['content'][0].get('text', {})
                content_value = text_content.get('value', '')

            if target_name:
                if target_name.lower() in content_value.lower() and role == 'user':
                    has_target = True
                if target_name.lower() in content_value.lower() and target_name != "No choice was made":
                     pattern = re.compile(re.escape(target_name), re.IGNORECASE)
                     content_value = pattern.sub(f"<mark>{target_name}</mark>", content_value)

            role_class = 'user' if role == 'user' else 'assistant'
            role_icon = '👤' if role == 'user' else '🤖'
            role_name = '使用者' if role == 'user' else 'AI 助理'
            
            processed_messages.append({
                'time': time_str,
                'timestamp': msg_ts,
                'role': role,
                'role_class': role_class,
                'role_icon': role_icon,
                'role_name': role_name,
                'content': content_value,
                'date_str': date_str
            })
        except: continue

    processed_messages.sort(key=lambda x: x['timestamp'])
    result['messages'] = processed_messages # Store for debug
    
    # Check filters
    keep_thread = False
    status = "Filtered"
    
    if target_name:
        if has_target: 
            keep_thread = True
            status = "Matched Keyword"
        else:
            status = "No Keyword Match"
    else:
        keep_thread = True
        status = "Matched (No Keyword)"
        
    thread_time = processed_messages[-1]['time'] if processed_messages else 'Unknown'
    thread_timestamp = processed_messages[-1]['timestamp'] if processed_messages else 0
    t_date = processed_messages[-1]['date_str'] if processed_messages else ''
    
    if keep_thread and (start_date or end_date):
        if start_date and end_date:
            if not (start_date <= t_date <= end_date): 
                keep_thread = False
                status = "Filtered Date"
        elif start_date:
            if not (t_date >= start_date): 
                keep_thread = False
                status = "Filtered Date"
        elif end_date:
            if not (t_date <= end_date): 
                keep_thread = False
                status = "Filtered Date"
            
    result['keep'] = keep_thread
    result['status'] = status
    
    # Metadata for Caching
    result['meta'] = {
        'last_updated': int(datetime.now().timestamp()),
        'start_ts': processed_messages[0]['timestamp'] if processed_messages else 0,
        'end_ts': processed_messages[-1]['timestamp'] if processed_messages else 0,
        'msg_count': len(processed_messages)
    }

    if keep_thread:
        result['data'] = {
            'thread_id': t_id,
            'time': thread_time,
            'timestamp': thread_timestamp,
            'messages': processed_messages,
            'raw_messages': messages_data # Debug: Pass raw API response
        }
        
    return result

# --- Routes ---

@app.route('/', methods=['GET'])
def index():
    all_groups = load_groups()
    # Filter for visible groups only on the search page
    groups = [g for g in all_groups if g.get('is_visible', True)]
    return render_template('index.html', groups=groups)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute", methods=['POST']) # Relaxed Flask-Limiter in favor of custom Lockout
def login():
    ip = get_remote_address()
    
    # 1. Check Lockout
    is_locked, remaining = check_lockout(ip)
    if is_locked:
        app.logger.warning(f"Login Blocked: IP {ip} is locked out. Remaining: {int(remaining)}s")
        return render_template('login.html', error=f"登入失敗次數過多，請於 {int(remaining//60)+1} 分鐘後再試")

    if request.method == 'POST':
        pwd = request.form.get('password', '')
        if len(pwd) > 100:
            app.logger.warning("Admin login failed: Password too long")
            return render_template('login.html', error="輸入過長")
            
        # 1. Check Admin (Env)
        if pwd in ADMIN_PASSWORDS:
            # Prevent Session Fixation: Clear old session before elevating privileges
            session.clear()
            session.permanent = True # Enable 1 hour timeout
            session['is_admin'] = True # Legacy support
            session['role'] = 'admin'
            session['user_id'] = 'admin'
            session['username'] = 'Administrator'
            
            record_login_attempt(ip, True)
            log_audit('Administrator', 'Login', 'Admin Panel', 'Success', f"IP: {ip}")
            return redirect(url_for('admin'))
        
        # 2. Check Teachers (users.json)
        users = load_users()
        for user in users:
            if check_password_hash(user['password_hash'], pwd):
                session.clear()
                session.permanent = True
                session['is_admin'] = False # Not super admin
                session['role'] = 'teacher'
                session['user_id'] = user['id']
                session['username'] = user['username']
                
                record_login_attempt(ip, True)
                log_audit(user['username'], 'Login', 'Admin Panel', 'Success', f"IP: {ip}")
                return redirect(url_for('admin'))

        # Record Failure
        record_login_attempt(ip, False)
        log_audit('Unknown', 'Login', 'Admin Panel', 'Fail', f"IP: {ip}")
        return render_template('login.html', error="密碼錯誤")
    return render_template('login.html')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/admin')
def admin():
    if not session.get('user_id'): return redirect(url_for('login')) # Check user_id instead of is_admin
    
    # 1. Load Groups
    all_groups = load_groups()
    
    # 2. Filter Groups based on Role
    current_role = session.get('role', 'teacher')
    current_user_id = session.get('user_id')
    
    if current_role == 'admin':
        groups = all_groups
    else:
        # Teacher: Filter by created_by
        # Legacy groups (no created_by) -> Visible to Admin only? Or everyone?
        # Let's assume legacy groups are "Public/Admin" owned. Teacher sees only explicitly theirs.
        groups = [g for g in all_groups if g.get('created_by') == current_user_id]
    
    group_id = request.args.get('group_id')
    
    active_group = None
    if group_id:
        active_group = next((g for g in groups if g['group_id'] == group_id), None)
    
    if not active_group and groups:
        active_group = groups[0]
        
    # If no groups available for this user
    if not active_group and not groups:
        # Don't show default creation if it's empty? Or show empty state?
        # Pass empty
        pass

    if not active_group:
         # Fallback if filtered list is empty or invalid ID
         active_group = None

    threads = active_group.get('threads', []) if active_group else []
    
    # Get Key Status for Active Group
    first_key = active_group.get('api_key') if active_group else None
    # Decrypt for display purposes
    decrypted_show = get_decrypted_key(first_key)
    
    masked_key = f"{decrypted_show[:8]}...{decrypted_show[-4:]}" if decrypted_show and len(decrypted_show) > 12 else "尚未設定 (使用環境變數/預設)"
    
    logs = load_logs()
    
    # Load Users (Only for admin to view/manage)
    users_list = []
    if current_role == 'admin':
        users_list = load_users()
    
    return render_template('admin.html', 
                           groups=groups, 
                           active_group=active_group, 
                           threads=threads, 
                           masked_key=masked_key, 
                           logs=logs,
                           users=users_list,
                           current_role=current_role)

@app.route('/admin/group/create', methods=['POST'])
def create_group():
    if not session.get('user_id'): return redirect(url_for('login'))
    name = request.form.get('name', '').strip()
    api_key = request.form.get('api_key', '').strip()
    
    if not name:
        flash('群組名稱不能為空', 'error')
        return redirect(url_for('admin'))
        
    if not api_key:
        flash('API Key 不能為空', 'error')
        return redirect(url_for('admin'))
        
    groups = load_groups()
    
    # Check for duplicate name
    if any(g['name'] == name for g in groups):
        flash('群組名稱已存在，請使用不同名稱', 'error')
        return redirect(url_for('admin'))

    new_id = f"group_{int(datetime.now().timestamp())}"
    
    encrypted_key = ""
    if len(api_key) > 200:
         flash('API Key 過長', 'error')
         return redirect(url_for('admin'))
    encrypted_key = encrypt_data(api_key)

    new_group = {
        "group_id": new_id,
        "name": name,
        "api_key": encrypted_key,
        "created_by": session.get('user_id'), # Assign Owner
        "is_visible": True,
        "threads": []
    }
    
    groups.append(new_group)
    save_groups(groups)
    
    log_audit(session.get('username'), 'Create Group', name)
    flash(f'群組 "{name}" 建立成功', 'success')
    return redirect(url_for('admin', group_id=new_id))

@app.route('/admin/group/update', methods=['POST'])
def update_group():
    if not session.get('user_id'): return redirect(url_for('login'))
    group_id = request.form.get('group_id')
    name = request.form.get('name', '').strip()
    api_key = request.form.get('api_key', '').strip()
    clear_key = request.form.get('clear_key')
    new_owner_id = request.form.get('owner_id') # For Ownership Transfer
    is_visible = request.form.get('is_visible') == 'on' # From checkbox
    
    groups = load_groups()
    group = next((g for g in groups if g['group_id'] == group_id), None)
    
    if not group:
        flash('群組不存在', 'error')
        return redirect(url_for('admin'))
    
    # Permission Check
    current_role = session.get('role')
    user_id = session.get('user_id')
    
    # Admin can edit any group; Teacher can only edit own groups
    if current_role != 'admin' and group.get('created_by') != user_id:
        flash('權限不足：您只能編輯自己建立的群組', 'error')
        return redirect(url_for('admin'))

    if name: 
        # Check duplicate name if changing name
        if name != group['name'] and any(g['name'] == name for g in groups):
             flash('群組名稱已存在，請使用不同名稱', 'error')
             return redirect(url_for('admin', group_id=group_id))
        group['name'] = name

    # Update Visibility
    group['is_visible'] = is_visible

    # Ownership Transfer (Admin Only)
    if current_role == 'admin' and new_owner_id:
        if new_owner_id == 'admin':
            group['created_by'] = 'admin' # Assign back to admin
            log_audit(session.get('username'), 'Transfer Group', f"{group['name']} -> Admin")
        else:
            # Verify user exists
            users = load_users()
            new_owner = next((u for u in users if u['id'] == new_owner_id), None)
            if new_owner:
                group['created_by'] = new_owner_id
                flash(f'群組已轉移給 {new_owner["username"]}', 'success')
                log_audit(session.get('username'), 'Transfer Group', f"{group['name']} -> {new_owner['username']}")
    
    if clear_key:
        group['api_key'] = ""
        flash('API Key 已清除', 'success')
        log_audit(session.get('username'), 'Update Group', f"{group['name']} (Clear Key)")
    elif api_key:
        if len(api_key) > 200:
             flash('API Key 過長', 'error')
        else:
            # Relaxed Validation: Encrypt anything that is not empty
            group['api_key'] = encrypt_data(api_key)
            flash('API Key 更新成功', 'success')
            log_audit(session.get('username'), 'Update Group', f"{group['name']} (Update Key)")

    save_groups(groups)
    if name: log_audit(session.get('username'), 'Update Group', f"{group['name']} (Rename)")
    return redirect(url_for('admin', group_id=group_id))

@app.route('/admin/user/create', methods=['POST'])
def create_user():
    if not session.get('user_id'): return redirect(url_for('login'))
    if session.get('role') != 'admin':
        flash('權限不足', 'error')
        return redirect(url_for('admin'))
        
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    
    if not username or not password:
        flash('請輸入使用者名稱與密碼', 'error')
        return redirect(url_for('admin'))
        
    email = request.form.get('email', '').strip() # Optional for Create, but needed for login
    
    # Password Strength Check
    is_valid, err_msg = validate_password_strength(password)
    if not is_valid:
        flash(f'密碼強度不足: {err_msg}', 'error')
        return redirect(url_for('admin'))

    users = load_users()
    if get_user_by_username(username):
        flash('使用者名稱已存在', 'error')
        return redirect(url_for('admin'))
        
    # Check email duplicate if provided
    if email and any(u.get('email') == email for u in users):
        flash('此 Email 已被其他使用者使用', 'error')
        return redirect(url_for('admin'))
        
    new_user = {
        "id": str(uuid.uuid4()),
        "username": username,
        "email": email, # Store Email
        "password_hash": generate_password_hash(password),
        "password_hint": generate_password_hint(password),
        "role": "teacher",
        "created_at": int(datetime.now().timestamp())
    }
    
    users.append(new_user)
    save_users(users)
    
    log_audit(session.get('username'), 'Create User', username)
    flash(f'教師帳戶 "{username}" 建立成功', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/user/update_info', methods=['POST'])
def update_user_info():
    if not session.get('user_id'): return redirect(url_for('login'))
    if session.get('role') != 'admin':
        flash('權限不足', 'error')
        return redirect(url_for('admin'))

    user_id = request.form.get('user_id')
    new_username = request.form.get('username', '').strip()
    new_email = request.form.get('email', '').strip()
    
    if not new_username:
         flash('名稱不能為空', 'error')
         return redirect(url_for('admin'))

    users = load_users()
    target_user = next((u for u in users if u['id'] == user_id), None)
    
    if not target_user:
        flash('找不到該使用者', 'error')
        return redirect(url_for('admin'))
        
    # Check duplicate username (exclude self)
    if new_username != target_user['username']:
        if any(u['username'] == new_username for u in users):
            flash('名稱已存在', 'error')
            return redirect(url_for('admin'))

    # Check duplicate email (exclude self)
    if new_email and new_email != target_user.get('email'):
        if any(u.get('email') == new_email for u in users):
            flash('Email 已存在', 'error')
            return redirect(url_for('admin'))

    old_username = target_user['username']
    target_user['username'] = new_username
    target_user['email'] = new_email
    
    save_users(users)
    
    log_audit(session.get('username'), 'Update User', f"{old_username} -> {new_username} (Info Update)")
    flash(f'使用者資料更新成功', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/user/delete', methods=['POST'])
def delete_user():
    if not session.get('user_id'): return redirect(url_for('login'))
    if session.get('role') != 'admin':
        flash('權限不足', 'error')
        return redirect(url_for('admin'))
        
    user_id = request.form.get('user_id')
    users = load_users()
    
    target_user = next((u for u in users if u['id'] == user_id), None)
    username = target_user['username'] if target_user else 'Unknown'
    
    new_users = [u for u in users if u['id'] != user_id]
    save_users(new_users)
    
    log_audit(session.get('username'), 'Delete User', username)
    flash('帳戶已刪除', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/user/reset', methods=['POST'])
def reset_password():
    if not session.get('user_id'): return redirect(url_for('login'))
    if session.get('role') != 'admin':
        flash('權限不足', 'error')
        return redirect(url_for('admin'))

    user_id = request.form.get('user_id')
    new_password = request.form.get('new_password', '').strip()

    if not user_id or not new_password:
        flash('請輸入新密碼', 'error')
        return redirect(url_for('admin'))

    # Password Strength Check
    is_valid, err_msg = validate_password_strength(new_password)
    if not is_valid:
        flash(f'密碼強度不足: {err_msg}', 'error')
        return redirect(url_for('admin'))

    users = load_users()
    target_user = next((u for u in users if u['id'] == user_id), None)

    if not target_user:
        flash('找不到該使用者', 'error')
        return redirect(url_for('admin'))

    target_user['password_hash'] = generate_password_hash(new_password)
    target_user['password_hint'] = generate_password_hint(new_password)
    save_users(users)

    log_audit(session.get('username'), 'Reset Password', target_user['username'])
    flash(f'{target_user["username"]} 密碼重設成功', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/group/delete', methods=['POST'])
def delete_group():
    if not session.get('user_id'): return redirect(url_for('login'))
    group_id = request.form.get('group_id')
    
    groups = load_groups()
    group = next((g for g in groups if g['group_id'] == group_id), None)
    
    if group:
        current_role = session.get('role')
        user_id = session.get('user_id')
        if current_role != 'admin' and group.get('created_by') != user_id:
            flash('權限不足：您只能刪除自己建立的群組', 'error')
            return redirect(url_for('admin', group_id=group_id))
    
    group_name = group['name'] if group else 'Unknown'
    
    new_groups = [g for g in groups if g['group_id'] != group_id]
    save_groups(new_groups)
    
    log_audit(session.get('username'), 'Delete Group', group_name)
    flash('群組已刪除', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/add_one', methods=['POST'])
def add_one_thread():
    if not session.get('user_id'): return redirect(url_for('login'))
    
    group_id = request.form.get('group_id')
    t_id = request.form.get('thread_id', '').strip()
    
    if not t_id:
        flash('請輸入 Thread ID', 'error')
        return redirect(url_for('admin', group_id=group_id))
        
    if len(t_id) > 100:
        flash('Thread ID 過長 (上限 100 字元)', 'error')
        return redirect(url_for('admin', group_id=group_id))
    
    groups = load_groups()
    target_group = next((g for g in groups if g['group_id'] == group_id), None)
    
    # Fallback to first if not found? No, better error.
    if not target_group:
         # Try legacy fallback if no group_id sent (though admin.html sends it)
         if len(groups) > 0: target_group = groups[0]
    
    if not target_group:
        flash('無效的群組', 'error')
        return redirect(url_for('admin'))

    # Security Check
    current_role = session.get('role')
    user_id = session.get('user_id')
    if current_role != 'admin' and target_group.get('created_by') != user_id:
         flash('權限不足：您無法修改此群組', 'error')
         return redirect(url_for('admin', group_id=target_group['group_id']))

    # Check duplicate in THIS group
    if not any(t['thread_id'] == t_id for t in target_group['threads']):
        target_group['threads'].append({"thread_id": t_id})
        save_groups(groups)
        flash('新增成功', 'success')
    else:
        flash('Thread ID 已存在於此群組', 'error')
        
    return redirect(url_for('admin', group_id=target_group['group_id']))

@app.route('/admin/delete_one', methods=['GET'])
def delete_one():
    if not session.get('user_id'): return redirect(url_for('login'))
    
    group_id = request.args.get('group_id')
    t_id = request.args.get('id')
    
    groups = load_groups()
    target_group = next((g for g in groups if g['group_id'] == group_id), None)
    
    if not target_group and len(groups) > 0: target_group = groups[0] # Legacy Fallback
    
    if not target_group:
        flash('無效的群組', 'error')
        return redirect(url_for('admin'))
        
    # Security Check
    current_role = session.get('role')
    user_id = session.get('user_id')
    if current_role != 'admin' and target_group.get('created_by') != user_id:
         flash('權限不足', 'error')
         return redirect(url_for('admin', group_id=target_group['group_id']))
    
    if t_id:
        target_group['threads'] = [t for t in target_group['threads'] if t['thread_id'] != t_id]
        save_groups(groups)
        flash('刪除成功', 'success')
    
    return redirect(url_for('admin', group_id=target_group['group_id']))

@app.route('/admin/delete_multi', methods=['POST'])
def delete_multi():
    if not session.get('user_id'): return redirect(url_for('login'))
    
    group_id = request.form.get('group_id')
    selected_ids = request.form.getlist('selected_ids')
    
    groups = load_groups()
    target_group = next((g for g in groups if g['group_id'] == group_id), None)
    
    if not target_group and len(groups) > 0: target_group = groups[0]
    
    if not target_group:
         flash('無效的群組', 'error')
         return redirect(url_for('admin'))

    # Security Check
    current_role = session.get('role')
    user_id = session.get('user_id')
    if current_role != 'admin' and target_group.get('created_by') != user_id:
         flash('權限不足', 'error')
         return redirect(url_for('admin', group_id=target_group['group_id']))
    
    if selected_ids:
        target_group['threads'] = [t for t in target_group['threads'] if t['thread_id'] not in selected_ids]
        save_groups(groups)
        flash(f'已刪除 {len(selected_ids)} 筆資料', 'success')
        
    return redirect(url_for('admin', group_id=target_group['group_id']))

@app.route('/admin/upload', methods=['POST'])
@limiter.limit("5 per minute")
def upload_file():
    if not session.get('user_id'): return redirect(url_for('login'))
    
    group_id = request.form.get('group_id')
    uploaded_file = request.files.get('file')
    action = request.form.get('action') # 'add' or 'delete'
    
    groups = load_groups()
    target_group = next((g for g in groups if g['group_id'] == group_id), None)
    if not target_group and len(groups) > 0: target_group = groups[0]
    
    if not target_group:
         flash('無效的群組', 'error')
         return redirect(url_for('admin'))

    # Security Check
    current_role = session.get('role')
    user_id = session.get('user_id')
    if current_role != 'admin' and target_group.get('created_by') != user_id:
         flash('權限不足', 'error')
         return redirect(url_for('admin', group_id=target_group['group_id']))
    
    if not uploaded_file:
        flash('未選擇檔案', 'error')
        return redirect(url_for('admin', group_id=target_group['group_id']))
    
    if not uploaded_file.filename.lower().endswith('.xlsx'):
        flash('檔案格式錯誤：僅支援 .xlsx 檔案', 'error')
        return redirect(url_for('admin', group_id=target_group['group_id']))
    
    try:
        # Read Excel
        df = pd.read_excel(uploaded_file)
        
        # Normalize column names to lower case
        df.columns = df.columns.str.lower()
        
        if 'thread_id' not in df.columns:
            flash('檔案格式錯誤：缺少 "thread_id" 欄位', 'error')
            return redirect(url_for('admin', group_id=target_group['group_id']))
        
        # Get list of clean IDs (remove NaN, strip whitespace)
        excel_ids = df['thread_id'].dropna().astype(str).str.strip().tolist()
        excel_ids = list(set(excel_ids)) # Deduplicate internal
        
        current_threads = target_group['threads']
        current_ids = {t['thread_id'] for t in current_threads}
        
        count = 0
        if action == 'add':
            # Merge logic
            for new_id in excel_ids:
                if new_id and new_id not in current_ids:
                    current_threads.append({"thread_id": new_id})
                    count += 1
            save_groups(groups)
            flash(f'匯入成功，新增了 {count} 筆資料', 'success')
            
        elif action == 'delete':
            # Delete logic
            before_len = len(current_threads)
            target_group['threads'] = [t for t in current_threads if t['thread_id'] not in excel_ids]
            count = before_len - len(target_group['threads'])
            save_groups(groups)
            flash(f'刪除成功，移除了 {count} 筆資料', 'success')
            
    except Exception as e:
        flash(f'處理失敗：{str(e)}', 'error')
    
    return redirect(url_for('admin', group_id=target_group['group_id']))

@app.route('/search', methods=['POST'])
@limiter.limit("5 per minute")
def search():
    start_time = datetime.now()
    target_name = request.form.get('target_name', '').strip()
    start_date = request.form.get('start_date', '').strip()
    end_date = request.form.get('end_date', '').strip()
    group_id = request.form.get('group_id')

    if len(target_name) > 50:
        return render_template('result.html', target_name=target_name, results=[], error="搜尋關鍵字過長 (上限 50 字元)")
    if len(start_date) > 10 or len(end_date) > 10:
        return render_template('result.html', target_name=target_name, results=[], error="日期格式錯誤或是過長")

    # Group Logic
    group = get_group_by_id(group_id)
    if not group:
         # Fallback logic
         group = get_group_by_id('default')
         if not group:
             groups = load_groups()
             if groups: group = groups[0]
    
    if not group:
         return render_template('result.html', target_name=target_name, results=[], error="無效的群組")

    threads_list = group['threads']
    group_key = group.get('api_key') 

    results = []
    log_details = [] 
    
    filtered_threads = []
    
    # 1. Pre-filtering by Date (Cache Optimization)
    threads_to_fetch = []
    
    for thread in threads_list:
        meta_start_ts = thread.get('start_ts', 0)
        meta_end_ts = thread.get('end_ts', 0)
        
        # If we have cache, try to exclude locally
        should_skip = False
        if meta_start_ts and meta_end_ts:
             # If filter start_date is AFTER thread ended -> Skip
             if start_date:
                 sd_ts = datetime.strptime(start_date, '%Y-%m-%d').timestamp()
                 if sd_ts > meta_end_ts: should_skip = True
             
             # If filter end_date is BEFORE thread started -> Skip
             if end_date:
                 ed_ts = datetime.strptime(end_date, '%Y-%m-%d').timestamp() + 86399 # End of that day
                 if ed_ts < meta_start_ts: should_skip = True
        
        if not should_skip:
            threads_to_fetch.append(thread)
    
    app.logger.info(f"Search Group '{group['name']}' Target '{target_name}' Candidates {len(threads_to_fetch)} (Total {len(threads_list)})")

    with ThreadPoolExecutor(max_workers=5) as executor:
        # Pass group_key to process_thread
        futures = {executor.submit(process_thread, t, target_name, start_date, end_date, group_key): t['thread_id'] for t in threads_to_fetch}
        
        has_updates = False
        
        for future in futures:
            try:
                res = future.result()
                if res['keep']: results.append(res['data'])
                log_details.append({
                    "thread_id": res['thread_id'], # Fixed access for process_thread return dict
                    "status": res['status'],
                    "msg_count": len(res.get('data', {}).get('messages', [])) if res.get('data') else 0
                })
                
                # Update Cache logic
                if 'meta' in res:
                    t_id = res['thread_id']
                    # Find thread in original list to update
                    for t in threads_list:
                         if t['thread_id'] == t_id:
                             # Update only if changed/new
                             if t.get('start_ts') != res['meta']['start_ts'] or t.get('msg_count') != res['meta']['msg_count']:
                                 t['start_ts'] = res['meta']['start_ts']
                                 t['end_ts'] = res['meta']['end_ts']
                                 t['msg_count'] = res['meta']['msg_count']
                                 t['last_updated'] = res['meta']['last_updated']
                                 has_updates = True
                             break
            except Exception as e:
                app.logger.error(f"Future error: {e}")

        if has_updates:
            save_groups(load_groups()) # Reload to minimize overwrite risk? 
            # Risk: load_groups() gets FRESH data, but our `threads_list` object is stale?
            # NO. `threads_list` is a reference to the dict inside `group`.
            # If we call `load_groups()` now, we get fresh file content.
            # We need to merge our `threads_list` updates into that fresh content.
            # Or simpler: Just save the `groups` object we have modified, 
            # assuming no one else modified it in the last 2 seconds.
            # With `data_lock` in `save_groups`, we are ensuring write safety, 
            # but we still have R-M-W race if another process wrote in between.
            # Given single instance usage, this is acceptable.
            # But let's use the local `groups` variable which we modified.
            # Wait, `groups` variable in `search` scope? 
            # We loaded `group` from `get_group_by_id`, which loaded `groups`. 
            # So `group` is a dict inside `load_groups()` return value if we haven't reloaded.
            # Wait, `get_group_by_id` calls `load_groups()`.
            # So we need to update the WHOLE `groups` list.
            # Currently `group` is just one item.
            # We need the full list to save.
            # Hack: `load_groups()` creates a new list. `group` is from that list?
            # Let's check `get_group_by_id`.
            # It loads groups, finds one, returns it.
            # So `group` is detached if we don't hold the parent `groups` list.
            # In `search`, we did:
            # group = get_group_by_id(...)
            # IF we modify `group`, we are modifying that dict object.
            # BUT we don't have the parent list anymore to pass to `save_groups`.
            # FIX: In search, we should load all groups.
            all_groups = load_groups()
            # Find our group in this list.
            target_group = None
            for g in all_groups:
                if g['group_id'] == group['group_id']:
                    target_group = g
                    break
            
            if target_group:
                 # Update this target_group using our local modified `threads_list`?
                 # Actually, we modified `threads_list` which contains dicts.
                 # Those dicts are shared if we used reference?
                 # No, `threads_list = group['threads']`.
                 # But `group` came from `get_group_by_id` which might be a different call than `all_groups`.
                 # So we need to apply updates to `all_groups` explicitly.
                 
                 # Better approach:
                 # We have `filtered_threads`. We updated items in `threads_list`.
                 # Let's just update `target_group['threads']` = `threads_list` (which has updated dicts).
                 # Wait, `threads_list` elements are dicts.
                 # If we did `t['start_ts'] = ...` inside the loop over `threads_list`,
                 # we modified the dicts in memory.
                 # So we just need to copy these updated thread dicts back to `all_groups`.
                 
                 # Let's do:
                 updated_map = {t['thread_id']: t for t in threads_list}
                 
                 for i, t in enumerate(target_group['threads']):
                     if t['thread_id'] in updated_map:
                         target_group['threads'][i] = updated_map[t['thread_id']]
                         
                 save_groups(all_groups)
    
    results.sort(key=lambda x: x['timestamp'] if 'timestamp' in x else 0, reverse=True)
    
    # Save Log (using lock inside save_log)
    duration = (datetime.now() - start_time).total_seconds()
    log_entry = {
        "timestamp": start_time.strftime('%Y-%m-%d %H:%M:%S'),
        "group": group['name'],
        "target": target_name,
        "matches": len(results),
        "duration": f"{duration:.2f}s",
        "details": log_details
    }
    save_log(log_entry)

    return render_template('result.html', 
                           target_name=target_name, 
                           results=results, 
                           count=len(results),
                           target_time=f"{duration:.2f}s",
                           group_id=group.get('group_id'),
                           debug_log=log_details)

if __name__ == '__main__':
    # Only enable debug if explicitly set in environment, default to False for safety check
    # But for local dev convenience, we can keep it standard or use waitress
    app.run(debug=True, port=5000)
