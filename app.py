from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, has_request_context
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timedelta
import time
import logging
from logging.handlers import RotatingFileHandler
import uuid
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
# PDF & Request Dependencies
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from weasyprint import HTML
import zipfile
import io
import math

# Internal Modules
import config
import utils
import security
import database
import services

# --- WeasyPrint Helper ---
def safe_url_fetcher(url, timeout=30):
    try:
        retry_strategy = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session = requests.Session()
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        # Mimic browser to avoid blocking
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        resp = session.get(url, timeout=timeout, stream=True, headers=headers)
        resp.raise_for_status()
        return {'file_obj': io.BytesIO(resp.content), 'mime_type': resp.headers.get('Content-Type'), 'encoding': resp.encoding, 'redirected_url': resp.url}
    except Exception as e:
        logging.warning(f"WeasyPrint URL Fetch Failed for {url}: {e}")
        return None

# --- PDF Generation Helper ---
def generate_pdf_bytes(html_content):
    return HTML(string=html_content, url_fetcher=safe_url_fetcher).write_pdf()

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.permanent_session_lifetime = timedelta(hours=1)
app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH

# --- Register Template Filters ---
app.jinja_env.filters['nl2br'] = utils.nl2br
app.jinja_env.filters['render_images'] = utils.render_markdown_images
app.jinja_env.filters['sanitize_html'] = utils.sanitize_html
app.jinja_env.filters['format_timestamp'] = utils.unix_to_utc8

# --- Logging Setup (Access Log) ---
log_handler = RotatingFileHandler('access.log', maxBytes=1000000, backupCount=5)
class RequestFormatter(logging.Formatter):
    def format(self, record):
        if has_request_context():
            record.remote_addr = request.remote_addr
        else:
            record.remote_addr = '-'
        return super().format(record)

log_handler.setFormatter(RequestFormatter(
    '[%(asctime)s] %(levelname)s [%(remote_addr)s] %(message)s'
))
app.logger.addHandler(log_handler)
app.logger.setLevel(logging.INFO)

# --- Security Setup ---
csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["10 per second"],
    storage_uri="memory://"
)

# --- Routes ---

@app.route('/', methods=['GET'])
def index():
    all_groups = database.load_groups()
    # Filter for visible groups
    groups = [g for g in all_groups if g.get('is_visible', True)]
    
    # Optional: Log visit (Unknown/User)
    database.log_audit(session.get('username', 'Unknown'), 'Visit', 'Home')
    
    return render_template('index.html', groups=groups)

@app.before_request
def check_ip_ban():
    # Helper to check if IP is banned
    ip = get_remote_address()
    is_banned, reason, remaining = security.check_ban(ip)
    
    if is_banned:
        # Check if it's a static file request or something innocuous? 
        # Usually we want to block everything.
        if request.endpoint and 'static' in request.endpoint:
            return None
            
        remaining_str = "永久" if remaining == -1 else f"{int(remaining)} 秒"
        return render_template('login.html', error=f"您的 IP ({ip}) 已被封鎖。原因: {reason}。剩餘時間: {remaining_str}"), 403

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute", methods=['POST']) 
def login():
    ip = get_remote_address()
    
    # Check Lockout
    is_locked, remaining = security.check_lockout(ip)
    if is_locked:
        app.logger.warning(f"Login Blocked: IP {ip} is locked out. Remaining: {int(remaining)}s")
        return render_template('login.html', error=f"登入失敗次數過多，請於 {int(remaining//60)+1} 分鐘後再試")

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        pwd = request.form.get('password', '')
        
        if len(pwd) > 100:
            app.logger.warning("Login failed: Password too long")
            return render_template('login.html', error="輸入過長")
            
        # 1. Check Admin (No Email or Email is 'admin')
        if not email or email.lower() == 'admin':
            if pwd in config.ADMIN_PASSWORDS:
                session.clear()
                session.permanent = True
                session['is_admin'] = True 
                session['role'] = 'admin'
                session['user_id'] = 'admin'
                session['username'] = 'Administrator'
                
                security.record_login_attempt(ip, True)
                database.log_audit('Administrator', 'Login', 'Admin Panel', 'Success', f"IP: {ip}")
                return redirect(url_for('admin'))
        
        # 2. Check Teachers (Must verify Email + Password)
        if email:
            users = database.load_users()
            # Case-insensitive email match
            user = next((u for u in users if u.get('email', '').lower() == email.lower()), None)
            
            if user and check_password_hash(user['password_hash'], pwd):
                session.clear()
                session.permanent = True
                session['is_admin'] = False
                session['role'] = 'teacher'
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['email'] = user.get('email', '')
                
                security.record_login_attempt(ip, True)
                database.log_audit(user['username'], 'Login', 'Admin Panel', 'Success', f"IP: {ip}")
                return redirect(url_for('admin'))

        # Record Failure
        security.record_login_attempt(ip, False)
        # Log which (Email) failed if provided
        log_user = email if email else 'Unknown'
        database.log_audit(log_user, 'Login', 'Admin Panel', 'Fail', f"IP: {ip}")
        return render_template('login.html', error="帳號或密碼錯誤")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/admin')
def admin():
    if not session.get('user_id'): return redirect(url_for('login'))
    
    database.log_audit(session.get('username'), 'Visit', 'Admin Panel')
    
    all_groups = database.load_groups()
    current_role = session.get('role', 'teacher')
    current_user_id = session.get('user_id')
    
    if current_role == 'admin':
        groups = all_groups
    else:
        # Teacher only sees own groups
        groups = [g for g in all_groups if str(current_user_id) in [str(o) for o in g.get('owners', [])]]
    
    group_id = request.args.get('group_id')
    active_group = None
    if group_id:
        active_group = next((g for g in groups if g['group_id'] == group_id), None)
    
    if not active_group and groups:
        active_group = groups[0]
        
    threads = active_group.get('threads', []) if active_group else []
    
    # Decrypt Key for Display
    first_key = active_group.get('api_key') if active_group else None
    decrypted_show = security.get_decrypted_key(first_key)
    
    if decrypted_show == "INVALID_KEY_RESET_REQUIRED":
        masked_key = "⚠️ 金鑰失效 (需重設)"
    elif decrypted_show and len(decrypted_show) > 12:
        masked_key = f"{decrypted_show[:8]}...{decrypted_show[-4:]}"
    else:
        masked_key = "尚未設定 (使用環境變數/預設)"
    
    logs = database.load_logs()
    
    logs = database.load_logs()
    
    users_list = []
    ip_activity = {}
    banned_ips = {}
    
    if current_role == 'admin':
        users_list = database.load_users()
        
        # Load IP Bans
        banned_ips = database.load_ip_bans()
        
        # Process Audit Logs for IP Activity
        audit_logs = database.load_audit_logs()
        for log in audit_logs:
            ip = log['ip']
            if ip not in ip_activity:
                ip_activity[ip] = {'logs': [], 'user': 'Guest', 'last_seen': 0}
            
            ip_activity[ip]['logs'].append(log)
            
            # Update last user seen on this IP
            if log['user'] and log['user'] != 'Unknown':
                 ip_activity[ip]['user'] = log['user']
                 
            # Note: logs are reversed (newest first), so first one is latest
            if ip_activity[ip]['last_seen'] == 0:
                # Parse time? Or just iterate. 
                # Since we just want grouping, order is preserved.
                pass

    user_map = {u['id']: u['username'] for u in users_list}

    return render_template('admin.html', 
                           user_map=user_map,
                           groups=groups, 
                           active_group=active_group, 
                           threads=threads, 
                           masked_key=masked_key, 
                           logs=logs,
                           users=users_list,
                           current_role=current_role,
                           ip_activity=ip_activity,
                           banned_ips=banned_ips)

@app.route('/admin/group/create', methods=['POST'])
def create_group():
    if not session.get('user_id'): return redirect(url_for('login'))
    name = request.form.get('name', '').strip()
    api_key = request.form.get('api_key', '').strip()
    
    if not name:
        flash('Project 名稱不能為空', 'error')
        return redirect(url_for('admin'))
        
    if not api_key:
        flash('API Key 不能為空', 'error')
        return redirect(url_for('admin'))
        
    groups = database.load_groups()
    if any(g['name'] == name for g in groups):
        flash('Project 名稱已存在，請使用不同名稱', 'error')
        return redirect(url_for('admin'))

    new_id = f"group_{int(datetime.now().timestamp())}"
    
    if len(api_key) > 200:
         flash('API Key 過長', 'error')
         return redirect(url_for('admin'))
         
    encrypted_key = security.encrypt_data(api_key)

    new_group = {
        "group_id": new_id,
        "name": name,
        "api_key": encrypted_key,
        "owners": [session.get('user_id')] if session.get('role') != 'admin' else [],
        "is_visible": True,
        "version": 1,
        "threads": []
    }
    
    groups.append(new_group)
    database.save_groups(groups)
    
    database.log_audit(session.get('username'), 'Create Group', name)
    flash(f'Project "{name}" 建立成功', 'success')
    return redirect(url_for('admin', group_id=new_id))

@app.route('/admin/group/delete', methods=['POST'])
def delete_group():
    if not session.get('user_id'): return redirect(url_for('login'))
    group_id = request.form.get('group_id')
    
    groups = database.load_groups()
    group = next((g for g in groups if g['group_id'] == group_id), None)
    
    if not group:
        flash('Project 不存在', 'error')
        return redirect(url_for('admin'))
        
    current_role = session.get('role')
    user_id = session.get('user_id')
    
    if current_role != 'admin' and user_id not in group.get('owners', []):
        flash('權限不足：您只能刪除自己建立的 Project', 'error')
        return redirect(url_for('admin'))
    
    groups = [g for g in groups if g['group_id'] != group_id]
    database.save_groups(groups)
    
    database.log_audit(session.get('username'), 'Delete Group', group['name'])
    flash(f'Project "{group["name"]}" 已刪除', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/group/update', methods=['POST'])
def update_group():
    if not session.get('user_id'): return redirect(url_for('login'))
    group_id = request.form.get('group_id')
    name = request.form.get('name', '').strip()
    api_key = request.form.get('api_key', '').strip()
    clear_key = request.form.get('clear_key')
    new_owner_ids = request.form.getlist('owner_ids')
    is_visible = request.form.get('is_visible') == 'on'
    client_version = request.form.get('version', type=int)
    
    groups = database.load_groups()
    group = next((g for g in groups if g['group_id'] == group_id), None)
    
    if not group:
        flash('Project 不存在', 'error')
        return redirect(url_for('admin'))
    
    current_role = session.get('role')
    user_id = session.get('user_id')
    
    if current_role != 'admin' and user_id not in group.get('owners', []):
        flash('權限不足：您只能編輯自己建立的 Project', 'error')
        return redirect(url_for('admin'))

    # Optimistic Locking Check
    current_version = group.get('version', 1)
    if client_version is not None and client_version != current_version:
        flash('資料已被其他人修改，請重新整理頁面後再試', 'error')
        return redirect(url_for('admin', group_id=group_id))

    if name: 
        if name != group['name'] and any(g['name'] == name for g in groups):
             flash('Project 名稱已存在，請使用不同名稱', 'error')
             return redirect(url_for('admin', group_id=group_id))
        group['name'] = name

    group['is_visible'] = is_visible

    if current_role == 'admin':
        # Admin can update owners
        # new_owner_ids is a list of user IDs
        group['owners'] = new_owner_ids
        database.log_audit(session.get('username'), 'Update Group Owners', f"{group['name']} -> {len(new_owner_ids)} owners")
    
    if clear_key:
        group['api_key'] = ""
        flash('API Key 已清除', 'success')
        database.log_audit(session.get('username'), 'Update Group', f"{group['name']} (Clear Key)")
    elif api_key:
        if len(api_key) > 200:
             flash('API Key 過長', 'error')
        else:
            group['api_key'] = security.encrypt_data(api_key)
            flash('API Key 更新成功', 'success')
            database.log_audit(session.get('username'), 'Update Group', f"{group['name']} (Update Key)")

    # Increment Version
    group['version'] = group.get('version', 1) + 1

    database.save_groups(groups)
    if name: database.log_audit(session.get('username'), 'Update Group', f"{group['name']} (Rename)")
    return redirect(url_for('admin', group_id=group_id))

@app.route('/admin/threads/add_one', methods=['POST'])
def add_one_thread():
    if not session.get('user_id'): return redirect(url_for('login'))
    group_id = request.form.get('group_id')
    thread_id = request.form.get('thread_id', '').strip()
    
    if not thread_id.startswith('thread_'):
        flash('Thread ID 格式錯誤', 'error')
        return redirect(url_for('admin', group_id=group_id))
        
    groups = database.load_groups()
    group = next((g for g in groups if g['group_id'] == group_id), None)
    if not group: return redirect(url_for('admin'))
    
    # Permission Check
    if session.get('role') != 'admin' and session.get('user_id') not in group.get('owners', []):
         return redirect(url_for('admin'))

    if 'threads' not in group: group['threads'] = []
    
    if any(t['thread_id'] == thread_id for t in group['threads']):
        flash('Thread ID 已存在', 'error')
    else:
        group['threads'].append({'thread_id': thread_id})
        # Note: List updates also bump version? Ideally yes.
        group['version'] = group.get('version', 1) + 1
        database.save_groups(groups)
        flash('Thread 新增成功', 'success')
        database.log_audit(session.get('username'), 'Add Thread', f"{thread_id} to {group['name']}")
        
    return redirect(url_for('admin', group_id=group_id))

@app.route('/admin/threads/delete', methods=['POST'])
def delete_one():
    if not session.get('user_id'): return redirect(url_for('login'))
    group_id = request.form.get('group_id')
    thread_id = request.form.get('thread_id')
    
    groups = database.load_groups()
    group = next((g for g in groups if g['group_id'] == group_id), None)
    if not group: return redirect(url_for('admin'))
    
    if session.get('role') != 'admin' and session.get('user_id') not in group.get('owners', []):
         return redirect(url_for('admin'))

    original_len = len(group['threads'])
    group['threads'] = [t for t in group['threads'] if t['thread_id'] != thread_id]
    
    if len(group['threads']) < original_len:
        group['version'] = group.get('version', 1) + 1
        database.save_groups(groups)
        flash('Thread 刪除成功', 'success')
        database.log_audit(session.get('username'), 'Delete Thread', f"{thread_id} from {group['name']}")
        
    return redirect(url_for('admin', group_id=group_id))

@app.route('/admin/threads/delete_multi', methods=['POST'])
def delete_multi():
    if not session.get('user_id'): return redirect(url_for('login'))
    group_id = request.form.get('group_id')
    thread_ids = request.form.getlist('selected_ids') # list of checked IDs
    
    if not thread_ids:
        flash('未選擇任何 Thread', 'error')
        return redirect(url_for('admin', group_id=group_id))

    groups = database.load_groups()
    group = next((g for g in groups if g['group_id'] == group_id), None)
    if not group: return redirect(url_for('admin'))

    if session.get('role') != 'admin' and session.get('user_id') not in group.get('owners', []):
         return redirect(url_for('admin'))

    original_len = len(group['threads'])
    group['threads'] = [t for t in group['threads'] if t['thread_id'] not in thread_ids]
    
    if len(group['threads']) < original_len:
        group['version'] = group.get('version', 1) + 1
        database.save_groups(groups)
        flash(f'已刪除 {len(thread_ids)} 個 Thread', 'success')
        database.log_audit(session.get('username'), 'Delete Multi', f"{len(thread_ids)} threads from {group['name']}")
    
    return redirect(url_for('admin', group_id=group_id))

@app.route('/admin/threads/upload', methods=['POST'])
def upload_file():
    if not session.get('user_id'): return redirect(url_for('login'))
    group_id = request.form.get('group_id')
    
    file = request.files.get('file')
    if not file or not file.filename.endswith('.xlsx'):
        flash('請上傳 Excel (.xlsx) 檔案', 'error')
        return redirect(url_for('admin', group_id=group_id))

    groups = database.load_groups()
    group = next((g for g in groups if g['group_id'] == group_id), None)
    if not group: return redirect(url_for('admin'))

    if session.get('role') != 'admin' and session.get('user_id') not in group.get('owners', []):
         return redirect(url_for('admin'))

    try:
        df = pd.read_excel(file)
        
        # Find column case-insensitively
        target_col = None
        for col in df.columns:
             # Check for "thread id" or "thread_id" in any casing
             clean_col = str(col).strip().lower()
             if clean_col == 'thread id' or clean_col == 'thread_id':
                 target_col = col
                 break
                 
        if not target_col:
            flash('Excel 必須包含 "Thread ID" 欄位', 'error')
            return redirect(url_for('admin', group_id=group_id))
            
        new_ids = df[target_col].dropna().astype(str).tolist()
        new_ids = [tid.strip() for tid in new_ids if tid.strip().startswith('thread_')]
        
        action = request.form.get('action', 'add')
        
        if action == 'delete':
            # Batch Delete Logic
            target_ids = set(new_ids)
            original_len = len(group['threads'])
            group['threads'] = [t for t in group['threads'] if t['thread_id'] not in target_ids]
            
            removed_count = original_len - len(group['threads'])
            
            if removed_count > 0:
                group['version'] = group.get('version', 1) + 1
                database.save_groups(groups)
                flash(f'成功刪除 {removed_count} 筆 Thread', 'success')
                database.log_audit(session.get('username'), 'Batch Delete Excel', f"{removed_count} threads from {group['name']}")
            else:
                 flash('沒有刪除任何 Thread (Excel 中的 ID 在 Project 中找不到)', 'warning')

        else:
            # Batch Add Logic
            current_ids = {t['thread_id'] for t in group['threads']}
            added_count = 0
            
            for tid in new_ids:
                if tid not in current_ids:
                    group['threads'].append({'thread_id': tid})
                    current_ids.add(tid)
                    added_count += 1
            
            if added_count > 0:
                group['version'] = group.get('version', 1) + 1
                database.save_groups(groups)
                flash(f'成功匯入 {added_count} 筆 Thread', 'success')
                database.log_audit(session.get('username'), 'Import Excel', f"{added_count} threads to {group['name']}")
            else:
                flash('沒有新增任何 Thread (可能已存在或格式不符)', 'warning')
            
    except Exception as e:
        flash(f'檔案處理失敗: {str(e)}', 'error')
        
    return redirect(url_for('admin', group_id=group_id))

@app.route('/search', methods=['POST'])
@limiter.limit("20 per minute")
def search():
    # Standard Form Submission
    group_id = request.form.get('group_id')
    target_name = request.form.get('target_name', '').strip()
    date_from = request.form.get('start_date')
    date_to = request.form.get('end_date')
    
    # 1. Permission/Group Check
    group = database.get_group_by_id(group_id)
    if not group: 
        return "Group not found", 404
        # Ideally render a nice error page or redirect with flash
        
    if not group.get('is_visible', True):
        return "Group is hidden", 403

    threads_list = group.get('threads', [])
    if not threads_list:
        return render_template('result.html', results=[], target_name=target_name, count=0, debug_log=[])

    # Start Processing
    results = []
    debug_log = []
    
    # Get Key
    api_key = group.get('api_key')
    if api_key:
        api_key = security.get_decrypted_key(api_key)
    
    # Audit Search (This now goes to audit.log for IP monitoring)
    # Note: Search params might be sensitive content, so maybe just log "Search" + Target Name length or generic?
    # User requested "search content", so we log target_name
    database.log_audit(session.get('username', 'Unknown'), 'Search', target_name or 'All', 'Success', f"Group: {group['name']}")
    
    
    start_time = time.time()

    try:
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for t in threads_list:
                futures.append(executor.submit(services.process_thread, t, target_name, date_from, date_to, api_key))
            
            for future in futures:
                res = future.result()
                debug_log.append(res)
                if res['keep']:
                    results.append(res['data'])
    except Exception as e:
        logging.getLogger().error(f"Search Error: {e}")
        return render_template('result.html', results=[], target_name=target_name, count=0, debug_log=[], error="搜尋發生錯誤，請稍後再試")

    # Save Log (Moved to after search to include results)
    log_entry = {
         'timestamp': int(datetime.now().timestamp()),
         'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
         'group': group['name'],
         'target': target_name,
         'date_range': f"{date_from}-{date_to}",
         'matches': len(results),
         'total': len(threads_list),
         'api_results': debug_log # List of results from process_thread
    }
    database.save_log(log_entry)
    
    end_time = time.time()
    duration = end_time - start_time
    target_time = f"{duration:.2f} 秒"
    
    # Sort by date descending
    results.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return render_template('result.html', 
        results=results, 
        target_name=target_name, 
        count=len(results),
        target_time=target_time,
        debug_log=debug_log
    )

# --- User Management (Admin) ---
@app.route('/admin/user/create', methods=['POST'])
def create_user():
    if not session.get('user_id') or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()
    
    if not username or not password:
        flash('欄位不完整', 'error')
        return redirect(url_for('admin'))
        
    users = database.load_users()
    if any(u['username'] == username for u in users):
        flash('Username 已存在', 'error')
        return redirect(url_for('admin'))

    # Check for duplicate email
    if email and any(u.get('email') == email for u in users):
        flash('Email 已存在', 'error')
        return redirect(url_for('admin'))
        
    # Validate Password
    is_valid, msg = security.validate_password_strength(password)
    if not is_valid:
        flash(msg, 'error')
        return redirect(url_for('admin'))

    new_user = {
        "id": str(uuid.uuid4()),
        "username": username,
        "email": email,
        "password_hash": generate_password_hash(password),
        "password_hint": security.generate_password_hint(password),
        "created_at": int(datetime.now().timestamp())
    }
    
    users.append(new_user)
    database.save_users(users)
    database.log_audit(session.get('username'), 'Create User', username)
    flash(f'教師帳戶 {username} 建立成功', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/user/reset', methods=['POST'])
def reset_user_password():
    if not session.get('user_id') or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    user_id = request.form.get('user_id')
    new_password = request.form.get('new_password', '').strip()
    
    users = database.load_users()
    user = next((u for u in users if u['id'] == user_id), None)
    
    if not user:
        flash('用戶不存在', 'error')
        return redirect(url_for('admin'))
        
    is_valid, msg = security.validate_password_strength(new_password)
    if not is_valid:
        flash(msg, 'error')
        return redirect(url_for('admin'))
        
    user['password_hash'] = generate_password_hash(new_password)
    user['password_hint'] = security.generate_password_hint(new_password)
    database.save_users(users)
    database.log_audit(session.get('username'), 'Reset Password', user['username'])
    flash(f'用戶 {user["username"]} 密碼重設成功', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/user/delete', methods=['POST'])
def delete_user():
    if not session.get('user_id') or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    user_id = request.form.get('user_id')
    users = database.load_users()
    
    original_len = len(users)
    users = [u for u in users if u['id'] != user_id]
    
    if len(users) < original_len:
        database.save_users(users)
        
        # Handle Orphaned Groups: Remove user from 'owners' lists
        all_groups = database.load_groups()
        groups_modified = False
        for g in all_groups:
             if 'owners' in g and user_id in g['owners']:
                 g['owners'].remove(user_id)
                 groups_modified = True
                 # If list becomes empty, it implicitly becomes Admin-managed (owners=[])
        
        if groups_modified:
            database.save_groups(all_groups)
            
        database.log_audit(session.get('username'), 'Delete User', user_id)
        flash('用戶已刪除', 'success')
        
    return redirect(url_for('admin'))

@app.route('/admin/user/update', methods=['POST'])
def update_user():
    if not session.get('user_id') or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    user_id = request.form.get('user_id')
    new_username = request.form.get('username', '').strip()
    new_email = request.form.get('email', '').strip()
    
    users = database.load_users()
    user = next((u for u in users if u['id'] == user_id), None)
    
    if not user:
        flash('用戶不存在', 'error')
        return redirect(url_for('admin'))
        
    # Check duplicate username
    if new_username != user['username']:
        if any(u['username'] == new_username for u in users):
            flash('Username 已存在', 'error')
            return redirect(url_for('admin'))
            
    user['username'] = new_username
    user['email'] = new_email
    
    database.save_users(users)
    database.log_audit(session.get('username'), 'Update User', new_username)
    flash(f'用戶 {new_username} 資料更新成功', 'success')
    return redirect(url_for('admin'))

@app.route('/print-view', methods=['POST'])
def print_view():
    if not session.get('user_id'): return redirect(url_for('login'))
    
    # Deprecated: Redirect to single download if one thread selected
    thread_ids = request.form.getlist('thread_ids')
    if thread_ids and len(thread_ids) == 1:
        return redirect(url_for('download_pdf', thread_id=thread_ids[0]))
    
    return "Batch print deprecated. Please download threads individually.", 400

@app.route('/download/pdf/<thread_id>')
def download_pdf(thread_id):
    if not session.get('user_id'): return redirect(url_for('login'))
    
    # 1. Fetch Group Context (Find which group contains this thread)
    groups = database.load_groups()
    api_key_enc = None
    
    # We need to find the group that owns this thread_id
    found_group = None
    for g in groups:
        # g['threads'] is a list of dicts like [{'thread_id': '...', ...}]
        # Check if thread_id exists in this group's threads
        if any(t.get('thread_id') == thread_id for t in g.get('threads', [])):
            found_group = g
            break
            
    if found_group:
         api_key_enc = found_group.get('api_key')
    else:
         # Fallback: Try session if defined, or just proceed (might use global key in services)
         if session.get('active_group_id'):
             active_group = next((g for g in groups if g['group_id'] == session['active_group_id']), None)
             if active_group:
                 api_key_enc = active_group.get('api_key')

    # 2. Process Thread
    thread_data = services.process_thread({'thread_id': thread_id}, None, None, None, api_key_enc)
    
    if not thread_data or not thread_data.get('data'):
        return "Thread not found or empty", 404
        
    messages = thread_data['data']['messages']
    
    # 3. Split Logic
    CHUNK_SIZE = 50
    total_messages = len(messages)
    
    # Render full or chunked
    if total_messages <= CHUNK_SIZE:
        html = render_template('print_view.html', threads=[thread_data['data']])
        pdf_bytes = generate_pdf_bytes(html)
        return io.BytesIO(pdf_bytes), 200, {
            'Content-Type': 'application/pdf',
            'Content-Disposition': f'attachment; filename="thread_{thread_id}.pdf"'
        }
    else:
        # Split into ZIP
        chunks = math.ceil(total_messages / CHUNK_SIZE)
        zip_buffer = io.BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            for i in range(chunks):
                start = i * CHUNK_SIZE
                end = start + CHUNK_SIZE
                chunk_msgs = messages[start:end]
                
                chunk_data = thread_data['data'].copy()
                chunk_data['messages'] = chunk_msgs
                
                # Append part info to title if possible, or just render
                html = render_template('print_view.html', threads=[chunk_data])
                pdf_bytes = generate_pdf_bytes(html)
                
                zf.writestr(f"thread_{thread_id}_part_{i+1}.pdf", pdf_bytes)
                
        zip_buffer.seek(0)
        return io.BytesIO(zip_buffer.getvalue()), 200, {
            'Content-Type': 'application/zip',
            'Content-Disposition': f'attachment; filename="thread_{thread_id}_split.zip"'
        }

@app.route('/settings', methods=['POST'])
def update_settings():
    # Only Admin can change global settings? 
    # Current implementation doesn't check RBAC for this route strictly, 
    # but the settings.json is used for Fallback API Key.
    if not session.get('user_id') or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
        
    data = request.json
    openai_key = data.get('openai_api_key')
    
    settings = database.load_settings()
    if openai_key:
        settings['openai_api_key'] = security.encrypt_data(openai_key)
        
    database.save_settings(settings)
    database.log_audit(session.get('username'), 'Update Global Settings', 'OpenAI Key')
    return jsonify({'success': True})

@app.route('/admin/ip/ban', methods=['POST'])
def ban_ip_route():
    if not session.get('user_id') or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    ip = request.form.get('ip')
    duration = request.form.get('duration', type=int) # seconds
    reason = request.form.get('reason', 'Admin Action')
    
    # Self-Ban Prevention
    current_ip = get_remote_address()
    if ip == current_ip:
        flash('⚠️ 安全警告：您不能封鎖自己的 IP！以免將自己拒於門外。', 'error')
        return redirect(url_for('admin'))
    
    if ip:
        security.ban_ip(ip, duration, reason)
        database.log_audit(session.get('username'), 'Ban IP', f"{ip} for {duration}s")
        flash(f'IP {ip} 已封鎖', 'success')
        
    return redirect(url_for('admin'))

@app.route('/admin/ip/unban', methods=['POST'])
def unban_ip_route():
    if not session.get('user_id') or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    ip = request.form.get('ip')
    
    if ip:
        security.unban_ip(ip)
        database.log_audit(session.get('username'), 'Unban IP', ip)
        flash(f'IP {ip} 已解除封鎖', 'success')
        
    return redirect(url_for('admin'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
