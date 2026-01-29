import bleach
from datetime import datetime, timezone, timedelta
from markupsafe import escape, Markup
import requests
import markdown
import logging
from collections import OrderedDict

# In-Memory Cache for IP Info (LRU with max size to prevent memory leaks)
IP_CACHE = OrderedDict()
IP_CACHE_MAX_SIZE = 1000  # Limit cache to 1000 IPs

def log_access(user, action):
    from flask import current_app
    current_app.logger.info(f"User: {user} | Action: {action}")

# --- Template Filters ---
# --- Template Filters ---
def nl2br(value):
    if not value: return ""
    return Markup(str(escape(value)).replace('\n', '<br>'))

def render_markdown(value):
    if not value: return ""
    # Use standard markdown with tables and fenced code
    # nl2br extension converts newlines to <br> which mimics previous behavior
    html = markdown.markdown(value, extensions=['fenced_code', 'tables', 'nl2br'])
    return html

def sanitize_html(value):
    if not value: return ""
    
    allowed_tags = [
        'a', 'abbr', 'acronym', 'b', 'blockquote', 'br', 'code', 'div', 'em', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'hr', 'i', 'img', 'li', 'ol', 'p', 'pre', 'span', 'strong', 'table', 'tbody', 'td', 'th', 'thead', 'tr', 'ul',
        'mark'
    ]
    
    allowed_attrs = {
        '*': ['class', 'style'],
        'a': ['href', 'title', 'target', 'rel'],
        'img': ['src', 'alt', 'title', 'width', 'height', 'loading']
    }
    
    from bleach.css_sanitizer import CSSSanitizer
    css_sanitizer = CSSSanitizer(allowed_css_properties=['text-align', 'color', 'background-color', 'font-weight', 'font-style', 'text-decoration'])
    
    cleaned = bleach.clean(value, tags=allowed_tags, attributes=allowed_attrs, strip=True, css_sanitizer=css_sanitizer)
    return Markup(cleaned)

def mask_credential(value):
    if not value: return ""
    val = str(value)
    if len(val) <= 2: return "*" * len(val)
    return f"{val[0]}{'*' * 8}{val[-1]}"

def get_client_ip():
    """
    Reliably extracts client IP from headers, prioritizing X-Real-Ip.
    This ensures consistent IP handling behind proxies (like Nginx).
    """
    from flask import request, has_request_context
    if not has_request_context(): return '0.0.0.0'
    
    # Priority 1: X-Real-Ip (Nginx Default)
    ip = request.headers.get('X-Real-Ip')
    
    # Priority 2: X-Forwarded-For
    if not ip:
        ip = request.headers.get('X-Forwarded-For')
        if ip:
            ip = ip.split(',')[0].strip()
            
    # Priority 3: Direct connection
    if not ip:
        ip = request.remote_addr
        
    return ip or '0.0.0.0'

def get_ip_info(ip):
    """
    Fetches ASN and Location info from ip-api.com.
    Uses LRU cache with size limit to prevent memory leaks.
    """
    # 0. Check Cache
    if ip in IP_CACHE:
        # Move to end (mark as recently used)
        IP_CACHE.move_to_end(ip)
        return IP_CACHE[ip]
        
    # 1. Skip Local/Private IPs (Basic Check)
    if ip == '127.0.0.1' or ip.startswith('192.168.') or ip.startswith('10.'):
        return 'Local / Private'
        
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=3)
        if response.status_code == 200:
            data = response.json()
            info = f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}"
            IP_CACHE[ip] = info
            if len(IP_CACHE) > IP_CACHE_MAX_SIZE:
                IP_CACHE.popitem(last=False)
            return info
    except Exception as e:
        logging.getLogger().debug(f"Failed to fetch IP info for {ip}: {e}")
    
    return 'Unknown'

# --- Date/Time Helpers ---
def unix_to_utc8(unix_timestamp):
    if not unix_timestamp:
        return 'Unknown Time'
    try:
        ts = int(unix_timestamp)
    except (ValueError, TypeError):
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

def hashed_url_for(endpoint, **values):
    """
    Generates a URL with a 'v' query parameter containing the file's modification timestamp.
    Used for cache busting static assets.
    """
    from flask import url_for, current_app
    import os

    if endpoint == 'static' and 'filename' in values:
        filename = values['filename']
        file_path = os.path.join(current_app.static_folder, filename)
        
        if os.path.exists(file_path):
            values['v'] = int(os.path.getmtime(file_path))

    return url_for(endpoint, **values)

def sanitize_filename(filename):
    """
    Sanitize filename to be safe for filesystem.
    Removes invalid characters.
    """
    import re
    # Remove potentially dangerous characters
    s = str(filename).strip().replace(' ', '_')
    # Keep only alphanumeric, hyphens, underscores, dots, and Chinese characters
    # But for broad compatibility, just remove explicitly bad chars is safer
    s = re.sub(r'(?u)[^-\w.\u4e00-\u9fa5]', '', s)
    if not s:
        s = 'untitled'
    
    # Truncate to reasonable length (e.g. 100 chars) to prevent filesystem errors
    # NTFS/Ext4 usually limit to 255 bytes, but we need space for suffix and ID
    if len(s) > 100:
        s = s[:100]
        
    return s

def generate_pdf_filename(thread_id, remark=None):
    """
    Generate PDF filename: 'remark (thread_id).pdf' or 'thread_thread_id.pdf'
    """
    if remark and remark.strip():
        safe_remark = sanitize_filename(remark.strip())
        return f"{safe_remark}_({thread_id}).pdf"
    return f"thread_{thread_id}.pdf"

def encode_filename_header(filename):
    """
    Generate RFC 5987 compliant Content-Disposition header for non-ASCII filenames.
    browsers support: filename*=UTF-8''encoded_value
    """
    from urllib.parse import quote
    encoded_filename = quote(filename)
    return f"attachment; filename*=UTF-8''{encoded_filename}"
