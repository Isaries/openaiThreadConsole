import bleach
from datetime import datetime, timezone, timedelta
from datetime import datetime, timezone, timedelta
from markupsafe import escape, Markup
import requests

# In-Memory Cache for IP Info
IP_CACHE = {}

def log_access(user, action):
    from flask import current_app
    current_app.logger.info(f"User: {user} | Action: {action}")

# --- Template Filters ---
def nl2br(value):
    if not value: return ""
    # Escape first, then replace newline with <br>
    return Markup(str(escape(value)).replace('\n', '<br>'))

def render_markdown_images(value):
    if not value: return ""
    # Replace ![alt](url) with <img src="url" alt="alt" class="chat-image">
    # Note: Regex allows for optional text in [] and non-empty url in ()
    import re
    pattern = re.compile(r'!\[(.*?)\]\((.*?)\)')
    
    def replace_func(match):
        alt = match.group(1)
        src = match.group(2)
        return f'<img src="{src}" alt="{alt}" class="chat-image" loading="lazy">'
    
    return pattern.sub(replace_func, value)

def sanitize_html(value):
    if not value: return ""
    allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'a', 'p', 'br', 'span', 'div', 'mark', 'code', 'pre', 'ul', 'li', 'ol', 'img']
    allowed_attrs = {
        '*': ['class', 'style'],
        'a': ['href', 'target', 'rel'],
        'img': ['src', 'alt', 'class', 'loading']
    }
    from bleach.css_sanitizer import CSSSanitizer
    css_sanitizer = CSSSanitizer(allowed_css_properties=['text-align', 'color', 'background-color'])
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
    Uses simple in-memory caching.
    """
    # 0. Check Cache
    if ip in IP_CACHE:
        return IP_CACHE[ip]
        
    # 1. Skip Local/Private IPs (Basic Check)
    if ip == '127.0.0.1' or ip.startswith('192.168.') or ip.startswith('10.'):
        return {'desc': 'Local / Private'}
        
    try:
        # 2. Request API
        # ip-api.com/json/{ip}?fields=status,message,country,city,isp,as
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,as,org", timeout=2)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('status') == 'success':
                # Format: "🇹🇼 Taipei, Chunghwa Telecom"
                # Add flag emoji logic if desired, or just text
                
                # Simple Flag Mapper (Partial)
                country = data.get('country', '')
                city = data.get('city', '')
                isp = data.get('isp', '')
                
                info = {
                    'country': country,
                    'city': city,
                    'isp': isp,
                    'desc': f"{country} {city}, {isp}"
                }
                
                # Cache it (Permanent for runtime)
                IP_CACHE[ip] = info
                return info
    except Exception as e:
        print(f"IP Lookup Failed for {ip}: {e}")
        
    return {'desc': 'Unknown'}

# --- Date/Time Helpers ---
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
