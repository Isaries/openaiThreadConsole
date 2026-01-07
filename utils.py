import bleach
from datetime import datetime, timezone, timedelta
from markupsafe import escape, Markup

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
