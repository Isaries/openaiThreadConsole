import bleach
from datetime import datetime, timezone, timedelta
from markupsafe import escape, Markup

# --- Template Filters ---
def nl2br(value):
    if not value: return ""
    # Escape first, then replace newline with <br>
    return Markup(str(escape(value)).replace('\n', '<br>'))

def sanitize_html(value):
    if not value: return ""
    allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'a', 'p', 'br', 'span', 'div', 'mark', 'code', 'pre', 'ul', 'li', 'ol']
    allowed_attrs = {
        '*': ['class', 'style'],
        'a': ['href', 'target', 'rel']
    }
    cleaned = bleach.clean(value, tags=allowed_tags, attributes=allowed_attrs, strip=True)
    return Markup(cleaned)

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
