import hashlib
import base64
import time
from cryptography.fernet import Fernet
import config

# --- Encryption Helper ---
def get_encryption_key():
    secret = config.SECRET_KEY.encode()
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
        # We can't log using app.logger easily here without circular import or passing logger.
        # For now, we suppress error or could print. 
        # In original code it used app.logger.debug.
        # We will return None which indicates failure.
        return None

def get_decrypted_key(key_string):
    """
    Attempts to decrypt the key. 
    If successful, returns decrypted key.
    If fails (e.g. not encrypted or invalid), returns the original string.
    """
    if not key_string: return None
    
    decrypted = decrypt_data(key_string)
    if decrypted: return decrypted
    
    # If decryption fails and it looks like a Fernet token, it's invalid
    if key_string.startswith("gAAAA"):
        return "INVALID_KEY_RESET_REQUIRED"
        
    # Otherwise assume it was plaintext (legacy support)
    return key_string

import hmac

def hash_api_key(api_key):
    """
    Returns HMAC-SHA256 hash of the API Key using the application SECRET_KEY.
    Salted (Keyed) with SECRET_KEY.
    """
    if not api_key: return None
    secret = config.SECRET_KEY.encode()
    return hmac.new(secret, api_key.strip().encode(), hashlib.sha256).hexdigest()

# --- Password Validation ---
def validate_password_strength(password):
    if len(password) < 10 or len(password) > 20:
        return False, "密碼長度需為 10-20 字元"
    
    has_alpha = any(c.isalpha() for c in password)
    has_num = any(c.isdigit() for c in password)
    
    if not (has_alpha and has_num):
        return False, "密碼需包含英文字母與數字"
        
    return True, ""

from werkzeug.security import check_password_hash

def check_password(p_hash, password):
    return check_password_hash(p_hash, password)

def generate_password_hint(password):
    if not password: return ""
    if len(password) <= 2: return "*" * len(password)
    return f"{password[0]}{'*' * 8}{password[-1]}"

# --- Security Policies (Lockout) ---
# LOGIN_ATTEMPTS = {} # Moved to Database
LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION = 15 * 60 # 15 minutes

def check_lockout(ip):
    try:
        from app.models import LoginAttempt
        attempt = LoginAttempt.query.get(ip)
        
        if not attempt:
            return False, 0
            
        if attempt.count >= LOCKOUT_THRESHOLD:
            remaining = attempt.lockout_until - time.time()
            if remaining > 0:
                return True, remaining
            else:
                # Expired, reset?
                # We can reset logic here or in record_login_attempt
                pass
                
        return False, 0
    except Exception as e:
        # If DB fails, fail open (allow)? or fail closed?
        # Safe to allow if DB is down? or Error?
        print(f"Lockout Check Failed: {e}")
        return False, 0

def record_login_attempt(ip, success):
    try:
        from app.extensions import db
        from app.models import LoginAttempt
        
        attempt = LoginAttempt.query.get(ip)
        
        if success:
            if attempt:
                db.session.delete(attempt)
                db.session.commit()
            return

        # Failed Login
        current_time = time.time()
        
        if not attempt:
            attempt = LoginAttempt(ip=ip, count=0, lockout_until=0)
            db.session.add(attempt)
        
        # Check if previous lockout expired, reset if so
        if attempt.lockout_until > 0 and attempt.lockout_until < current_time:
             attempt.count = 0
             attempt.lockout_until = 0

        attempt.count += 1
        attempt.last_attempt = current_time
        
        if attempt.count >= LOCKOUT_THRESHOLD:
            # Refresh lockout time only if not already locked? 
            # Or extend? Usually extend or set if not set.
            if attempt.lockout_until <= current_time:
                attempt.lockout_until = current_time + LOCKOUT_DURATION
                
        db.session.commit()
        
    except Exception as e:
        # It's important to not crash app logic if audit fails
        print(f"Record Login Attempt Failed: {e}")
        try:
             db.session.rollback()
        except:
             pass

# --- IP Banning System ---
import database

def check_ban(ip):
    """
    Returns (True, reason, remaining_seconds) if banned.
    Returns (False, "", 0) if allowed.
    """
    # Optimized: Query DB directly? 
    # Or keep using database.load_ip_bans() which queries DB all().
    # For now, keep using database.load_ip_bans() for caching effect compatibility,
    # OR better: use atomic check if we want real-time.
    # Given database.load_ip_bans() now queries all(), safe to use.
    
    bans = database.load_ip_bans()
    if ip not in bans:
        return False, "", 0
        
    ban_info = bans[ip]
    until = ban_info.get('expires_at')
    
    # If until is 0 or -1, it means permanent
    if until <= 0:
        return True, ban_info.get('reason', 'Banned'), -1
        
    now = time.time()
    if now < until:
        return True, ban_info.get('reason', 'Banned'), int(until - now)
    else:
        return False, "", 0

def ban_ip(ip, duration_seconds, reason="Admin Ban"):
    """
    bans ip for duration_seconds. If duration_seconds <= 0, permanent.
    """
    until = 0 # Permanent
    if duration_seconds > 0:
        until = time.time() + duration_seconds
        
    return database.add_ip_ban(ip, reason, until)

def unban_ip(ip):
    return database.remove_ip_ban(ip)
