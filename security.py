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
    
    return key_string

# --- Password Validation ---
def validate_password_strength(password):
    if len(password) < 10 or len(password) > 20:
        return False, "密碼長度需為 10-20 字元"
    
    has_alpha = any(c.isalpha() for c in password)
    has_num = any(c.isdigit() for c in password)
    
    if not (has_alpha and has_num):
        return False, "密碼需包含英文字母與數字"
        
    return True, ""

def generate_password_hint(password):
    if not password: return ""
    if len(password) <= 4: return "*" * len(password)
    return f"{password[:2]}***{password[-2:]}"

# --- Security Policies (Lockout) ---
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
