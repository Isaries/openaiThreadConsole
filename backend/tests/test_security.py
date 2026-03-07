"""
Tests for security.py — encryption, hashing, password, lockout, IP banning.
Directly exercises the cryptography.fernet module (PR #3 verification target).
"""
import time
import pytest


class TestEncryption:
    """Tests for Fernet encrypt/decrypt (uses cryptography library)."""

    def test_encrypt_decrypt_roundtrip(self, app):
        """Encrypted text should decrypt back to original."""
        with app.app_context():
            import security
            plaintext = "sk-abc123-my-super-secret-key"
            encrypted = security.encrypt_data(plaintext)
            assert encrypted != plaintext
            assert encrypted != ""
            decrypted = security.decrypt_data(encrypted)
            assert decrypted == plaintext

    def test_encrypt_empty_string(self, app):
        with app.app_context():
            import security
            assert security.encrypt_data("") == ""
            assert security.encrypt_data(None) == ""

    def test_decrypt_empty_string(self, app):
        with app.app_context():
            import security
            assert security.decrypt_data("") == ""
            assert security.decrypt_data(None) == ""

    def test_decrypt_invalid_token(self, app):
        with app.app_context():
            import security
            result = security.decrypt_data("not-a-valid-fernet-token")
            assert result is None

    def test_get_decrypted_key_success(self, app):
        with app.app_context():
            import security
            key = "sk-real-key-value"
            encrypted = security.encrypt_data(key)
            assert security.get_decrypted_key(encrypted) == key

    def test_get_decrypted_key_plaintext_fallback(self, app):
        """Non-fernet strings should be returned as-is (legacy support)."""
        with app.app_context():
            import security
            plain = "sk-plaintext-key"
            assert security.get_decrypted_key(plain) == plain

    def test_get_decrypted_key_invalid_fernet(self, app):
        """Strings starting with gAAAA that fail decryption → INVALID."""
        with app.app_context():
            import security
            result = security.get_decrypted_key("gAAAABogus")
            assert result == "INVALID_KEY_RESET_REQUIRED"

    def test_get_decrypted_key_none(self, app):
        with app.app_context():
            import security
            assert security.get_decrypted_key(None) is None
            assert security.get_decrypted_key("") is None


class TestHashing:
    """Tests for HMAC API key hashing."""

    def test_hash_api_key_consistency(self, app):
        with app.app_context():
            import security
            key = "sk-test-key"
            h1 = security.hash_api_key(key)
            h2 = security.hash_api_key(key)
            assert h1 == h2
            assert len(h1) == 64  # SHA-256 hex

    def test_hash_api_key_different_for_different_keys(self, app):
        with app.app_context():
            import security
            h1 = security.hash_api_key("key-one")
            h2 = security.hash_api_key("key-two")
            assert h1 != h2

    def test_hash_api_key_none(self, app):
        with app.app_context():
            import security
            assert security.hash_api_key(None) is None
            assert security.hash_api_key("") is None


class TestPasswordValidation:
    """Tests for validate_password_strength."""

    def test_valid_password(self, app):
        with app.app_context():
            import security
            ok, msg = security.validate_password_strength("MyPassword1")
            assert ok is True

    def test_too_short(self, app):
        with app.app_context():
            import security
            ok, msg = security.validate_password_strength("Ab1")
            assert ok is False
            assert "10-20" in msg

    def test_too_long(self, app):
        with app.app_context():
            import security
            ok, msg = security.validate_password_strength("a" * 21)
            assert ok is False

    def test_no_digits(self, app):
        with app.app_context():
            import security
            ok, msg = security.validate_password_strength("OnlyLetters")
            assert ok is False

    def test_no_alpha(self, app):
        with app.app_context():
            import security
            ok, msg = security.validate_password_strength("1234567890")
            assert ok is False


class TestCheckPassword:
    """Tests for password hash checking (uses werkzeug.security)."""

    def test_correct_password(self, app):
        from werkzeug.security import generate_password_hash
        with app.app_context():
            import security
            h = generate_password_hash("TestPass123")
            assert security.check_password(h, "TestPass123") is True

    def test_wrong_password(self, app):
        from werkzeug.security import generate_password_hash
        with app.app_context():
            import security
            h = generate_password_hash("TestPass123")
            assert security.check_password(h, "WrongPass") is False


class TestPasswordHint:

    def test_hint_normal(self, app):
        with app.app_context():
            import security
            hint = security.generate_password_hint("MyPassword")
            assert hint == "M********d"

    def test_hint_short(self, app):
        with app.app_context():
            import security
            assert security.generate_password_hint("ab") == "**"

    def test_hint_empty(self, app):
        with app.app_context():
            import security
            assert security.generate_password_hint("") == ""


class TestLockout:
    """Tests for login attempt lockout."""

    def test_no_lockout_initially(self, app, db):
        with app.app_context():
            import security
            locked, remaining = security.check_lockout("192.168.1.100")
            assert locked is False
            assert remaining == 0

    def test_lockout_after_threshold(self, app, db):
        with app.app_context():
            import security
            ip = "10.0.0.99"
            for _ in range(security.LOCKOUT_THRESHOLD):
                security.record_login_attempt(ip, False)
            locked, remaining = security.check_lockout(ip)
            assert locked is True
            assert remaining > 0

    def test_lockout_reset_on_success(self, app, db):
        with app.app_context():
            import security
            ip = "10.0.0.50"
            for _ in range(3):
                security.record_login_attempt(ip, False)
            security.record_login_attempt(ip, True)
            locked, _ = security.check_lockout(ip)
            assert locked is False


class TestIPBan:
    """Tests for IP banning system."""

    def test_ban_and_check(self, app, db):
        with app.app_context():
            import security
            security.ban_ip("1.2.3.4", 3600, "Test ban")
            banned, reason, remaining = security.check_ban("1.2.3.4")
            assert banned is True
            assert "Test ban" in reason
            assert remaining > 0

    def test_permanent_ban(self, app, db):
        with app.app_context():
            import security
            security.ban_ip("5.6.7.8", 0, "Perm ban")
            banned, reason, remaining = security.check_ban("5.6.7.8")
            assert banned is True
            assert remaining == -1

    def test_unban(self, app, db):
        with app.app_context():
            import security
            security.ban_ip("9.9.9.9", 3600, "Temp")
            security.unban_ip("9.9.9.9")
            banned, _, _ = security.check_ban("9.9.9.9")
            assert banned is False

    def test_not_banned(self, app, db):
        with app.app_context():
            import security
            banned, _, _ = security.check_ban("100.100.100.100")
            assert banned is False
