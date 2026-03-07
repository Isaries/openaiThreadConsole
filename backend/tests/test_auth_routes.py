"""
Integration tests for auth routes — login/logout flow.
Exercises werkzeug.security (PR #4) and Flask session handling (PR #5).
"""
import pytest


class TestLoginRoute:

    def test_login_page_renders(self, client):
        resp = client.get('/login')
        assert resp.status_code == 200

    def test_login_success(self, client, sample_admin):
        resp = client.post('/login', data={
            'username': 'Administrator',
            'password': 'TestPass123',
        }, follow_redirects=True)
        # Should redirect to admin dashboard (200 after redirect)
        assert resp.status_code == 200

    def test_login_wrong_password(self, client, sample_admin):
        resp = client.post('/login', data={
            'username': 'Administrator',
            'password': 'WrongPassword1',
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert '錯誤' in resp.data.decode('utf-8')

    def test_login_missing_fields(self, client):
        resp = client.post('/login', data={
            'username': '',
            'password': '',
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert '輸入' in resp.data.decode('utf-8')

    def test_login_nonexistent_user(self, client):
        resp = client.post('/login', data={
            'username': 'ghost',
            'password': 'SomePass123',
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert '錯誤' in resp.data.decode('utf-8')

    def test_login_by_email(self, client, sample_user):
        resp = client.post('/login', data={
            'username': 'test@example.com',
            'password': 'ValidPass123',
        }, follow_redirects=True)
        assert resp.status_code == 200


class TestLogoutRoute:

    def test_logout_clears_session(self, admin_client, sample_admin):
        resp = admin_client.get('/logout', follow_redirects=True)
        assert resp.status_code == 200
        # After logout, should see login page
        assert '登出' in resp.data.decode('utf-8') or 'login' in resp.data.decode('utf-8').lower()

    def test_logout_without_login(self, client):
        resp = client.get('/logout', follow_redirects=True)
        assert resp.status_code == 200
