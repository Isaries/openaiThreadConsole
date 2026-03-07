"""
Integration tests for API routes — /api/search endpoint.
Tests API key validation via security.hash_api_key (uses cryptography).
"""
import pytest


class TestSearchAPI:

    def test_missing_auth_header(self, client):
        resp = client.post('/api/search', json={'query': 'test'})
        assert resp.status_code == 401
        assert 'Authorization' in resp.json.get('error', '')

    def test_invalid_api_key(self, client):
        resp = client.post(
            '/api/search',
            json={'query': 'test'},
            headers={'Authorization': 'Bearer sk-invalid-key-12345'},
        )
        assert resp.status_code == 403
        assert 'Invalid' in resp.json.get('error', '')

    def test_valid_api_key(self, app, db, client):
        """Test that a properly hashed API key authenticates."""
        with app.app_context():
            import security
            from app.models import Project

            raw_key = 'sk-test-api-key-for-project'
            hashed = security.hash_api_key(raw_key)

            project = Project(
                id='api-proj',
                name='API Test Project',
                api_key_hash=hashed,
                is_visible=True,
                version=1,
            )
            db.session.add(project)
            db.session.commit()

        resp = client.post(
            '/api/search',
            json={'query': 'hello'},
            headers={'Authorization': f'Bearer {raw_key}'},
        )
        assert resp.status_code == 200
        data = resp.json
        assert data['status'] == 'success'
        assert data['project'] == 'API Test Project'

    def test_missing_query(self, app, db, client):
        """Valid key but missing query param."""
        with app.app_context():
            import security
            from app.models import Project

            raw_key = 'sk-another-key'
            hashed = security.hash_api_key(raw_key)

            project = Project(
                id='api-proj2',
                name='API Project 2',
                api_key_hash=hashed,
                is_visible=True,
                version=1,
            )
            db.session.add(project)
            db.session.commit()

        resp = client.post(
            '/api/search',
            json={},
            headers={'Authorization': f'Bearer {raw_key}'},
        )
        assert resp.status_code == 400

    def test_bearer_prefix_stripped(self, app, db, client):
        """Authorization header with 'Bearer ' prefix should work."""
        with app.app_context():
            import security
            from app.models import Project

            raw_key = 'sk-bearer-test-key'
            hashed = security.hash_api_key(raw_key)

            project = Project(
                id='api-proj3',
                name='Bearer Project',
                api_key_hash=hashed,
                is_visible=True,
                version=1,
            )
            db.session.add(project)
            db.session.commit()

        resp = client.post(
            '/api/search',
            json={'query': 'test'},
            headers={'Authorization': f'Bearer {raw_key}'},
        )
        assert resp.status_code == 200
