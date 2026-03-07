"""
Shared test fixtures for the entire test suite.
Provides a Flask test app with in-memory SQLite, test client, and auth helpers.
"""
import os
import sys
import pytest

# Ensure backend/ is on sys.path so `import config`, `import security`, `import database` work
BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

# Set required env vars BEFORE importing anything that reads config
os.environ.setdefault('ADMIN_PASSWORD', 'TestPass123')
os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-unit-tests')


def _resolve_template_dir():
    """Find template dir regardless of where tests are run from.
    Checks for login.html to verify the dir has actual templates."""
    base = BACKEND_DIR
    # Local dev layout: frontend/templates (sibling to backend) — check first
    t = os.path.join(base, '..', 'frontend', 'templates')
    if os.path.isdir(t) and os.path.isfile(os.path.join(t, 'login.html')):
        return os.path.abspath(t)
    # Docker layout: backend/templates
    t = os.path.join(base, 'templates')
    if os.path.isdir(t) and os.path.isfile(os.path.join(t, 'login.html')):
        return os.path.abspath(t)
    # Fallback to whatever exists
    for candidate in [os.path.join(base, '..', 'frontend', 'templates'),
                      os.path.join(base, 'templates')]:
        if os.path.isdir(candidate):
            return os.path.abspath(candidate)
    return None


def _resolve_static_dir():
    base = BACKEND_DIR
    # Local dev layout first
    s = os.path.join(base, '..', 'frontend', 'static')
    if os.path.isdir(s):
        return os.path.abspath(s)
    s = os.path.join(base, 'static')
    if os.path.isdir(s):
        return os.path.abspath(s)
    return None


@pytest.fixture(scope='session')
def app():
    """Create a Flask application for the full test session."""
    from flask import Flask
    from app.extensions import db as _db, limiter, csrf
    from app.routes.auth import auth_bp
    from app.routes.main import main_bp
    from app.routes.admin import admin_bp
    from app.routes.api import api_bp
    from app.routes.files import files_bp

    template_dir = _resolve_template_dir()
    static_dir = _resolve_static_dir()

    test_app = Flask(
        'app',
        template_folder=template_dir,
        static_folder=static_dir,
        root_path=BACKEND_DIR,
    )
    test_app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'WTF_CSRF_ENABLED': False,
        'SECRET_KEY': 'test-secret-key-for-unit-tests',
        'PERMANENT_SESSION_LIFETIME': 3600,
        'MAX_CONTENT_LENGTH': 2 * 1024 * 1024,
    })

    # Initialize Extensions
    _db.init_app(test_app)
    csrf.init_app(test_app)
    limiter.init_app(test_app)

    # Register Blueprints
    test_app.register_blueprint(auth_bp)
    test_app.register_blueprint(main_bp)
    test_app.register_blueprint(admin_bp)
    test_app.register_blueprint(api_bp)
    test_app.register_blueprint(files_bp)

    # Register filters (needed for template rendering)
    from app import register_filters
    register_filters(test_app)

    # Register CSP nonce global (needed by templates)
    import base64
    from flask import request as flask_request, has_request_context
    def get_csp_nonce():
        if not has_request_context():
            return ''
        if not getattr(flask_request, 'csp_nonce', None):
            flask_request.csp_nonce = base64.b64encode(os.urandom(16)).decode()
        return flask_request.csp_nonce

    test_app.jinja_env.globals['csp_nonce'] = get_csp_nonce

    with test_app.app_context():
        _db.create_all()

    yield test_app


@pytest.fixture(scope='function')
def db(app):
    """Provide a clean database for each test function."""
    from app.extensions import db as _db

    with app.app_context():
        _db.create_all()
        yield _db
        _db.session.rollback()
        _db.drop_all()


@pytest.fixture(scope='function')
def client(app, db):
    """Flask test client."""
    with app.test_client() as c:
        with app.app_context():
            yield c


@pytest.fixture(scope='function')
def admin_client(app, db):
    """Flask test client with admin session."""
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess['user_id'] = 'admin'
            sess['username'] = 'Administrator'
            sess['role'] = 'admin'
        with app.app_context():
            yield c


@pytest.fixture(scope='function')
def user_client(app, db):
    """Flask test client with regular user session."""
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess['user_id'] = 'user-1'
            sess['username'] = 'TestUser'
            sess['role'] = 'user'
        with app.app_context():
            yield c


@pytest.fixture
def sample_user(app, db):
    """Create a sample non-admin user in DB."""
    from app.models import User
    from werkzeug.security import generate_password_hash

    user = User(
        id='user-1',
        username='TestUser',
        email='test@example.com',
        password_hash=generate_password_hash('ValidPass123'),
        is_admin=False,
    )
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def sample_admin(app, db):
    """Create the admin user in DB."""
    from app.models import User
    from werkzeug.security import generate_password_hash

    user = User(
        id='admin',
        username='Administrator',
        password_hash=generate_password_hash('TestPass123'),
        is_admin=True,
    )
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def sample_project(app, db):
    """Create a sample project."""
    from app.models import Project

    project = Project(
        id='proj-001',
        name='Test Project',
        api_key='enc-fake-key',
        is_visible=True,
        version=1,
    )
    db.session.add(project)
    db.session.commit()
    return project


@pytest.fixture
def sample_thread(app, db, sample_project):
    """Create a sample thread in the sample project."""
    from app.models import Thread

    thread = Thread(
        thread_id='thread_abc123',
        project_id=sample_project.id,
        remark='Test Thread',
    )
    db.session.add(thread)
    db.session.commit()
    return thread
