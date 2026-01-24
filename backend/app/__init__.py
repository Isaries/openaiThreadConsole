from flask import Flask
from .extensions import db, limiter, csrf
from .routes.auth import auth_bp
from .routes.main import main_bp
from .routes.admin import admin_bp
from .routes.api import api_bp
from .routes.files import files_bp
from flask_talisman import Talisman
import config
import logging
from logging.handlers import RotatingFileHandler
from flask import request, has_request_context

import os

def create_app():
    # Dynamic Path Resolution
    base_dir = os.path.abspath(os.path.dirname(__file__))
    
    # Check for Docker path first (../templates), then Local path (../../frontend/templates)
    template_dir = os.path.join(base_dir, '../templates')
    static_dir = os.path.join(base_dir, '../static')
    
    if not os.path.exists(template_dir):
        # Fallback to local development structure
        template_dir = os.path.join(base_dir, '../../frontend/templates')
        static_dir = os.path.join(base_dir, '../../frontend/static')

    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
    app.config.from_object(config)
    
    # Initialize Extensions
    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    
    # Auto-create tables
    with app.app_context():
        db.create_all()
        
        # Security: Ensure Admin Exists (No Backdoor)
        from . import commands
        commands.ensure_admin_exists()
    
    # Security Headers
    # We disable Talisman's CSP to manually handle Nonce generation
    # because the installed version lacks 'nonce_in' support and function-based policy support.
    Talisman(app, content_security_policy=False, force_https=False)
    
    # CSP Nonce & Header Logic
    import base64
    def get_csp_nonce():
        if not getattr(request, 'csp_nonce', None):
            request.csp_nonce = base64.b64encode(os.urandom(16)).decode()
        return request.csp_nonce

    app.jinja_env.globals['csp_nonce'] = get_csp_nonce

    @app.after_request
    def set_csp_header(response):
        if not response.headers.get('Content-Security-Policy'):
            nonce = get_csp_nonce()
            policy = (
                f"default-src 'self'; "
                f"script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
                f"style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com https://cdn.jsdelivr.net; "
                f"font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
                f"img-src *; "
                f"connect-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net"
            )
            response.headers['Content-Security-Policy'] = policy
        return response
    
    # Register Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(files_bp)
    
    # Logging
    setup_logging(app)
    
    # Proxy Fix
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
    
    # Filters
    register_filters(app)
    
    # Global IP Ban Check
    @app.before_request
    def check_ip_ban():
        from . import utils
        import security
        from flask import render_template
        
        # Helper to check if IP is banned
        ip = utils.get_client_ip()
        is_banned, reason, remaining = security.check_ban(ip)
        
        if is_banned:
            # Allow static resources to render the ban page correctly
            if request.endpoint and 'static' in request.endpoint:
                return None
                
            remaining_str = "永久" if remaining == -1 else f"{int(remaining)} 秒"
            return render_template('login.html', error=f"您的 IP ({ip}) 已被封鎖。原因: {reason}。剩餘時間: {remaining_str}"), 403

    return app

def setup_logging(app):
    log_handler = RotatingFileHandler('access.log', maxBytes=1000000, backupCount=5)
    class RequestFormatter(logging.Formatter):
        def format(self, record):
            if has_request_context():
                ip = request.headers.get('X-Real-Ip') or request.headers.get('X-Forwarded-For') or request.remote_addr
                if ip and ',' in ip: ip = ip.split(',')[0].strip()
                record.remote_addr = ip or '-'
            else:
                record.remote_addr = '-'
            return super().format(record)
            
    log_handler.setFormatter(RequestFormatter('[%(asctime)s] %(levelname)s [%(remote_addr)s] %(message)s'))
    app.logger.addHandler(log_handler)
    app.logger.setLevel(logging.INFO)

def register_filters(app):
    from . import utils
    app.jinja_env.filters['nl2br'] = utils.nl2br
    app.jinja_env.filters['render_markdown'] = utils.render_markdown
    app.jinja_env.filters['sanitize_html'] = utils.sanitize_html
    app.jinja_env.filters['format_timestamp'] = utils.unix_to_utc8
    app.jinja_env.filters['mask_credential'] = utils.mask_credential
