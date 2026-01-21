from flask import Blueprint
import json

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.app_template_filter('pretty_json')
def pretty_json(value):
    return json.dumps(value, indent=2, ensure_ascii=False)

# Import Routes
# These modules will import admin_bp from here
from . import dashboard, users, projects, threads, security, system
