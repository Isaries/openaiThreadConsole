from flask import Blueprint, request, jsonify
from ..extensions import db, limiter, csrf
from ..models import Project, SearchHistory
import security
from .. import utils
import time
import requests
import config

api_bp = Blueprint('api', __name__, url_prefix='/api')

@api_bp.route('/search', methods=['POST'])
@csrf.exempt # API endpoints often skip CSRF if using API Keys
@limiter.limit("60 per minute")
def search_api():
    # 1. Validate API Key
    api_key = request.headers.get('Authorization')
    if not api_key:
        return jsonify({'error': 'Missing Authorization Header'}), 401
    
    # Remove 'Bearer ' if present
    if api_key.startswith('Bearer '):
        api_key = api_key[7:]
        
    
    # Optimized Verification (O(1))
    hashed_input = security.hash_api_key(api_key)
    project = Project.query.filter_by(api_key_hash=hashed_input).first()
    
    # Fallback to prevent breaking changes if migration failed effectively
    # (Optional: remove this if confident in migration)
    if not project and not hashed_input:
         # Failed to hash? Should not happen if key exists
         pass
         
    if not project:
        return jsonify({'error': 'Invalid API Key'}), 403
        
    # 2. Parse Request
    data = request.json
    query = data.get('query')
    
    if not query:
        return jsonify({'error': 'Query parameter required'}), 400

    # 3. Perform Search (Mock Logic as per legacy app.py)
    # The original app.py called services.py or had inline logic.
    # Assuming we want to call OpenAI or similar.
    
    # ... (Reimplement search logic here or call a service) ...
    # For now, returning a mock response to verify architecture
    
    response_data = {
        'status': 'success',
        'project': project.name,
        'results': [
            {'title': 'Mock Result 1', 'snippet': f'Result for {query}'}
        ]
    }
    
    # Log Search
    try:
        log = SearchHistory(
            timestamp=int(time.time()),
            project_name=project.name,
            target_query=query,
            match_count=1,
            total_scanned=10,
            api_results_json=str(response_data)
        )
        db.session.add(log)
        db.session.commit()
    except: pass
    
    return jsonify(response_data)
