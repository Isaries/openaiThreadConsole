from flask import Blueprint, request, session, redirect, url_for, flash, current_app, render_template, Response, jsonify
from app.models import Project
import database
import security
from app.services import pdf_service
from .. import logic as legacy_services
import requests
import io
import math
import zipfile

from ..extensions import limiter

files_bp = Blueprint('files', __name__)

def get_pdf_limit():
    """
    Dynamic Rate Limit Policy
    - Admin: 200/hour
    - User (Teacher): 100/hour
    - Guest: 3/hour
    """
    if session.get('role') == 'admin':
        return "200 per hour"
    if session.get('user_id'):
        return "100 per hour"
    return "3 per hour"

@files_bp.route('/print-view', methods=['POST'])
def print_view():
    thread_ids = request.form.getlist('thread_ids')
    if thread_ids and len(thread_ids) == 1:
        return redirect(url_for('files.download_pdf', thread_id=thread_ids[0]))
    
    return "Batch print deprecated. Please download threads individually.", 400

@files_bp.route('/download/pdf/<thread_id>')
@limiter.limit(get_pdf_limit)
def download_pdf(thread_id):
    # 1. Fetch Group Context
    groups = database.load_groups()
    
    found_group = None
    for g in groups:
        if any(t.get('thread_id') == thread_id for t in g.get('threads', [])):
            found_group = g
            break
            
    if not found_group:
        return "Thread not found or not assigned to any project", 404

    # --- Security Check: if group is hidden, verify session ---
    if not found_group.get('is_visible', True):
        user_id = session.get('user_id')
        role = session.get('role')
        if not user_id:
            return redirect(url_for('auth.login'))
        if role != 'admin' and user_id not in found_group.get('owners', []):
            return "Permission Denied: This Project is private.", 403
            
    api_key_enc = found_group.get('api_key')
    
    # 2. Process Thread
    thread_data = legacy_services.process_thread({'thread_id': thread_id}, None, None, None, api_key_enc, found_group['group_id'])
    
    if not thread_data or not thread_data.get('data'):
        return "Thread not found or empty", 404
        
    messages = thread_data['data']['messages']
    
    # 3. Split Logic
    CHUNK_SIZE = 50
    total_messages = len(messages)
    
    # helper for header retrieval
    def get_headers_callback(key):
        return legacy_services.get_headers(key)

    if total_messages <= CHUNK_SIZE:
        html = render_template('print_view.html', threads=[thread_data['data']])
        html, temp_files = pdf_service.preprocess_html_for_pdf(html, found_group['group_id'], get_headers_callback)
        try:
            pdf_bytes = pdf_service.generate_pdf_bytes(html)
            return Response(pdf_bytes, mimetype='application/pdf', headers={
                'Content-Disposition': f'attachment; filename="thread_{thread_id}.pdf"'
            })
        finally:
            pdf_service.cleanup_temp_images(temp_files)
    else:
        # Split into ZIP
        chunks = math.ceil(total_messages / CHUNK_SIZE)
        zip_buffer = io.BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            for i in range(chunks):
                start = i * CHUNK_SIZE
                end = start + CHUNK_SIZE
                chunk_msgs = messages[start:end]
                
                chunk_data = thread_data['data'].copy()
                chunk_data['messages'] = chunk_msgs
                
                html = render_template('print_view.html', threads=[chunk_data])
                html, temp_files = pdf_service.preprocess_html_for_pdf(html, found_group['group_id'], get_headers_callback)
                
                try:
                    pdf_bytes = pdf_service.generate_pdf_bytes(html)
                    zf.writestr(f"thread_{thread_id}_part_{i+1}.pdf", pdf_bytes)
                finally:
                    pdf_service.cleanup_temp_images(temp_files)
                
        zip_buffer.seek(0)
        return Response(zip_buffer.getvalue(), mimetype='application/zip', headers={
            'Content-Disposition': f'attachment; filename="thread_{thread_id}_split.zip"'
        })

@files_bp.route('/file/<file_id>')
def proxy_file(file_id):
    # Security: Validate file_id format (OpenAI files usually start with file-)
    import re
    if not re.match(r'^file-[A-Za-z0-9]+$', file_id):
        return "Invalid File ID format", 400
        
    group_id = request.args.get('group_id')
    if not group_id: return "Missing group_id", 400
    
    groups = database.load_groups()
    group = next((g for g in groups if g['group_id'] == group_id), None)
    if not group: return "Group not found", 404
    
    if not group.get('is_visible', True):
        user_id = session.get('user_id')
        role = session.get('role')
        if not user_id: return "Unauthorized", 401
        if role != 'admin' and user_id not in group.get('owners', []):
            return "Permission Denied", 403
            
    api_key_enc = group.get('api_key')
    headers = legacy_services.get_headers(api_key_enc)
    
    try:
        url = f"https://api.openai.com/v1/files/{file_id}/content"
        resp = requests.get(url, headers=headers, stream=True, timeout=30)
        
        if resp.status_code != 200:
            return f"OpenAI Error: {resp.status_code}", 502
            
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in resp.raw.headers.items()
                   if name.lower() not in excluded_headers]
                   
        return Response(resp.content, resp.status_code, headers)
    except requests.exceptions.Timeout:
        return "OpenAI Request Timeout", 504
    except Exception as e:
        current_app.logger.error(f"Proxy Error for {file_id}: {e}")
        return "Internal Proxy Error", 500
