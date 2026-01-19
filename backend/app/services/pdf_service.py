import os
import io
import requests
import hashlib
import logging
from flask import current_app
from bs4 import BeautifulSoup
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def _get_retry_session():
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    return session

# --- Configuration ---
TEMP_PDF_IMG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'temp_pdf_images')
if not os.path.exists(TEMP_PDF_IMG_DIR):
    os.makedirs(TEMP_PDF_IMG_DIR)

# --- WeasyPrint Helper ---
def safe_url_fetcher(url, timeout=50):
    if url.startswith('file://'):
        try:
            from urllib.parse import unquote
            # Remove file:// scheme
            if os.name == 'nt':
                 # Windows: file:///C:/path -> C:/path
                 path = unquote(url.replace('file:///', ''))
            else:
                 # Linux/Unix: file:///path -> /path
                 path = unquote(url.replace('file://', ''))
            
            # Path Security Check
            abs_path = os.path.abspath(path)
            # Ensure TEMP_PDF_IMG_DIR is absolute
            allowed_dir = os.path.abspath(TEMP_PDF_IMG_DIR)
            
            if not abs_path.startswith(allowed_dir):
                current_app.logger.warning(f"Security Alert: Blocked file access to {abs_path}")
                raise PermissionError("Access to this file is forbidden.")

            if not os.path.exists(abs_path):
                 raise FileNotFoundError(f"File not found: {abs_path}")

            with open(abs_path, 'rb') as f:
                content = f.read()
            
            import mimetypes
            mime_type, _ = mimetypes.guess_type(path)
            
            return {
                'file_obj': io.BytesIO(content),
                'mime_type': mime_type or 'application/octet-stream',
                'encoding': None,
                'redirected_url': url
            }
        except Exception as e:
            current_app.logger.warning(f"WeasyPrint File Fetch Failed for {url}: {e}")
            raise e

    try:
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        retry_strategy = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session = requests.Session()
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        # Mimic browser to avoid blocking
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        resp = session.get(url, timeout=timeout, stream=True, headers=headers)
        resp.raise_for_status()
        return {'file_obj': io.BytesIO(resp.content), 'mime_type': resp.headers.get('Content-Type'), 'encoding': resp.encoding, 'redirected_url': resp.url}
    except Exception as e:
        current_app.logger.warning(f"WeasyPrint URL Fetch Failed for {url}: {e}")
        raise e 

def generate_pdf_bytes(html_content):
    """
    Generates PDF from HTML and returns bytes.
    Handles Gtk import error gracefully.
    """
    try:
        from weasyprint import HTML
        # Use safe_url_fetcher
        pdf = HTML(string=html_content, url_fetcher=safe_url_fetcher).write_pdf()
        return pdf
    except ImportError:
        current_app.logger.error("WeasyPrint not installed or GTK missing.")
        return b"Error: PDF Generation is not available on this server."
    except Exception as e:
        import traceback
        current_app.logger.error(f"PDF Generation Failed: {e}\n{traceback.format_exc()}")
        return b"Error: PDF Generation Failed"

def get_real_mime_type(data, default='image/png'):
    """Detect MIME type from magic numbers"""
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'image/png'
    elif data.startswith(b'\xff\xd8'):
        return 'image/jpeg'
    elif data.startswith(b'GIF8'):
        return 'image/gif'
    elif data.startswith(b'RIFF') and b'WEBP' in data[:20]:
        return 'image/webp'
    return default

def save_image_locally(url, content, mime_type):
    """Save raw image bytes to temp file and return absolute file:/// path"""
    try:
        # Determine extension
        ext = 'png'
        if 'jpeg' in mime_type or 'jpg' in mime_type: ext = 'jpg'
        elif 'gif' in mime_type: ext = 'gif'
        elif 'webp' in mime_type: ext = 'webp'
        
        # Unique filename from hash or UUID
        file_hash = hashlib.md5(url.encode('utf-8')).hexdigest()
        filename = f"{file_hash}.{ext}"
        filepath = os.path.join(TEMP_PDF_IMG_DIR, filename)
        
        # Write file
        with open(filepath, 'wb') as f:
            f.write(content)
            
        from pathlib import Path
        return Path(filepath).as_uri()
    except Exception as e:
        current_app.logger.warning(f"Failed to save temp image: {e}")
        return None

def fetch_image_local_path(src, headers=None):
    """
    Helper for parallel fetching.
    Downloads image and returns local file:/// URI.
    """
    try:
        url = src
        request_headers = {}
        
        # Scenario 1: OpenAI File Proxy
        if '/file/' in src:
            try:
                path_part = src.split('?')[0] 
                file_id = path_part.split('/')[-1]
                if file_id.startswith('file-'):
                    url = f"https://api.openai.com/v1/files/{file_id}/content"
                    request_headers = headers # Auth headers passed from caller
            except:
                pass # Fallback to original src if parsing fails
        
        # Scenario 2: External URL (Assistant Images)
        elif src.lower().startswith('http'):
            # Mimic Browser but ENFORCE standard formats to avoid WebP which WeasyPrint might not support on Windows
            request_headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'image/png, image/jpeg, image/gif, image/svg+xml;q=0.9, */*;q=0.8'
            }
            
        if not url: return src, None

        # Perform Fetch using Retry Session
        session = _get_retry_session()
        resp = session.get(url, headers=request_headers, timeout=50)
        
        if resp.status_code == 200:
            content_type = resp.headers.get('Content-Type', 'image/png')
            
            # OpenAI often returns application/octet-stream, which breaks Data URIs.
            # We MUST sniff the content to be sure.
            real_mime = get_real_mime_type(resp.content, content_type)
            if real_mime != content_type:
                 content_type = real_mime

            # Log unexpected content types
            if 'webp' in content_type.lower():
                current_app.logger.warning(f"Warning: Server returned WebP for {src} despite Accept headers. WeasyPrint may fail.")

            # Save Locally
            local_uri = save_image_locally(url, resp.content, content_type)
            if local_uri:
                 # current_app.logger.info(f"Saved PDF Image: {local_uri}")
                 return src, local_uri
            
            return src, None
        else:
             current_app.logger.warning(f"Fetch Error {resp.status_code} for {url}")
             
    except Exception as e:
        current_app.logger.warning(f"Failed to fetch image {src}: {str(e)}")
    
    return src, None

def preprocess_html_for_pdf(html_content, group_id, get_headers_func):
    """
    Parses HTML, finds <img> pointing to /file/..., fetches them using group_id context in PARALLEL,
    and replaces src with base64 data URI.
    
    get_headers_func: callback (api_key) -> headers
    """
    current_app.logger.info(f"Preprocessing PDF HTML for group_id: {group_id}")
    
    soup = BeautifulSoup(html_content, 'html.parser')
    images = soup.find_all('img')
    
    # Target ALL images for parallel pre-fetching 
    target_images = [img for img in images if img.get('src')]
    
    if not target_images:
        return html_content, []

    from app.models import Project
    import security
    
    # We need to fetch the key to pass headers
    # Ideally this should be passed in, but logic in legacy was mixed.
    # Refactor: Controller should pass the headers or api_key.
    # For now, let's fetch group again or use what we can.
    # Actually, legacy code: groups = load_groups()... api_key_enc = group.get('api_key')
    # So we need the key.
    
    project = Project.query.get(group_id)
    openai_headers = {}
    if project and project.api_key:
        api_key_enc = project.api_key
        openai_headers = get_headers_func(api_key_enc)
    
    changed = False
    
    # max_workers=20 to handle mixed external/internal requests
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_src = {
            executor.submit(fetch_image_local_path, img.get('src'), openai_headers): img.get('src') 
            for img in target_images
        }
        
        # Results map: src -> new_src
        results = {}
        for future in concurrent.futures.as_completed(future_to_src):
            src, new_blob = future.result()
            if new_blob:
                results[src] = new_blob

    # Apply updates
    created_files = []
    for img in target_images:
        src = img.get('src')
        # Remove loading="lazy" as it confuses WeasyPrint
        if img.has_attr('loading'):
            del img['loading']
            
        if src in results:
            new_src = results[src]
            img['src'] = new_src
            changed = True
            created_files.append(new_src)
            
    return (str(soup) if changed else html_content), created_files

def cleanup_temp_images(file_paths):
    """Delete temporary image files."""
    if not file_paths: return
    for path_uri in file_paths:
        try:
            # Convert file URI to path
            if path_uri.startswith('file:///'):
                 from urllib.parse import unquote
                 if os.name == 'nt':
                     path = unquote(path_uri.replace('file:///', ''))
                 else:
                     path = unquote(path_uri.replace('file://', ''))
            else:
                path = path_uri
                
            if os.path.exists(path):
                os.remove(path)
        except Exception as e:
            current_app.logger.warning(f"Failed to cleanup temp file {path_uri}: {e}")
