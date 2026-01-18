
import os
import requests
import re
import logging
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
# Internal
import database
import security
from . import utils
import config
import database # For loading settings in get_headers
from app.extensions import db
from app.models import Thread, Message
import time

def get_headers(custom_key=None):
    # Support Group Key override
    api_key = custom_key
    
    # If no group key provided, try global settings
    if not api_key:
        settings = {}
        # We can use database.load_settings()
        settings = database.load_settings()
        
        api_key_from_settings = settings.get('openai_api_key')
        
        if api_key_from_settings:
            # Try to decrypt
            decrypted = security.decrypt_data(api_key_from_settings)
            if decrypted:
                api_key = decrypted
            else:
                # Fallback check
                if not api_key_from_settings.startswith("sk-"):
                     api_key = None 
    
    if api_key:
        # It might be encrypted even if passed as custom_key? 
        # In app.py logic, custom_key came from database which IS encrypted.
        # Wait, in app.py: get_headers(active_group['api_key'])
        # active_group['api_key'] IS encrypted.
        # So we must decrypt it.
        # security.get_decrypted_key handles decryption.
        api_key = security.get_decrypted_key(api_key)

    # Fallback to ENV
    if not api_key:
        api_key = config.OPENAI_API_KEY

    return {
        "Authorization": f"Bearer {api_key}",
        "OpenAI-Beta": "assistants=v2",
        "Content-Type": "application/json"
    }

def _get_retry_session():
    """Helper to create a Session with automatic retry"""
    session = requests.Session()
    retry = Retry(
        total=3,
        read=3,
        connect=3,
        backoff_factor=1, # 1s, 2s, 4s
        status_forcelist=[500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    return session

def fetch_thread_messages(thread_id, api_key=None):
    if not thread_id: return None
    base_url = config.OPENAI_API_URL.format(thread_id)
    headers = get_headers(api_key)
    
    all_messages = []
    params = {"limit": 100} # Max limit per page to reduce requests
    
    session = _get_retry_session()
    
    try:
        while True:
            # User Requirement: Timeout 50s
            response = session.get(base_url, headers=headers, params=params, timeout=50)
            
            if response.status_code != 200:
                if all_messages: 
                    logging.getLogger().warning(f"Partial fetch for {thread_id}: {response.status_code}")
                    break 
                else: 
                     return None
            
            data = response.json()
            messages = data.get('data', [])
            all_messages.extend(messages)
            
            if data.get('has_more') and messages:
                params['after'] = messages[-1]['id']
            else:
                break
                
        return {'data': all_messages}
    except Exception as e:
        logging.getLogger().error(f"Fetch error {thread_id}: {e}")
        return None

def process_thread(thread_data, target_name, start_date, end_date, api_key=None, group_id=None):
    t_id = thread_data.get('thread_id')
    
    # Default return structure
    result = {
        'thread_id': t_id,
        'keep': False,
        'status': 'Unknown',
        'data': None,
        'messages': []
    }

    api_response = fetch_thread_messages(t_id, api_key)
    if not api_response or 'data' not in api_response:
        result['status'] = 'API Error'
        return result
    
    messages_data = api_response['data']
    if not messages_data:
        result['status'] = 'Empty Messages'
        return result

    processed_messages = []
    has_target = False
    
    for msg in messages_data:
        try:
            role = msg.get('role')
            if not role: continue
            
            created_at = msg.get('created_at')
            try:
                msg_ts = int(created_at)
            except:
                msg_ts = 0
                
            time_str = utils.unix_to_utc8(msg_ts)
            date_str = utils.unix_to_date_str(msg_ts)
            
            content_value = ""
            if msg.get('content'):
                for part in msg['content']:
                    if part.get('type') == 'text':
                         content_value += part.get('text', {}).get('value', '')
                    elif part.get('type') == 'image_file':
                         file_id = part.get('image_file', {}).get('file_id')
                         if file_id:
                             # Use proxy URL with group_id for auth
                             gid_param = f"?group_id={group_id}" if group_id else ""
                             content_value += f"![User Image](/file/{file_id}{gid_param})"
                         else:
                             content_value += "[圖片錯誤]"

            if target_name:
                if target_name.lower() in content_value.lower():
                    has_target = True
                if target_name.lower() in content_value.lower() and target_name != "No choice was made":
                     pattern = re.compile(re.escape(target_name), re.IGNORECASE)
                     # Use lambda to preserve original casing of the matched text
                     content_value = pattern.sub(lambda m: f"<mark>{m.group(0)}</mark>", content_value)

            role_class = 'user' if role == 'user' else 'assistant'
            role_icon = '👤' if role == 'user' else '🤖'
            role_name = '使用者' if role == 'user' else 'AI Agent'
            
            processed_messages.append({
                'time': time_str,
                'timestamp': msg_ts,
                'role': role,
                'role_class': role_class,
                'role_icon': role_icon,
                'role_name': role_name,
                'content': content_value,
                'date_str': date_str
            })
        except: continue

    processed_messages.sort(key=lambda x: x['timestamp'])
    result['messages'] = processed_messages # Store for debug
    
    # Check filters
    keep_thread = False
    status = "Filtered"
    
    thread_remark = thread_data.get('remark', '') or ''
    
    if target_name:
        is_remark_match = target_name.lower() in thread_remark.lower()
        if has_target or (target_name.lower() in t_id.lower()) or is_remark_match: 
            keep_thread = True
            if is_remark_match:
                status = "Matched Remark"
            elif has_target:
                status = "Matched Keyword"
            else:
                status = "Matched ID"
        else:
            status = "No Keyword Match"
    else:
        keep_thread = True
        status = "Matched (No Keyword)"
        
    thread_time = processed_messages[-1]['time'] if processed_messages else 'Unknown'
    thread_timestamp = processed_messages[-1]['timestamp'] if processed_messages else 0
    t_date = processed_messages[-1]['date_str'] if processed_messages else ''
    
    if keep_thread and (start_date or end_date):
        if start_date and end_date:
            if not (start_date <= t_date <= end_date): 
                keep_thread = False
                status = "Filtered Date"
        elif start_date:
            if not (t_date >= start_date): 
                keep_thread = False
                status = "Filtered Date"
        elif end_date:
            if not (t_date <= end_date): 
                keep_thread = False
                status = "Filtered Date"
            
    result['keep'] = keep_thread
    result['status'] = status
    
    # Metadata for Caching
    result['meta'] = {
        'last_updated': int(datetime.now().timestamp()),
        'start_ts': processed_messages[0]['timestamp'] if processed_messages else 0,
        'end_ts': processed_messages[-1]['timestamp'] if processed_messages else 0,
        'msg_count': len(processed_messages)
    }

    if keep_thread:
        result['data'] = {
            'thread_id': t_id,
            'time': thread_time,
            'timestamp': thread_timestamp,
            'messages': processed_messages,
            'raw_messages': messages_data # Debug: Pass raw API response
        }
    
    # Always include raw messages for System Log debugging
    result['raw_messages'] = messages_data
        
    return result

# --- Cache Optimization Logic ---

def sync_thread_to_db(thread_id_str, api_key=None, project_id=None):
    """
    Sets up the DB state for a thread. 
    Can be called by "Refresh" button or scheduled task.
    """
    try:
        # 1. Fetch from API
        api_response = fetch_thread_messages(thread_id_str, api_key)
        if not api_response or 'data' not in api_response:
            return False, 'API Error'
        
        messages_data = api_response['data']
        
        # 2. Find Thread in DB
        thread = Thread.query.filter_by(thread_id=thread_id_str).first()
        
        if not thread:
            if not project_id:
                # If project_id is missing, we try to guess or fail?
                # Usually tasks.py will pass project_id.
                return False, 'Thread valid but project_id missing for initial sync'
            
            thread = Thread(thread_id=thread_id_str, project_id=project_id)
            db.session.add(thread)
            db.session.flush() # Get ID
        
        # 3. Clear old messages (simpler than syncing diffs for now)
        Message.query.filter_by(thread_id=thread.id).delete()
        
        # 4. Insert new
        new_msgs = []
        for msg in messages_data:
            role = msg.get('role', 'unknown')
            created_at = msg.get('created_at', 0)
            
            content_value = ""
            if msg.get('content'):
                for part in msg['content']:
                    if part.get('type') == 'text':
                         content_value += part.get('text', {}).get('value', '')
                    elif part.get('type') == 'image_file':
                         file_id = part.get('image_file', {}).get('file_id')
                         if file_id:
                             gid_param = f"?group_id={thread.project_id}" 
                             content_value += f"![User Image](/file/{file_id}{gid_param})"
            
            new_msgs.append(Message(
                thread_id=thread.id,
                role=role,
                content=content_value,
                created_at=int(created_at)
            ))
            
        db.session.bulk_save_objects(new_msgs)
        
        # 5. Metadata
        thread.last_synced_at = int(time.time())
        thread.message_count = len(new_msgs)
        
        db.session.commit()
        return True, f'Synced {len(new_msgs)} messages'
        
    except Exception as e:
        db.session.rollback()
        logging.getLogger().error(f"Sync error {thread_id_str}: {e}")
        return False, str(e)

def process_thread_from_db(thread_db_obj, target_name, start_date, end_date):
    """
    Search using DB cache.
    Returns dict compatible with process_thread result.
    """
    t_id = thread_db_obj.thread_id
    
    result = {
        'thread_id': t_id,
        'keep': False,
        'status': 'Unknown',
        'data': None,
        'messages': []
    }
    
    # Load Messages (Using relationship, should be efficient if lazy=True and accessed here)
    # Sorted by created_at 
    db_messages = sorted(thread_db_obj.messages, key=lambda m: m.created_at)
    
    # If no messages, maybe return empty or handle specially
    # BUT we must return the structure regardless
    
    processed_messages = []
    has_target = False
    
    for msg in db_messages:
        try:
            msg_ts = msg.created_at
            time_str = utils.unix_to_utc8(msg_ts)
            date_str = utils.unix_to_date_str(msg_ts)
            content_value = msg.content or ""
            role = msg.role
            
            # Highlight Logic
            if target_name:
                if target_name.lower() in content_value.lower():
                    has_target = True
                if target_name.lower() in content_value.lower() and target_name != "No choice was made":
                     pattern = re.compile(re.escape(target_name), re.IGNORECASE)
                     content_value = pattern.sub(lambda m: f"<mark>{m.group(0)}</mark>", content_value)

            role_class = 'user' if role == 'user' else 'assistant'
            role_icon = '👤' if role == 'user' else '🤖'
            role_name = '使用者' if role == 'user' else 'AI Agent'
            
            processed_messages.append({
                'time': time_str,
                'timestamp': msg_ts,
                'role': role,
                'role_class': role_class,
                'role_icon': role_icon,
                'role_name': role_name,
                'content': content_value,
                'date_str': date_str
            })
        except: continue

    result['messages'] = processed_messages
    
    # Filter Logic
    keep_thread = False
    thread_remark = thread_db_obj.remark or ''
    
    if target_name:
        is_remark_match = target_name.lower() in thread_remark.lower()
        if has_target or (target_name.lower() in t_id.lower()) or is_remark_match: 
            keep_thread = True
            result['status'] = "Matched (Cache)"
        else:
            result['status'] = "No Match"
    else:
        keep_thread = True
        result['status'] = "Matched (All)"
        
    # Date Filtering
    t_date = processed_messages[-1]['date_str'] if processed_messages else ''
    if keep_thread and (start_date or end_date):
        if start_date and end_date:
            if not (start_date <= t_date <= end_date): keep_thread = False
        elif start_date:
            if not (t_date >= start_date): keep_thread = False
        elif end_date:
            if not (t_date <= end_date): keep_thread = False

    result['keep'] = keep_thread
    
    if keep_thread:
        result['data'] = {
            'thread_id': t_id,
            'messages': processed_messages,
            'timestamp': processed_messages[-1]['timestamp'] if processed_messages else 0
        }
        
    return result

def search_threads_sql(project_id, target_name, start_date, end_date):
    """
    Optimized SQL-based search.
    Returns list of Thread objects that match criteria.
    """
    query = Thread.query.filter(Thread.project_id == project_id)
    
    # Validation timestamps
    start_ts = 0
    end_ts = 0
    
    from dateutil import parser
    
    if start_date:
        try:
            # Robust parsing (handles many formats)
            dt = parser.parse(start_date)
            start_ts = int(dt.timestamp())
        except Exception as e:
            logging.getLogger().warning(f"Date Parse Error (Start): {start_date} - {e}")
            pass
        
    if end_date:
        try:
            dt = parser.parse(end_date)
            # End of day
            dt = dt.replace(hour=23, minute=59, second=59)
            end_ts = int(dt.timestamp())
        except Exception as e:
            logging.getLogger().warning(f"Date Parse Error (End): {end_date} - {e}")
            pass

    # Join Messages if needed (Target Name or Date)
    if target_name or start_date or end_date:
        query = query.outerjoin(Message)
        
        filters = []
        
        if target_name:
            # Case insensitive search
            # SQLite 'ilike' equivalent is via explicit call or just ilike if supported by alchemy dialect
            # Flask-SQLAlchemy usually supports ilike
            filters.append(Message.content.ilike(f'%{target_name}%'))
            # Also check if target_name matches Thread ID
            # Or Thread Remark?
            # Existing logic: if target_name in t_id or remark or content.
            # SQL: (Message.content LIKE %..%) OR (Thread.thread_id LIKE %..%) OR (Thread.remark LIKE %..%)
            # But Thread fields don't need Join Message?
            # If we Join Message, we get duplicates. Distinct needed.
            
            t_filter = (Message.content.ilike(f'%{target_name}%'))
            # Combined filter for Thread fields
            t_meta_filter = (Thread.thread_id.ilike(f'%{target_name}%')) | (Thread.remark.ilike(f'%{target_name}%'))
            
            # The query logic: Threads where (Any Message matches) OR (Thread ID/Remark matches)
            # Careful: If we filter by Date, does it apply to the Message or the Thread?
            # Existing logic: Filter by Last Message Date.
            # SQL Logic: Filter by *Message* date?
            
            # Let's simplify:
            # 1. Filter by Keyword (Content OR Meta)
            # 2. Filter by Date (Message Time)
            
            kw_condition = t_filter | t_meta_filter
            filters.append(kw_condition)

        if start_date:
            filters.append(Message.created_at >= start_ts)
        if end_date:
            filters.append(Message.created_at <= end_ts)
            
        if filters:
            from sqlalchemy import and_
            query = query.filter(and_(*filters))

    # Distinct because multiple messages can match
    return query.distinct().all()

def get_search_result_page(task_id, page_index=0):
    """
    Retrieves a specific page of search results for a given task.
    Returns a list of dicts (the results).
    """
    from .models import SearchResultChunk
    import json
    
    chunk = SearchResultChunk.query.filter_by(task_id=task_id, page_index=page_index).first()
    
    if chunk and chunk.data_json:
        try:
            return json.loads(chunk.data_json)
        except Exception as e:
            logging.error(f"Failed to parse chunk JSON for task {task_id}, page {page_index}: {e}")
            return []
            
    return []
