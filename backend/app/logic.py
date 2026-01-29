
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

from app.extensions import db
from app.models import Thread, Message, Assistant
import time

# Optional: tiktoken for precise token counting
try:
    import tiktoken
    TIKTOKEN_AVAILABLE = True
except ImportError:
    TIKTOKEN_AVAILABLE = False
    # Warning will be logged on first use to ensure logger is initialized

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
                     return {'error': f"HTTP {response.status_code}"}
            
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
        return {'error': str(e)}


def fetch_assistant_info(assistant_id, api_key=None):
    """
    Fetch assistant details from OpenAI API.
    Returns the assistant name or None if failed.
    """
    if not assistant_id:
        return None
    
    base_url = config.OPENAI_BASE_URL
    url = f"{base_url}/assistants/{assistant_id}"
    headers = get_headers(api_key)
    
    session = _get_retry_session()
    
    try:
        response = session.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            return data.get('name')
        else:
            logging.getLogger().warning(f"Failed to fetch assistant {assistant_id}: HTTP {response.status_code}")
            return None
    except Exception as e:
        logging.getLogger().error(f"Error fetching assistant {assistant_id}: {e}")
        return None


def get_or_sync_assistants(assistant_ids, api_key=None, project_id=None):
    """
    Batch check and sync assistant names.
    - Check local cache for existing entries
    - Filter out expired (configurable, default 3 days) or missing entries
    - Fetch from OpenAI API only for those
    - Update cache
    
    Returns: dict mapping assistant_id -> assistant_name
    """
    from app.models import Assistant
    
    if not assistant_ids:
        return {}
    
    result = {}
    current_ts = int(time.time())
    
    # Read expiry from settings (default: 3 days)
    settings = database.load_settings()
    assistant_cache_config = settings.get('assistant_cache', {})
    expiry_days = assistant_cache_config.get('expiry_days', 3)
    cache_expiry = expiry_days * 24 * 60 * 60  # Convert to seconds
    
    # 1. Batch query existing cache
    cached_assistants = Assistant.query.filter(Assistant.id.in_(assistant_ids)).all()
    cached_map = {a.id: a for a in cached_assistants}
    
    # 2. Determine which need refresh
    ids_to_fetch = []
    for asst_id in assistant_ids:
        cached = cached_map.get(asst_id)
        if cached:
            last_sync = cached.last_synced_at or 0
            if (current_ts - last_sync) > cache_expiry:
                # Expired, need refresh
                ids_to_fetch.append(asst_id)
            else:
                # Valid cache
                result[asst_id] = cached.name
        else:
            # Not in cache
            ids_to_fetch.append(asst_id)
    
    # 3. Fetch missing/expired from API
    for asst_id in ids_to_fetch:
        name = fetch_assistant_info(asst_id, api_key)
        
        # Update or create cache entry
        existing = cached_map.get(asst_id)
        if existing:
            existing.name = name
            existing.last_synced_at = current_ts
        else:
            new_assistant = Assistant(
                id=asst_id,
                name=name,
                project_id=project_id,
                last_synced_at=current_ts
            )
            db.session.add(new_assistant)
        
        result[asst_id] = name
        
        # Small delay to avoid rate limiting
        time.sleep(0.1)
    
    return result


def calculate_messages_tokens(messages_data):
    """
    Calculates the total tokens for reading thread messages.
    This represents the cost of fetching/reading messages, not the cost of running the assistant.
    
    Args:
        messages_data: List of message objects from OpenAI API
        
    Returns:
        int: Total token count for all messages, or None if calculation fails
    """
    if not messages_data:
        return 0
    
    total_tokens = 0
    
    try:
        if TIKTOKEN_AVAILABLE:
            # Use tiktoken for precise token counting
            # Using cl100k_base encoding (used by gpt-4, gpt-3.5-turbo)
            encoding = tiktoken.get_encoding("cl100k_base")
            
            for msg in messages_data:
                # Count tokens in message content
                if msg.get('content'):
                    for part in msg['content']:
                        if part.get('type') == 'text':
                            text_value = part.get('text', {}).get('value', '')
                            if text_value:
                                total_tokens += len(encoding.encode(text_value))
                        elif part.get('type') == 'image_file':
                            # Images don't consume tokens in message retrieval
                            # (they consume tokens when processed by vision models)
                            pass
                
                # Add overhead for message metadata (role, timestamp, etc.)
                # Approximate: ~10 tokens per message for metadata
                total_tokens += 10
        else:
            # Fallback: Character-based estimation
            # Log warning only once
            if not hasattr(calculate_messages_tokens, '_warned'):
                logging.getLogger().warning("tiktoken not available, using character-based token estimation")
                calculate_messages_tokens._warned = True
            
            # Rough estimate: 1 token ≈ 4 characters for English, ≈ 1.5 for Chinese
            for msg in messages_data:
                char_count = 0
                if msg.get('content'):
                    for part in msg['content']:
                        if part.get('type') == 'text':
                            text_value = part.get('text', {}).get('value', '')
                            char_count += len(text_value)
                
                # Estimate tokens (conservative: assume mixed language)
                # Use 2.5 chars per token as middle ground
                total_tokens += int(char_count / 2.5) + 10  # +10 for metadata
        
        return total_tokens
        
    except Exception as e:
        logging.getLogger().error(f"Token calculation error: {e}")
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

    # Pre-fetch Assistant Names for display
    assistant_names_map = {}
    try:
        assistant_ids = set()
        for msg in messages_data:
            if msg.get('role') == 'assistant' and msg.get('assistant_id'):
                assistant_ids.add(msg.get('assistant_id'))
        
        if assistant_ids:
            from .models import Assistant 
            assistants = Assistant.query.filter(Assistant.id.in_(assistant_ids)).all()
            for ast in assistants:
                if ast.name:
                    assistant_names_map[ast.id] = ast.name
    except Exception as e:
        logging.getLogger().warning(f"Failed to fetch assistant names: {e}")

    processed_messages = []
    has_target = False
    
    for msg in messages_data:
        try:
            role = msg.get('role')
            if not role: continue
            
            created_at = msg.get('created_at')
            try:
                msg_ts = int(created_at)
            except (ValueError, TypeError) as e:
                logging.getLogger().debug(f"Invalid timestamp for message: {e}")
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
            
            if role == 'user':
                role_name = '使用者'
            else:
                aid = msg.get('assistant_id')
                role_name = assistant_names_map.get(aid) or 'AI Agent'
            
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
        except Exception as e:
            logging.getLogger().warning(f"Failed to process message in thread {thread_data.get('thread_id', 'unknown')}: {e}")
            continue

    processed_messages.sort(key=lambda x: x['timestamp'])
    result['messages'] = processed_messages # Store for debug
    
    # Check filters
    keep_thread = False
    status = "Filtered"
    
    thread_remark = thread_data.get('remark', '') or ''
    # If remark is missing in input data, try to fetch from DB
    if not thread_remark:
        try:
            from .models import Thread
            # logic.py might be used where app context is active
            # Use local import to avoid circular dependency
            db_thread = Thread.query.filter_by(thread_id=t_id).first()
            if db_thread and db_thread.remark:
                thread_remark = db_thread.remark
        except Exception:
            # DB might not be initialized or accessible (e.g. during tests without app context)
            pass

    
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
            'project_id': group_id, # Added project_id
            'remark': thread_remark, # Added remark
            'time': thread_time,
            'timestamp': thread_timestamp,
            'messages': processed_messages,
            'raw_messages': messages_data # Debug: Pass raw API response
        }
    
    # Always include raw messages for System Log debugging
    result['raw_messages'] = messages_data
        
    return result

# --- Cache Optimization Logic ---

def sync_thread_to_db(thread_id_str, api_key=None, project_id=None, force_active=False):
    """
    Sets up the DB state for a thread. 
    Can be called by "Refresh" button or scheduled task.
    Minimizes Transaction Scope to prevent SQLite locking issues.
    
    force_active: If True, resets stale count and priority to 'normal' (Unfreezes thread).
    """
    try:
        # 1. Fetch from API (Heavy Network I/O - OUTSIDE Transaction)
        api_response = fetch_thread_messages(thread_id_str, api_key)
        if not api_response or 'data' not in api_response:
             # Check if it was because of empty? 
             # If fetch returns None, it's error.
             error_msg = api_response.get('error', 'Unknown API Error') if api_response else 'API Connection Failed'
             return False, error_msg
        
        messages_data = api_response['data']
        
        # 1.5 Calculate Message Tokens (based on message content)
        # This represents the cost of reading/fetching messages, not running the assistant
        total_tokens = calculate_messages_tokens(messages_data)
        
        # 1.6 Collect all assistant_ids for cache sync
        assistant_ids = set()
        for msg in messages_data:
            if msg.get('role') == 'assistant' and msg.get('assistant_id'):
                assistant_ids.add(msg.get('assistant_id'))
        
        # 2. Prepare Data Objects
        new_msgs = []
        # We need thread foreign key `thread.id` (Integer PK), not string ID.
        # But we don't have it yet if thread doesn't exist.
        # So we might need a small transaction to get/create Thread first.
        
        thread_pk = None
        
        # --- Transaction A: Get/Create Thread ---
        # This is fast.
        thread = Thread.query.filter_by(thread_id=thread_id_str).first()
        if not thread:
            if not project_id:
                return False, 'Thread valid but project_id missing for initial sync'
            
            thread = Thread(thread_id=thread_id_str, project_id=project_id)
            db.session.add(thread)
            db.session.commit() # Commit to get ID
            thread_pk = thread.id
        else:
            thread_pk = thread.id
        
        # 2.5 Sync assistant names to cache (before processing messages)
        # This ensures we have the latest names cached
        if assistant_ids:
            get_or_sync_assistants(list(assistant_ids), api_key, project_id)
            
        # 3. Process Data (CPU Bound - OUTSIDE Transaction)
        for msg in messages_data:
            role = msg.get('role', 'unknown')
            created_at = msg.get('created_at', 0)
            msg_assistant_id = msg.get('assistant_id') if role == 'assistant' else None
            
            content_value = ""
            if msg.get('content'):
                for part in msg['content']:
                    if part.get('type') == 'text':
                         content_value += part.get('text', {}).get('value', '')
                    elif part.get('type') == 'image_file':
                         file_id = part.get('image_file', {}).get('file_id')
                         if file_id:
                             # We assume project_id is available or we use thread's project_id
                             # We can use Thread object if accessible or pass explicit
                             # Here we construct the string efficiently
                             gid_param = f"?group_id={project_id}" if project_id else ""
                             content_value += f"![User Image](/file/{file_id}{gid_param})"
            
            new_msgs.append(Message(
                thread_id=thread_pk, # Use the Int PK we got
                role=role,
                content=content_value,
                created_at=int(created_at),
                assistant_id=msg_assistant_id  # Store assistant_id
            ))

        # 3.5 Calculate latest message timestamp for smart refresh
        latest_msg_ts = max((msg.get('created_at', 0) for msg in messages_data), default=0)

        # 4. Atomic Write (Deletion + Insertion - INSIDE Transaction)
        # This is where we lock. Keep it fast.
        
        # Delete old
        Message.query.filter_by(thread_id=thread_pk).delete()
        
        # Insert New
        if new_msgs:
            db.session.bulk_save_objects(new_msgs)
        
        # Update Meta
        # We need to re-fetch thread object attached to this session or use update query
        # Using update query is faster/cleaner
        
        # Smart Refresh: Check if content changed
        old_thread = Thread.query.filter_by(id=thread_pk).first()
        old_last_msg_ts = old_thread.last_message_timestamp if old_thread else None
        
        # Determine if content changed
        # - If old_last_msg_ts is None, this is first sync -> always consider as change
        # - Otherwise, compare timestamps
        if old_last_msg_ts is None:
            has_change = True  # First sync
        else:
            has_change = (latest_msg_ts > old_last_msg_ts)
        
        update_payload = {
            'last_synced_at': int(time.time()),
            'message_count': len(new_msgs),
            'last_message_timestamp': latest_msg_ts
        }
        
        if force_active:
             # Manual override: Unfreeze and reset
             update_payload['stale_refresh_count'] = 0
             update_payload['refresh_priority'] = 'normal'
        elif has_change:
            # Content changed - reset staleness
            update_payload['stale_refresh_count'] = 0
            update_payload['refresh_priority'] = 'normal'
        else:
            # No change - increment staleness
            new_stale_count = (old_thread.stale_refresh_count or 0) + 1
            update_payload['stale_refresh_count'] = new_stale_count
            
            # Update priority based on staleness
            if new_stale_count >= 5:
                update_payload['refresh_priority'] = 'frozen'
            elif new_stale_count >= 3:
                update_payload['refresh_priority'] = 'low'
            else:
                update_payload['refresh_priority'] = 'normal'
        
        if total_tokens is not None:
            update_payload['total_tokens'] = total_tokens
            
        Thread.query.filter_by(id=thread_pk).update(update_payload)
        
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
    
    # Collect assistant_ids for batch lookup
    assistant_ids = set()
    for msg in db_messages:
        if msg.assistant_id:
            assistant_ids.add(msg.assistant_id)
    
    # Batch lookup assistant names from cache
    assistant_names = {}
    if assistant_ids:
        cached_assistants = Assistant.query.filter(Assistant.id.in_(assistant_ids)).all()
        assistant_names = {a.id: a.name for a in cached_assistants}
    
    processed_messages = []
    has_target = False
    
    for msg in db_messages:
        try:
            msg_ts = msg.created_at
            time_str = utils.unix_to_utc8(msg_ts)
            date_str = utils.unix_to_date_str(msg_ts)
            content_value = msg.content or ""
            role = msg.role
            
            # Get assistant name from cache
            assistant_name = None
            if msg.assistant_id:
                assistant_name = assistant_names.get(msg.assistant_id)
            
            # Highlight Logic
            if target_name:
                if target_name.lower() in content_value.lower():
                    has_target = True
                # Also check assistant name match
                if assistant_name and target_name.lower() in assistant_name.lower():
                    has_target = True
                if target_name.lower() in content_value.lower() and target_name != "No choice was made":
                     pattern = re.compile(re.escape(target_name), re.IGNORECASE)
                     content_value = pattern.sub(lambda m: f"<mark>{m.group(0)}</mark>", content_value)

            role_class = 'user' if role == 'user' else 'assistant'
            role_icon = '👤' if role == 'user' else '🤖'
            # Use assistant name if available, otherwise default
            role_name = '使用者' if role == 'user' else (assistant_name or 'AI Agent')
            
            processed_messages.append({
                'time': time_str,
                'timestamp': msg_ts,
                'role': role,
                'role_class': role_class,
                'role_icon': role_icon,
                'role_name': role_name,
                'assistant_name': assistant_name,  # Include for frontend use
                'content': content_value,
                'date_str': date_str
            })
        except Exception as e:
            logging.getLogger().warning(f"Failed to process message in thread_from_db {thread_db_obj.thread_id}: {e}")
            continue

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
            'project_id': thread_db_obj.project_id, # Added project_id
            'remark': thread_remark, # Added remark
            'messages': processed_messages,
            'time': processed_messages[-1]['time'] if processed_messages else 'Unknown', # Ensure time is present
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
    
    from sqlalchemy.orm import subqueryload, joinedload
    from datetime import timezone, timedelta
    from dateutil import parser
    
    # Pre-load messages to avoid N+1 problem
    query = query.options(subqueryload(Thread.messages))
    
    utc8 = timezone(timedelta(hours=8))

    if start_date:
        try:
            # Robust parsing (handles many formats)
            dt = parser.parse(start_date)
            # FORCE UTC+8
            dt = dt.replace(tzinfo=utc8)
            start_ts = int(dt.timestamp())
        except Exception as e:
            logging.getLogger().warning(f"Date Parse Error (Start): {start_date} - {e}")
            pass
        
    if end_date:
        try:
            dt = parser.parse(end_date)
            dt = dt.replace(tzinfo=utc8)
            # End of day
            dt = dt.replace(hour=23, minute=59, second=59)
            end_ts = int(dt.timestamp())
        except Exception as e:
            logging.getLogger().warning(f"Date Parse Error (End): {end_date} - {e}")
            pass

    # Join Messages if needed (Target Name or Date)
    if target_name or start_date or end_date:
        query = query.outerjoin(Message)
        
        # Join Assistant table for name search
        if target_name:
            query = query.outerjoin(Assistant, Message.assistant_id == Assistant.id)
        
        filters = []
        
        if target_name:
            # Logic: Match keyword in Message Content OR Thread ID OR Remark OR Assistant Name
            
            t_filter = (Message.content.ilike(f'%{target_name}%'))
            t_meta_filter = (Thread.thread_id.ilike(f'%{target_name}%')) | (Thread.remark.ilike(f'%{target_name}%'))
            t_assistant_filter = (Assistant.name.ilike(f'%{target_name}%'))
            
            kw_condition = t_filter | t_meta_filter | t_assistant_filter
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
