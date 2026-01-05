import os
import requests
import re
import logging
from datetime import datetime
import config
import security
import utils
import database # For loading settings in get_headers

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

def fetch_thread_messages(thread_id, api_key=None):
    if not thread_id: return None
    base_url = config.OPENAI_API_URL.format(thread_id)
    headers = get_headers(api_key)
    
    all_messages = []
    params = {"limit": 100} # Max limit per page to reduce requests
    
    try:
        while True:
            response = requests.get(base_url, headers=headers, params=params, timeout=20)
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

def process_thread(thread_data, target_name, start_date, end_date, api_key=None):
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
            if msg.get('content') and msg['content']:
                text_content = msg['content'][0].get('text', {})
                content_value = text_content.get('value', '')

            if target_name:
                if target_name.lower() in content_value.lower() and role == 'user':
                    has_target = True
                if target_name.lower() in content_value.lower() and target_name != "No choice was made":
                     pattern = re.compile(re.escape(target_name), re.IGNORECASE)
                     # Use lambda to preserve original casing of the matched text
                     content_value = pattern.sub(lambda m: f"<mark>{m.group(0)}</mark>", content_value)

            role_class = 'user' if role == 'user' else 'assistant'
            role_icon = '👤' if role == 'user' else '🤖'
            role_name = '使用者' if role == 'user' else 'AI 助理'
            
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
    
    if target_name:
        if has_target: 
            keep_thread = True
            status = "Matched Keyword"
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
        
    return result
