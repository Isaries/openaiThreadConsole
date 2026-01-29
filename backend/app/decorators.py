from functools import wraps
from flask import request, session, g
from . import utils
import json

def audit_required(action, target_extractor=None):
    """
    Decorator to automatically log audit events.
    
    :param action: The name of the action (e.g., 'Update Project')
    :param target_extractor: Optional function(return_value, *args, **kwargs) to extract target name. 
                             If None, tries to use request.form/json or defaults to 'Unknown'.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 1. Capture 'Before' state if needed (relies on route implementation to store in g.audit_pre_state)
            # This is optional and handled within the route logic usually, 
            # but the decorator provides a hook if we wanted to standardize it further.
            
            response = f(*args, **kwargs)
            
            try:
                # 2. Extract Target
                target = "Unknown"
                if target_extractor:
                    # Try to match signature (response, *args, **kwargs) or just (*args, **kwargs) context
                    # Simplest is to pass the return value (often response object or tuple)
                    try:
                        target = target_extractor(response, *args, **kwargs)
                    except Exception:
                        target = "Extraction Failed"
                else:
                    # Default heuristics
                    if request.method == 'POST':
                        # Try common fields
                        form_data = request.form.to_dict() or request.json or {}
                        target = form_data.get('name') or form_data.get('username') or form_data.get('id') or form_data.get('group_id') or "Unknown"

                # 3. Extract Details (Diffs)
                # Routes should store specific diffs in g.audit_details (dict) if they calculated it.
                details = getattr(g, 'audit_details', None)
                
                # If no explicit diff, maybe dump payload (carefully)? 
                # For now, let's strictly use g.audit_details for rich info to avoid leaking secrets inadvertently.
                
                # 4. Log it
                # status check: if response is 2xx or 3xx -> Success. 
                # Flask response object check could be complex if it's a tuple or json dict.
                # Simplified: Assume success if no exception raised.
                
                if details or target != "Unknown":
                    # Only log if we have something meaningful or forced
                    utils.log_audit(action, target, details)
                    
            except Exception as e:
                # Never fail the request just because logging failed
                print(f"Audit Decorator Error: {e}")
                
            return response
        return decorated_function
    return decorator
