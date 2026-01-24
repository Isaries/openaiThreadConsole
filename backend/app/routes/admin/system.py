from flask import render_template, flash, session, redirect, url_for, request, jsonify
from . import admin_bp
from ...models import SystemMetric, Tag
from ...extensions import db
import database
from .security import log_audit
import security as core_security
import psutil
import time
import json
import config
from datetime import datetime
from ... import utils

def get_dashboard_system_data():
    masked_key = f"sk-{'*' * 20}"
    # Only show tags that are currently in use (have at least one project)
    all_tags = [t.name for t in Tag.query.all() if len(t.projects) > 0]
    return {
        'masked_key': masked_key,
        'all_tags': all_tags,
        'openai_base_url': config.OPENAI_BASE_URL
    }

@admin_bp.route('/settings', methods=['POST'])
def update_settings():
    if not session.get('user_id') or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
        
    data = request.json
    openai_key = data.get('openai_api_key')
    
    settings = database.load_settings()
    if openai_key:
        settings['openai_api_key'] = core_security.encrypt_data(openai_key)
        
    try:
        database.save_settings(settings)
        log_audit('Update Global Settings', 'OpenAI Key')
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/settings/refresh_schedule', methods=['POST'])
def update_refresh_schedule():
    if not session.get('user_id') or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
        
    data = request.json
    enabled = data.get('enabled', False)
    try:
        frequency = int(data.get('frequency', 1))
        hour = int(data.get('hour', 2))
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid parameters'}), 400
        
    if not (1 <= frequency <= 360):
        return jsonify({'error': 'Frequency must be between 1 and 360 days'}), 400
        
    if not (0 <= hour <= 23):
        return jsonify({'error': 'Hour must be between 0 and 23'}), 400
    
    settings = database.load_settings()
    current_config = settings.get('auto_refresh', {})
    last_run = current_config.get('last_run')
    
    settings['auto_refresh'] = {
        'enabled': enabled,
        'frequency_days': frequency,
        'hour': hour,
        'last_run': last_run
    }
    
    database.save_settings(settings)
    
    return jsonify({'success': True})

@admin_bp.route('/settings/refresh_now', methods=['POST'])
def trigger_manual_refresh():
    if not session.get('user_id') or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
        
    from ... import tasks
    
    force_refresh = request.json.get('force', False)
    tasks.manual_global_refresh_task(force=force_refresh)
    
    # Log Audit
    log_audit(session.get('username'), 'Manual Refresh', 'Global')
    
    return jsonify({'success': True, 'message': 'Manual global refresh started.'})


@admin_bp.route('/performance')
def performance_dashboard():
    if not session.get('user_id'): return redirect(url_for('auth.login'))
    if session.get('role') != 'admin':
        flash('權限不足', 'error')
        return redirect(url_for('admin.index'))
        
    # 1. Fetch History
    metrics_query = SystemMetric.query.order_by(SystemMetric.timestamp.asc()).all()
    
    max_history_seconds = 10 * 86400
    cutoff = datetime.now().timestamp() - max_history_seconds
    
    metrics = [m for m in metrics_query if m.timestamp >= cutoff]
    
    
    chart_data = []
    for i, m in enumerate(metrics):
        tokens_delta = 0
        if i > 0:
            # Calculate incremental growth from previous data point
            tokens_delta = m.total_managed_tokens - metrics[i-1].total_managed_tokens
        
        chart_data.append({
            'time': utils.unix_to_utc8(m.timestamp),
            'timestamp': m.timestamp,
            'cpu': m.cpu_percent,
            'mem_pct': m.memory_percent,
            'mem_gb': m.memory_used,
            'tokens': m.total_managed_tokens,
            'tokens_delta': max(0, tokens_delta)  # Prevent negative deltas from data cleanup
        })

    
    # 2. Real-time Snapshot
    # Get current token count
    from ...models import Thread
    from sqlalchemy import func
    current_tokens = db.session.query(func.sum(Thread.total_tokens)).scalar() or 0
    try:
        current_cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        current_mem_pct = mem.percent
        current_mem_gb = round(mem.used / (1024**3), 2)
        current_mem_total = round(mem.total / (1024**3), 2)
        
        # Calculate delta from last historical data point
        last_tokens_delta = 0
        if len(chart_data) > 0:
            last_tokens_delta = current_tokens - chart_data[-1]['tokens']
        elif len(chart_data) == 0:
             # Logic Fix: If no history exists, the entire current volume is the "Delta" (Growth from 0)
             last_tokens_delta = current_tokens
        
        current_snapshot = {
            'time': '現在 (即時)',
            'timestamp': int(time.time()),
            'cpu': current_cpu,
            'mem_pct': current_mem_pct,
            'mem_gb': current_mem_gb,
            'tokens': current_tokens,
            'tokens_delta': max(0, last_tokens_delta)
        }
        chart_data.append(current_snapshot)

        
    except ImportError:
        flash('錯誤: 尚未安裝 psutil 套件', 'error')
        current_snapshot = {'time': 'N/A', 'cpu': 0, 'mem_pct': 0, 'mem_gb': 0, 'tokens': 0}
        current_mem_total = 0
    except Exception as e:
        flash(f'讀取系統數據失敗: {str(e)}', 'error')
        current_snapshot = {'time': 'Error', 'cpu': 0, 'mem_pct': 0, 'mem_gb': 0, 'tokens': 0}
        current_mem_total = 0
    
    return render_template('admin/performance.html', 
                           chart_data=chart_data, 
                           current=current_snapshot,
                           mem_total=current_mem_total)

@admin_bp.route('/performance/recalculate', methods=['POST'])
def recalculate_tokens_trigger():
    if not session.get('user_id') or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
        
    from ... import tasks
    tasks.recalculate_tokens_task()
    
    return jsonify({'success': True, 'message': 'Token recalculation started in background.'})

