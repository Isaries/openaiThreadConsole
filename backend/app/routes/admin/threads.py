from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, session
from . import admin_bp
from ...models import Thread, Project, Message
from ... import logic
from ... import tasks
from ...extensions import db, limiter
import security as core_security
from .security import log_audit
import re

@admin_bp.route('/threads/view/<thread_id>')
def view_thread(thread_id):
    if not session.get('user_id'): return redirect(url_for('auth.login'))
    
    group_id = request.args.get('group_id')
    
    project = None
    if group_id:
        project = Project.query.get(group_id)
    else:
        t = Thread.query.filter_by(thread_id=thread_id).first()
        if t:
            project = t.project
            
    if not project:
        flash('Project not found for this thread', 'error')
        return redirect(url_for('admin.index'))
        
    is_owner = any(o.id == session.get('user_id') for o in project.owners)
    if session.get('role') != 'admin' and not is_owner:
         flash('Permission Denied', 'error')
         return redirect(url_for('admin.index'))
         
    thread_obj = Thread.query.filter_by(thread_id=thread_id).first()
    
    is_syncing = False
    result = None
    
    if thread_obj:
        try:
             tasks.refresh_specific_threads.schedule(args=(project.id, [thread_id]), delay=0)
             if not request.args.get('nomsg'):
                 flash('正在後台更新數據，頁面顯示為快取資料。', 'info')
        except Exception as e:
             current_app.logger.warning(f"Failed to trigger async task: {e}")
        
        result = logic.process_thread_from_db(thread_obj, target_name="", start_date=None, end_date=None)
    
    else:
        try:
             tasks.refresh_specific_threads.schedule(args=(project.id, [thread_id]), delay=0)
             is_syncing = True
             result = {'data': {'thread_id': thread_id}, 'remark': '', 'messages': []}
        except Exception as e:
             flash(f'無法啟動同步任務: {e}', 'error')
             return redirect(url_for('admin.index', group_id=project.id))

    return render_template('admin_thread_view.html', 
        result=result, 
        project=project,
        active_group={'group_id': project.id, 'name': project.name},
        is_syncing=is_syncing
    )

@admin_bp.route('/threads/add_one', methods=['POST'])
def add_one_thread():
    if not session.get('user_id'): return redirect(url_for('auth.login'))
    
    group_id = request.form.get('group_id')
    thread_id = request.form.get('thread_id', '').strip()
    
    if not re.fullmatch(r'thread_[A-Za-z0-9]+', thread_id):
        flash('Thread ID 格式錯誤 (必須以 thread_ 開頭，且僅包含英數字元)', 'error')
        return redirect(url_for('admin.index', group_id=group_id))
        
    project = Project.query.get(group_id)
    if not project: return redirect(url_for('admin.index'))
    
    is_owner = any(o.id == session.get('user_id') for o in project.owners)
    if session.get('role') != 'admin' and not is_owner:
        flash('權限不足', 'error')
        return redirect(url_for('admin.index', group_id=group_id))
    
    exists = any(t.thread_id == thread_id for t in project.threads)
    if exists:
        flash('Thread ID already exists in this project', 'error')
    else:
        remark = request.form.get('remark', '').strip() or None
        new_t = Thread(thread_id=thread_id, project_id=project.id, remark=remark)
        db.session.add(new_t)
        project.version += 1
        db.session.commit()
        flash('Thread added with remark' if remark else 'Thread added', 'success')
        
    return redirect(url_for('admin.index', group_id=group_id))

@admin_bp.route('/threads/delete_multi', methods=['POST'])
def delete_multi():
    if not session.get('user_id'): return redirect(url_for('auth.login'))
    
    group_id = request.form.get('group_id')
    project = Project.query.get(group_id)
    if not project: return redirect(url_for('admin.index'))
    
    is_owner = any(o.id == session.get('user_id') for o in project.owners)
    if session.get('role') != 'admin' and not is_owner:
        flash('權限不足', 'error')
        return redirect(url_for('admin.index', group_id=group_id))
    
    select_all_pages = request.form.get('select_all_pages') == 'true'
    count = 0
    
    if select_all_pages:
        search_q = request.form.get('search_q', '').strip()
        base_query = db.session.query(Thread.id).filter_by(project_id=project.id)
        if search_q:
            base_query = base_query.filter(
                (Thread.thread_id.contains(search_q)) | 
                (Thread.remark.contains(search_q))
            )
        threads_subquery = base_query.subquery()
        Message.query.filter(Message.thread_id.in_(threads_subquery)).delete(synchronize_session=False)
        count = Thread.query.filter(Thread.id.in_(threads_subquery)).delete(synchronize_session=False)
    else:
        thread_ids = request.form.getlist('selected_ids')
        if not thread_ids:
            single_id = request.form.get('thread_id')
            if single_id: thread_ids = [single_id]
        
        if not thread_ids:
            flash('No threads selected', 'warning')
            return redirect(url_for('admin.index', group_id=group_id))
        
        for tid in thread_ids:
            t = Thread.query.filter_by(thread_id=tid, project_id=project.id).first()
            if t:
                db.session.delete(t)
                count += 1
                
    if count > 0: project.version += 1
    db.session.commit()
    flash(f'{count} threads deleted', 'success')
    return redirect(url_for('admin.index', group_id=group_id))

@admin_bp.route('/threads/update_remark', methods=['POST'])
def update_thread_remark():
    if not session.get('user_id'): return {'error': 'Unauthorized'}, 401
    
    data = request.json
    thread_id = data.get('thread_id')
    group_id = data.get('group_id')
    new_remark = data.get('remark', '').strip()
    
    project = Project.query.get(group_id)
    if not project: return {'error': 'Project not found'}, 404
    
    is_owner = any(o.id == session.get('user_id') for o in project.owners)
    if session.get('role') != 'admin' and not is_owner:
        return {'error': 'Permission denied'}, 403
        
    thread = Thread.query.filter_by(thread_id=thread_id, project_id=project.id).first()
    if thread:
        thread.remark = new_remark
        db.session.commit()
        return {'success': True}
    
    return {'error': 'Thread not found'}, 404

@admin_bp.route('/threads/refresh', methods=['POST'])
@limiter.limit("10 per hour")
def refresh_threads_cache():
    if not session.get('user_id'): return redirect(url_for('auth.login'))
    
    group_id = request.form.get('group_id')
    project = Project.query.get(group_id)
    if not project: return redirect(url_for('admin.index'))
    
    is_owner = any(o.id == session.get('user_id') for o in project.owners)
    if session.get('role') != 'admin' and not is_owner:
         flash('Permission Denied', 'error')
         return redirect(url_for('admin.index', group_id=group_id))
         
    select_all_pages = request.form.get('select_all_pages') == 'true'
    search_q = request.form.get('search_q', '').strip()
    thread_ids = []
    
    if select_all_pages:
        query = Thread.query.with_entities(Thread.thread_id).filter_by(project_id=project.id)
        if search_q:
            query = query.filter(
                (Thread.thread_id.contains(search_q)) | 
                (Thread.remark.contains(search_q))
            )
        thread_ids = [t.thread_id for t in query.all()]
    else:
        thread_ids = request.form.getlist('selected_ids')
        if not thread_ids:
            single = request.form.get('thread_id')
            if single: thread_ids = [single]
            
    if not thread_ids:
        flash('未選擇任何 Thread', 'warning')
        return redirect(url_for('admin.index', group_id=group_id))
        
    tasks.refresh_specific_threads(group_id, thread_ids, group_name=project.name)
    flash(f'已排程更新 {len(thread_ids)} 筆資料的快取', 'success')
    return redirect(url_for('admin.index', group_id=group_id))

@admin_bp.route('/threads/export', methods=['POST'])
def export_excel():
    if not session.get('user_id'): return redirect(url_for('auth.login'))
    
    group_id = request.form.get('group_id')
    project = Project.query.get(group_id)
    if not project: return redirect(url_for('admin.index'))
         
    is_owner = any(o.id == session.get('user_id') for o in project.owners)
    if session.get('role') != 'admin' and not is_owner:
         flash('Permission Denied', 'error')
         return redirect(url_for('admin.index'))
         
    from ...services import excel_service
    try:
        select_all_pages = request.form.get('select_all_pages') == 'true'
        search_q = request.form.get('search_q', '').strip()
        filtered_ids = None
        
        if not select_all_pages:
             ids = request.form.getlist('selected_ids')
             if not ids and request.form.get('thread_id'):
                 ids = [request.form.get('thread_id')]
             if ids: filtered_ids = ids
        
        return excel_service.generate_excel_export(
            project.id, 
            project.name, 
            filtered_ids=filtered_ids, 
            search_q=search_q if select_all_pages else None
        )
    except Exception as e:
        flash(f'Export Failed: {e}', 'error')
        return redirect(url_for('admin.index', group_id=group_id))

@admin_bp.route('/threads/upload', methods=['POST'])
def upload_file():
    if not session.get('user_id'): return redirect(url_for('auth.login'))
    group_id = request.form.get('group_id')
    
    file = request.files.get('file')
    if not file or not file.filename.endswith('.xlsx'):
        flash('請上傳 Excel (.xlsx) 檔案', 'error')
        return redirect(url_for('admin.index', group_id=group_id))

    project = Project.query.get(group_id)
    if not project: return redirect(url_for('admin.index'))

    # Optimistic Locking
    client_version = request.form.get('version', type=int)
    current_version = project.version if project.version else 1
    if client_version is not None and client_version != current_version:
        flash('資料已被其他人修改，請重新整理頁面後再試', 'error')
        return redirect(url_for('admin.index', group_id=group_id))

    is_owner = any(o.id == session.get('user_id') for o in project.owners)
    if session.get('role') != 'admin' and not is_owner:
         return redirect(url_for('admin.index'))

    from ...services import excel_service
    thread_data_map, error = excel_service.parse_excel_for_import(file)

    if error:
        flash(error, 'error')
        return redirect(url_for('admin.index', group_id=group_id))
        
    new_ids = list(thread_data_map.keys())
    action = request.form.get('action', 'add')
    
    try:
        stats = excel_service.process_import_data(project.id, thread_data_map, action)
        
        if 'error' in stats:
             flash(f"處理失敗: {stats['error']}", 'error')
        else:
             if action == 'delete':
                 count = stats['deleted']
                 if count > 0:
                     flash(f'成功刪除 {count} 筆 Thread', 'success')
                     log_audit('Batch Delete Excel', f"{count} threads from {project.name}")
                 else:
                     flash('沒有刪除任何 Thread', 'warning')
             else:
                 added = stats['added']
                 updated = stats['updated']
                 if added > 0 or updated > 0:
                     flash(f'處理完成: 新增 {added} 筆, 更新 {updated} 筆備註', 'success')
                     log_audit('Import Excel', f"{added} added, {updated} updated in {project.name}")
                 else:
                     flash('沒有處理任何資料', 'warning')
    except Exception as e:
        flash(f'檔案處理失敗: {str(e)}', 'error')
        
    return redirect(url_for('admin.index', group_id=group_id))
