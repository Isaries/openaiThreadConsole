import pandas as pd
import io
from flask import send_file
from datetime import datetime
from ..models import Thread, Project
from ..extensions import db

def sanitize_for_excel(value):
    """
    Sanitize value to prevent CSV/Excel Formula Injection.
    Prefixes values starting with =, +, -, @ with a single quote.
    """
    if not value: return ""
    val_str = str(value)
    if val_str.startswith(('=', '+', '-', '@')):
        return f"'{val_str}"
    return val_str

def parse_excel_for_import(file, default_remark=None):
    """
    Parses an uploaded Excel file to extract thread IDs and remarks.
    Returns:
        tuple: (thread_data_map, error_message)
        thread_data_map: dict {thread_id: remark}
        error_message: str (None if success)
    """
    try:
        df = pd.read_excel(file)
        
        # Find column case-insensitively
        target_col = None
        for col in df.columns:
             clean_col = str(col).strip().lower()
             if clean_col == 'thread_id':
                 target_col = col
                 break
                 
        if not target_col:
            return None, 'Excel 必須包含 "thread_id" 欄位 (不分大小寫，需有底線)'
            
        # Find 'remark' column (case-insensitive)
        remark_col = None
        for col in df.columns:
             if str(col).strip().lower() == 'remark':
                 remark_col = col
                 break

        thread_data_map = {} # tid -> remark
        
        # Iterate DF to get IDs and Remarks
        for _, row in df.iterrows():
            raw_id = str(row[target_col])
            if pd.isna(row[target_col]) or not raw_id.strip(): continue
            
            tid = raw_id.strip()
            if not tid.startswith('thread_'): continue
            
            remark_val = default_remark
            if remark_col and not pd.isna(row[remark_col]):
                remark_val = str(row[remark_col]).strip()
                # De-sanitize: If it starts with ' followed by formula char, strip the quote
                # This handles round-trip of sanitized data (e.g. '+1' -> ''+1' -> '+1')
                if len(remark_val) > 1 and remark_val.startswith("'") and remark_val[1] in ('=', '+', '-', '@'):
                    remark_val = remark_val[1:]
                
            thread_data_map[tid] = remark_val
            
        return thread_data_map, None
        
    except Exception as e:
        return None, f"解析失敗: {str(e)}"


def process_import_data(project_id, thread_data_map, action='add'):
    """
    Process the imported thread data (add/update or delete).
    Returns a stats dictionary with results.
    """
    try:
        project = Project.query.get(project_id)
        if not project:
            return {'error': 'Project not found'}

        stats = {
            'added': 0,
            'updated': 0,
            'deleted': 0,
            'project_name': project.name
        }
        
        new_ids = list(thread_data_map.keys())
        has_changes = False

        if action == 'delete':
            # Batch Delete Logic
            threads_to_delete = Thread.query.filter(
                Thread.project_id == project.id,
                Thread.thread_id.in_(new_ids)
            ).all()
            
            removed_count = len(threads_to_delete)
            if removed_count > 0:
                for t in threads_to_delete:
                    db.session.delete(t)
                has_changes = True
                stats['deleted'] = removed_count

        else:
            # Batch Add / Update Logic
            all_threads = Thread.query.filter_by(project_id=project.id).all()
            existing_map = {t.thread_id: t for t in all_threads}
            
            for tid in new_ids:
                remark_val = thread_data_map.get(tid)
                
                if tid in existing_map:
                    # Update Existing
                    if remark_val is not None:
                        t = existing_map[tid]
                        if t.remark != remark_val:
                            t.remark = remark_val
                            stats['updated'] += 1
                            has_changes = True
                else:
                    # Create New
                    new_thread = Thread(thread_id=tid, project_id=project.id, remark=remark_val)
                    db.session.add(new_thread)
                    existing_map[tid] = new_thread # Update local map
                    stats['added'] += 1
                    has_changes = True
        
        if has_changes:
            # Atomic version update within the same transaction
            project.version += 1
            db.session.commit()
            
        return stats

    except Exception as e:
        db.session.rollback()
        return {'error': str(e)}

def generate_excel_export(project_id, project_name, filtered_ids=None, search_q=None):
    """
    Generates an Excel file for the threads of a project.
    Supports filtering by specific IDs or search query.
    """
    try:
        query = Thread.query.filter_by(project_id=project_id)
        
        # Priority 1: Specific IDs (Selection)
        if filtered_ids:
             query = query.filter(Thread.thread_id.in_(filtered_ids))
        
        # Priority 2: Search Query (Select All pages with filter)
        elif search_q:
             query = query.filter(
                (Thread.thread_id.contains(search_q)) | 
                (Thread.remark.contains(search_q))
             )
             
        threads = query.all()
        data = []
        for t in threads:
            data.append({
                'thread_id': sanitize_for_excel(t.thread_id),
                'remark': sanitize_for_excel(t.remark)
            })
            
        df = pd.DataFrame(data)
        
        # Generate Excel
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Threads')
            
        output.seek(0)
        
        filename = f"{project_name}_threads_{datetime.now().strftime('%Y%m%d')}.xlsx"
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        raise e
