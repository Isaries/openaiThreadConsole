import pandas as pd
import io
from flask import send_file
from datetime import datetime
from ..models import Thread, Project
from ..extensions import db

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
                
            thread_data_map[tid] = remark_val
            
        return thread_data_map, None
        
    except Exception as e:
        return None, f"解析失敗: {str(e)}"

def generate_excel_export(project_id, project_name):
    """
    Generates an Excel file for the threads of a project.
    """
    try:
        threads = Thread.query.filter_by(project_id=project_id).all()
        data = []
        for t in threads:
            data.append({
                'thread_id': t.thread_id,
                'remark': t.remark
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
