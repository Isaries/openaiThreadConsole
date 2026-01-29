-- migrations/add_pdf_export_tasks.sql
-- Add support for batch PDF export background tasks

CREATE TABLE IF NOT EXISTS pdf_export_tasks (
    id VARCHAR(100) PRIMARY KEY,
    user_id INTEGER NOT NULL,
    project_id VARCHAR(50) NOT NULL,
    thread_count INTEGER,
    status VARCHAR(20) NOT NULL,
    progress_current INTEGER DEFAULT 0,
    progress_total INTEGER,
    file_path VARCHAR(500),
    error_message TEXT,
    created_at INTEGER NOT NULL,
    completed_at INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (project_id) REFERENCES projects(id)
);

CREATE INDEX IF NOT EXISTS idx_pdf_export_user ON pdf_export_tasks(user_id);
CREATE INDEX IF NOT EXISTS idx_pdf_export_created ON pdf_export_tasks(created_at);
