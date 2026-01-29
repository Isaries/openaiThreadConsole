-- Migration: Add assistant name support
-- Date: 2026-01-29
-- Description: Add assistants cache table and assistant_id column to messages

-- 1. Create assistants cache table
CREATE TABLE IF NOT EXISTS assistants (
    id VARCHAR(100) PRIMARY KEY,
    name VARCHAR(200),
    project_id VARCHAR(50) NOT NULL,
    last_synced_at INTEGER,
    FOREIGN KEY (project_id) REFERENCES projects(id)
);

-- 2. Add indexes for faster lookups
CREATE INDEX IF NOT EXISTS idx_assistants_project ON assistants(project_id);
CREATE INDEX IF NOT EXISTS idx_assistants_name ON assistants(name);

-- 3. Add assistant_id column to messages table
ALTER TABLE messages ADD COLUMN assistant_id VARCHAR(100);

-- 4. Add index for search performance
CREATE INDEX IF NOT EXISTS idx_messages_assistant ON messages(assistant_id);
