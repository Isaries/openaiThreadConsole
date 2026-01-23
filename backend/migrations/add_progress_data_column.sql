-- Migration: Add progress_data column to search_result_chunks table
-- Date: 2026-01-23
-- Description: Add progress_data column for tracking search task progress

-- Add the new column
ALTER TABLE search_result_chunks ADD COLUMN progress_data TEXT;

-- Optional: Add index if needed for performance
-- CREATE INDEX idx_search_result_chunks_progress ON search_result_chunks(task_id, page_index) WHERE page_index = -1;
