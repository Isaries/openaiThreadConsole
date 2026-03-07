"""
Tests for Excel service — sanitization, import parsing, export.
"""
import io
import pytest
import pandas as pd


class TestSanitizeForExcel:

    def test_normal_text(self, app):
        with app.app_context():
            from app.services.excel_service import sanitize_for_excel
            assert sanitize_for_excel("hello") == "hello"

    def test_formula_injection_equals(self, app):
        with app.app_context():
            from app.services.excel_service import sanitize_for_excel
            assert sanitize_for_excel("=CMD()") == "'=CMD()"

    def test_formula_injection_plus(self, app):
        with app.app_context():
            from app.services.excel_service import sanitize_for_excel
            assert sanitize_for_excel("+1+2") == "'+1+2"

    def test_formula_injection_minus(self, app):
        with app.app_context():
            from app.services.excel_service import sanitize_for_excel
            assert sanitize_for_excel("-1-2") == "'-1-2"

    def test_formula_injection_at(self, app):
        with app.app_context():
            from app.services.excel_service import sanitize_for_excel
            assert sanitize_for_excel("@SUM(A1)") == "'@SUM(A1)"

    def test_empty(self, app):
        with app.app_context():
            from app.services.excel_service import sanitize_for_excel
            assert sanitize_for_excel("") == ""
            assert sanitize_for_excel(None) == ""


class TestParseExcelForImport:

    def _make_excel_buffer(self, data):
        """Helper: create an in-memory Excel file from a list of dicts."""
        df = pd.DataFrame(data)
        buf = io.BytesIO()
        df.to_excel(buf, index=False)
        buf.seek(0)
        return buf

    def test_valid_import(self, app, db):
        with app.app_context():
            from app.services.excel_service import parse_excel_for_import
            buf = self._make_excel_buffer([
                {'thread_id': 'thread_aaa', 'remark': 'Remark A'},
                {'thread_id': 'thread_bbb', 'remark': 'Remark B'},
            ])
            data_map, err = parse_excel_for_import(buf)
            assert err is None
            assert len(data_map) == 2
            assert data_map['thread_aaa'] == 'Remark A'

    def test_missing_thread_id_column(self, app, db):
        with app.app_context():
            from app.services.excel_service import parse_excel_for_import
            buf = self._make_excel_buffer([{'name': 'foo'}])
            data_map, err = parse_excel_for_import(buf)
            assert data_map is None
            assert err is not None
            assert "thread_id" in err

    def test_filters_non_thread_ids(self, app, db):
        with app.app_context():
            from app.services.excel_service import parse_excel_for_import
            buf = self._make_excel_buffer([
                {'thread_id': 'thread_ok'},
                {'thread_id': 'not-a-thread'},
                {'thread_id': 'random_123'},
            ])
            data_map, err = parse_excel_for_import(buf)
            assert err is None
            assert len(data_map) == 1
            assert 'thread_ok' in data_map


class TestProcessImportData:

    def test_add_new_threads(self, app, db, sample_project):
        with app.app_context():
            from app.services.excel_service import process_import_data
            stats = process_import_data(sample_project.id, {
                'thread_new1': 'Remark 1',
                'thread_new2': 'Remark 2',
            }, action='add')
            assert stats['added'] == 2
            assert 'error' not in stats

    def test_delete_threads(self, app, db, sample_project, sample_thread):
        with app.app_context():
            from app.services.excel_service import process_import_data
            stats = process_import_data(sample_project.id, {
                sample_thread.thread_id: None,
            }, action='delete')
            assert stats['deleted'] == 1

    def test_project_not_found(self, app, db):
        with app.app_context():
            from app.services.excel_service import process_import_data
            stats = process_import_data('nonexistent', {'thread_x': None})
            assert 'error' in stats
