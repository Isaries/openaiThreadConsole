"""
Tests for app/utils.py — template filters, IP handling, date helpers, filename utils.
"""
import pytest
from markupsafe import Markup


class TestNl2br:

    def test_basic(self, app):
        with app.app_context():
            from app.utils import nl2br
            result = nl2br("line1\nline2")
            assert "<br>" in str(result)

    def test_empty(self, app):
        with app.app_context():
            from app.utils import nl2br
            assert nl2br("") == ""
            assert nl2br(None) == ""

    def test_xss_escaped(self, app):
        with app.app_context():
            from app.utils import nl2br
            result = str(nl2br("<script>alert(1)</script>"))
            assert "<script>" not in result


class TestRenderMarkdown:

    def test_basic(self, app):
        with app.app_context():
            from app.utils import render_markdown
            result = render_markdown("**bold**")
            assert "<strong>bold</strong>" in result

    def test_fenced_code(self, app):
        with app.app_context():
            from app.utils import render_markdown
            result = render_markdown("```python\nprint('hi')\n```")
            assert "<code" in result

    def test_empty(self, app):
        with app.app_context():
            from app.utils import render_markdown
            assert render_markdown("") == ""


class TestSanitizeHtml:

    def test_allows_safe_tags(self, app):
        with app.app_context():
            from app.utils import sanitize_html
            result = sanitize_html("<b>bold</b> <i>italic</i>")
            assert "<b>bold</b>" in result
            assert "<i>italic</i>" in result

    def test_strips_script(self, app):
        with app.app_context():
            from app.utils import sanitize_html
            result = sanitize_html("<script>alert(1)</script>Safe")
            assert "<script>" not in result
            assert "Safe" in result

    def test_empty(self, app):
        with app.app_context():
            from app.utils import sanitize_html
            assert sanitize_html("") == ""


class TestMaskCredential:

    def test_normal(self, app):
        with app.app_context():
            from app.utils import mask_credential
            result = mask_credential("sk-abcdef123456")
            assert result.startswith("s")
            assert result.endswith("6")
            assert "********" in result

    def test_short(self, app):
        with app.app_context():
            from app.utils import mask_credential
            assert mask_credential("ab") == "**"

    def test_empty(self, app):
        with app.app_context():
            from app.utils import mask_credential
            assert mask_credential("") == ""


class TestGetClientIp:

    def test_x_real_ip(self, app):
        with app.app_context():
            with app.test_request_context(headers={'X-Real-Ip': '10.0.0.1'}):
                from app.utils import get_client_ip
                assert get_client_ip() == '10.0.0.1'

    def test_x_forwarded_for(self, app):
        with app.app_context():
            with app.test_request_context(headers={'X-Forwarded-For': '1.2.3.4, 5.6.7.8'}):
                from app.utils import get_client_ip
                assert get_client_ip() == '1.2.3.4'

    def test_no_headers(self, app):
        with app.app_context():
            with app.test_request_context():
                from app.utils import get_client_ip
                ip = get_client_ip()
                assert ip  # Should fallback to remote_addr or '0.0.0.0'


class TestUnixToUtc8:

    def test_valid_timestamp(self, app):
        with app.app_context():
            from app.utils import unix_to_utc8
            # 2024-01-01 08:00:00 UTC+8 = 1704067200
            result = unix_to_utc8(1704067200)
            assert "2024-01-01" in result

    def test_none(self, app):
        with app.app_context():
            from app.utils import unix_to_utc8
            assert unix_to_utc8(None) == 'Unknown Time'

    def test_invalid(self, app):
        with app.app_context():
            from app.utils import unix_to_utc8
            assert unix_to_utc8("not_a_number") == 'Invalid Time'


class TestSanitizeFilename:

    def test_basic(self, app):
        with app.app_context():
            from app.utils import sanitize_filename
            assert sanitize_filename("hello world.txt") == "hello_world.txt"

    def test_dangerous_chars(self, app):
        with app.app_context():
            from app.utils import sanitize_filename
            result = sanitize_filename("file<>:\"/\\|?*.txt")
            assert "<" not in result
            assert ">" not in result

    def test_chinese(self, app):
        with app.app_context():
            from app.utils import sanitize_filename
            result = sanitize_filename("測試報告.pdf")
            assert "測試報告" in result

    def test_empty(self, app):
        with app.app_context():
            from app.utils import sanitize_filename
            assert sanitize_filename("") == "untitled"

    def test_truncation(self, app):
        with app.app_context():
            from app.utils import sanitize_filename
            long_name = "a" * 200 + ".pdf"
            result = sanitize_filename(long_name)
            assert len(result) <= 104  # 100 + .pdf


class TestGeneratePdfFilename:

    def test_with_remark(self, app):
        with app.app_context():
            from app.utils import generate_pdf_filename
            result = generate_pdf_filename("thread_abc", "我的報告")
            assert "我的報告" in result
            assert "thread_abc" in result
            assert result.endswith(".pdf")

    def test_without_remark(self, app):
        with app.app_context():
            from app.utils import generate_pdf_filename
            result = generate_pdf_filename("thread_xyz")
            assert result == "thread_thread_xyz.pdf"


class TestEncodeFilenameHeader:

    def test_ascii(self, app):
        with app.app_context():
            from app.utils import encode_filename_header
            result = encode_filename_header("report.pdf")
            assert "attachment;" in result
            assert "UTF-8''" in result

    def test_chinese(self, app):
        with app.app_context():
            from app.utils import encode_filename_header
            result = encode_filename_header("報告.pdf")
            assert "UTF-8''" in result
            # Chinese chars should be percent-encoded
            assert "%" in result
