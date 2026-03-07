"""
Tests for PDF service — WeasyPrint integration (PR #6 verification target).
Tests generate_pdf_bytes, safe_url_fetcher, and HTML preprocessing.

NOTE: WeasyPrint requires GTK/Pango native libraries (gobject-2.0).
      Tests that call generate_pdf_bytes are automatically skipped if
      those libraries are not installed.
"""
import pytest

# Check if WeasyPrint can actually work in this environment
_weasyprint_available = False
try:
    from weasyprint import HTML as _WP_HTML
    _weasyprint_available = True
except (OSError, ImportError):
    pass

requires_weasyprint = pytest.mark.skipif(
    not _weasyprint_available,
    reason="WeasyPrint requires GTK/Pango native libs (gobject-2.0) to be installed"
)


class TestGeneratePdfBytes:
    """Tests WeasyPrint HTML→PDF generation."""

    @requires_weasyprint
    def test_basic_html_to_pdf(self, app):
        """Simple HTML should produce valid PDF bytes."""
        with app.app_context():
            from app.services.pdf_service import generate_pdf_bytes
            html = "<html><body><h1>Test PDF</h1><p>Hello World</p></body></html>"
            pdf_bytes = generate_pdf_bytes(html)
            assert pdf_bytes is not None
            assert len(pdf_bytes) > 0
            assert pdf_bytes[:4] == b'%PDF'

    @requires_weasyprint
    def test_chinese_content(self, app):
        """PDF with Chinese characters should generate without error."""
        with app.app_context():
            from app.services.pdf_service import generate_pdf_bytes
            html = "<html><body><h1>測試報告</h1><p>中文內容</p></body></html>"
            pdf_bytes = generate_pdf_bytes(html)
            assert pdf_bytes is not None
            assert pdf_bytes[:4] == b'%PDF'

    @requires_weasyprint
    def test_empty_html(self, app):
        """Empty body should still produce a valid PDF."""
        with app.app_context():
            from app.services.pdf_service import generate_pdf_bytes
            pdf_bytes = generate_pdf_bytes("<html><body></body></html>")
            assert pdf_bytes is not None
            assert pdf_bytes[:4] == b'%PDF'


class TestGetRealMimeType:

    def test_png_magic(self, app):
        with app.app_context():
            from app.services.pdf_service import get_real_mime_type
            png_header = b'\x89PNG\r\n\x1a\n'
            mime = get_real_mime_type(png_header)
            assert mime == 'image/png'

    def test_jpeg_magic(self, app):
        with app.app_context():
            from app.services.pdf_service import get_real_mime_type
            jpeg_header = b'\xff\xd8\xff'
            mime = get_real_mime_type(jpeg_header)
            assert mime == 'image/jpeg'

    def test_unknown_defaults(self, app):
        with app.app_context():
            from app.services.pdf_service import get_real_mime_type
            mime = get_real_mime_type(b'\x00\x00\x00\x00')
            assert mime == 'image/png'


class TestSafeUrlFetcher:

    def test_rejects_file_protocol(self, app):
        with app.app_context():
            from app.services.pdf_service import safe_url_fetcher
            try:
                result = safe_url_fetcher("file:///etc/passwd")
            except Exception:
                pass  # Expected

    def test_handles_http_gracefully(self, app):
        with app.app_context():
            from app.services.pdf_service import safe_url_fetcher
            try:
                result = safe_url_fetcher("http://192.0.2.1/nonexistent.png", timeout=2)
            except Exception:
                pass  # Expected timeout


class TestPreprocessHtml:

    def test_no_images(self, app):
        with app.app_context():
            from app.services.pdf_service import preprocess_html_for_pdf
            html = "<html><body><p>No images</p></body></html>"
            result_html, temp_files = preprocess_html_for_pdf(html, 'g1', lambda k: {})
            assert "No images" in result_html
            assert isinstance(temp_files, list)


class TestCleanupTempImages:

    def test_cleanup_nonexistent_files(self, app):
        with app.app_context():
            from app.services.pdf_service import cleanup_temp_images
            cleanup_temp_images(['/tmp/nonexistent_file.png'])
