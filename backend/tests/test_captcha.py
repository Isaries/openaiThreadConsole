"""
Tests for CaptchaService — SVG CAPTCHA generation (text and math).
"""
import pytest


class TestCaptchaTextMode:

    def test_generate_normal_returns_svg(self, app):
        with app.app_context():
            from app.services.captcha_service import CaptchaService
            result = CaptchaService.generate(mode='normal')
            assert 'image' in result
            assert 'answer' in result
            assert result['content_type'] == 'image/svg+xml'
            assert b'<svg' in result['image']

    def test_normal_answer_length(self, app):
        with app.app_context():
            from app.services.captcha_service import CaptchaService
            result = CaptchaService.generate(mode='normal')
            assert len(result['answer']) == 4

    def test_normal_answer_chars(self, app):
        with app.app_context():
            from app.services.captcha_service import CaptchaService
            valid_chars = set('ABCDEFGHJKLMNPQRSTUVWXYZ23456789')
            for _ in range(10):
                result = CaptchaService.generate(mode='normal')
                for ch in result['answer']:
                    assert ch in valid_chars


class TestCaptchaMathMode:

    def test_generate_math_returns_svg(self, app):
        with app.app_context():
            from app.services.captcha_service import CaptchaService
            result = CaptchaService.generate(mode='math')
            assert b'<svg' in result['image']
            assert result['content_type'] == 'image/svg+xml'

    def test_math_answer_is_numeric(self, app):
        with app.app_context():
            from app.services.captcha_service import CaptchaService
            for _ in range(20):
                result = CaptchaService.generate(mode='math')
                # Answer should be parseable as integer
                int(result['answer'])

    def test_math_svg_width_larger(self, app):
        """Math captcha SVG should be wider than text captcha."""
        with app.app_context():
            from app.services.captcha_service import CaptchaService
            text_result = CaptchaService.generate(mode='normal')
            math_result = CaptchaService.generate(mode='math')
            assert b'width="200"' in math_result['image']
            assert b'width="120"' in text_result['image']
