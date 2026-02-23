"""
Unit тесты для domain_normalizer.
"""

import pytest
from utils.domain_normalizer import normalize_domains, normalize_domain


class TestNormalizeDomain:
    """Тесты для функции normalize_domain."""
    
    def test_simple_domain(self):
        """Тест простого домена."""
        assert normalize_domain("example.com") == "example.com"
    
    def test_domain_with_https(self):
        """Тест домена с https://."""
        assert normalize_domain("https://example.com") == "example.com"
    
    def test_domain_with_http(self):
        """Тест домена с http://."""
        assert normalize_domain("http://example.com") == "example.com"
    
    def test_domain_with_path(self):
        """Тест домена с путем."""
        assert normalize_domain("https://example.com/path/to/page") == "example.com"
    
    def test_domain_with_query(self):
        """Тест домена с query параметрами."""
        assert normalize_domain("https://example.com?param=value") == "example.com"
    
    def test_domain_with_port(self):
        """Тест домена с портом."""
        assert normalize_domain("example.com:8080") == "example.com"
    
    def test_domain_with_subdomain(self):
        """Тест домена с поддоменом."""
        assert normalize_domain("sub.example.com") == "sub.example.com"
    
    def test_invalid_domain(self):
        """Тест некорректного домена."""
        assert normalize_domain("not a domain") is None
        assert normalize_domain("") is None
        assert normalize_domain("   ") is None


class TestNormalizeDomains:
    """Тесты для функции normalize_domains."""
    
    def test_single_domain(self):
        """Тест одного домена."""
        assert normalize_domains(["example.com"]) == ["example.com"]
    
    def test_multiple_domains(self):
        """Тест нескольких доменов."""
        domains = ["example.com", "test.ru", "site.org"]
        assert normalize_domains(domains) == domains
    
    def test_mixed_formats(self):
        """Тест доменов в разных форматах."""
        input_domains = [
            "example.com",
            "https://test.ru",
            "http://site.org/path",
            "sub.example.com:8080"
        ]
        expected = ["example.com", "test.ru", "site.org", "sub.example.com"]
        assert normalize_domains(input_domains) == expected
    
    def test_with_invalid_domains(self):
        """Тест с некорректными доменами."""
        input_domains = ["example.com", "not a domain", "test.ru"]
        result = normalize_domains(input_domains)
        assert "example.com" in result
        assert "test.ru" in result
        assert "not a domain" not in result
    
    def test_empty_list(self):
        """Тест пустого списка."""
        assert normalize_domains([]) == []
    
    def test_duplicates(self):
        """Тест дубликатов."""
        domains = ["example.com", "example.com", "test.ru"]
        result = normalize_domains(domains)
        assert result == ["example.com", "test.ru"] or result == ["test.ru", "example.com"]
    
    def test_talent_mos_ru(self):
        """Тест домена talent.mos.ru с протоколом."""
        assert normalize_domain("https://talent.mos.ru") == "talent.mos.ru"
        assert normalize_domain("http://talent.mos.ru") == "talent.mos.ru"
        assert normalize_domain("talent.mos.ru") == "talent.mos.ru"
    
    def test_domain_with_various_protocols(self):
        """Тест доменов с различными протоколами."""
        assert normalize_domain("ftp://example.com") == "example.com"
        assert normalize_domain("ws://example.com") == "example.com"
        assert normalize_domain("tcp://example.com") == "example.com"
    
    def test_domain_with_complex_path(self):
        """Тест домена со сложным путем."""
        assert normalize_domain("https://example.com/path/to/page?param=value&other=123#anchor") == "example.com"
    
    def test_domain_with_unicode(self):
        """Тест домена с Unicode символами (если поддерживается)."""
        # Проверяем, что функция не падает на Unicode
        result = normalize_domain("https://пример.рф")
        # Может вернуть None или Punycode в зависимости от наличия idna
        assert result is None or isinstance(result, str)
    
    def test_domain_with_trailing_slash(self):
        """Тест домена с завершающим слэшем."""
        assert normalize_domain("https://example.com/") == "example.com"
    
    def test_domain_with_multiple_slashes(self):
        """Тест домена с множественными слэшами."""
        assert normalize_domain("https://example.com///path") == "example.com"
    
    def test_domain_with_spaces(self):
        """Тест домена с пробелами (должен очищаться)."""
        assert normalize_domain("  https://example.com  ") == "example.com"
        assert normalize_domain("example.com ") == "example.com"
    
    def test_domain_with_special_chars_in_path(self):
        """Тест домена со специальными символами в пути."""
        assert normalize_domain("https://example.com/path%20with%20spaces") == "example.com"
    
    def test_invalid_domains_edge_cases(self):
        """Тест некорректных доменов - edge cases."""
        assert normalize_domain("http://") is None
        assert normalize_domain("https://") is None
        assert normalize_domain("://example.com") == "example.com"  # extracts domain from malformed URL
        assert normalize_domain("example") is None  # Нет TLD
        assert normalize_domain(".example.com") == "example.com"  # strips leading dot





