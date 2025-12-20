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

