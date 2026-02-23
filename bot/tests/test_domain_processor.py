"""
Tests for domain_processor — especially validate_and_normalize_domains fix.
"""

import pytest
from utils.domain_processor import validate_and_normalize_domains


class TestValidateAndNormalizeDomains:
    """Tests for the fixed validate_and_normalize_domains."""

    def test_urls_are_not_marked_as_bad(self):
        """URLs that normalize to valid domains should NOT appear in bad list."""
        domains, bad = validate_and_normalize_domains(
            "https://example.com/path http://test.ru?q=1"
        )
        assert "example.com" in domains
        assert "test.ru" in domains
        assert len(bad) == 0

    def test_truly_invalid_items_are_bad(self):
        """Items that don't normalize to a valid domain should appear in bad."""
        domains, bad = validate_and_normalize_domains("notadomain 123 example.com")
        assert "example.com" in domains
        assert "notadomain" in bad or "123" in bad

    def test_duplicates_deduplicated(self):
        """Duplicate inputs yield unique output."""
        domains, bad = validate_and_normalize_domains(
            "example.com https://example.com example.com"
        )
        assert domains.count("example.com") == 1

    def test_empty_input(self):
        """Empty input returns empty lists."""
        domains, bad = validate_and_normalize_domains("")
        assert domains == []
        assert bad == []

    def test_mixed_valid_and_invalid(self):
        """Mixed input correctly partitions items."""
        domains, bad = validate_and_normalize_domains(
            "https://site.com, , , baddomain, test.ru"
        )
        assert "site.com" in domains
        assert "test.ru" in domains
        assert "baddomain" in bad

    def test_domain_with_port(self):
        """Domain with port normalizes correctly."""
        domains, bad = validate_and_normalize_domains("example.com:8080")
        assert "example.com" in domains
        assert len(bad) == 0
