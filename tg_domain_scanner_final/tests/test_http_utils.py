"""Tests for utils/http_utils.py."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from utils.http_utils import _empty_result, _parse_security_headers


def test_empty_result_structure():
    r = _empty_result()
    assert r["redirect_chain"] == []
    assert r["final_url"] is None
    assert r["status_code"] is None
    assert r["server"] is None
    assert r["https_available"] is False
    assert r["http_to_https_redirect"] is False
    assert isinstance(r["security_headers"], dict)
    assert all(v is False for v in r["security_headers"].values())


def test_parse_security_headers_present():
    class FakeHeaders:
        _d = {
            "strict-transport-security": "max-age=31536000",
            "x-frame-options": "DENY",
            "content-security-policy": "default-src 'self'",
        }
        def get(self, key, default=None):
            return self._d.get(key, default)

    result = _parse_security_headers(FakeHeaders())
    assert result["strict_transport_security"] == "max-age=31536000"
    assert result["x_frame_options"] == "DENY"
    assert result["content_security_policy"] == "default-src 'self'"
    assert result["x_content_type_options"] is False
    assert result["permissions_policy"] is False
    assert result["x_xss_protection"] is False


def test_parse_security_headers_empty():
    class EmptyHeaders:
        def get(self, key, default=None):
            return default

    result = _parse_security_headers(EmptyHeaders())
    assert all(v is False for v in result.values())
