"""
Tests for WAF monitoring fix: test_waf returns tuple, monitoring should unpack it.
"""

import pytest
import sys
from unittest.mock import AsyncMock, patch, MagicMock

# Stub out aiogram before importing monitoring so it doesn't fail
aiogram_mock = MagicMock()
sys.modules.setdefault("aiogram", aiogram_mock)
sys.modules.setdefault("aiogram.types", aiogram_mock)
sys.modules.setdefault("aiogram.enums", aiogram_mock)

# Stub utils.chat_settings in case it can't import
chat_settings_mock = MagicMock()
chat_settings_mock.get_notification_chat_id = MagicMock(return_value=None)
sys.modules.setdefault("utils.chat_settings", chat_settings_mock)


class TestMonitoringWAFUnpacking:
    """Verify that _get_domain_state correctly unpacks test_waf tuple results."""

    @pytest.mark.asyncio
    async def test_waf_tuple_unpacked_correctly(self):
        """_get_domain_state should unpack (True, 'policy') into waf=True."""
        with patch.dict("sys.modules", {
            "utils.file_utils": MagicMock(
                async_read_json=AsyncMock(return_value={}),
                async_write_json=AsyncMock(),
            ),
        }):
            # Need to import after patching
            import importlib
            if "utils.monitoring" in sys.modules:
                importlib.reload(sys.modules["utils.monitoring"])

            with patch("utils.monitoring.fetch_dns", new_callable=AsyncMock) as mock_dns, \
                 patch("utils.monitoring.fetch_ssl", new_callable=AsyncMock) as mock_ssl, \
                 patch("utils.monitoring.test_waf", new_callable=AsyncMock) as mock_waf, \
                 patch("utils.monitoring.settings") as mock_settings:

                mock_settings.DNS_TIMEOUT = 5
                mock_dns.return_value = {"A": ["1.2.3.4"], "AAAA": [], "MX": [], "NS": []}
                mock_ssl.return_value = {
                    "gost": True,
                    "NotAfter": None,
                    "GostNotAfter": None,
                }
                mock_waf.return_value = (True, "policy")

                from utils.monitoring import _get_domain_state
                state = await _get_domain_state("example.com", user_id=1)

                assert state["waf"] is True

    @pytest.mark.asyncio
    async def test_waf_false_tuple_unpacked(self):
        """_get_domain_state should unpack (False, 'light') into waf=False."""
        with patch.dict("sys.modules", {
            "utils.file_utils": MagicMock(
                async_read_json=AsyncMock(return_value={}),
                async_write_json=AsyncMock(),
            ),
        }):
            with patch("utils.monitoring.fetch_dns", new_callable=AsyncMock) as mock_dns, \
                 patch("utils.monitoring.fetch_ssl", new_callable=AsyncMock) as mock_ssl, \
                 patch("utils.monitoring.test_waf", new_callable=AsyncMock) as mock_waf, \
                 patch("utils.monitoring.settings") as mock_settings:

                mock_settings.DNS_TIMEOUT = 5
                mock_dns.return_value = {"A": [], "AAAA": [], "MX": [], "NS": []}
                mock_ssl.return_value = {"gost": False, "NotAfter": None, "GostNotAfter": None}
                mock_waf.return_value = (False, "light")

                from utils.monitoring import _get_domain_state
                state = await _get_domain_state("example.com", user_id=1)

                assert state["waf"] is False

    @pytest.mark.asyncio
    async def test_waf_exception_handled(self):
        """_get_domain_state should handle test_waf exceptions gracefully."""
        with patch.dict("sys.modules", {
            "utils.file_utils": MagicMock(
                async_read_json=AsyncMock(return_value={}),
                async_write_json=AsyncMock(),
            ),
        }):
            with patch("utils.monitoring.fetch_dns", new_callable=AsyncMock) as mock_dns, \
                 patch("utils.monitoring.fetch_ssl", new_callable=AsyncMock) as mock_ssl, \
                 patch("utils.monitoring.test_waf", new_callable=AsyncMock) as mock_waf, \
                 patch("utils.monitoring.settings") as mock_settings:

                mock_settings.DNS_TIMEOUT = 5
                mock_dns.return_value = {"A": [], "AAAA": [], "MX": [], "NS": []}
                mock_ssl.return_value = {"gost": False, "NotAfter": None, "GostNotAfter": None}
                mock_waf.side_effect = Exception("WAF check failed")

                from utils.monitoring import _get_domain_state
                state = await _get_domain_state("example.com", user_id=1)

                assert state["waf"] is False
