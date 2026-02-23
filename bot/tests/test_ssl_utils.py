"""
Tests for ssl_utils — especially the WireGuard fallback.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import asyncio


class TestDirectGostCheck:
    """Tests for _direct_gost_check fallback function."""

    @pytest.mark.asyncio
    async def test_gost_detected(self):
        """_direct_gost_check returns True when GOST is found in output."""
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(b"Cipher    : GOST2012-GOST8912-GOST89\n", b"")
        )
        mock_proc.kill = MagicMock()
        mock_proc.wait = AsyncMock()

        with patch("utils.ssl_utils.asyncio.create_subprocess_exec", return_value=mock_proc):
            from utils.ssl_utils import _direct_gost_check
            result = await _direct_gost_check("example.com", timeout=10)

        assert result is True

    @pytest.mark.asyncio
    async def test_gost_not_detected(self):
        """_direct_gost_check returns False when no GOST in output."""
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(b"Cipher    : TLS_AES_256_GCM_SHA384\n", b"")
        )
        mock_proc.kill = MagicMock()
        mock_proc.wait = AsyncMock()

        with patch("utils.ssl_utils.asyncio.create_subprocess_exec", return_value=mock_proc):
            from utils.ssl_utils import _direct_gost_check
            result = await _direct_gost_check("example.com", timeout=10)

        assert result is False

    @pytest.mark.asyncio
    async def test_timeout_returns_none(self):
        """_direct_gost_check returns None on timeout."""
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError)
        mock_proc.kill = MagicMock()
        mock_proc.wait = AsyncMock()

        with patch("utils.ssl_utils.asyncio.create_subprocess_exec", return_value=mock_proc):
            from utils.ssl_utils import _direct_gost_check
            result = await _direct_gost_check("example.com", timeout=1)

        assert result is None

    @pytest.mark.asyncio
    async def test_openssl_not_found(self):
        """_direct_gost_check returns None when openssl is not installed."""
        with patch(
            "utils.ssl_utils.asyncio.create_subprocess_exec",
            side_effect=FileNotFoundError,
        ):
            from utils.ssl_utils import _direct_gost_check
            result = await _direct_gost_check("example.com", timeout=10)

        assert result is None

    @pytest.mark.asyncio
    async def test_empty_output_returns_none(self):
        """_direct_gost_check returns None on empty output."""
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_proc.kill = MagicMock()
        mock_proc.wait = AsyncMock()

        with patch("utils.ssl_utils.asyncio.create_subprocess_exec", return_value=mock_proc):
            from utils.ssl_utils import _direct_gost_check
            result = await _direct_gost_check("example.com", timeout=10)

        assert result is None
