"""
Tests for WireGuard utilities.
"""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path


class TestWireGuardUtils:
    """Tests for wireguard_utils module."""

    def test_check_wg_connection_no_config(self, tmp_path):
        """check_wg_connection returns error when no config found."""
        with patch("utils.wireguard_utils._get_wg_config_path") as mock_path:
            mock_path.return_value = tmp_path / "nonexistent.conf"

            from utils.wireguard_utils import check_wg_connection
            result = check_wg_connection()

            assert result["config_found"] is False
            assert result["last_error"] is not None

    def test_check_wg_connection_with_config(self, tmp_path):
        """check_wg_connection parses config when found."""
        conf = tmp_path / "TGBOT.conf"
        conf.write_text("[Interface]\nAddress = 10.0.0.2/32\nPrivateKey = dummy\n")

        with patch("utils.wireguard_utils._get_wg_config_path", return_value=conf), \
             patch("utils.wireguard_utils._check_wg_container_available", return_value=False):
            from utils.wireguard_utils import check_wg_connection
            result = check_wg_connection()

            assert result["config_found"] is True
            assert result["interface_ip"] == "10.0.0.2"
            assert result["interface_up"] is False

    def test_container_available_resolves(self):
        """_check_wg_container_available returns True when DNS resolves."""
        with patch("utils.wireguard_utils.socket.gethostbyname", return_value="172.18.0.2"):
            from utils.wireguard_utils import _check_wg_container_available
            assert _check_wg_container_available() is True

    def test_container_unavailable_on_dns_failure(self):
        """_check_wg_container_available returns False when DNS fails."""
        import socket
        with patch("utils.wireguard_utils.socket.gethostbyname", side_effect=socket.gaierror):
            from utils.wireguard_utils import _check_wg_container_available
            assert _check_wg_container_available() is False

    def test_ensure_wg_interface_down_noop(self):
        """ensure_wg_interface_down always returns True (no-op in Docker mode)."""
        from utils.wireguard_utils import ensure_wg_interface_down
        assert ensure_wg_interface_down() is True
