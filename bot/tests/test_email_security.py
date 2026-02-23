"""Tests for utils/email_security.py."""

import asyncio
import sys
import os
from unittest.mock import AsyncMock, patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from utils.email_security import (
    _extract_spf,
    _extract_dmarc_policy,
    fetch_email_security,
)


def test_extract_spf_found():
    records = ["v=spf1 include:_spf.google.com ~all", "other record"]
    assert _extract_spf(records) == "v=spf1 include:_spf.google.com ~all"


def test_extract_spf_not_found():
    records = ["some txt record", "another"]
    assert _extract_spf(records) is None


def test_extract_spf_empty():
    assert _extract_spf([]) is None


def test_extract_dmarc_policy_reject():
    record = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
    assert _extract_dmarc_policy(record) == "reject"


def test_extract_dmarc_policy_none():
    record = "v=DMARC1; p=none"
    assert _extract_dmarc_policy(record) == "none"


def test_extract_dmarc_policy_quarantine():
    record = "v=DMARC1;p=quarantine;sp=quarantine"
    assert _extract_dmarc_policy(record) == "quarantine"


def test_extract_dmarc_policy_missing():
    record = "v=DMARC1; rua=mailto:a@b.com"
    assert _extract_dmarc_policy(record) is None


@pytest.mark.asyncio
async def test_fetch_email_security_full():
    spf_txt = "v=spf1 include:example.com ~all"
    dmarc_txt = "v=DMARC1; p=reject; rua=mailto:d@example.com"

    async def mock_query_txt(name, timeout):
        if name.startswith("_dmarc."):
            return [dmarc_txt]
        return [spf_txt, "unrelated"]

    with patch("utils.email_security._query_txt", side_effect=mock_query_txt):
        result = await fetch_email_security("test-full-email-sec.example.com")

    assert result["spf"] == spf_txt
    assert result["spf_valid"] is True
    assert result["dmarc"] == dmarc_txt
    assert result["dmarc_policy"] == "reject"


@pytest.mark.asyncio
async def test_fetch_email_security_no_records():
    async def mock_query_txt(name, timeout):
        return []

    with patch("utils.email_security._query_txt", side_effect=mock_query_txt):
        result = await fetch_email_security("test-no-records-email-sec.example.com")

    assert result["spf"] is None
    assert result["spf_valid"] is False
    assert result["dmarc"] is None
    assert result["dmarc_policy"] is None
