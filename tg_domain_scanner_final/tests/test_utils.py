import pytest
from utils.dns_utils import fetch_dns
from utils.ssl_utils import fetch_ssl
from utils.waf_utils import test_waf

@pytest.mark.asyncio
async def test_dns():
    res = await fetch_dns("example.com", timeout=10)
    assert res["A"]

@pytest.mark.asyncio
async def test_ssl():
    res = await fetch_ssl("example.com")
    assert res["CN"]

@pytest.mark.asyncio
async def test_waf_returns_tuple():
    """test_waf returns (bool, str) tuple."""
    result = await test_waf("example.com", timeout=10)
    assert isinstance(result, tuple)
    assert len(result) == 2
    waf_enabled, waf_method = result
    assert isinstance(waf_enabled, bool)
    assert isinstance(waf_method, str)
    assert waf_method in ("policy", "light")
