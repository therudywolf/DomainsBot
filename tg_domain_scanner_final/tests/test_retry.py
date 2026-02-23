"""Tests for utils/retry.py async_retry decorator."""

import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from utils.retry import async_retry


@pytest.mark.asyncio
async def test_succeeds_on_first_try():
    call_count = 0

    @async_retry(max_retries=2, base_delay=0.01)
    async def ok():
        nonlocal call_count
        call_count += 1
        return "ok"

    result = await ok()
    assert result == "ok"
    assert call_count == 1


@pytest.mark.asyncio
async def test_retries_on_failure_then_succeeds():
    call_count = 0

    @async_retry(max_retries=2, base_delay=0.01)
    async def flaky():
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise ValueError("transient")
        return "recovered"

    result = await flaky()
    assert result == "recovered"
    assert call_count == 3


@pytest.mark.asyncio
async def test_raises_after_max_retries():
    call_count = 0

    @async_retry(max_retries=1, base_delay=0.01)
    async def always_fail():
        nonlocal call_count
        call_count += 1
        raise RuntimeError("permanent")

    with pytest.raises(RuntimeError, match="permanent"):
        await always_fail()
    assert call_count == 2  # initial + 1 retry


@pytest.mark.asyncio
async def test_only_catches_specified_exceptions():
    call_count = 0

    @async_retry(max_retries=2, base_delay=0.01, exceptions=(ValueError,))
    async def type_error():
        nonlocal call_count
        call_count += 1
        raise TypeError("wrong type")

    with pytest.raises(TypeError):
        await type_error()
    assert call_count == 1  # no retry for TypeError


@pytest.mark.asyncio
async def test_preserves_function_metadata():

    @async_retry()
    async def my_func():
        """My docstring."""

    assert my_func.__name__ == "my_func"
    assert my_func.__doc__ == "My docstring."
