"""Shared fixtures for all tests - eliminates code duplication.

Provides automated fixture generation following factory pattern.
"""

from __future__ import annotations

import pytest

from tests import m, u


@pytest.fixture
def real_entry() -> m.Ldif.Entry:
    """Provide a real Entry model for testing."""
    return u.Ldif.Tests.Factory.create_real_entry()


@pytest.fixture
def real_ldif_content() -> str:
    """Provide real LDIF content for testing."""
    return u.Ldif.Tests.Factory.create_real_ldif_content()


@pytest.fixture(params=u.Ldif.Tests.Factory.parametrize_real_data())
def parametrized_real_data(request: pytest.FixtureRequest) -> m.Ldif.Tests.LdifTestData:
    """Provide parametrized real test data."""
    return request.param


@pytest.fixture
def large_test_dataset() -> str:
    """Provide large dataset for performance testing."""
    return u.Ldif.Tests.Factory.create_real_ldif_content(entries_count=100)
