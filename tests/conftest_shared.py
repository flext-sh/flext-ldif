"""Shared fixtures for all tests - eliminates code duplication.

Provides automated fixture generation following factory pattern.
"""

from __future__ import annotations

import pytest

from flext_ldif import (
    FlextLdifParser,
    FlextLdifWriter,
)
from tests import c, m
from tests.test_factory import FlextLdifTestFactory


def _create_sample_schema_attribute() -> m.Ldif.SchemaAttribute:
    return m.Ldif.SchemaAttribute(
        oid=c.RFC.ATTR_OID_CN,
        name=c.RFC.ATTR_NAME_CN,
        desc=None,
        sup=None,
        equality=None,
        ordering=None,
        substr=None,
        syntax=None,
        length=None,
        usage=None,
        x_origin=None,
        x_file_ref=None,
        x_name=None,
        x_alias=None,
        x_oid=None,
    )


def _create_sample_schema_objectclass() -> m.Ldif.SchemaObjectClass:
    return m.Ldif.SchemaObjectClass(
        oid=c.RFC.OC_OID_PERSON,
        name=c.RFC.OC_NAME_PERSON,
        desc=None,
        sup=None,
    )


def _create_sample_acl() -> m.Ldif.Acl:
    return m.Ldif.Acl(raw_acl="test: acl", server_type="rfc")


def _create_real_parser_service() -> FlextLdifParser:
    return FlextLdifParser()


def _create_real_writer_service() -> FlextLdifWriter:
    return FlextLdifWriter()


@pytest.fixture
def real_entry() -> object:
    """Provide a real Entry model for testing."""
    return FlextLdifTestFactory.create_real_entry()


@pytest.fixture
def real_ldif_content() -> str:
    """Provide real LDIF content for testing."""
    return FlextLdifTestFactory.create_real_ldif_content()


@pytest.fixture(params=FlextLdifTestFactory.parametrize_real_data())
def parametrized_real_data(request: pytest.FixtureRequest) -> object:
    """Provide parametrized real test data."""
    return request.param


@pytest.fixture
def large_test_dataset() -> str:
    """Provide large dataset for performance testing."""
    return FlextLdifTestFactory.create_real_ldif_content(entries_count=100)
