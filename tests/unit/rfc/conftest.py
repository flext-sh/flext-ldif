"""Shared fixtures for RFC tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

import pytest

from flext_ldif import (
    FlextLdifConstants,
    FlextLdifParser,
    FlextLdifWriter,
)
from flext_ldif.models import m
from flext_ldif.servers.rfc import FlextLdifServersRfc
from tests import c


@pytest.fixture(autouse=True)
def cleanup_state() -> None:
    """Autouse fixture to clean shared state between tests.

    Runs after each test to prevent state pollution to subsequent tests.
    Ensures test isolation even when fixtures have shared state.
    """
    return
    # Post-test cleanup - ensures each test has clean state


@pytest.fixture
def rfc_quirk() -> FlextLdifServersRfc:
    """Provides RFC quirk instance for tests."""
    return FlextLdifServersRfc()


@pytest.fixture
def rfc_schema_quirk(rfc_quirk: FlextLdifServersRfc) -> FlextLdifServersRfc.Schema:
    """Provides RFC Schema quirk instance for tests."""
    return cast("FlextLdifServersRfc.Schema", rfc_quirk.schema_quirk)


@pytest.fixture
def rfc_entry_quirk(rfc_quirk: FlextLdifServersRfc) -> FlextLdifServersRfc.Entry:
    """Provides RFC Entry quirk instance for tests."""
    return cast("FlextLdifServersRfc.Entry", rfc_quirk.entry_quirk)


@pytest.fixture
def rfc_acl_quirk(rfc_quirk: FlextLdifServersRfc) -> FlextLdifServersRfc.Acl:
    """Provides RFC ACL quirk instance for tests."""
    return cast("FlextLdifServersRfc.Acl", rfc_quirk.acl_quirk)


@pytest.fixture
def sample_schema_attribute() -> m.SchemaAttribute:
    """Provides a sample SchemaAttribute for tests with all required parameters."""
    return m.SchemaAttribute(
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


@pytest.fixture
def sample_schema_objectclass() -> m.SchemaObjectClass:
    """Provides a sample SchemaObjectClass for tests with all required parameters."""
    return m.SchemaObjectClass(
        oid=c.RFC.OC_OID_PERSON,
        name=c.RFC.OC_NAME_PERSON,
        desc=None,
        sup=None,
    )


@pytest.fixture
def sample_acl() -> m.Acl:
    """Provides a sample Acl for tests."""
    return m.Acl(raw_acl="test: acl", server_type="rfc")


@pytest.fixture
def real_parser_service() -> FlextLdifParser:
    """Provides real parser service for RFC tests."""
    return FlextLdifParser()


@pytest.fixture
def real_writer_service() -> FlextLdifWriter:
    """Provides real writer service for RFC tests."""
    return FlextLdifWriter()


@pytest.fixture
def sample_entry() -> m.Entry:
    """Provides a sample Entry for RFC tests."""
    result = m.Entry.create(
        dn="cn=Test User,dc=example,dc=com",
        attributes={
            "cn": ["Test User"],
            "sn": ["User"],
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["person", "organizationalPerson"],
            "mail": ["test@example.com"],
        },
    )
    return cast("m.Entry", result.unwrap())


@pytest.fixture
def sample_entries(
    sample_entry: m.Entry,
) -> list[m.Entry]:
    """Provides multiple sample entries for RFC tests."""
    entry2_result = m.Entry.create(
        dn="cn=Another User,dc=example,dc=com",
        attributes={
            "cn": ["Another User"],
            "sn": ["User"],
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["person"],
        },
    )
    return [sample_entry, cast("m.Entry", entry2_result.unwrap())]
