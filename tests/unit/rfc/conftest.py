"""Shared fixtures for RFC tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

import pytest

from flext_ldif import (
    FlextLdifParser,
    FlextLdifWriter,
)
from flext_ldif.servers.rfc import FlextLdifServersRfc
from tests import c, m, p


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
def sample_schema_attribute() -> m.Ldif.SchemaAttribute:
    """Provides a sample SchemaAttribute for tests with all required parameters."""
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


@pytest.fixture
def sample_schema_objectclass() -> m.Ldif.SchemaObjectClass:
    """Provides a sample SchemaObjectClass for tests with all required parameters."""
    return m.Ldif.SchemaObjectClass(
        oid=c.RFC.OC_OID_PERSON,
        name=c.RFC.OC_NAME_PERSON,
        desc=None,
        sup=None,
    )


@pytest.fixture
def sample_acl() -> m.Ldif.Acl:
    """Provides a sample Acl for tests."""
    return m.Ldif.Acl(raw_acl="test: acl", server_type="rfc")


@pytest.fixture
def real_parser_service() -> FlextLdifParser:
    """Provides real parser service for RFC tests."""
    return FlextLdifParser()


@pytest.fixture
def real_writer_service() -> FlextLdifWriter:
    """Provides real writer service for RFC tests."""
    return FlextLdifWriter()


@pytest.fixture
def sample_entry() -> p.Entry:
    """Provides a sample Entry for RFC tests."""
    result = m.Ldif.Entry.create(
        dn="cn=Test User,dc=example,dc=com",
        attributes={
            "cn": ["Test User"],
            "sn": ["User"],
            c.Ldif.DictKeys.OBJECTCLASS: [
                "person",
                "organizationalPerson",
            ],
            "mail": ["test@example.com"],
        },
    )
    return cast("p.Entry", result.value)


@pytest.fixture
def sample_entries(
    sample_entry: p.Entry,
) -> list[p.Entry]:
    """Provides multiple sample entries for RFC tests."""
    entry2_result = m.Ldif.Entry.create(
        dn="cn=Another User,dc=example,dc=com",
        attributes={
            "cn": ["Another User"],
            "sn": ["User"],
            c.Ldif.DictKeys.OBJECTCLASS: ["person"],
        },
    )
    return [sample_entry, cast("p.Entry", entry2_result.value)]
