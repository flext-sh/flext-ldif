"""Shared fixtures for RFC tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_ldif import (
    FlextLdifParser,
    FlextLdifWriter,
)
from flext_ldif.servers.rfc import FlextLdifServersRfc

from tests import c, m, p
from tests.conftest_shared import (
    _create_real_parser_service,
    _create_real_writer_service,
    _create_sample_acl,
    _create_sample_schema_attribute,
    _create_sample_schema_objectclass,
)


@pytest.fixture
def rfc_quirk() -> FlextLdifServersRfc:
    """Provides RFC quirk instance for tests."""
    return FlextLdifServersRfc()


@pytest.fixture
def rfc_schema_quirk(rfc_quirk: FlextLdifServersRfc) -> FlextLdifServersRfc.Schema:
    """Provides RFC Schema quirk instance for tests."""
    schema_quirk = rfc_quirk.schema_quirk
    assert isinstance(schema_quirk, FlextLdifServersRfc.Schema)
    return schema_quirk


@pytest.fixture
def rfc_entry_quirk(rfc_quirk: FlextLdifServersRfc) -> FlextLdifServersRfc.Entry:
    """Provides RFC Entry quirk instance for tests."""
    entry_quirk = rfc_quirk.entry_quirk
    assert isinstance(entry_quirk, FlextLdifServersRfc.Entry)
    return entry_quirk


@pytest.fixture
def rfc_acl_quirk(rfc_quirk: FlextLdifServersRfc) -> FlextLdifServersRfc.Acl:
    """Provides RFC ACL quirk instance for tests."""
    acl_quirk = rfc_quirk.acl_quirk
    assert isinstance(acl_quirk, FlextLdifServersRfc.Acl)
    return acl_quirk


@pytest.fixture
def sample_schema_attribute() -> m.Ldif.SchemaAttribute:
    """Provides a sample SchemaAttribute for tests with all required parameters."""
    return _create_sample_schema_attribute()


@pytest.fixture
def sample_schema_objectclass() -> m.Ldif.SchemaObjectClass:
    """Provides a sample SchemaObjectClass for tests with all required parameters."""
    return _create_sample_schema_objectclass()


@pytest.fixture
def sample_acl() -> m.Ldif.Acl:
    """Provides a sample Acl for tests."""
    return _create_sample_acl()


@pytest.fixture
def real_parser_service() -> FlextLdifParser:
    """Provides real parser service for RFC tests."""
    return _create_real_parser_service()


@pytest.fixture
def real_writer_service() -> FlextLdifWriter:
    """Provides real writer service for RFC tests."""
    return _create_real_writer_service()


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
    assert result.is_success
    entry = result.value
    assert entry is not None
    return entry


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
    assert entry2_result.is_success
    entry2 = entry2_result.value
    assert entry2 is not None
    return [sample_entry, entry2]
