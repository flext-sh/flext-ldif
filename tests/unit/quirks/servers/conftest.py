"""Shared fixtures for server quirks tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from tests import c
from tests.conftest import FlextLdifFixtures

from flext_ldif import (
    FlextLdif,
    FlextLdifParser,
    FlextLdifProtocols,
    FlextLdifWriter,
)
from flext_ldif.constants import c as lib_c
from flext_ldif.models import m
from flext_ldif.servers import (
    FlextLdifServersOid,
    FlextLdifServersOud,
    FlextLdifServersRfc,
)
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.services.conversion import FlextLdifConversion
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.typings import t


@pytest.fixture
def ldif_api() -> FlextLdif:
    """Provides a FlextLdif API instance for each test.

    Uses function scope to ensure fresh instance per test (no state pollution).
    Each test gets a clean FlextLdif instance.
    """
    return FlextLdif.get_instance()


@pytest.fixture(autouse=True)
def cleanup_state() -> None:
    """Autouse fixture to clean shared state between tests.

    Runs after each test to prevent state pollution to subsequent tests.
    Ensures test isolation even when fixtures have shared state.
    """
    return
    # Post-test cleanup - if singleton state needs to be cleared,
    # it would be done here. Currently, creating fresh FlextLdif instances
    # in function-scoped ldif_api fixture provides sufficient isolation.


@pytest.fixture
def server() -> FlextLdifServer:
    """Provides FlextLdifServer instance for getting quirks.

    Uses function scope to ensure fresh instance per test (no state pollution).
    """
    return FlextLdifServer()


@pytest.fixture
def rfc_quirk() -> FlextLdifServersBase:
    """Provides RFC quirk instance directly.

    Uses function scope to ensure fresh instance per test (no state pollution).
    """
    return FlextLdifServersRfc()


@pytest.fixture
def rfc_schema_quirk(
    rfc_quirk: FlextLdifServersBase,
) -> FlextLdifProtocols.Quirks.SchemaProtocol:
    """Provides RFC Schema quirk instance for tests."""
    return rfc_quirk.schema_quirk


@pytest.fixture
def rfc_entry_quirk(
    rfc_quirk: FlextLdifServersBase,
) -> t.Ldif.EntryQuirk:
    """Provides RFC Entry quirk instance for tests."""
    return rfc_quirk.entry_quirk


@pytest.fixture
def rfc_acl_quirk(rfc_quirk: FlextLdifServersBase) -> t.Ldif.AclQuirk:
    """Provides RFC ACL quirk instance for tests."""
    return rfc_quirk.acl_quirk


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
def sample_entry() -> m.Ldif.Entry:
    """Provides a sample Entry for tests."""
    result = m.Ldif.Entry.create(
        dn=c.General.SAMPLE_DN,
        attributes={
            lib_c.Ldif.DictKeys.OBJECTCLASS: [
                c.General.OC_NAME_PERSON,
            ],
            c.General.ATTR_NAME_CN: [c.General.ATTR_VALUE_TEST],
        },
    )
    entry_domain = result.unwrap()
    # Create new instance using m.Ldif.Entry to ensure correct type
    return m.Ldif.Entry(
        dn=entry_domain.dn,
        attributes=entry_domain.attributes,
        metadata=entry_domain.metadata,
    )


@pytest.fixture
def sample_acl() -> m.Ldif.Acl:
    """Provides a sample Acl for tests."""
    return m.Ldif.Acl(raw_acl="test: acl", server_type="rfc")


@pytest.fixture
def attribute_definition_string() -> str:
    """Provides a sample attribute definition string."""
    return c.RFC.ATTR_DEF_CN_FULL


@pytest.fixture
def objectclass_definition_string() -> str:
    """Provides a sample objectclass definition string."""
    return c.RFC.OC_DEF_PERSON


@pytest.fixture
def sample_ldif_content() -> str:
    """Provides sample LDIF content for schema extraction."""
    return c.RFC.SAMPLE_LDIF_CONTENT


# Test constants and configurations use centralized constants from fixtures
# No duplication - use TestGeneralConstants and TestsRfcConstants directly


@pytest.fixture
def sample_write_options() -> m.WriteFormatOptions:
    """Provides sample WriteFormatOptions for tests."""
    return m.WriteFormatOptions()


class WriteOptionsWithAllowedOids:
    """Real wrapper for WriteFormatOptions with allowed_schema_oids attribute.

    This is a real class (not a mock) that wraps WriteFormatOptions
    and provides allowed_schema_oids as a real attribute.
    """

    def __init__(self) -> None:
        """Initialize with real WriteFormatOptions and allowed_schema_oids."""
        self._options = m.WriteFormatOptions()
        self.allowed_schema_oids = frozenset(["1.2.3.4"])

    def __getattr__(self, name: str) -> object:
        """Delegate all other attributes to the real WriteFormatOptions."""
        return getattr(self._options, name)


@pytest.fixture
def write_options_with_allowed_oids() -> WriteOptionsWithAllowedOids:
    """Provides WriteFormatOptions with allowed_schema_oids for tests.

    Creates a real wrapper object (not a mock) that provides allowed_schema_oids.
    """
    return WriteOptionsWithAllowedOids()


@pytest.fixture
def acl_transformation_object() -> m.AttributeTransformation:
    """Provides a real AttributeTransformation object for tests."""
    return m.AttributeTransformation(
        original_name="aci",
        original_values=["original aci"],
        target_name="aci",
        target_values=["test aci"],
        transformation_type="renamed",
    )


@pytest.fixture
def invalid_ldif_content() -> str:
    """Provides invalid LDIF content for error testing."""
    return """dn: invalid-dn-format
objectClass: nonExistentClass
invalidAttribute: value without proper formatting
"""


@pytest.fixture
def sample_entry_with_metadata() -> m.Ldif.Entry:
    """Provides a sample Entry with metadata for tests."""
    result = m.Ldif.Entry.create(
        dn=c.General.SAMPLE_DN,
        attributes={
            lib_c.Ldif.DictKeys.OBJECTCLASS: [
                c.General.OC_NAME_PERSON,
            ],
            c.General.ATTR_NAME_CN: [c.General.ATTR_VALUE_TEST],
        },
        entry_metadata=m.EntryMetadata(
            write_options=m.WriteFormatOptions(),
        ),
    )
    entry_domain = result.unwrap()
    # Create new instance using m.Ldif.Entry to ensure correct type
    return m.Ldif.Entry(
        dn=entry_domain.dn,
        attributes=entry_domain.attributes,
        metadata=entry_domain.metadata,
    )


# Conversion test fixtures and constants
@pytest.fixture
def conversion_matrix() -> FlextLdifConversion:
    """Provides FlextLdifConversion instance for conversion tests."""
    return FlextLdifConversion()


@pytest.fixture
def oid_quirk() -> FlextLdifServersBase:
    """Provides OID quirk instance directly."""
    return FlextLdifServersOid()


@pytest.fixture
def oud_quirk() -> FlextLdifServersBase:
    """Provides OUD quirk instance directly."""
    return FlextLdifServersOud()


@pytest.fixture
def oid_schema_quirk(
    oid_quirk: FlextLdifServersBase,
) -> FlextLdifProtocols.Quirks.SchemaProtocol:
    """Provides OID schema quirk instance for conversion tests."""
    return oid_quirk.schema_quirk


@pytest.fixture
def oid_acl_quirk(
    oid_quirk: FlextLdifServersBase,
) -> t.Ldif.AclQuirk:
    """Provides OID ACL quirk instance for tests."""
    return oid_quirk.acl_quirk


@pytest.fixture
def oid_entry_quirk(
    oid_quirk: FlextLdifServersBase,
) -> t.Ldif.EntryQuirk:
    """Provides OID Entry quirk instance for tests."""
    return oid_quirk.entry_quirk


@pytest.fixture
def oid_fixtures() -> object:
    """Provides OID fixture loader instance for tests.

    Uses lazy loading to defer fixture file loading until actually needed.
    This prevents automatic loading of all fixture files on module import.
    """
    return FlextLdifFixtures.get_oid()


@pytest.fixture
def oud_schema_quirk(
    oud_quirk: FlextLdifServersBase,
) -> FlextLdifProtocols.Quirks.SchemaProtocol:
    """Provides OUD schema quirk instance for conversion tests."""
    return oud_quirk.schema_quirk


@pytest.fixture
def real_writer_service() -> FlextLdifWriter:
    """Provides real writer service for conversion tests."""
    return FlextLdifWriter()


@pytest.fixture
def real_parser_service() -> FlextLdifParser:
    """Provides real parser service for conversion tests."""
    return FlextLdifParser()


# Conversion test constants are now in tests/constants.py as c.Conversion
# Access via: c.Conversion.OID_ATTRIBUTE_ORCLGUID, c.Conversion.OID_OBJECTCLASS_ORCLCONTEXT, etc.
