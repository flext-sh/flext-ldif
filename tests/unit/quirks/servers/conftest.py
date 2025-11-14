"""Shared fixtures for server quirks tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif.api import FlextLdif
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from tests.unit.quirks.servers.fixtures.general_constants import TestGeneralConstants
from tests.unit.quirks.servers.fixtures.rfc_constants import TestsRfcConstants


@pytest.fixture(scope="module")
def ldif_api() -> FlextLdif:
    """Provides a FlextLdif API instance for the test module.

    Creates a FlextLdif instance using the singleton pattern.
    """
    return FlextLdif.get_instance()


@pytest.fixture
def rfc_quirk() -> FlextLdifServersRfc:
    """Provides RFC quirk instance for tests."""
    return FlextLdifServersRfc()


@pytest.fixture
def rfc_schema_quirk(rfc_quirk: FlextLdifServersRfc) -> FlextLdifServersRfc.Schema:
    """Provides RFC Schema quirk instance for tests."""
    return rfc_quirk.schema_quirk


@pytest.fixture
def rfc_entry_quirk(rfc_quirk: FlextLdifServersRfc) -> FlextLdifServersRfc.Entry:
    """Provides RFC Entry quirk instance for tests."""
    return rfc_quirk.entry_quirk


@pytest.fixture
def rfc_acl_quirk(rfc_quirk: FlextLdifServersRfc) -> FlextLdifServersRfc.Acl:
    """Provides RFC ACL quirk instance for tests."""
    return rfc_quirk.acl_quirk


@pytest.fixture
def sample_schema_attribute() -> FlextLdifModels.SchemaAttribute:
    """Provides a sample SchemaAttribute for tests with all required parameters."""
    return FlextLdifModels.SchemaAttribute(
        oid=TestsRfcConstants.ATTR_OID_CN,
        name=TestsRfcConstants.ATTR_NAME_CN,
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
def sample_schema_objectclass() -> FlextLdifModels.SchemaObjectClass:
    """Provides a sample SchemaObjectClass for tests with all required parameters."""
    return FlextLdifModels.SchemaObjectClass(
        oid=TestsRfcConstants.OC_OID_PERSON,
        name=TestsRfcConstants.OC_NAME_PERSON,
        desc=None,
        sup=None,
    )


@pytest.fixture
def sample_entry() -> FlextLdifModels.Entry:
    """Provides a sample Entry for tests."""
    from flext_ldif.constants import FlextLdifConstants

    return FlextLdifModels.Entry.create(
        dn=TestGeneralConstants.SAMPLE_DN,
        attributes={
            FlextLdifConstants.DictKeys.OBJECTCLASS: [
                TestGeneralConstants.OC_NAME_PERSON
            ],
            TestGeneralConstants.ATTR_NAME_CN: [TestGeneralConstants.ATTR_VALUE_TEST],
        },
    ).unwrap()


@pytest.fixture
def sample_acl() -> FlextLdifModels.Acl:
    """Provides a sample Acl for tests."""
    return FlextLdifModels.Acl(raw_acl="test: acl", server_type="rfc")


@pytest.fixture
def attribute_definition_string() -> str:
    """Provides a sample attribute definition string."""
    return TestsRfcConstants.ATTR_DEF_CN_FULL


@pytest.fixture
def objectclass_definition_string() -> str:
    """Provides a sample objectclass definition string."""
    return TestsRfcConstants.OC_DEF_PERSON


@pytest.fixture
def sample_ldif_content() -> str:
    """Provides sample LDIF content for schema extraction."""
    return TestsRfcConstants.SAMPLE_LDIF_CONTENT


# Test constants and configurations use centralized constants from fixtures
# No duplication - use TestGeneralConstants and TestsRfcConstants directly


@pytest.fixture
def sample_write_options() -> FlextLdifModels.WriteFormatOptions:
    """Provides sample WriteFormatOptions for tests."""
    return FlextLdifModels.WriteFormatOptions()


class WriteOptionsWithAllowedOids:
    """Real wrapper for WriteFormatOptions with allowed_schema_oids attribute.

    This is a real class (not a mock) that wraps WriteFormatOptions
    and provides allowed_schema_oids as a real attribute.
    """

    def __init__(self) -> None:
        """Initialize with real WriteFormatOptions and allowed_schema_oids."""
        self._options = FlextLdifModels.WriteFormatOptions()
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
def acl_transformation_object() -> FlextLdifModels.AttributeTransformation:
    """Provides a real AttributeTransformation object for tests."""
    return FlextLdifModels.AttributeTransformation(
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
def sample_entry_with_metadata() -> FlextLdifModels.Entry:
    """Provides a sample Entry with metadata for tests."""
    from flext_ldif.constants import FlextLdifConstants

    return FlextLdifModels.Entry.create(
        dn=TestGeneralConstants.SAMPLE_DN,
        attributes={
            FlextLdifConstants.DictKeys.OBJECTCLASS: [
                TestGeneralConstants.OC_NAME_PERSON
            ],
            TestGeneralConstants.ATTR_NAME_CN: [TestGeneralConstants.ATTR_VALUE_TEST],
        },
        entry_metadata={
            "write_options": FlextLdifModels.WriteFormatOptions(),
        },
    ).unwrap()


# Conversion test fixtures and constants
@pytest.fixture
def conversion_matrix() -> object:
    """Provides FlextLdifConversion instance for conversion tests."""
    from flext_ldif.services.conversion import FlextLdifConversion

    return FlextLdifConversion()


@pytest.fixture
def oid_quirk() -> object:
    """Provides OID quirk instance for conversion tests."""
    from flext_ldif.servers.oid import FlextLdifServersOid

    return FlextLdifServersOid()


@pytest.fixture
def oud_quirk() -> object:
    """Provides OUD quirk instance for conversion tests."""
    from flext_ldif.servers.oud import FlextLdifServersOud

    return FlextLdifServersOud()


@pytest.fixture
def oid_schema_quirk(oid_quirk: object) -> object:
    """Provides OID schema quirk instance for conversion tests."""
    return oid_quirk.schema_quirk


@pytest.fixture
def oud_schema_quirk(oud_quirk: object) -> object:
    """Provides OUD schema quirk instance for conversion tests."""
    return oud_quirk.schema_quirk


@pytest.fixture
def real_writer_service() -> object:
    """Provides real writer service for conversion tests."""
    from flext_ldif.services.writer import FlextLdifWriter

    return FlextLdifWriter()


@pytest.fixture
def real_parser_service() -> object:
    """Provides real parser service for conversion tests."""
    from flext_ldif.services.parser import FlextLdifParser

    return FlextLdifParser()


class ConversionTestConstants:
    """Constants for conversion tests."""

    # OID attribute definitions
    OID_ATTRIBUTE_ORCLGUID = (
        "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
        "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )"
    )
    OID_ATTRIBUTE_ORCLDBNAME = (
        "( 2.16.840.1.113894.1.1.2 NAME 'orclDBName' "
        "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
    )
    OID_ATTRIBUTE_ORCLGUID_COMPLEX = (
        "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
        "DESC 'Oracle Global Unique Identifier' "
        "EQUALITY caseIgnoreMatch "
        "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 "
        "SINGLE-VALUE )"
    )

    # OUD attribute definitions
    OUD_ATTRIBUTE_ORCLGUID = (
        "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
        "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )"
    )

    # OID objectClass definitions
    OID_OBJECTCLASS_ORCLCONTEXT = (
        "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )"
    )
    OID_OBJECTCLASS_ORCLCONTAINER = (
        "( 2.16.840.1.113894.1.2.2 NAME 'orclContainer' SUP top STRUCTURAL MUST cn )"
    )
    OID_OBJECTCLASS_ORCLCONTEXT_WITH_MAY = (
        "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' "
        "SUP top STRUCTURAL "
        "MUST cn "
        "MAY ( description $ orclVersion ) )"
    )

    # OUD objectClass definitions
    OUD_OBJECTCLASS_ORCLCONTEXT = (
        "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )"
    )

    # Invalid test data (use constants from general_constants - no duplication)
    INVALID_ATTRIBUTE = TestGeneralConstants.INVALID_ATTRIBUTE
    INVALID_DN = TestGeneralConstants.INVALID_DN
    INVALID_DATA_TYPE = TestGeneralConstants.INVALID_DATA_TYPE

    # Sample LDIF entries for conversion (use constants from general_constants)
    SAMPLE_LDIF_ENTRY = TestGeneralConstants.SAMPLE_LDIF_ENTRY

    # Error messages (use constants from general_constants - no duplication)
    WRITER_FAILED_MSG = TestGeneralConstants.WRITER_FAILED_MSG
    PARSER_ERROR_MSG = TestGeneralConstants.PARSER_ERROR_MSG
    DN_ERROR_MSG = TestGeneralConstants.DN_ERROR_MSG
    INVALID_ENTRY_MSG = TestGeneralConstants.INVALID_ENTRY_MSG
    PARSE_FAILED_MSG = TestGeneralConstants.PARSE_FAILED_MSG
    WRITE_FAILED_MSG = TestGeneralConstants.WRITE_FAILED_MSG


@pytest.fixture
def conversion_constants() -> ConversionTestConstants:
    """Provides conversion test constants."""
    return ConversionTestConstants()
