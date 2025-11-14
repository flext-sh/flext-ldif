"""Shared fixtures for server quirks tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif.models import FlextLdifModels


@pytest.fixture(scope="module")
def ldif_api():
    """Provides a FlextLdif API instance for the test module.

    Creates a FlextLdif instance using the singleton pattern.
    """
    from flext_ldif.api import FlextLdif

    return FlextLdif.get_instance()


@pytest.fixture
def rfc_quirk() -> object:
    """Provides RFC quirk instance for tests."""
    from flext_ldif.servers.rfc import FlextLdifServersRfc

    return FlextLdifServersRfc()


@pytest.fixture
def rfc_schema_quirk(rfc_quirk: object) -> object:
    """Provides RFC Schema quirk instance for tests."""
    return rfc_quirk.schema_quirk


@pytest.fixture
def rfc_entry_quirk(rfc_quirk: object) -> object:
    """Provides RFC Entry quirk instance for tests."""
    return rfc_quirk.entry_quirk


@pytest.fixture
def rfc_acl_quirk(rfc_quirk: object) -> object:
    """Provides RFC ACL quirk instance for tests."""
    return rfc_quirk.acl_quirk


@pytest.fixture
def sample_schema_attribute() -> FlextLdifModels.SchemaAttribute:
    """Provides a sample SchemaAttribute for tests."""
    return FlextLdifModels.SchemaAttribute(oid="2.5.4.3", name="cn")


@pytest.fixture
def sample_schema_objectclass() -> FlextLdifModels.SchemaObjectClass:
    """Provides a sample SchemaObjectClass for tests."""
    return FlextLdifModels.SchemaObjectClass(oid="2.5.6.6", name="person")


@pytest.fixture
def sample_entry() -> FlextLdifModels.Entry:
    """Provides a sample Entry for tests."""
    return FlextLdifModels.Entry.create(
        dn="cn=test,dc=example,dc=com",
        attributes={"objectClass": ["person"], "cn": ["test"]},
    ).unwrap()


@pytest.fixture
def sample_acl() -> FlextLdifModels.Acl:
    """Provides a sample Acl for tests."""
    return FlextLdifModels.Acl(raw_acl="test: acl", server_type="rfc")


@pytest.fixture
def attribute_definition_string():
    """Provides a sample attribute definition string."""
    return "( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch )"


@pytest.fixture
def objectclass_definition_string():
    """Provides a sample objectclass definition string."""
    return "( 2.5.6.6 NAME 'person' STRUCTURAL )"


@pytest.fixture
def sample_ldif_content():
    """Provides sample LDIF content for schema extraction."""
    return """dn: cn=schema
attributeTypes: ( 2.5.4.3 NAME 'cn' )
objectClasses: ( 2.5.6.6 NAME 'person' STRUCTURAL )
"""


# Test constants and configurations (following OUD test pattern)
class TestConstants:
    """Test constants for server quirks tests."""

    # Sample OIDs
    SAMPLE_ATTRIBUTE_OID = "2.5.4.3"
    SAMPLE_OBJECTCLASS_OID = "2.5.6.6"
    SAMPLE_ORACLE_OID = "2.16.840.1.113894.1.1.1"

    # Sample names
    SAMPLE_ATTRIBUTE_NAME = "cn"
    SAMPLE_OBJECTCLASS_NAME = "person"
    SAMPLE_ORACLE_ATTRIBUTE_NAME = "orclGUID"

    # Sample DNs
    SAMPLE_DN = "cn=test,dc=example,dc=com"
    SAMPLE_SCHEMA_DN = "cn=schema"
    SAMPLE_USER_DN = "uid=testuser,ou=people,dc=example,dc=com"

    # Sample attribute definitions
    SAMPLE_ATTRIBUTE_DEF = "( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch )"
    SAMPLE_OBJECTCLASS_DEF = "( 2.5.6.6 NAME 'person' STRUCTURAL )"
    SAMPLE_ORACLE_ATTRIBUTE_DEF = (
        "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
    )

    # Sample LDIF content
    SAMPLE_LDIF_ENTRY = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
"""

    SAMPLE_LDIF_SCHEMA = """dn: cn=schema
attributeTypes: ( 2.5.4.3 NAME 'cn' )
objectClasses: ( 2.5.6.6 NAME 'person' STRUCTURAL )
"""

    # Error messages for testing
    WRITER_FAILED_MSG = "Writer failed"
    PARSER_ERROR_MSG = "Parser error"
    DN_ERROR_MSG = "DN error"
    INVALID_ENTRY_MSG = "Invalid entry"
    PARSE_FAILED_MSG = "Parse failed"
    WRITE_FAILED_MSG = "Write failed"


@pytest.fixture
def test_constants() -> TestConstants:
    """Provides test constants for server quirks tests."""
    return TestConstants()


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
    return FlextLdifModels.Entry.create(
        dn="cn=test,dc=example,dc=com",
        attributes={"objectClass": ["person"], "cn": ["test"]},
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
        "( 2.16.840.1.113894.1.2.2 NAME 'orclContainer' "
        "SUP top STRUCTURAL MUST cn )"
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

    # Invalid test data
    INVALID_ATTRIBUTE = "this is not a valid attribute definition"
    INVALID_DN = "invalid-dn-format"
    INVALID_DATA_TYPE = "invalid_type"

    # Sample LDIF entries for conversion
    SAMPLE_LDIF_ENTRY = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: user
"""

    # Error messages
    WRITER_FAILED_MSG = "Writer failed"
    PARSER_ERROR_MSG = "Parser error"
    DN_ERROR_MSG = "DN error"
    INVALID_ENTRY_MSG = "Invalid entry"
    PARSE_FAILED_MSG = "Parse failed"
    WRITE_FAILED_MSG = "Write failed"


@pytest.fixture
def conversion_constants() -> ConversionTestConstants:
    """Provides conversion test constants."""
    return ConversionTestConstants()
