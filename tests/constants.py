"""Test constant definitions extending src constants for centralized test constants.

This module provides test-specific constants that complement but do not duplicate
src/flext_ldif/constants.py. These constants are used exclusively in tests for:
- Test data generation
- Test fixtures
- Test assertions
- Mock data

Important: This module should NOT duplicate constants from src/constants.py.
Instead, it should import and reuse them when possible, or define test-specific
constants that are not part of the production codebase.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from flext_ldif import FlextLdif
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import m
from flext_ldif.services.entries import FlextLdifEntries
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.schema import FlextLdifSchema
from flext_ldif.services.writer import FlextLdifWriter
from flext_tests.constants import FlextTestsConstants


class TestsFlextLdifConstants(FlextTestsConstants, FlextLdifConstants):
    """Constants for flext-ldif tests using COMPOSITION INHERITANCE.

    MANDATORY: Inherits from BOTH:
    1. FlextTestsConstants - for test infrastructure (.Tests.*)
    2. FlextLdifConstants - for domain constants (.Ldif.*)

    Access patterns:
    - tc.Tests.Docker.* (container testing)
    - tc.Tests.Matcher.* (assertion messages)
    - tc.Tests.Factory.* (test data generation)
    - tc.Ldif.* (domain constants from production)
    - tc.TestLdif.* (project-specific test data)

    Rules:
    - NEVER duplicate constants from FlextTestsConstants or FlextLdifConstants
    - Only flext-ldif-specific test constants allowed
    - All generic constants come from FlextTestsConstants
    - All production constants come from FlextLdifConstants
    """

    # Create Schema namespace for test convenience
    # Maps c.Schema.AUXILIARY and c.Schema.STRUCTURAL to Ldif.AclSubjectTypes constants
    class Schema:
        """Schema constants wrapper for test convenience."""

        STRUCTURAL: str = FlextLdifConstants.Ldif.AclSubjectTypes.STRUCTURAL
        AUXILIARY: str = FlextLdifConstants.Ldif.AclSubjectTypes.AUXILIARY
        ABSTRACT: str = FlextLdifConstants.Ldif.AclSubjectTypes.ABSTRACT
        ACTIVE: str = FlextLdifConstants.Ldif.AclSubjectTypes.ACTIVE
        DEPRECATED: str = FlextLdifConstants.Ldif.AclSubjectTypes.DEPRECATED

    class Names:
        """Standard LDAP attribute names for test fixtures."""

        CN: Final[str] = "cn"
        SN: Final[str] = "sn"
        GIVEN_NAME: Final[str] = "givenName"
        MAIL: Final[str] = "mail"
        OBJECT_CLASS: Final[str] = "objectClass"
        OBJECTCLASS: Final[str] = "objectClass"
        DESCRIPTION: Final[str] = "description"
        TELEPHONE_NUMBER: Final[str] = "telephoneNumber"
        STREET: Final[str] = "street"
        LOCALITY: Final[str] = "l"
        STATE_OR_PROVINCE: Final[str] = "st"
        POSTAL_CODE: Final[str] = "postalCode"
        ORGANIZATION: Final[str] = "o"
        ORGANIZATIONAL_UNIT: Final[str] = "ou"
        ORGANIZATIONAL_PERSON: Final[str] = "organizationalPerson"
        USER_PASSWORD: Final[str] = "userPassword"
        JPEG_PHOTO: Final[str] = "jpegPhoto"
        EMPLOYEE_ID: Final[str] = "employeeID"
        DN: Final[str] = "dn"
        UID: Final[str] = "uid"
        PERSON: Final[str] = "person"
        TOP: Final[str] = "top"
        INETORGPERSON: Final[str] = "inetOrgPerson"
        INET_ORG_PERSON: Final[str] = "inetOrgPerson"

    # =========================================================================
    # FIXTURE DIRECTORY CONSTANTS
    # =========================================================================

    class Fixtures:
        """Test fixture directory names used in tests/fixtures/."""

        OID: Final[str] = "oid"
        OUD: Final[str] = "oud"
        OPENLDAP: Final[str] = "openldap"
        OPENLDAP2: Final[str] = "openldap2"
        RFC: Final[str] = "rfc"

    # =========================================================================
    # RFC TEST CONSTANTS
    # =========================================================================

    class Rfc:
        """RFC test constants for schema and entry testing."""

        # Attribute definitions
        ATTR_DEF_CN: Final[str] = (
            "( 2.5.4.3 NAME 'cn' DESC 'Common Name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
        )
        ATTR_DEF_CN_COMPLETE: Final[str] = (
            "( 2.5.4.3 NAME 'cn' DESC 'Common Name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
        )
        ATTR_DEF_CN_MINIMAL: Final[str] = "( 2.5.4.3 )"
        ATTR_DEF_SN: Final[str] = (
            "( 2.5.4.4 NAME 'sn' DESC 'Surname' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{255} )"
        )
        ATTR_DEF_ST: Final[str] = (
            "( 2.5.4.8 NAME 'st' DESC 'State or Province Name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch )"
        )
        ATTR_DEF_MAIL: Final[str] = (
            "( 0.9.2342.19200300.100.1.3 NAME 'mail' SUP name DESC 'Email address' )"
        )
        ATTR_DEF_MODIFY_TIMESTAMP: Final[str] = (
            "( 2.5.18.2 NAME 'modifyTimestamp' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )"
        )
        ATTR_DEF_OBSOLETE: Final[str] = (
            "( 2.5.4.10 NAME 'o' DESC 'Organization Name' OBSOLETE SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        ATTR_DEF_OBJECTCLASS: Final[str] = (
            "( 2.5.4.0 NAME 'objectClass' DESC 'Object Class' SYNTAX '1.3.6.1.4.1.1466.115.121.1.38' )"
        )

        # OIDs
        ATTR_OID_CN: Final[str] = "2.5.4.3"
        ATTR_OID_SN: Final[str] = "2.5.4.4"
        ATTR_OID_ST: Final[str] = "2.5.4.8"
        ATTR_OID_MAIL: Final[str] = "0.9.2342.19200300.100.1.3"
        ATTR_OID_MODIFY_TIMESTAMP: Final[str] = "2.5.18.2"
        ATTR_OID_O: Final[str] = "2.5.4.10"
        ATTR_OID_OBJECTCLASS: Final[str] = "2.5.4.0"

        # Attribute names
        ATTR_NAME_CN: Final[str] = "cn"
        ATTR_NAME_SN: Final[str] = "sn"
        ATTR_NAME_ST: Final[str] = "st"
        ATTR_NAME_MAIL: Final[str] = "mail"
        ATTR_NAME_MODIFY_TIMESTAMP: Final[str] = "modifyTimestamp"
        ATTR_NAME_O: Final[str] = "o"
        ATTR_NAME_OBJECTCLASS: Final[str] = "objectClass"

        # Syntax OIDs
        SYNTAX_OID_DIRECTORY_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.15"
        SYNTAX_OID_BOOLEAN: Final[str] = "1.3.6.1.4.1.1466.115.121.1.7"
        SYNTAX_OID_INTEGER: Final[str] = "1.3.6.1.4.1.1466.115.121.1.27"
        SYNTAX_OID_IA5_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.26"
        SYNTAX_OID_GENERALIZED_TIME: Final[str] = "1.3.6.1.4.1.1466.115.121.1.24"
        SYNTAX_OID_OID: Final[str] = "1.3.6.1.4.1.1466.115.121.1.38"

        # ObjectClass definitions
        OC_DEF_PERSON: Final[str] = (
            "( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) )"
        )
        OC_DEF_PERSON_FULL: Final[str] = OC_DEF_PERSON
        OC_DEF_PERSON_BASIC: Final[str] = (
            "( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL )"
        )
        OC_DEF_PERSON_MINIMAL: Final[str] = "( 2.5.6.6 NAME 'person' STRUCTURAL )"
        OC_OID_PERSON: Final[str] = "2.5.6.6"
        OC_NAME_PERSON: Final[str] = "person"

        # Schema DNs
        SCHEMA_DN_SUBSCHEMA: Final[str] = "cn=subschema"
        SCHEMA_DN_SCHEMA: Final[str] = "cn=schema"
        SCHEMA_DN_SCHEMA_SYSTEM: Final[str] = "cn=schema,o=system"

        # Test DNs
        TEST_DN: Final[str] = "cn=test,dc=example,dc=com"
        TEST_DN_USER1: Final[str] = "cn=user1,dc=example,dc=com"
        TEST_DN_USER2: Final[str] = "cn=user2,dc=example,dc=com"
        TEST_DN_TEST_USER: Final[str] = "cn=Test User,dc=example,dc=com"
        INVALID_DN: Final[str] = "invalid-dn-format"

        # Aliases for SAMPLE_* (legacy test compatibility)
        SAMPLE_DN: Final[str] = TEST_DN
        SAMPLE_DN_USER1: Final[str] = TEST_DN_USER1
        SAMPLE_DN_USER2: Final[str] = TEST_DN_USER2
        SAMPLE_ATTRIBUTE_CN: Final[str] = "cn"
        SAMPLE_ATTRIBUTE_SN: Final[str] = "sn"

        # LDIF content samples
        SAMPLE_LDIF_BASIC: Final[str] = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: user
"""
        SAMPLE_LDIF_MULTIPLE: Final[str] = """dn: cn=user1,dc=example,dc=com
objectClass: person
cn: user1

dn: cn=user2,dc=example,dc=com
objectClass: person
cn: user2
"""
        SAMPLE_LDIF_BINARY: Final[str] = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
photo:: UGhvdG8gZGF0YQ==
"""
        SAMPLE_SCHEMA_CONTENT: Final[str] = """dn: cn=subschema
objectClass: top
objectClass: subentry
objectClass: subschema
cn: subschema
attributeTypes: ( 2.5.4.4 NAME 'sn' DESC 'Surname' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
objectClasses: ( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) )
"""

        # Invalid definitions
        INVALID_ATTR_DEF: Final[str] = "NAME 'cn' DESC 'Common Name'"
        INVALID_OC_DEF: Final[str] = "invalid objectclass definition"

        # ACL samples
        ACL_SAMPLE_BROWSE: Final[str] = "access to entry by * (browse)"
        ACL_SAMPLE_READ: Final[str] = "access to entry by * (read)"

    # =========================================================================
    # TEST DATA CONSTANTS
    # =========================================================================

    class TestData:
        """Test data generation constants."""

        # Sample DNs for testing
        SAMPLE_BASE_DN: Final[str] = "dc=test,dc=local"
        SAMPLE_USER_DN: Final[str] = "cn=testuser,dc=test,dc=local"
        SAMPLE_GROUP_DN: Final[str] = "cn=testgroup,dc=test,dc=local"
        SAMPLE_OU_DN: Final[str] = "ou=testou,dc=test,dc=local"

        # Sample attributes for testing
        SAMPLE_ATTRIBUTES: Final[dict[str, list[str]]] = {
            "objectClass": ["inetOrgPerson", "organizationalPerson", "person", "top"],
            "cn": ["Test User"],
            "sn": ["User"],
            "mail": ["test@example.com"],
            "uid": ["testuser"],
        }

        # Sample LDIF content for parsing tests
        SAMPLE_LDIF_ENTRY: Final[str] = """dn: cn=Test User,dc=test,dc=local
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: Test User
sn: User
mail: test@example.com
uid: testuser
"""

    # =========================================================================
    # FIXTURE CONSTANTS (Consolidated from tests/unit/quirks/servers/fixtures/)
    # =========================================================================

    class General:
        """General test constants (from fixtures/general_constants.py)."""

        # Sample DNs
        SAMPLE_DN: Final[str] = "cn=test,dc=example,dc=com"
        SAMPLE_DN_1: Final[str] = "cn=test1,dc=example,dc=com"
        SAMPLE_DN_2: Final[str] = "cn=test2,dc=example,dc=com"
        SAMPLE_SCHEMA_DN: Final[str] = "cn=schema"
        SAMPLE_USER_DN: Final[str] = "uid=testuser,ou=people,dc=example,dc=com"
        SAMPLE_SUBSCHEMA_DN: Final[str] = "cn=subschema"

        # Sample LDIF entries
        SAMPLE_LDIF_ENTRY: Final[str] = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: user
"""

        SAMPLE_LDIF_TWO_ENTRIES: Final[str] = """dn: cn=test1,dc=example,dc=com
cn: test1

dn: cn=test2,dc=example,dc=com
cn: test2
"""

        # Error messages for testing
        WRITER_FAILED_MSG: Final[str] = "Writer failed"
        PARSER_ERROR_MSG: Final[str] = "Parser error"
        DN_ERROR_MSG: Final[str] = "DN error"
        INVALID_ENTRY_MSG: Final[str] = "Invalid entry"
        PARSE_FAILED_MSG: Final[str] = "Parse failed"
        WRITE_FAILED_MSG: Final[str] = "Write failed"

        # Invalid test data
        INVALID_ATTRIBUTE: Final[str] = "this is not a valid attribute definition"
        INVALID_DN: Final[str] = "invalid-dn-format"
        INVALID_DATA_TYPE: Final[str] = "invalid_type"

        # Common attribute names
        ATTR_NAME_CN: Final[str] = "cn"
        ATTR_NAME_SN: Final[str] = "sn"
        ATTR_NAME_OBJECTCLASS: Final[str] = "objectClass"

        # Common attribute values
        ATTR_VALUE_TEST: Final[str] = "test"
        ATTR_VALUE_TEST1: Final[str] = "test1"
        ATTR_VALUE_TEST2: Final[str] = "test2"
        ATTR_VALUE_USER: Final[str] = "user"

        # Common objectClass names
        OC_NAME_PERSON: Final[str] = "person"
        OC_NAME_TOP: Final[str] = "top"

    class RFC:
        """RFC server test constants (from fixtures/rfc_constants.py)."""

        # RFC attribute definitions
        ATTR_DEF_CN: Final[str] = "( 2.5.4.3 NAME 'cn' )"
        ATTR_DEF_CN_FULL: Final[str] = "( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch )"
        ATTR_DEF_CN_COMPLETE: Final[str] = (
            "( 2.5.4.3 NAME 'cn' DESC 'Common Name' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
        )
        ATTR_DEF_SN: Final[str] = (
            "( 2.5.4.4 NAME 'sn' DESC 'Surname' "
            "SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )"
        )
        ATTR_DEF_OBJECTCLASS: Final[str] = (
            "( 2.5.4.0 NAME 'objectClass' DESC 'Object Class' "
            "SYNTAX '1.3.6.1.4.1.1466.115.121.1.38' )"
        )
        ATTR_OID_CN: Final[str] = "2.5.4.3"
        ATTR_OID_OBJECTCLASS: Final[str] = "2.5.4.0"
        ATTR_NAME_CN: Final[str] = "cn"
        ATTR_OID_SN: Final[str] = "2.5.4.4"
        ATTR_NAME_SN: Final[str] = "sn"

        # RFC objectClass definitions
        OC_DEF_PERSON: Final[str] = "( 2.5.6.6 NAME 'person' STRUCTURAL )"
        OC_DEF_PERSON_FULL: Final[str] = (
            "( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' "
            "SUP top STRUCTURAL MUST ( sn $ cn ) )"
        )
        OC_DEF_PERSON_BASIC: Final[str] = (
            "( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL )"
        )
        OC_OID_PERSON: Final[str] = "2.5.6.6"
        OC_NAME_PERSON: Final[str] = "person"

        # Test DNs and origins
        TEST_DN: Final[str] = "cn=test,dc=example,dc=com"
        TEST_ORIGIN: Final[str] = "test.ldif"
        SCHEMA_DN_SUBSCHEMA: Final[str] = "cn=subschema"
        SCHEMA_DN_SCHEMA: Final[str] = "cn=schema"
        SCHEMA_DN_SCHEMA_SYSTEM: Final[str] = "cn=schema,o=system"

        # Additional attribute definitions for testing
        ATTR_DEF_CN_MINIMAL: Final[str] = "( 2.5.4.3 )"
        ATTR_DEF_ST: Final[str] = (
            "( 2.5.4.8 NAME 'st' DESC 'State or Province Name' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
            "EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch "
            "SUBSTR caseIgnoreSubstringsMatch )"
        )
        ATTR_DEF_MAIL: Final[str] = (
            "( 0.9.2342.19200300.100.1.3 NAME 'mail' SUP name DESC 'Email address' )"
        )
        ATTR_OID_MAIL: Final[str] = "0.9.2342.19200300.100.1.3"
        ATTR_NAME_MAIL: Final[str] = "mail"
        ATTR_DEF_MODIFY_TIMESTAMP: Final[str] = (
            "( 2.5.18.2 NAME 'modifyTimestamp' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 "
            "SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )"
        )
        ATTR_DEF_OBSOLETE: Final[str] = (
            "( 2.5.4.10 NAME 'o' DESC 'Organization Name' OBSOLETE "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        ATTR_OID_O: Final[str] = "2.5.4.10"
        ATTR_NAME_O: Final[str] = "o"

        # Syntax OIDs
        SYNTAX_OID_DIRECTORY_STRING: Final[str] = "1.3.6.1.4.1.1466.115.121.1.15"
        SYNTAX_OID_BOOLEAN: Final[str] = "1.3.6.1.4.1.1466.115.121.1.7"
        SYNTAX_OID_INTEGER: Final[str] = "1.3.6.1.4.1.1466.115.121.1.27"

        # Invalid definitions for error testing
        INVALID_ATTR_DEF: Final[str] = "NAME 'cn' DESC 'Common Name'"
        INVALID_OC_DEF: Final[str] = "invalid objectclass definition"

        # Sample LDIF content
        SAMPLE_LDIF_CONTENT: Final[str] = """dn: cn=schema
attributeTypes: ( 2.5.4.3 NAME 'cn' )
objectClasses: ( 2.5.6.6 NAME 'person' STRUCTURAL )
"""

        SAMPLE_SCHEMA_CONTENT: Final[str] = """dn: cn=subschema
objectClass: top
objectClass: subentry
objectClass: subschema
cn: subschema
attributeTypes: ( 2.5.4.4 NAME 'sn' DESC 'Surname' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
objectClasses: ( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) )
"""

        # LDIF parser test constants
        SAMPLE_DN: Final[str] = "cn=test,dc=example,dc=com"
        SAMPLE_DN_USER1: Final[str] = "cn=user1,dc=example,dc=com"
        SAMPLE_DN_USER2: Final[str] = "cn=user2,dc=example,dc=com"
        SAMPLE_DN_TEST_USER: Final[str] = "cn=Test User,dc=example,dc=com"
        INVALID_DN: Final[str] = "invalid-dn-format"
        SAMPLE_LDIF_BASIC: Final[str] = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: user
"""
        SAMPLE_LDIF_MULTIPLE: Final[str] = """dn: cn=user1,dc=example,dc=com
objectClass: person
cn: user1

dn: cn=user2,dc=example,dc=com
objectClass: person
cn: user2
"""
        SAMPLE_LDIF_BINARY: Final[str] = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
photo:: UGhvdG8gZGF0YQ==
"""
        SAMPLE_ATTRIBUTE_CN: Final[str] = "cn"
        SAMPLE_ATTRIBUTE_SN: Final[str] = "sn"
        SAMPLE_ATTRIBUTE_PHOTO: Final[str] = "photo"
        SAMPLE_VALUE_TEST: Final[str] = "test"
        SAMPLE_VALUE_USER: Final[str] = "user"
        SAMPLE_VALUE_USER1: Final[str] = "user1"
        SAMPLE_VALUE_USER2: Final[str] = "user2"
        SAMPLE_OBJECTCLASS_PERSON: Final[str] = "person"
        BASE64_PHOTO_DATA: Final[str] = "UGhvdG8gZGF0YQ=="

        # ACL test constants
        ACL_LINE_SAMPLE: Final[str] = (
            '(targetattr="*")(version 3.0; acl "test"; '
            'allow (read) userdn="ldap:///self";)'
        )
        ACL_LINE_EMPTY_OID: Final[str] = ""
        ACL_LINE_INVALID_OID: Final[str] = "invalid.oid.format"

    class OID:
        """OID server test constants (from fixtures/oid_constants.py)."""

        # Oracle OID namespace
        ORACLE_OID_NAMESPACE: Final[str] = "2.16.840.1.113894"

        # OID attribute definitions
        ATTRIBUTE_ORCLGUID: Final[str] = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )"
        )
        ATTRIBUTE_ORCLDBNAME: Final[str] = (
            "( 2.16.840.1.113894.1.1.2 NAME 'orclDBName' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        ATTRIBUTE_ORCLGUID_COMPLEX: Final[str] = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
            "DESC 'Oracle Global Unique Identifier' "
            "EQUALITY caseIgnoreMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 "
            "SINGLE-VALUE )"
        )

        # OID objectClass definitions
        OBJECTCLASS_ORCLCONTEXT: Final[str] = (
            "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )"
        )
        OBJECTCLASS_ORCLCONTAINER: Final[str] = (
            "( 2.16.840.1.113894.1.2.2 NAME 'orclContainer' "
            "SUP top STRUCTURAL MUST cn )"
        )
        OBJECTCLASS_ORCLCONTEXT_WITH_MAY: Final[str] = (
            "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' "
            "SUP top STRUCTURAL "
            "MUST cn "
            "MAY ( description $ orclVersion ) )"
        )

        # OID attribute names
        ATTRIBUTE_NAME_ORCLGUID: Final[str] = "orclGUID"
        ATTRIBUTE_NAME_ORCLDBNAME: Final[str] = "orclDBName"

        # OID objectClass names
        OBJECTCLASS_NAME_ORCLCONTEXT: Final[str] = "orclContext"
        OBJECTCLASS_NAME_ORCLCONTAINER: Final[str] = "orclContainer"

    class OUD:
        """OUD server test constants (from fixtures/oud_constants.py)."""

        # OUD schema DN
        SCHEMA_DN: Final[str] = "cn=schema"
        SCHEMA_DN_SUBSCHEMA: Final[str] = "cn=subschemasubentry"

    # =========================================================================
    # DN CONSTANTS (For backward compatibility - used in tests)
    # =========================================================================

    class DNs:
        """DN constants for testing."""

        EXAMPLE: Final[str] = "dc=example,dc=com"
        TEST_USER: Final[str] = "cn=testuser,dc=example,dc=com"
        TEST_GROUP: Final[str] = "cn=testgroup,dc=example,dc=com"
        SCHEMA: Final[str] = "cn=schema"
        BASE: Final[str] = "dc=example,dc=com"

    # =========================================================================
    # VALUE CONSTANTS (For backward compatibility - used in tests)
    # =========================================================================

    class Values:
        """Value constants for testing."""

        TEST: Final[str] = "test"
        USER: Final[str] = "user"
        USER1: Final[str] = "user1"
        USER2: Final[str] = "user2"
        ADMIN: Final[str] = "REDACTED_LDAP_BIND_PASSWORD"
        EXAMPLE: Final[str] = "example"
        USER1_EMAIL: Final[str] = "user1@example.com"
        USER2_EMAIL: Final[str] = "user2@example.com"

        # Sample OUD attribute definitions
        ATTRIBUTE_ORCLGUID: Final[str] = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )"
        )
        ATTRIBUTE_ORCLGUID_WITH_X_ORIGIN: Final[str] = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 X-ORIGIN 'Oracle' )"
        )
        ATTRIBUTE_ORCLGUID_WITH_X_EXTENSIONS: Final[str] = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 "
            "X-ORIGIN 'Oracle' X-FILE-REF '99-user.ldif' "
            "X-NAME 'TestName' X-ALIAS 'testAlias' X-OID '1.2.3.5' )"
        )
        ATTRIBUTE_SYNTAX_WITH_QUOTES: Final[str] = (
            "( 1.2.3.4 NAME 'testAttr' SYNTAX '1.3.6.1.4.1.1466.115.121.1.7' )"
        )
        ATTRIBUTE_SYNTAX_WITHOUT_QUOTES: Final[str] = (
            "( 1.2.3.4 NAME 'testAttr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )"
        )
        ATTRIBUTE_INVALID_OID: Final[str] = "( invalid@oid!format NAME 'testAttr' )"

        # OUD objectClass definitions
        OBJECTCLASS_ORCLCONTEXT: Final[str] = (
            "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )"
        )
        OBJECTCLASS_MULTIPLE_SUP: Final[str] = (
            "( 1.2.3.4 NAME 'testOC' SUP ( top $ person ) STRUCTURAL )"
        )
        OBJECTCLASS_SINGLE_SUP: Final[str] = (
            "( 1.2.3.4 NAME 'testOC' SUP top STRUCTURAL )"
        )

        # Sample OIDs
        SAMPLE_ATTRIBUTE_OID: Final[str] = "1.2.3.4"
        SAMPLE_ATTRIBUTE_OID_2: Final[str] = "1.2.3.5"
        SAMPLE_OBJECTCLASS_OID: Final[str] = "1.2.3.6"
        SAMPLE_SYNTAX_OID: Final[str] = "1.3.6.1.4.1.1466.115.121.1.15"
        SAMPLE_SYNTAX_OID_QUOTED: Final[str] = "1.3.6.1.4.1.1466.115.121.1.7"

        # Sample attribute and objectclass names
        SAMPLE_ATTRIBUTE_NAME: Final[str] = "testAttr"
        SAMPLE_ATTRIBUTE_NAME_2: Final[str] = "testAttr2"
        SAMPLE_OBJECTCLASS_NAME: Final[str] = "testOC"

        # Sample attribute definitions
        SAMPLE_ATTRIBUTE_DEF: Final[str] = (
            "( 1.2.3.4 NAME 'testAttr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        SAMPLE_ATTRIBUTE_DEF_2: Final[str] = (
            "( 1.2.3.5 NAME 'testAttr2' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        SAMPLE_OBJECTCLASS_DEF: Final[str] = (
            "( 1.2.3.6 NAME 'testOC' SUP top STRUCTURAL )"
        )

        # Sample DNs
        SAMPLE_DN: Final[str] = "cn=test,dc=example,dc=com"
        SAMPLE_SCHEMA_DN: Final[str] = "cn=schema"

        # Sample ACL/ACI values
        SAMPLE_ACI: Final[str] = (
            '(targetattr="*")(version 3.0; acl "test"; '
            'allow (read) userdn="ldap:///self";)'
        )
        SAMPLE_ACI_WITH_MACRO_SUBJECT: Final[str] = (
            '(targetattr="*")(version 3.0; acl "test"; '
            'allow (read) userdn="ldap:///($dn)";)'
        )
        SAMPLE_ACI_WITH_MACRO_TARGET: Final[str] = (
            '(target="($dn)")(version 3.0; acl "test"; '
            'allow (read) userdn="ldap:///($dn)";)'
        )
        SAMPLE_ACI_WITH_MACRO_SUBJECT_NO_TARGET: Final[str] = (
            '(targetattr="*")(version 3.0; acl "test"; '
            'allow (read) userdn="ldap:///[$dn]";)'
        )

        # OUD ACL attribute names
        ACL_ATTRIBUTE_ACI: Final[str] = "aci"
        ACL_ATTRIBUTE_ORCLACI: Final[str] = "orclaci"

        # Matching rules (should be filtered out)
        MATCHING_RULE_DEF: Final[str] = (
            "( 1.2.3.7 NAME 'testMR' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        MATCHING_RULE_USE_DEF: Final[str] = (
            "( 1.2.3.8 NAME 'testMRU' APPLIES testAttr )"
        )

    class Conversion:
        """Conversion test constants (from conftest ConversionTestConstants)."""

        # OID attribute definitions
        OID_ATTRIBUTE_ORCLGUID: Final[str] = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )"
        )
        OID_ATTRIBUTE_ORCLDBNAME: Final[str] = (
            "( 2.16.840.1.113894.1.1.2 NAME 'orclDBName' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        OID_ATTRIBUTE_ORCLGUID_COMPLEX: Final[str] = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
            "DESC 'Oracle Global Unique Identifier' "
            "EQUALITY caseIgnoreMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 "
            "SINGLE-VALUE )"
        )

        # OUD attribute definitions
        OUD_ATTRIBUTE_ORCLGUID: Final[str] = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )"
        )

        # OID objectClass definitions
        OID_OBJECTCLASS_ORCLCONTEXT: Final[str] = (
            "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )"
        )
        OID_OBJECTCLASS_ORCLCONTAINER: Final[str] = (
            "( 2.16.840.1.113894.1.2.2 NAME 'orclContainer' "
            "SUP top STRUCTURAL MUST cn )"
        )
        OID_OBJECTCLASS_ORCLCONTEXT_WITH_MAY: Final[str] = (
            "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' "
            "SUP top STRUCTURAL "
            "MUST cn "
            "MAY ( description $ orclVersion ) )"
        )

        # OUD objectClass definitions
        OUD_OBJECTCLASS_ORCLCONTEXT: Final[str] = (
            "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )"
        )

        # Invalid test data, sample LDIF, and error messages
        # Access via TestsFlextLdifConstants.General.* at runtime:
        #   c.General.INVALID_ATTRIBUTE
        #   c.General.INVALID_DN
        #   c.General.INVALID_DATA_TYPE
        #   c.General.SAMPLE_LDIF_ENTRY
        #   c.General.WRITER_FAILED_MSG
        #   c.General.PARSER_ERROR_MSG
        #   c.General.DN_ERROR_MSG
        #   c.General.INVALID_ENTRY_MSG
        #   c.General.PARSE_FAILED_MSG
        #   c.General.WRITE_FAILED_MSG
        # (Cannot reference nested class from class body)


# ============================================================================
# FILTER AND HELPER ALIASES FOR BACKWARD COMPATIBILITY
# ============================================================================
# These provide access to server types and test data via the Filters namespace
# used by existing test files. Maps to c.LdapServers and test constants.


class Filters:
    """Test filter constants and server types for categorization tests."""

    # Server types
    SERVER_RFC: Final[str] = FlextLdifConstants.Ldif.ServerTypes.RFC.value
    SERVER_OID: Final[str] = FlextLdifConstants.Ldif.ServerTypes.OID.value
    SERVER_OUD: Final[str] = FlextLdifConstants.Ldif.ServerTypes.OUD.value

    # Test DNs
    DN_USER_JOHN: Final[str] = "cn=john.doe,ou=users,dc=example,dc=com"
    DN_USER_JANE: Final[str] = "cn=jane.doe,ou=users,dc=example,dc=com"
    DN_USER_ADMIN: Final[str] = (
        "cn=REDACTED_LDAP_BIND_PASSWORD,ou=users,dc=example,dc=com"
    )
    DN_OU_USERS: Final[str] = "ou=users,dc=example,dc=com"
    DN_OU_GROUPS: Final[str] = "ou=groups,dc=example,dc=com"
    DN_ACL_POLICY: Final[str] = "cn=acl-policy,dc=example,dc=com"
    DN_REJECTED: Final[str] = "cn=rejected,dc=example,dc=com"

    # DN Patterns
    DN_PATTERN_USERS: Final[str] = "ou=users,*"
    DN_PATTERN_GROUPS: Final[str] = "ou=groups,*"
    DN_PATTERN_OU: Final[str] = "ou=*,*"

    # ObjectClasses
    OC_GROUP_OF_NAMES: Final[str] = "groupOfNames"
    OC_ORGANIZATIONAL_UNIT: Final[str] = "organizationalUnit"
    OC_INET_ORG_PERSON: Final[str] = "inetOrgPerson"
    OC_PERSON: Final[str] = "person"
    OC_DOMAIN: Final[str] = "domain"

    ATTR_MAIL: Final[str] = "mail"
    ATTR_SN: Final[str] = "sn"
    ATTR_CN: Final[str] = "cn"
    ATTR_OBJECTCLASS: Final[str] = "objectClass"

    # =========================================================================
    # DN CONSTANTS (For backward compatibility - used in tests)
    # =========================================================================

    class DNs:
        """DN constants for testing."""

        EXAMPLE: Final[str] = "dc=example,dc=com"
        TEST_USER: Final[str] = "cn=testuser,dc=example,dc=com"
        TEST_GROUP: Final[str] = "cn=testgroup,dc=example,dc=com"
        SCHEMA: Final[str] = "cn=schema"
        BASE: Final[str] = "dc=example,dc=com"

    # =========================================================================
    # VALUE CONSTANTS (For backward compatibility - used in tests)
    # =========================================================================

    class Values:
        """Value constants for testing."""

        TEST: Final[str] = "test"
        USER: Final[str] = "user"
        USER1: Final[str] = "user1"
        USER2: Final[str] = "user2"
        ADMIN: Final[str] = "REDACTED_LDAP_BIND_PASSWORD"
        EXAMPLE: Final[str] = "example"


class OIDs:
    """OID constant namespace for cleaner test access.

    Aliases constants from TestsFlextLdifConstants.Rfc for convenient access.
    Used by test files to reference OID constants with short names.
    """

    # Attribute OIDs
    CN: Final[str] = TestsFlextLdifConstants.Rfc.ATTR_OID_CN  # "2.5.4.3"
    SN: Final[str] = TestsFlextLdifConstants.Rfc.ATTR_OID_SN  # "2.5.4.4"
    ST: Final[str] = TestsFlextLdifConstants.Rfc.ATTR_OID_ST  # "2.5.4.8"
    MAIL: Final[str] = (
        TestsFlextLdifConstants.Rfc.ATTR_OID_MAIL
    )  # "0.9.2342.19200300.100.1.3"
    MODIFY_TIMESTAMP: Final[str] = (
        TestsFlextLdifConstants.Rfc.ATTR_OID_MODIFY_TIMESTAMP
    )  # "2.5.18.2"
    OID_O: Final[str] = (
        TestsFlextLdifConstants.Rfc.ATTR_OID_O
    )  # "2.5.4.10" (Organization attribute)
    OBJECTCLASS: Final[str] = (
        TestsFlextLdifConstants.Rfc.ATTR_OID_OBJECTCLASS
    )  # "2.5.4.0"

    # ObjectClass OIDs
    PERSON: Final[str] = TestsFlextLdifConstants.Rfc.OC_OID_PERSON  # "2.5.6.6"

    # Syntax OIDs (for convenience)
    DIRECTORY_STRING: Final[str] = (
        TestsFlextLdifConstants.Rfc.SYNTAX_OID_DIRECTORY_STRING
    )
    BOOLEAN: Final[str] = TestsFlextLdifConstants.Rfc.SYNTAX_OID_BOOLEAN
    INTEGER: Final[str] = TestsFlextLdifConstants.Rfc.SYNTAX_OID_INTEGER
    IA5_STRING: Final[str] = TestsFlextLdifConstants.Rfc.SYNTAX_OID_IA5_STRING
    GENERALIZED_TIME: Final[str] = (
        TestsFlextLdifConstants.Rfc.SYNTAX_OID_GENERALIZED_TIME
    )
    OID: Final[str] = TestsFlextLdifConstants.Rfc.SYNTAX_OID_OID


class Syntax:
    """Syntax OID constant namespace for cleaner test access.

    Aliases syntax constants from TestsFlextLdifConstants.Rfc for convenient access.
    Used by test files to reference syntax OIDs with short names.
    """

    DIRECTORY_STRING: Final[str] = (
        TestsFlextLdifConstants.Rfc.SYNTAX_OID_DIRECTORY_STRING
    )  # "1.3.6.1.4.1.1466.115.121.1.15"
    BOOLEAN: Final[str] = (
        TestsFlextLdifConstants.Rfc.SYNTAX_OID_BOOLEAN
    )  # "1.3.6.1.4.1.1466.115.121.1.7"
    INTEGER: Final[str] = (
        TestsFlextLdifConstants.Rfc.SYNTAX_OID_INTEGER
    )  # "1.3.6.1.4.1.1466.115.121.1.27"
    IA5_STRING: Final[str] = (
        TestsFlextLdifConstants.Rfc.SYNTAX_OID_IA5_STRING
    )  # "1.3.6.1.4.1.1466.115.121.1.26"
    GENERALIZED_TIME: Final[str] = (
        TestsFlextLdifConstants.Rfc.SYNTAX_OID_GENERALIZED_TIME
    )  # "1.3.6.1.4.1.1466.115.121.1.24"
    OID: Final[str] = (
        TestsFlextLdifConstants.Rfc.SYNTAX_OID_OID
    )  # "1.3.6.1.4.1.1466.115.121.1.38"


class RfcTestHelpers:
    """RFC test helper utilities for LDIF testing."""

    @staticmethod
    def test_parse_ldif_content(
        parser_service: object,
        content: str,
        expected_count: int,
        server_type: str = "rfc",
    ) -> list[object]:
        """Parse LDIF content and return entries.

        Args:
            parser_service: The parser service instance
            content: LDIF content to parse
            expected_count: Expected number of entries (for validation)
            server_type: Server type for parsing

        Returns:
            List of parsed entries

        """
        if not isinstance(parser_service, FlextLdifParser):
            raise TypeError(f"Expected FlextLdifParser, got {type(parser_service)}")

        result = parser_service.parse_string(
            content=content,
            server_type=server_type,
        )

        if result.is_failure:
            raise AssertionError(f"Parsing failed: {result.error}")

        entries = result.value.entries
        if len(entries) != expected_count:
            raise AssertionError(
                f"Expected {expected_count} entries, got {len(entries)}",
            )

        return list(entries)

    @staticmethod
    def test_entry_create_and_unwrap(
        dn: str,
        attributes: dict[str, object],
    ) -> object:
        """Create an entry and unwrap the result.

        Args:
            dn: Distinguished Name for the entry
            attributes: Dictionary of attributes for the entry

        Returns:
            The unwrapped Entry instance

        Raises:
            AssertionError: If entry creation fails

        """
        result = m.Ldif.Entry.create(dn=dn, attributes=attributes)
        if result.is_failure:
            raise AssertionError(f"Entry creation failed: {result.error}")

        return result.value

    @staticmethod
    def test_quirk_schema_parse_and_assert_properties(
        quirk: object,
        schema_def: str,
        *,
        expected_oid: str | None = None,
        expected_name: str | None = None,
        expected_desc: str | None = None,
        expected_syntax: str | None = None,
        expected_single_value: bool | None = None,
        expected_length: int | None = None,
        expected_kind: str | None = None,
        expected_sup: str | None = None,
        expected_must: list[str] | None = None,
        expected_may: list[str] | None = None,
    ) -> object:
        """Parse schema definition and assert properties.

        Args:
            quirk: Schema quirk instance
            schema_def: Schema definition string (attribute or objectClass)
            expected_oid: Expected OID
            expected_name: Expected NAME
            expected_desc: Expected DESC
            expected_syntax: Expected SYNTAX (without length)
            expected_single_value: Expected SINGLE-VALUE flag
            expected_length: Expected syntax length (e.g., 256 from {256})
            expected_kind: Expected KIND (STRUCTURAL, AUXILIARY, ABSTRACT)
            expected_sup: Expected SUP (superior class)
            expected_must: Expected MUST attributes
            expected_may: Expected MAY attributes

        Returns:
            The parsed schema object

        Raises:
            AssertionError: If parsing fails or properties don't match

        """
        # Determine parse method based on content
        if (
            "STRUCTURAL" in schema_def
            or "AUXILIARY" in schema_def
            or "ABSTRACT" in schema_def
        ):
            parse_method = getattr(quirk, "parse_objectclass", None)
        else:
            parse_method = getattr(quirk, "parse_attribute", None)

        if parse_method is None:
            parse_method = getattr(quirk, "parse", None)

        if parse_method is None:
            msg = "Quirk has no suitable parse method"
            raise AssertionError(msg)

        result = parse_method(schema_def)

        if hasattr(result, "is_failure") and result.is_failure:
            raise AssertionError(f"Parsing failed: {result.error}")

        value = result.value if hasattr(result, "value") else result

        # Assert expected properties
        if expected_oid is not None:
            actual_oid = getattr(value, "oid", None)
            if actual_oid != expected_oid:
                raise AssertionError(
                    f"Expected OID '{expected_oid}', got '{actual_oid}'",
                )

        if expected_name is not None:
            actual_name = getattr(value, "name", None)
            if actual_name != expected_name:
                raise AssertionError(
                    f"Expected NAME '{expected_name}', got '{actual_name}'",
                )

        if expected_desc is not None:
            actual_desc = getattr(value, "desc", None)
            if actual_desc != expected_desc:
                raise AssertionError(
                    f"Expected DESC '{expected_desc}', got '{actual_desc}'",
                )

        if expected_syntax is not None:
            actual_syntax = getattr(value, "syntax", None)
            if actual_syntax != expected_syntax:
                raise AssertionError(
                    f"Expected SYNTAX '{expected_syntax}', got '{actual_syntax}'",
                )

        if expected_single_value is not None:
            actual_sv = getattr(value, "single_value", None)
            if actual_sv != expected_single_value:
                raise AssertionError(
                    f"Expected SINGLE-VALUE {expected_single_value}, got {actual_sv}",
                )

        if expected_length is not None:
            actual_length = getattr(value, "length", None)
            if actual_length != expected_length:
                raise AssertionError(
                    f"Expected length {expected_length}, got {actual_length}",
                )

        if expected_kind is not None:
            actual_kind = getattr(value, "kind", None)
            if actual_kind != expected_kind:
                raise AssertionError(
                    f"Expected KIND '{expected_kind}', got '{actual_kind}'",
                )

        if expected_sup is not None:
            actual_sup = getattr(value, "sup", None)
            if actual_sup != expected_sup:
                raise AssertionError(
                    f"Expected SUP '{expected_sup}', got '{actual_sup}'",
                )

        if expected_must is not None:
            actual_must = getattr(value, "must", None) or []
            if list(actual_must) != expected_must:
                raise AssertionError(
                    f"Expected MUST {expected_must}, got {list(actual_must)}",
                )

        if expected_may is not None:
            actual_may = getattr(value, "may", None) or []
            if list(actual_may) != expected_may:
                raise AssertionError(
                    f"Expected MAY {expected_may}, got {list(actual_may)}",
                )

        return value

    @staticmethod
    def test_result_success_and_unwrap(
        result: object,
        expected_type: type | None = None,
        expected_count: int | None = None,
    ) -> object:
        """Assert result is successful and unwrap its value.

        Args:
            result: FlextResult instance to check
            expected_type: Optional expected type for the unwrapped value
            expected_count: Optional expected count if value is a sequence

        Returns:
            The unwrapped value from the result

        Raises:
            AssertionError: If result is failure or type mismatch

        """
        # Check result has is_failure attribute (duck typing for FlextResult)
        if not hasattr(result, "is_failure"):
            raise TypeError(f"Expected FlextResult-like object, got {type(result)}")

        if result.is_failure:
            error = getattr(result, "error", "Unknown error")
            raise AssertionError(f"Result is failure: {error}")

        value = result.value
        if expected_type is not None and not isinstance(value, expected_type):
            raise AssertionError(
                f"Expected {expected_type.__name__}, got {type(value).__name__}",
            )

        if expected_count is not None:
            if not hasattr(value, "__len__"):
                raise AssertionError(
                    f"Cannot check count on {type(value).__name__} - not a sequence",
                )
            if len(value) != expected_count:
                raise AssertionError(
                    f"Expected count {expected_count}, got {len(value)}",
                )

        return value

    @staticmethod
    def test_create_entry_and_unwrap(
        dn: str,
        attributes: dict[str, object] | None = None,
    ) -> object:
        """Create an entry and unwrap the result.

        Alias for test_entry_create_and_unwrap for naming consistency.

        Args:
            dn: Distinguished Name for the entry
            attributes: Dictionary of attributes for the entry

        Returns:
            The unwrapped Entry instance

        Raises:
            AssertionError: If entry creation fails

        """
        if attributes is None:
            attributes = {}
        result = m.Ldif.Entry.create(dn=dn, attributes=attributes)
        if result.is_failure:
            raise AssertionError(f"Entry creation failed: {result.error}")

        return result.value

    @staticmethod
    def test_create_schema_attribute_and_unwrap(
        oid: str,
        name: str,
        desc: str | None = None,
        syntax: str | None = None,
        *,
        single_value: bool = False,
    ) -> object:
        """Create a schema attribute and unwrap the result.

        Args:
            oid: Object Identifier
            name: Attribute name
            desc: Description
            syntax: Syntax OID
            single_value: Single value flag

        Returns:
            The unwrapped SchemaAttribute instance

        Raises:
            AssertionError: If creation fails

        """
        return m.Ldif.SchemaAttribute(
            oid=oid,
            name=name,
            desc=desc,
            syntax=syntax,
            single_value=single_value,
        )

    @staticmethod
    def test_create_schema_objectclass_and_unwrap(
        oid: str,
        name: str,
        desc: str | None = None,
        kind: str = "STRUCTURAL",
        sup: str | None = None,
        must: list[str] | None = None,
        may: list[str] | None = None,
    ) -> object:
        """Create a schema objectClass and unwrap the result.

        Args:
            oid: Object Identifier
            name: ObjectClass name
            desc: Description
            kind: Kind (STRUCTURAL, AUXILIARY, ABSTRACT)
            sup: Superior class
            must: Required attributes
            may: Optional attributes

        Returns:
            The unwrapped SchemaObjectClass instance

        Raises:
            AssertionError: If creation fails

        """
        return m.Ldif.SchemaObjectClass(
            oid=oid,
            name=name,
            desc=desc,
            kind=kind,
            sup=sup,
            must=must or [],
            may=may or [],
        )

    @staticmethod
    def test_quirk_parse_success_and_unwrap(
        quirk: object,
        content: str,
        parse_method: str | None = None,
    ) -> object:
        """Parse using quirk and assert success.

        Args:
            quirk: Schema quirk instance
            content: Content to parse
            parse_method: Optional specific parse method name

        Returns:
            The parsed value

        Raises:
            AssertionError: If parsing fails

        """
        if parse_method:
            method = getattr(quirk, parse_method, None)
            if method is None:
                raise AssertionError(f"Quirk has no method '{parse_method}'")
            result = method(content)
        else:
            result = quirk.parse(content)

        if hasattr(result, "is_failure") and result.is_failure:
            error = getattr(result, "error", "Unknown error")
            raise AssertionError(f"Parsing failed: {error}")

        return result.value if hasattr(result, "value") else result

    @staticmethod
    def test_schema_quirk_parse_and_assert(
        quirk: object,
        content: str,
        expected_oid: str | None = None,
        expected_name: str | None = None,
        expected_desc: str | None = None,
        expected_sup: str | None = None,
        expected_kind: str | None = None,
        expected_must: list[str] | None = None,
        expected_may: list[str] | None = None,
        expected_syntax: str | None = None,
        expected_equality: str | None = None,
        expected_single_value: bool | None = None,
    ) -> object:
        """Parse schema content and assert properties.

        Args:
            quirk: Schema quirk instance
            content: Schema definition content
            expected_oid: Expected OID
            expected_name: Expected name

        Returns:
            The parsed schema object

        Raises:
            AssertionError: If parsing fails or properties don't match

        """
        # Determine parse method based on content
        if "STRUCTURAL" in content or "AUXILIARY" in content or "ABSTRACT" in content:
            parse_method = getattr(quirk, "parse_objectclass", None)
        else:
            parse_method = getattr(quirk, "parse_attribute", None)

        if parse_method is None:
            parse_method = getattr(quirk, "parse", None)

        if parse_method is None:
            msg = "Quirk has no suitable parse method"
            raise AssertionError(msg)

        result = parse_method(content)

        if hasattr(result, "is_failure") and result.is_failure:
            raise AssertionError(f"Parsing failed: {result.error}")

        value = result.value if hasattr(result, "value") else result

        if expected_oid is not None:
            actual_oid = getattr(value, "oid", None)
            if actual_oid != expected_oid:
                raise AssertionError(
                    f"Expected OID '{expected_oid}', got '{actual_oid}'",
                )

        if expected_name is not None:
            actual_name = getattr(value, "name", None)
            if actual_name != expected_name:
                raise AssertionError(
                    f"Expected name '{expected_name}', got '{actual_name}'",
                )

        if expected_desc is not None:
            actual_desc = getattr(value, "desc", None)
            if actual_desc != expected_desc:
                raise AssertionError(
                    f"Expected desc '{expected_desc}', got '{actual_desc}'",
                )

        if expected_sup is not None:
            actual_sup = getattr(value, "sup", None)
            if actual_sup != expected_sup:
                raise AssertionError(
                    f"Expected sup '{expected_sup}', got '{actual_sup}'",
                )

        if expected_kind is not None:
            actual_kind = getattr(value, "kind", None)
            if actual_kind != expected_kind:
                raise AssertionError(
                    f"Expected kind '{expected_kind}', got '{actual_kind}'",
                )

        if expected_must is not None:
            actual_must = getattr(value, "must", None)
            if actual_must != expected_must:
                raise AssertionError(
                    f"Expected must '{expected_must}', got '{actual_must}'",
                )

        if expected_may is not None:
            actual_may = getattr(value, "may", None)
            if actual_may != expected_may:
                raise AssertionError(
                    f"Expected may '{expected_may}', got '{actual_may}'",
                )

        if expected_syntax is not None:
            actual_syntax = getattr(value, "syntax", None)
            if actual_syntax != expected_syntax:
                raise AssertionError(
                    f"Expected syntax '{expected_syntax}', got '{actual_syntax}'",
                )

        if expected_equality is not None:
            actual_equality = getattr(value, "equality", None)
            if actual_equality != expected_equality:
                raise AssertionError(
                    f"Expected equality '{expected_equality}', got '{actual_equality}'",
                )

        if expected_single_value is not None:
            actual_single_value = getattr(value, "single_value", None)
            if actual_single_value != expected_single_value:
                raise AssertionError(
                    f"Expected single_value '{expected_single_value}', got '{actual_single_value}'",
                )

        return value

    @staticmethod
    def test_create_schema_attribute_from_dict(
        data: dict[str, object],
    ) -> object:
        """Create a schema attribute from dictionary.

        Args:
            data: Dictionary with attribute properties

        Returns:
            The SchemaAttribute instance

        """
        return m.Ldif.SchemaAttribute(
            oid=str(data.get("oid", "")),
            name=str(data.get("name", "")),
            desc=data.get("desc"),
            syntax=data.get("syntax"),
            single_value=bool(data.get("single_value")),
        )

    @staticmethod
    def test_create_schema_objectclass_from_dict(
        data: dict[str, object],
    ) -> object:
        """Create a schema objectClass from dictionary.

        Args:
            data: Dictionary with objectClass properties

        Returns:
            The SchemaObjectClass instance

        """
        must = data.get("must", [])
        may = data.get("may", [])
        return m.Ldif.SchemaObjectClass(
            oid=str(data.get("oid", "")),
            name=str(data.get("name", "")),
            desc=data.get("desc"),
            kind=str(data.get("kind", "STRUCTURAL")),
            sup=data.get("sup"),
            must=list(must) if must else [],
            may=list(may) if may else [],
        )

    @staticmethod
    def test_schema_parse_attribute(
        schema_quirk: object,
        attr_def: str,
        expected_oid: str,
        expected_name: str,
    ) -> object:
        """Parse attribute definition and validate expected properties.

        Args:
            schema_quirk: Schema quirk instance
            attr_def: Attribute definition string
            expected_oid: Expected OID
            expected_name: Expected name

        Returns:
            The parsed SchemaAttribute instance

        Raises:
            AssertionError: If parsing fails or properties don't match

        """
        # Get parse method
        parse_method = getattr(schema_quirk, "_parse_attribute", None)
        if parse_method is None:
            parse_method = getattr(schema_quirk, "parse_attribute", None)

        if parse_method is None:
            msg = "Schema quirk has no attribute parse method"
            raise AssertionError(msg)

        result = parse_method(attr_def)

        if hasattr(result, "is_failure") and result.is_failure:
            raise AssertionError(f"Attribute parsing failed: {result.error}")

        value = result.value if hasattr(result, "value") else result

        # Validate expected properties
        actual_oid = getattr(value, "oid", None)
        if actual_oid != expected_oid:
            raise AssertionError(f"Expected OID '{expected_oid}', got '{actual_oid}'")

        actual_name = getattr(value, "name", None)
        if actual_name != expected_name:
            raise AssertionError(
                f"Expected name '{expected_name}', got '{actual_name}'",
            )

        return value

    @staticmethod
    def test_schema_parse_objectclass(
        schema_quirk: object,
        oc_def: str,
        expected_oid: str,
        expected_name: str,
    ) -> object:
        """Parse objectClass definition and validate expected properties.

        Args:
            schema_quirk: Schema quirk instance
            oc_def: ObjectClass definition string
            expected_oid: Expected OID
            expected_name: Expected name

        Returns:
            The parsed SchemaObjectClass instance

        Raises:
            AssertionError: If parsing fails or properties don't match

        """
        # Get parse method
        parse_method = getattr(schema_quirk, "_parse_objectclass", None)
        if parse_method is None:
            parse_method = getattr(schema_quirk, "parse_objectclass", None)

        if parse_method is None:
            msg = "Schema quirk has no objectClass parse method"
            raise AssertionError(msg)

        result = parse_method(oc_def)

        if hasattr(result, "is_failure") and result.is_failure:
            raise AssertionError(f"ObjectClass parsing failed: {result.error}")

        value = result.value if hasattr(result, "value") else result

        # Validate expected properties
        actual_oid = getattr(value, "oid", None)
        if actual_oid != expected_oid:
            raise AssertionError(f"Expected OID '{expected_oid}', got '{actual_oid}'")

        actual_name = getattr(value, "name", None)
        if actual_name != expected_name:
            raise AssertionError(
                f"Expected name '{expected_name}', got '{actual_name}'",
            )

        return value

    @staticmethod
    def test_schema_write_attribute_with_metadata(
        schema_quirk: object,
        attr_def: str,
        expected_oid: str,
        expected_name: str,
        must_contain: list[str] | None = None,
    ) -> tuple[object, str]:
        """Parse attribute definition, write it back, and validate output.

        Args:
            schema_quirk: Schema quirk instance
            attr_def: Attribute definition string to parse
            expected_oid: Expected OID in the parsed attribute
            expected_name: Expected name in the parsed attribute
            must_contain: List of strings that must appear in written output

        Returns:
            Tuple of (parsed attribute, written string)

        Raises:
            AssertionError: If parsing/writing fails or validations don't pass

        """
        # First parse the attribute
        attr = RfcTestHelpers.test_schema_parse_attribute(
            schema_quirk,
            attr_def,
            expected_oid,
            expected_name,
        )

        # Get write method
        write_method = getattr(schema_quirk, "write_attribute", None)
        if write_method is None:
            msg = "Schema quirk has no write_attribute method"
            raise AssertionError(msg)

        # Write the attribute back
        result = write_method(attr)

        if hasattr(result, "is_failure") and result.is_failure:
            raise AssertionError(f"Attribute writing failed: {result.error}")

        written = result.value if hasattr(result, "value") else result

        # Validate written contains expected elements
        if must_contain:
            for element in must_contain:
                if element not in written:
                    raise AssertionError(
                        f"Expected '{element}' in written output: {written}",
                    )

        return attr, written

    @staticmethod
    def test_parse_and_assert_entry_structure(
        parser_service: object,
        content: str,
        expected_dn: str,
        expected_attributes: list[str],
        expected_count: int = 1,
    ) -> list[object]:
        """Parse LDIF content and assert entry structure.

        Args:
            parser_service: The parser service instance
            content: LDIF content to parse
            expected_dn: Expected DN of first entry
            expected_attributes: Expected attribute names
            expected_count: Expected number of entries

        Returns:
            List of parsed entries

        Raises:
            AssertionError: If parsing fails or structure doesn't match

        """
        if not isinstance(parser_service, FlextLdifParser):
            raise TypeError(f"Expected FlextLdifParser, got {type(parser_service)}")

        result = parser_service.parse_string(content=content, server_type="rfc")

        if result.is_failure:
            raise AssertionError(f"Parsing failed: {result.error}")

        entries = list(result.value.entries)
        if len(entries) != expected_count:
            raise AssertionError(
                f"Expected {expected_count} entries, got {len(entries)}",
            )

        if entries and expected_dn:
            actual_dn = getattr(entries[0], "dn", None)
            if str(actual_dn) != expected_dn:
                raise AssertionError(f"Expected DN '{expected_dn}', got '{actual_dn}'")

        if entries and expected_attributes:
            entry = entries[0]
            attrs = getattr(entry, "attributes", {})
            for attr_name in expected_attributes:
                if attr_name not in attrs:
                    raise AssertionError(
                        f"Expected attribute '{attr_name}' not found in entry",
                    )

        return entries

    @staticmethod
    def test_parse_and_assert_multiple_entries(
        parser_service: object,
        content: str,
        expected_dns: list[str],
        expected_count: int,
    ) -> list[object]:
        """Parse LDIF content with multiple entries and assert structure.

        Args:
            parser_service: The parser service instance
            content: LDIF content to parse
            expected_dns: Expected DNs of entries (in order)
            expected_count: Expected number of entries

        Returns:
            List of parsed entries

        Raises:
            AssertionError: If parsing fails or structure doesn't match

        """
        if not isinstance(parser_service, FlextLdifParser):
            raise TypeError(f"Expected FlextLdifParser, got {type(parser_service)}")

        result = parser_service.parse_string(content=content, server_type="rfc")

        if result.is_failure:
            raise AssertionError(f"Parsing failed: {result.error}")

        entries = list(result.value.entries)
        if len(entries) != expected_count:
            raise AssertionError(
                f"Expected {expected_count} entries, got {len(entries)}",
            )

        for i, expected_dn in enumerate(expected_dns):
            if i < len(entries):
                actual_dn = getattr(entries[i], "dn", None)
                if str(actual_dn) != expected_dn:
                    raise AssertionError(
                        f"Entry {i}: Expected DN '{expected_dn}', got '{actual_dn}'",
                    )

        return entries

    @staticmethod
    def test_create_entry(
        dn: str,
        attributes: dict[str, object],
    ) -> object:
        """Create an entry for testing.

        Args:
            dn: Distinguished Name for the entry
            attributes: Dictionary of attributes for the entry

        Returns:
            Entry instance

        Raises:
            AssertionError: If entry creation fails

        """
        result = m.Ldif.Entry.create(dn=dn, attributes=attributes)
        if result.is_failure:
            raise AssertionError(f"Entry creation failed: {result.error}")
        return result.value

    @staticmethod
    def test_write_entries_to_string(
        writer_service: object,
        entries: list[object],
        expected_content: list[str] | None = None,
    ) -> str:
        """Write entries to LDIF string.

        Args:
            writer_service: The writer service instance
            entries: List of entries to write
            expected_content: Optional list of strings that must appear in output

        Returns:
            LDIF string

        Raises:
            AssertionError: If writing fails or expected content not found

        """
        if not isinstance(writer_service, FlextLdifWriter):
            raise TypeError(f"Expected FlextLdifWriter, got {type(writer_service)}")

        result = writer_service.write_to_string(entries=entries)

        if result.is_failure:
            raise AssertionError(f"Writing failed: {result.error}")

        ldif_string = result.value
        if not isinstance(ldif_string, str):
            raise AssertionError(f"Expected string, got {type(ldif_string)}")

        if expected_content:
            for substring in expected_content:
                if substring not in ldif_string:
                    raise AssertionError(f"'{substring}' not found in LDIF output")

        return ldif_string

    @staticmethod
    def test_write_entries_to_file(
        writer_service: object,
        entries: list[object],
        file_path: object,
        expected_content: list[str] | None = None,
    ) -> None:
        """Write entries to LDIF file.

        Args:
            writer_service: The writer service instance
            entries: List of entries to write
            file_path: Path to write to
            expected_content: Optional list of strings that must appear in output

        Raises:
            AssertionError: If writing fails or expected content not found

        """
        if not isinstance(writer_service, FlextLdifWriter):
            raise TypeError(f"Expected FlextLdifWriter, got {type(writer_service)}")

        if not isinstance(file_path, Path):
            raise TypeError(f"Expected Path, got {type(file_path)}")

        result = writer_service.write_to_file(entries=entries, path=file_path)

        if result.is_failure:
            raise AssertionError(f"Writing to file failed: {result.error}")

        if not file_path.exists():
            raise AssertionError(f"Output file {file_path} was not created")

        if expected_content:
            content = file_path.read_text()
            for substring in expected_content:
                if substring not in content:
                    raise AssertionError(f"'{substring}' not found in file content")

    @staticmethod
    def test_parse_edge_case(
        parser_service: object,
        content: str,
        should_succeed: bool | None = None,
    ) -> object | None:
        """Parse edge case LDIF content.

        Args:
            parser_service: The parser service instance
            content: LDIF content to parse
            should_succeed: Expected success state (None = either outcome acceptable)

        Returns:
            Parse result value if successful, None otherwise

        Raises:
            AssertionError: If should_succeed specified and result doesn't match

        """
        if not isinstance(parser_service, FlextLdifParser):
            raise TypeError(f"Expected FlextLdifParser, got {type(parser_service)}")

        result = parser_service.parse_string(content=content, server_type="rfc")

        if should_succeed is True and result.is_failure:
            raise AssertionError(f"Expected success but got failure: {result.error}")

        if should_succeed is False and result.is_success:
            msg = "Expected failure but got success"
            raise AssertionError(msg)

        return result.map_or(None)

    @staticmethod
    def test_write_entry_variations(
        writer_service: object,
        entry_data: dict[str, dict[str, str | dict[str, list[str]]]],
    ) -> None:
        """Test writing entries with various data types.

        Args:
            writer_service: The writer service instance
            entry_data: Dict mapping test case names to entry data

        Raises:
            AssertionError: If any write operation fails

        """
        if not isinstance(writer_service, FlextLdifWriter):
            raise TypeError(f"Expected FlextLdifWriter, got {type(writer_service)}")

        for test_name, data in entry_data.items():
            dn = str(data.get("dn", ""))
            attributes = data.get("attributes", {})
            if not isinstance(attributes, dict):
                attributes = {}

            entry_result = m.Ldif.Entry.create(dn=dn, attributes=attributes)
            if entry_result.is_failure:
                raise AssertionError(
                    f"Entry creation failed for {test_name}: {entry_result.error}",
                )

            write_result = writer_service.write_to_string(entries=[entry_result.value])
            if write_result.is_failure:
                raise AssertionError(
                    f"Write failed for {test_name}: {write_result.error}",
                )

            if dn and dn not in write_result.value:
                raise AssertionError(f"DN '{dn}' not found in output for {test_name}")

    @staticmethod
    def test_entry_quirk_can_handle(
        entry_quirk: object,
        entry: object,
        expected: bool,
    ) -> None:
        """Test Entry quirk can_handle method.

        Args:
            entry_quirk: Entry quirk instance
            entry: Entry to test
            expected: Expected result from can_handle

        Raises:
            AssertionError: If can_handle returns unexpected result

        """
        can_handle_method = getattr(entry_quirk, "can_handle", None)
        if can_handle_method is None:
            msg = "Entry quirk has no can_handle method"
            raise AssertionError(msg)

        dn = str(getattr(entry, "dn", ""))
        attributes = getattr(entry, "attributes", {})

        result = can_handle_method(dn, attributes)
        if result != expected:
            raise AssertionError(
                f"Expected can_handle to return {expected}, got {result}",
            )

    @staticmethod
    def test_acl_quirk_parse_and_verify(
        acl_quirk: object,
        acl_line: str,
        expected_raw_acl: str | None = None,
    ) -> object:
        """Parse ACL and verify result.

        Args:
            acl_quirk: ACL quirk instance
            acl_line: ACL line to parse
            expected_raw_acl: Expected raw ACL value

        Returns:
            Parsed ACL object

        Raises:
            AssertionError: If parsing fails or verification fails

        """
        parse_method = getattr(acl_quirk, "parse", None)
        if parse_method is None:
            msg = "ACL quirk has no parse method"
            raise AssertionError(msg)

        result = parse_method(acl_line)

        if hasattr(result, "is_failure") and result.is_failure:
            raise AssertionError(f"ACL parsing failed: {result.error}")

        value = result.value if hasattr(result, "value") else result

        if expected_raw_acl is not None:
            raw_acl = getattr(value, "raw_acl", None)
            if raw_acl != expected_raw_acl:
                raise AssertionError(
                    f"Expected raw_acl '{expected_raw_acl}', got '{raw_acl}'",
                )

        return value

    @staticmethod
    def test_acl_quirk_write_and_verify(
        acl_quirk: object,
        acl: object,
        expected_content: str | None = None,
    ) -> str:
        """Write ACL and verify result.

        Args:
            acl_quirk: ACL quirk instance
            acl: ACL object to write
            expected_content: Expected content in output

        Returns:
            Written ACL string

        Raises:
            AssertionError: If writing fails or verification fails

        """
        write_method = getattr(acl_quirk, "write", None)
        if write_method is None:
            msg = "ACL quirk has no write method"
            raise AssertionError(msg)

        result = write_method(acl)

        if hasattr(result, "is_failure") and result.is_failure:
            raise AssertionError(f"ACL writing failed: {result.error}")

        output = result.value if hasattr(result, "value") else result

        if not isinstance(output, str):
            raise AssertionError(f"Expected string output, got {type(output)}")

        if expected_content is not None and expected_content not in output:
            raise AssertionError(f"Expected '{expected_content}' not found in output")

        return output

    @staticmethod
    def test_parse_error_handling(
        schema_quirk: object,
        invalid_def: str,
        *,
        should_fail: bool = True,
    ) -> object | None:
        """Test parsing error handling for invalid definitions.

        Args:
            schema_quirk: Schema quirk instance
            invalid_def: Invalid attribute/objectClass definition string
            should_fail: Whether parsing should fail (default True)

        Returns:
            Parse result value if successful, None otherwise

        Raises:
            AssertionError: If should_fail and parsing succeeds,
                           or if not should_fail and parsing fails

        """
        # Try attribute parse method
        parse_method = getattr(schema_quirk, "_parse_attribute", None)
        if parse_method is None:
            parse_method = getattr(schema_quirk, "parse_attribute", None)

        if parse_method is None:
            msg = "Schema quirk has no attribute parse method"
            raise AssertionError(msg)

        result = parse_method(invalid_def)

        if hasattr(result, "is_failure"):
            is_failure = result.is_failure
        else:
            is_failure = result is None

        if should_fail and not is_failure:
            msg = "Expected parsing to fail but it succeeded"
            raise AssertionError(msg)

        if not should_fail and is_failure:
            error_msg = result.error if hasattr(result, "error") else "Unknown error"
            raise AssertionError(f"Expected parsing to succeed but got: {error_msg}")

        if is_failure:
            return None

        return result.value if hasattr(result, "value") else result


class TestDeduplicationHelpers:
    """Test helpers for deduplication functionality."""

    @staticmethod
    def create_entries_batch(
        entries_data: list[dict[str, object]],
        *,
        validate_all: bool = True,
    ) -> list[object]:
        """Create multiple entries from data dictionaries.

        Args:
            entries_data: List of dicts with 'dn' and 'attributes' keys
            validate_all: Whether to validate all entries (currently unused)

        Returns:
            List of created Entry instances

        """
        service = FlextLdifEntries()
        entries = []
        for entry_data in entries_data:
            dn: str = entry_data["dn"]
            attrs: dict[str, object] = entry_data["attributes"]
            result = service.create_entry(dn=dn, attributes=attrs)
            if result.is_success:
                entries.append(result.value)
        return entries

    @staticmethod
    def batch_parse_and_assert(
        parser_service: object,
        test_cases: list[dict[str, object]],
        *,
        validate_all: bool = True,
    ) -> list[object]:
        """Batch parse LDIF content and assert results.

        Args:
            parser_service: The parser service instance
            test_cases: List of dicts with 'ldif_content', 'should_succeed',
                       and optionally 'server_type' keys
            validate_all: Whether to validate all results strictly

        Returns:
            List of parse results

        Raises:
            AssertionError: If validation fails when validate_all is True

        """
        if not isinstance(parser_service, FlextLdifParser):
            raise TypeError(f"Expected FlextLdifParser, got {type(parser_service)}")

        results = []
        for test_case in test_cases:
            ldif_content = str(test_case.get("ldif_content", ""))
            should_succeed = test_case.get("should_succeed")
            server_type = str(test_case.get("server_type", "rfc"))

            result = parser_service.parse_string(
                content=ldif_content,
                server_type=server_type,
            )

            if validate_all and should_succeed is True and result.is_failure:
                raise AssertionError(
                    f"Expected success but got failure: {result.error}",
                )

            if validate_all and should_succeed is False and result.is_success:
                msg = "Expected failure but got success"
                raise AssertionError(msg)

            results.append(result)

        return results

    @staticmethod
    def helper_api_write_and_unwrap(
        api: object,
        entries: list[object],
        must_contain: list[str] | None = None,
    ) -> str:
        """Write entries to string and unwrap result.

        Args:
            api: FlextLdif instance
            entries: List of entries to write
            must_contain: List of strings that must appear in output

        Returns:
            LDIF string

        """
        assert isinstance(api, FlextLdif)
        result = api.write(entries)
        assert result.is_success, f"write() failed: {result.error}"
        ldif_string = result.value
        assert isinstance(ldif_string, str)

        if must_contain:
            for substring in must_contain:
                assert substring in ldif_string, (
                    f"'{substring}' not found in LDIF output"
                )

        return ldif_string

    @staticmethod
    def api_parse_write_file_and_assert(
        api: object,
        entries: list[object],
        output_file: object,
        must_contain: list[str] | None = None,
    ) -> None:
        """Write entries to file and assert content.

        Args:
            api: FlextLdif instance
            entries: List of entries to write
            output_file: Path to output file
            must_contain: List of strings that must appear in output

        """
        assert isinstance(api, FlextLdif)
        assert isinstance(output_file, Path)

        ldif_string = TestDeduplicationHelpers.helper_api_write_and_unwrap(
            api,
            entries,
            must_contain=must_contain,
        )

        output_file.write_text(ldif_string)
        assert output_file.exists(), f"Output file {output_file} was not created"

    @staticmethod
    def api_parse_write_string_and_assert(
        api: object,
        entries: list[object],
        must_contain: list[str] | None = None,
    ) -> None:
        """Write entries to string and assert content.

        Args:
            api: FlextLdif instance
            entries: List of entries to write
            must_contain: List of strings that must appear in output

        """
        TestDeduplicationHelpers.helper_api_write_and_unwrap(
            api,
            entries,
            must_contain=must_contain,
        )

    @staticmethod
    def quirk_parse_and_unwrap(
        quirk: object,
        content: str,
        msg: str | None = None,
        parse_method: str | None = None,
        expected_type: type | None = None,
        should_succeed: bool | None = None,
    ) -> object | None:
        """Parse using quirk and unwrap result.

        Args:
            quirk: Schema quirk instance with parse method
            content: Content to parse
            msg: Optional message for assertion
            parse_method: Optional specific parse method name (e.g., 'parse_attribute')
            expected_type: Optional expected type for validation
            should_succeed: Expected outcome (True=must succeed, False=must fail,
                None=any outcome acceptable)

        Returns:
            Parsed result value if successful, None if expected failure

        Raises:
            AssertionError: If should_succeed specified and result doesn't match,
                or if type doesn't match

        """
        # Get the appropriate parse method
        if parse_method:
            method = getattr(quirk, parse_method, None)
            if method is None:
                raise AssertionError(f"Quirk has no method '{parse_method}'")
            result = method(content)
        else:
            result = quirk.parse(content)

        # Handle expected failure cases
        if should_succeed is False:
            if result.is_success:
                raise AssertionError(msg or "Expected failure but parse succeeded")
            return None  # Expected failure, return None

        # Handle expected success or default case
        if should_succeed is True and result.is_failure:
            raise AssertionError(
                msg or f"Expected success but parse failed: {result.error}",
            )

        # Default behavior for should_succeed=None: assert success
        if should_succeed is None:
            assert result.is_success, msg or f"quirk.parse() failed: {result.error}"

        # For failures with should_succeed=None, return None
        if result.is_failure:
            return None

        value = result.value
        if expected_type is not None:
            # For Protocol types, use duck typing check
            if hasattr(expected_type, "__protocol_attrs__"):
                # It's a Protocol, just return the value (structural typing)
                pass
            elif not isinstance(value, expected_type):
                raise AssertionError(
                    f"Expected {expected_type.__name__}, got {type(value).__name__}",
                )
        return value

    @staticmethod
    def quirk_write_and_unwrap(
        quirk: object,
        data: object,
        msg: str | None = None,
        write_method: str | None = None,
        must_contain: list[str] | None = None,
    ) -> str:
        """Write using quirk and unwrap result.

        Args:
            quirk: Schema quirk instance with write method
            data: Data to write (Entry, SchemaAttribute, SchemaObjectClass, etc.)
            msg: Optional message for assertion
            write_method: Optional specific write method name (e.g., '_write_attribute')
            must_contain: Optional list of strings that must appear in output

        Returns:
            Written string result

        Raises:
            AssertionError: If writing fails or must_contain strings not found

        """
        # Get the appropriate write method
        if write_method:
            method = getattr(quirk, write_method, None)
            if method is None:
                raise AssertionError(f"Quirk has no method '{write_method}'")
            result = method(data)
        else:
            method = getattr(quirk, "write", None)
            if method is None:
                msg = "Quirk has no write method"
                raise AssertionError(msg)
            result = method(data)

        # Handle FlextResult or direct string
        if hasattr(result, "is_success"):
            assert result.is_success, msg or f"quirk.write() failed: {result.error}"
            output = result.value
        else:
            output = result

        assert isinstance(output, str), f"Expected str, got {type(output).__name__}"

        # Check must_contain strings
        if must_contain:
            for substring in must_contain:
                if substring not in output:
                    raise AssertionError(
                        f"'{substring}' not found in output: {output[:200]}...",
                    )

        return output

    @staticmethod
    def helper_convert_and_assert_strings(
        conversion_matrix: object,
        source_quirk: object,
        target_quirk: object,
        conversion_type: str,
        data: str,
        must_contain: list[str] | None = None,
        expected_type: type | None = None,
    ) -> str:
        """Convert data between quirks and assert result.

        Args:
            conversion_matrix: FlextLdifConversion instance
            source_quirk: Source server quirk
            target_quirk: Target server quirk
            conversion_type: Type of conversion ('attribute', 'objectClass', etc.)
            data: Data to convert (string)
            must_contain: List of strings that must appear in output
            expected_type: Expected type for validation (default: str)

        Returns:
            Converted string result

        Raises:
            AssertionError: If conversion fails or validation fails

        """
        # Get convert method
        convert_method = getattr(conversion_matrix, "convert", None)
        if convert_method is None:
            msg = "conversion_matrix has no convert method"
            raise AssertionError(msg)

        # Parse data into model instance based on conversion type
        conversion_type_lower = conversion_type.lower()
        if conversion_type_lower == "attribute":
            schema_service = FlextLdifSchema()
            parse_result = schema_service.parse_attribute(data)
            if not parse_result.is_success:
                raise AssertionError(f"Failed to parse attribute: {parse_result.error}")
            model_instance = parse_result.value
        elif conversion_type_lower in {"objectclass", "objectclasses"}:
            schema_service = FlextLdifSchema()
            parse_result = schema_service.parse_objectclass(data)
            if not parse_result.is_success:
                raise AssertionError(
                    f"Failed to parse objectclass: {parse_result.error}",
                )
            model_instance = parse_result.value
        else:
            raise AssertionError(f"Unknown conversion_type: {conversion_type}")

        # Perform conversion
        result = convert_method(
            source=source_quirk,
            target=target_quirk,
            model_instance=model_instance,
        )

        # Check result
        if hasattr(result, "is_success"):
            assert result.is_success, f"convert() failed: {result.error}"
            output = result.value
        else:
            output = result

        # Convert model instances to string if expected
        if expected_type is str and not isinstance(output, str):
            output = str(output)

        # Type check
        if expected_type is not None and not isinstance(output, expected_type):
            raise AssertionError(
                f"Expected {expected_type.__name__}, got {type(output).__name__}",
            )

        # Check must_contain strings
        if must_contain and isinstance(output, str):
            for substring in must_contain:
                if substring not in output:
                    raise AssertionError(
                        f"'{substring}' not found in output: {output[:200]}...",
                    )

        return output

    @staticmethod
    def helper_get_supported_conversions_and_assert(
        conversion_matrix: object,
        quirk: object,
        must_have_keys: list[str] | None = None,
        expected_support: dict[str, bool] | None = None,
    ) -> dict[str, bool]:
        """Get supported conversions and assert result.

        Args:
            conversion_matrix: FlextLdifConversion instance
            quirk: Server quirk to check support for
            must_have_keys: List of keys that must appear in result
            expected_support: Dict of expected key:bool values

        Returns:
            Dict of supported conversion types

        Raises:
            AssertionError: If result doesn't have expected keys or values

        """
        # Get supported conversions method
        get_support_method = getattr(
            conversion_matrix,
            "get_supported_conversions",
            None,
        )
        if get_support_method is None:
            msg = "conversion_matrix has no get_supported_conversions"
            raise AssertionError(msg)

        # Get supported conversions
        result = get_support_method(quirk)

        # Handle FlextResult
        if hasattr(result, "is_success"):
            assert result.is_success, (
                f"get_supported_conversions failed: {result.error}"
            )
            support_dict = result.value
        else:
            support_dict = result

        assert isinstance(support_dict, dict), (
            f"Expected dict, got {type(support_dict).__name__}"
        )

        # Check must_have_keys
        if must_have_keys:
            for key in must_have_keys:
                assert key in support_dict, f"Missing key '{key}' in support dict"

        # Check expected_support values
        if expected_support:
            for key, expected_value in expected_support.items():
                if key in support_dict:
                    assert support_dict[key] == expected_value, (
                        f"Expected {key}={expected_value}, got {support_dict[key]}"
                    )

        return support_dict

    @staticmethod
    def helper_batch_convert_and_assert(
        conversion_matrix: object,
        source_quirk: object,
        target_quirk: object,
        conversion_type: str,
        items: list[object],
        expected_count: int | None = None,
    ) -> list[object]:
        """Batch convert items and assert result.

        Args:
            conversion_matrix: FlextLdifConversion instance
            source_quirk: Source server quirk
            target_quirk: Target server quirk
            conversion_type: Type of conversion ('attribute', 'objectClass', etc.)
            items: List of items to convert
            expected_count: Expected number of results (default: len(items))

        Returns:
            List of converted items

        Raises:
            AssertionError: If conversion fails or count doesn't match

        """
        # Get batch_convert method
        batch_convert_method = getattr(conversion_matrix, "batch_convert", None)
        if batch_convert_method is None:
            msg = "conversion_matrix has no batch_convert method"
            raise AssertionError(msg)

        # Parse items into model instances based on conversion type
        model_list = []
        conversion_type_lower = conversion_type.lower()
        if conversion_type_lower == "attribute":
            schema_service = FlextLdifSchema()
            for item in items:
                parse_result = schema_service.parse_attribute(item)
                if not parse_result.is_success:
                    raise AssertionError(
                        f"Failed to parse attribute: {parse_result.error}",
                    )
                model_list.append(parse_result.value)
        elif conversion_type_lower in {"objectclass", "objectclasses"}:
            schema_service = FlextLdifSchema()
            for item in items:
                parse_result = schema_service.parse_objectclass(item)
                if not parse_result.is_success:
                    raise AssertionError(
                        f"Failed to parse objectclass: {parse_result.error}",
                    )
                model_list.append(parse_result.value)
        else:
            raise AssertionError(f"Unknown conversion_type: {conversion_type}")

        # Perform batch conversion
        result = batch_convert_method(
            source=source_quirk,
            target=target_quirk,
            model_list=model_list,
        )

        # Handle FlextResult
        if hasattr(result, "is_success"):
            assert result.is_success, f"batch_convert() failed: {result.error}"
            converted_items = result.value
        else:
            converted_items = result

        assert isinstance(converted_items, list), (
            f"Expected list, got {type(converted_items).__name__}"
        )

        # Check expected count
        if expected_count is not None:
            assert len(converted_items) == expected_count, (
                f"Expected {expected_count} items, got {len(converted_items)}"
            )

        return converted_items


# Short aliases per FLEXT convention
tc = TestsFlextLdifConstants  # Primary test constants alias
c = TestsFlextLdifConstants  # Alternative alias for compatibility

__all__ = [
    "Filters",
    "OIDs",
    "Syntax",
    "TestsFlextLdifConstants",
    "c",
    "tc",
]
