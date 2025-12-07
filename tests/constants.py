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

from typing import Final

from flext_tests.constants import FlextTestsConstants

from flext_ldif.constants import FlextLdifConstants


class TestsFlextLdifConstants(FlextTestsConstants, FlextLdifConstants):
    """Test-specific constants extending FlextTestsConstants and FlextLdifConstants.

    Provides test-specific constants without duplicating parent functionality.
    All parent constants are accessible via inheritance hierarchy.

    Naming convention: Tests[FlextLdif] where FlextLdif is the project name.
    Short name 'c' for convenient access in tests.
    """

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

    class Names:
        """Common LDAP attribute names for testing."""

        CN: Final[str] = "cn"
        SN: Final[str] = "sn"
        MAIL: Final[str] = "mail"
        OBJECTCLASS: Final[str] = "objectClass"
        PERSON: Final[str] = "person"
        INETORGPERSON: Final[str] = "inetOrgPerson"

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
        EXAMPLE: Final[str] = "example"

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
    SERVER_RFC: Final[str] = TestsFlextLdifConstants.Ldif.ServerTypes.RFC.value
    SERVER_OID: Final[str] = TestsFlextLdifConstants.Ldif.ServerTypes.OID.value
    SERVER_OUD: Final[str] = TestsFlextLdifConstants.Ldif.ServerTypes.OUD.value

    # Test DNs
    DN_USER_JOHN: Final[str] = "cn=john.doe,ou=users,dc=example,dc=com"
    DN_OU_USERS: Final[str] = "ou=users,dc=example,dc=com"

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
        EXAMPLE: Final[str] = "example"

    # ObjectClasses
    OC_GROUP_OF_NAMES: Final[str] = "groupOfNames"
    OC_ORGANIZATIONAL_UNIT: Final[str] = "organizationalUnit"


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

    # Placeholder for RFC helper methods if needed


class TestDeduplicationHelpers:
    """Test helpers for deduplication functionality."""

    # Placeholder for deduplication helper methods if needed


class TestCategorization:
    """Test categorization helpers."""

    # Placeholder for categorization helper methods if needed


# Standardized short name for use in tests (same pattern as flext-core)
c = TestsFlextLdifConstants

__all__ = [
    "Filters",
    "OIDs",
    "RfcTestHelpers",
    "Syntax",
    "TestCategorization",
    "TestDeduplicationHelpers",
    "TestsFlextLdifConstants",
    "c",
]
