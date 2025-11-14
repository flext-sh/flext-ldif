"""RFC test constants module.

Flat class containing all RFC-specific test constants.
Constants are defined at module level without type checking.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""


class Rfc:
    """Flat namespace for RFC test constants - no type checking."""

    # Attribute definitions
    ATTR_DEF_CN = "( 2.5.4.3 NAME 'cn' DESC 'Common Name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
    ATTR_DEF_CN_COMPLETE = "( 2.5.4.3 NAME 'cn' DESC 'Common Name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
    ATTR_DEF_CN_MINIMAL = "( 2.5.4.3 )"
    ATTR_DEF_SN = (
        "( 2.5.4.4 NAME 'sn' DESC 'Surname' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{255} )"
    )
    ATTR_DEF_ST = "( 2.5.4.8 NAME 'st' DESC 'State or Province Name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch )"
    ATTR_DEF_MAIL = (
        "( 0.9.2342.19200300.100.1.3 NAME 'mail' SUP name DESC 'Email address' )"
    )
    ATTR_DEF_MODIFY_TIMESTAMP = "( 2.5.18.2 NAME 'modifyTimestamp' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )"
    ATTR_DEF_OBSOLETE = "( 2.5.4.10 NAME 'o' DESC 'Organization Name' OBSOLETE SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
    ATTR_DEF_OBJECTCLASS = "( 2.5.4.0 NAME 'objectClass' DESC 'Object Class' SYNTAX '1.3.6.1.4.1.1466.115.121.1.38' )"

    # OIDs
    ATTR_OID_CN = "2.5.4.3"
    ATTR_OID_SN = "2.5.4.4"
    ATTR_OID_ST = "2.5.4.8"
    ATTR_OID_MAIL = "0.9.2342.19200300.100.1.3"
    ATTR_OID_MODIFY_TIMESTAMP = "2.5.18.2"
    ATTR_OID_O = "2.5.4.10"
    ATTR_OID_OBJECTCLASS = "2.5.4.0"

    # Attribute names
    ATTR_NAME_CN = "cn"
    ATTR_NAME_SN = "sn"
    ATTR_NAME_ST = "st"
    ATTR_NAME_MAIL = "mail"
    ATTR_NAME_MODIFY_TIMESTAMP = "modifyTimestamp"
    ATTR_NAME_O = "o"
    ATTR_NAME_OBJECTCLASS = "objectClass"

    # Syntax OIDs
    SYNTAX_OID_DIRECTORY_STRING = "1.3.6.1.4.1.1466.115.121.1.15"
    SYNTAX_OID_BOOLEAN = "1.3.6.1.4.1.1466.115.121.1.7"
    SYNTAX_OID_INTEGER = "1.3.6.1.4.1.1466.115.121.1.27"
    SYNTAX_OID_IA5_STRING = "1.3.6.1.4.1.1466.115.121.1.26"
    SYNTAX_OID_GENERALIZED_TIME = "1.3.6.1.4.1.1466.115.121.1.24"
    SYNTAX_OID_OID = "1.3.6.1.4.1.1466.115.121.1.38"

    # ObjectClass definitions
    OC_DEF_PERSON = "( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) )"
    OC_DEF_PERSON_BASIC = (
        "( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL )"
    )
    OC_DEF_PERSON_MINIMAL = "( 2.5.6.6 NAME 'person' STRUCTURAL )"
    OC_OID_PERSON = "2.5.6.6"
    OC_NAME_PERSON = "person"

    # Schema DNs
    SCHEMA_DN_SUBSCHEMA = "cn=subschema"
    SCHEMA_DN_SCHEMA = "cn=schema"
    SCHEMA_DN_SCHEMA_SYSTEM = "cn=schema,o=system"

    # Test DNs
    TEST_DN = "cn=test,dc=example,dc=com"
    TEST_DN_USER1 = "cn=user1,dc=example,dc=com"
    TEST_DN_USER2 = "cn=user2,dc=example,dc=com"
    TEST_DN_TEST_USER = "cn=Test User,dc=example,dc=com"
    INVALID_DN = "invalid-dn-format"

    # LDIF content samples
    SAMPLE_LDIF_BASIC = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: user
"""
    SAMPLE_LDIF_MULTIPLE = """dn: cn=user1,dc=example,dc=com
objectClass: person
cn: user1

dn: cn=user2,dc=example,dc=com
objectClass: person
cn: user2
"""
    SAMPLE_LDIF_BINARY = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
photo:: UGhvdG8gZGF0YQ==
"""
    SAMPLE_SCHEMA_CONTENT = """dn: cn=subschema
objectClass: top
objectClass: subentry
objectClass: subschema
cn: subschema
attributeTypes: ( 2.5.4.4 NAME 'sn' DESC 'Surname' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
objectClasses: ( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) )
"""

    # Invalid definitions
    INVALID_ATTR_DEF = "NAME 'cn' DESC 'Common Name'"
    INVALID_OC_DEF = "invalid objectclass definition"

    # ACL samples
    ACL_SAMPLE_BROWSE = "access to entry by * (browse)"
    ACL_SAMPLE_READ = "access to entry by * (read)"
