"""RFC server test constants.

Constants for RFC server quirks tests.
All constants defined as Flat class at module level without type checking.
"""


class TestsRfcConstants:
    """Flat class with RFC server test constants - no type checking."""

    # RFC attribute definitions
    ATTR_DEF_CN = "( 2.5.4.3 NAME 'cn' )"
    ATTR_DEF_CN_FULL = "( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch )"
    ATTR_DEF_CN_COMPLETE = "( 2.5.4.3 NAME 'cn' DESC 'Common Name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
    ATTR_DEF_SN = (
        "( 2.5.4.4 NAME 'sn' DESC 'Surname' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )"
    )
    ATTR_DEF_OBJECTCLASS = "( 2.5.4.0 NAME 'objectClass' DESC 'Object Class' SYNTAX '1.3.6.1.4.1.1466.115.121.1.38' )"
    ATTR_OID_CN = "2.5.4.3"
    ATTR_OID_OBJECTCLASS = "2.5.4.0"
    ATTR_NAME_CN = "cn"
    ATTR_OID_SN = "2.5.4.4"
    ATTR_NAME_SN = "sn"

    # RFC objectClass definitions
    OC_DEF_PERSON = "( 2.5.6.6 NAME 'person' STRUCTURAL )"
    OC_DEF_PERSON_FULL = "( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) )"
    OC_DEF_PERSON_BASIC = (
        "( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL )"
    )
    OC_OID_PERSON = "2.5.6.6"
    OC_NAME_PERSON = "person"

    # Test DNs and origins
    TEST_DN = "cn=test,dc=example,dc=com"
    TEST_ORIGIN = "test.ldif"
    SCHEMA_DN_SUBSCHEMA = "cn=subschema"
    SCHEMA_DN_SCHEMA = "cn=schema"
    SCHEMA_DN_SCHEMA_SYSTEM = "cn=schema,o=system"

    # Additional attribute definitions for testing
    ATTR_DEF_CN_MINIMAL = "( 2.5.4.3 )"
    ATTR_DEF_ST = "( 2.5.4.8 NAME 'st' DESC 'State or Province Name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch )"
    ATTR_DEF_MAIL = (
        "( 0.9.2342.19200300.100.1.3 NAME 'mail' SUP name DESC 'Email address' )"
    )
    ATTR_OID_MAIL = "0.9.2342.19200300.100.1.3"
    ATTR_NAME_MAIL = "mail"
    ATTR_DEF_MODIFY_TIMESTAMP = "( 2.5.18.2 NAME 'modifyTimestamp' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )"
    ATTR_DEF_OBSOLETE = "( 2.5.4.10 NAME 'o' DESC 'Organization Name' OBSOLETE SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
    ATTR_OID_O = "2.5.4.10"
    ATTR_NAME_O = "o"

    # Syntax OIDs
    SYNTAX_OID_DIRECTORY_STRING = "1.3.6.1.4.1.1466.115.121.1.15"
    SYNTAX_OID_BOOLEAN = "1.3.6.1.4.1.1466.115.121.1.7"
    SYNTAX_OID_INTEGER = "1.3.6.1.4.1.1466.115.121.1.27"

    # Invalid definitions for error testing
    INVALID_ATTR_DEF = "NAME 'cn' DESC 'Common Name'"
    INVALID_OC_DEF = "invalid objectclass definition"

    # Sample LDIF content
    SAMPLE_LDIF_CONTENT = """dn: cn=schema
attributeTypes: ( 2.5.4.3 NAME 'cn' )
objectClasses: ( 2.5.6.6 NAME 'person' STRUCTURAL )
"""

    SAMPLE_SCHEMA_CONTENT = """dn: cn=subschema
objectClass: top
objectClass: subentry
objectClass: subschema
cn: subschema
attributeTypes: ( 2.5.4.4 NAME 'sn' DESC 'Surname' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )
objectClasses: ( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) )
"""

    # LDIF parser test constants
    SAMPLE_DN = "cn=test,dc=example,dc=com"
    SAMPLE_DN_USER1 = "cn=user1,dc=example,dc=com"
    SAMPLE_DN_USER2 = "cn=user2,dc=example,dc=com"
    SAMPLE_DN_TEST_USER = "cn=Test User,dc=example,dc=com"
    INVALID_DN = "invalid-dn-format"
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
    SAMPLE_ATTRIBUTE_CN = "cn"
    SAMPLE_ATTRIBUTE_SN = "sn"
    SAMPLE_ATTRIBUTE_PHOTO = "photo"
    SAMPLE_VALUE_TEST = "test"
    SAMPLE_VALUE_USER = "user"
    SAMPLE_VALUE_USER1 = "user1"
    SAMPLE_VALUE_USER2 = "user2"
    SAMPLE_OBJECTCLASS_PERSON = "person"
    BASE64_PHOTO_DATA = "UGhvdG8gZGF0YQ=="

    # ACL test constants
    ACL_LINE_SAMPLE = (
        '(targetattr="*")(version 3.0; acl "test"; allow (read) userdn="ldap:///self";)'
    )
    ACL_LINE_EMPTY_OID = ""
    ACL_LINE_INVALID_OID = "invalid.oid.format"
