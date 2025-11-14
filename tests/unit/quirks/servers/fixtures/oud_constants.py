"""OUD server test constants.

Constants for Oracle Unified Directory (OUD) server quirks tests.
All constants defined as Flat class at module level without type checking.
"""


class TestsOudConstants:
    """Flat class with OUD server test constants - no type checking."""

    # OUD schema DN
    SCHEMA_DN = "cn=schema"
    SCHEMA_DN_SUBSCHEMA = "cn=subschemasubentry"

    # Sample OUD attribute definitions
    ATTRIBUTE_ORCLGUID = (
        "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
        "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )"
    )
    ATTRIBUTE_ORCLGUID_WITH_X_ORIGIN = (
        "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
        "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 X-ORIGIN 'Oracle' )"
    )
    ATTRIBUTE_ORCLGUID_WITH_X_EXTENSIONS = (
        "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
        "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 "
        "X-ORIGIN 'Oracle' X-FILE-REF '99-user.ldif' "
        "X-NAME 'TestName' X-ALIAS 'testAlias' X-OID '1.2.3.5' )"
    )
    ATTRIBUTE_SYNTAX_WITH_QUOTES = (
        "( 1.2.3.4 NAME 'testAttr' SYNTAX '1.3.6.1.4.1.1466.115.121.1.7' )"
    )
    ATTRIBUTE_SYNTAX_WITHOUT_QUOTES = (
        "( 1.2.3.4 NAME 'testAttr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )"
    )
    ATTRIBUTE_INVALID_OID = "( invalid@oid!format NAME 'testAttr' )"

    # OUD objectClass definitions
    OBJECTCLASS_ORCLCONTEXT = (
        "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )"
    )
    OBJECTCLASS_MULTIPLE_SUP = (
        "( 1.2.3.4 NAME 'testOC' SUP ( top $ person ) STRUCTURAL )"
    )
    OBJECTCLASS_SINGLE_SUP = "( 1.2.3.4 NAME 'testOC' SUP top STRUCTURAL )"

    # Sample OIDs
    SAMPLE_ATTRIBUTE_OID = "1.2.3.4"
    SAMPLE_ATTRIBUTE_OID_2 = "1.2.3.5"
    SAMPLE_OBJECTCLASS_OID = "1.2.3.6"
    SAMPLE_SYNTAX_OID = "1.3.6.1.4.1.1466.115.121.1.15"
    SAMPLE_SYNTAX_OID_QUOTED = "1.3.6.1.4.1.1466.115.121.1.7"

    # Sample attribute and objectclass names
    SAMPLE_ATTRIBUTE_NAME = "testAttr"
    SAMPLE_ATTRIBUTE_NAME_2 = "testAttr2"
    SAMPLE_OBJECTCLASS_NAME = "testOC"

    # Sample attribute definitions
    SAMPLE_ATTRIBUTE_DEF = (
        f"( {SAMPLE_ATTRIBUTE_OID} NAME '{SAMPLE_ATTRIBUTE_NAME}' "
        f"SYNTAX {SAMPLE_SYNTAX_OID} )"
    )
    SAMPLE_ATTRIBUTE_DEF_2 = (
        f"( {SAMPLE_ATTRIBUTE_OID_2} NAME '{SAMPLE_ATTRIBUTE_NAME_2}' "
        f"SYNTAX {SAMPLE_SYNTAX_OID} )"
    )
    SAMPLE_OBJECTCLASS_DEF = (
        f"( {SAMPLE_OBJECTCLASS_OID} NAME '{SAMPLE_OBJECTCLASS_NAME}' "
        "SUP top STRUCTURAL )"
    )

    # Sample DNs
    SAMPLE_DN = "cn=test,dc=example,dc=com"
    SAMPLE_SCHEMA_DN = "cn=schema"

    # Sample ACL/ACI values
    SAMPLE_ACI = (
        '(targetattr="*")(version 3.0; acl "test"; allow (read) userdn="ldap:///self";)'
    )
    SAMPLE_ACI_WITH_MACRO_SUBJECT = (
        '(targetattr="*")(version 3.0; acl "test"; '
        'allow (read) userdn="ldap:///($dn)";)'
    )
    SAMPLE_ACI_WITH_MACRO_TARGET = (
        '(target="($dn)")(version 3.0; acl "test"; '
        'allow (read) userdn="ldap:///($dn)";)'
    )
    SAMPLE_ACI_WITH_MACRO_SUBJECT_NO_TARGET = (
        '(targetattr="*")(version 3.0; acl "test"; '
        'allow (read) userdn="ldap:///[$dn]";)'
    )

    # OUD ACL attribute names
    ACL_ATTRIBUTE_ACI = "aci"
    ACL_ATTRIBUTE_ORCLACI = "orclaci"

    # Matching rules (should be filtered out)
    MATCHING_RULE_DEF = "( 1.2.3.7 NAME 'testMR' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
    MATCHING_RULE_USE_DEF = "( 1.2.3.8 NAME 'testMRU' APPLIES testAttr )"
