"""OID server test constants.

Constants for Oracle Internet Directory (OID) server quirks tests.
All constants defined as Flat class at module level without type checking.
"""


class TestsOidConstants:
    """Flat class with OID server test constants - no type checking."""

    # Oracle OID namespace
    ORACLE_OID_NAMESPACE = "2.16.840.1.113894"

    # OID attribute definitions
    ATTRIBUTE_ORCLGUID = (
        "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
        "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )"
    )
    ATTRIBUTE_ORCLDBNAME = (
        "( 2.16.840.1.113894.1.1.2 NAME 'orclDBName' "
        "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
    )
    ATTRIBUTE_ORCLGUID_COMPLEX = (
        "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
        "DESC 'Oracle Global Unique Identifier' "
        "EQUALITY caseIgnoreMatch "
        "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 "
        "SINGLE-VALUE )"
    )

    # OID objectClass definitions
    OBJECTCLASS_ORCLCONTEXT = (
        "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )"
    )
    OBJECTCLASS_ORCLCONTAINER = (
        "( 2.16.840.1.113894.1.2.2 NAME 'orclContainer' SUP top STRUCTURAL MUST cn )"
    )
    OBJECTCLASS_ORCLCONTEXT_WITH_MAY = (
        "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' "
        "SUP top STRUCTURAL "
        "MUST cn "
        "MAY ( description $ orclVersion ) )"
    )

    # OID attribute names
    ATTRIBUTE_NAME_ORCLGUID = "orclGUID"
    ATTRIBUTE_NAME_ORCLDBNAME = "orclDBName"

    # OID objectClass names
    OBJECTCLASS_NAME_ORCLCONTEXT = "orclContext"
    OBJECTCLASS_NAME_ORCLCONTAINER = "orclContainer"
