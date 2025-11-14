"""Active Directory server test constants.

Constants for Active Directory server quirks tests.
All constants defined as Flat class at module level without type checking.
"""


class TestsAdConstants:
    """Flat class with Active Directory server test constants - no type checking."""

    # Microsoft AD OID namespace
    MICROSOFT_OID_NAMESPACE = "1.2.840.113556"

    # AD attribute definitions
    ATTRIBUTE_SAMACCOUNTNAME = (
        "( 1.2.840.113556.1.4.221 NAME 'sAMAccountName' "
        "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
    )
    ATTRIBUTE_USERPRINCIPALNAME = (
        "( 1.2.840.113556.1.4.656 NAME 'userPrincipalName' "
        "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
    )

    # AD attribute names
    ATTRIBUTE_NAME_SAMACCOUNTNAME = "sAMAccountName"
    ATTRIBUTE_NAME_USERPRINCIPALNAME = "userPrincipalName"

    # AD objectClass definitions
    OBJECTCLASS_USER = (
        "( 1.2.840.113556.1.5.9 NAME 'user' SUP organizationalPerson STRUCTURAL )"
    )

    # AD objectClass names
    OBJECTCLASS_NAME_USER = "user"

    # Sample DNs
    SAMPLE_DN = "cn=test,dc=example,dc=com"
    SAMPLE_USER_DN = "CN=John Doe,CN=Users,DC=example,DC=com"

    # AD ACL/ACE values
    SAMPLE_ACE = "(A;CI;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)"
