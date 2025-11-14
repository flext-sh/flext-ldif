"""389 Directory Server test constants.

Constants for 389 Directory Server quirks tests.
All constants defined as Flat class at module level without type checking.
"""


class TestsDs389Constants:
    """Flat class with 389 Directory Server test constants - no type checking."""

    # 389 DS OID namespace
    DS389_OID_NAMESPACE = "1.3.6.1.4.1.1466.115.121"

    # 389 DS attribute definitions
    ATTRIBUTE_NSUNIQUEID = (
        "( 2.16.840.1.113730.3.1.1 NAME 'nsUniqueId' "
        "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
    )

    # 389 DS attribute names
    ATTRIBUTE_NAME_NSUNIQUEID = "nsUniqueId"

    # Sample DNs
    SAMPLE_DN = "cn=test,dc=example,dc=com"
