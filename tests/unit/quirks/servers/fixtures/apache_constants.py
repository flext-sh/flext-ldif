"""Apache Directory Server test constants.

Constants for Apache Directory Server quirks tests.
All constants defined as Flat class at module level without type checking.
"""


class TestsApacheConstants:
    """Flat class with Apache Directory Server test constants - no type checking."""

    # Apache DS OID namespace
    APACHE_OID_NAMESPACE = "1.3.6.1.4.1.18060"

    # Apache attribute definitions
    ATTRIBUTE_ADS_ENABLED = (
        "( 1.3.6.1.4.1.18060.0.4.1.2.100 NAME 'ads-enabled' "
        "SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )"
    )
    ATTRIBUTE_ADS_SEARCHBASEDN = (
        "( 2.16.840.1.113730.3.1.1 NAME 'ads-searchBaseDN' "
        "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )"
    )

    # Apache attribute names
    ATTRIBUTE_NAME_ADS_ENABLED = "ads-enabled"
    ATTRIBUTE_NAME_ADS_SEARCHBASEDN = "ads-searchBaseDN"

    # Sample DNs
    SAMPLE_DN = "cn=test,dc=example,dc=com"
