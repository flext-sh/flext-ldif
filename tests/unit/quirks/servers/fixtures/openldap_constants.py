"""OpenLDAP server test constants.

Constants for OpenLDAP server quirks tests.
All constants defined as Flat class at module level without type checking.
"""


class TestsOpenldapConstants:
    """Flat class with OpenLDAP server test constants - no type checking."""

    # OpenLDAP OID namespace
    OPENLDAP_OID_NAMESPACE = "1.3.6.1.4.1.4203"

    # OpenLDAP attribute definitions (olcAttributeTypes format)
    ATTRIBUTE_OLCBACKEND = (
        "( 1.3.6.1.4.1.4203.1.1.1 NAME 'olcBackend' "
        "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
    )

    # OpenLDAP attribute names
    ATTRIBUTE_NAME_OLCBACKEND = "olcBackend"

    # Sample DNs
    SAMPLE_DN = "cn=test,dc=example,dc=com"
    CONFIG_DN = "cn=config"
