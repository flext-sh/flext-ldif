"""Novell eDirectory server test constants.

Constants for Novell eDirectory server quirks tests.
All constants defined as Flat class at module level without type checking.
"""


class TestsNovellConstants:
    """Flat class with Novell eDirectory server test constants - no type checking."""

    # Novell OID namespace
    NOVELL_OID_NAMESPACE = "2.16.840.1.113719"

    # Novell attribute definitions
    ATTRIBUTE_GUID = (
        "( 2.16.840.1.113719.1.1.5.1.1 NAME 'GUID' "
        "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
    )

    # Novell attribute names
    ATTRIBUTE_NAME_GUID = "GUID"

    # Sample DNs
    SAMPLE_DN = "cn=test,dc=example,dc=com"
