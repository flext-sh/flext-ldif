"""IBM Tivoli Directory Server test constants.

Constants for IBM Tivoli Directory Server quirks tests.
All constants defined as Flat class at module level without type checking.
"""


class TestsTivoliConstants:
    """Flat class with IBM Tivoli Directory Server test constants - no type checking."""

    # IBM Tivoli OID namespace
    TIVOLI_OID_NAMESPACE = "1.3.18.0.2.4"

    # Tivoli attribute definitions
    ATTRIBUTE_IBMENTRYUUID = (
        "( 1.3.18.0.2.4.1 NAME 'ibmEntryUUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
    )

    # Tivoli attribute names
    ATTRIBUTE_NAME_IBMENTRYUUID = "ibmEntryUUID"

    # Sample DNs
    SAMPLE_DN = "cn=test,dc=example,dc=com"
