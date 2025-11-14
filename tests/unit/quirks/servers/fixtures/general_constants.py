"""General test constants.

Constants shared across all server quirks tests.
All constants defined as single flat class at module level without type checking.
No duplication, no multiple declarations, no multiple modules for same thing.
"""


class TestGeneralConstants:
    """Single flat class with general test constants - no type checking."""

    # Sample DNs
    SAMPLE_DN = "cn=test,dc=example,dc=com"
    SAMPLE_DN_1 = "cn=test1,dc=example,dc=com"
    SAMPLE_DN_2 = "cn=test2,dc=example,dc=com"
    SAMPLE_SCHEMA_DN = "cn=schema"
    SAMPLE_USER_DN = "uid=testuser,ou=people,dc=example,dc=com"
    SAMPLE_SUBSCHEMA_DN = "cn=subschema"

    # Sample LDIF entries
    SAMPLE_LDIF_ENTRY = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: user
"""

    SAMPLE_LDIF_TWO_ENTRIES = """dn: cn=test1,dc=example,dc=com
cn: test1

dn: cn=test2,dc=example,dc=com
cn: test2
"""

    # Error messages for testing
    WRITER_FAILED_MSG = "Writer failed"
    PARSER_ERROR_MSG = "Parser error"
    DN_ERROR_MSG = "DN error"
    INVALID_ENTRY_MSG = "Invalid entry"
    PARSE_FAILED_MSG = "Parse failed"
    WRITE_FAILED_MSG = "Write failed"

    # Invalid test data
    INVALID_ATTRIBUTE = "this is not a valid attribute definition"
    INVALID_DN = "invalid-dn-format"
    INVALID_DATA_TYPE = "invalid_type"

    # Common attribute names
    ATTR_NAME_CN = "cn"
    ATTR_NAME_SN = "sn"
    ATTR_NAME_OBJECTCLASS = "objectClass"

    # Common attribute values
    ATTR_VALUE_TEST = "test"
    ATTR_VALUE_TEST1 = "test1"
    ATTR_VALUE_TEST2 = "test2"
    ATTR_VALUE_USER = "user"

    # Common objectClass names
    OC_NAME_PERSON = "person"
    OC_NAME_TOP = "top"
