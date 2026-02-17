"""RFC 4512 Compliant Server Quirks - Base LDAP Schema/ACL/Entry Implementation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

from flext_core import FlextLogger

from flext_ldif.servers._base import FlextLdifServersBaseConstants

logger = FlextLogger(__name__)


class FlextLdifServersRfcConstants(FlextLdifServersBaseConstants):
    """RFC baseline constants (RFC 4512 compliant)."""

    SERVER_TYPE: ClassVar[str] = "rfc"
    PRIORITY: ClassVar[int] = 100

    DEFAULT_PORT: ClassVar[int] = 389
    DEFAULT_SSL_PORT: ClassVar[int] = 636
    DEFAULT_PAGE_SIZE: ClassVar[int] = 1000

    CANONICAL_NAME: ClassVar[str] = "rfc"
    ALIASES: ClassVar[frozenset[str]] = frozenset([
        "rfc",
        "generic",
    ])

    CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset([
        "rfc",
    ])
    CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset([
        "rfc",
    ])

    ACL_FORMAT: ClassVar[str] = "rfc_generic"
    ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"

    ACL_METADATA_KEY_FILTER: ClassVar[str] = "filter"
    ACL_METADATA_KEY_CONSTRAINT: ClassVar[str] = "added_object_constraint"
    ACL_METADATA_KEY_ORIGINAL_FORMAT: ClassVar[str] = "original_format"

    PERMISSION_READ: ClassVar[str] = "read"
    PERMISSION_WRITE: ClassVar[str] = "write"
    PERMISSION_ADD: ClassVar[str] = "add"
    PERMISSION_DELETE: ClassVar[str] = "delete"
    PERMISSION_SEARCH: ClassVar[str] = "search"
    PERMISSION_COMPARE: ClassVar[str] = "compare"

    SUPPORTED_PERMISSIONS: ClassVar[frozenset[str]] = frozenset(
        [
            PERMISSION_READ,
            PERMISSION_WRITE,
            PERMISSION_ADD,
            PERMISSION_DELETE,
            PERMISSION_SEARCH,
            PERMISSION_COMPARE,
        ],
    )

    SCHEMA_DN: ClassVar[str] = "cn=schema"

    SCHEMA_SUP_SEPARATOR: ClassVar[str] = "$"

    ATTRIBUTE_FIELDS: ClassVar[frozenset[str]] = frozenset([])

    OBJECTCLASS_REQUIREMENTS: ClassVar[Mapping[str, bool]] = {
        "requires_sup_for_auxiliary": True,
        "allows_multiple_sup": False,
        "requires_explicit_structural": False,
    }

    ATTRIBUTE_ALIASES: ClassVar[Mapping[str, list[str]]] = {}

    OPERATIONAL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
        [
            "createTimestamp",
            "modifyTimestamp",
            "creatorsName",
            "modifiersName",
            "subschemaSubentry",
            "structuralObjectClass",
        ],
    )

    PRESERVE_ON_MIGRATION: ClassVar[frozenset[str]] = frozenset(
        [
            "createTimestamp",
            "modifyTimestamp",
        ],
    )

    CATEGORIZATION_PRIORITY: ClassVar[list[str]] = [
        "users",
        "hierarchy",
        "groups",
        "acl",
    ]

    CATEGORY_OBJECTCLASSES: ClassVar[dict[str, frozenset[str]]] = {
        "users": frozenset(
            [
                "person",
                "inetOrgPerson",
                "organizationalPerson",
                "residentialPerson",
            ],
        ),
        "hierarchy": frozenset(
            [
                "organizationalUnit",
                "organization",
                "locality",
                "country",
            ],
        ),
        "groups": frozenset(
            [
                "groupOfNames",
                "groupOfUniqueNames",
                "posixGroup",
            ],
        ),
    }

    CATEGORIZATION_ACL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
        ["aci", "acl"],
    )

    DETECTION_OID_PATTERN: ClassVar[str] = r".*"
    DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset([])
    DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset([])
    DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset([])

    ENCODING_UTF8: ClassVar[str] = "utf-8"
    ENCODING_UTF16LE: ClassVar[str] = "utf-16-le"
    ENCODING_ASCII: ClassVar[str] = "ascii"
    ENCODING_LATIN1: ClassVar[str] = "latin-1"

    ENCODING_ERROR_REPLACE: ClassVar[str] = "replace"
    ENCODING_ERROR_IGNORE: ClassVar[str] = "ignore"
    ENCODING_ERROR_STRICT: ClassVar[str] = "strict"

    LDIF_DN_PREFIX: ClassVar[str] = "dn: "
    LDIF_ATTR_SEPARATOR: ClassVar[str] = ": "
    LDIF_NEWLINE: ClassVar[str] = "\n"
    LDIF_ENTRY_SEPARATOR: ClassVar[str] = "\n\n"
    LDIF_COMMENT_PREFIX: ClassVar[str] = "# "
    LDIF_VERSION_PREFIX: ClassVar[str] = "version: "
    LDIF_CHANGETYPE_PREFIX: ClassVar[str] = "changetype: "
    LDIF_BASE64_PREFIX: ClassVar[str] = ": "

    LDIF_LINE_LENGTH_LIMIT: ClassVar[int] = 76
    LDIF_LINE_LENGTH_WITH_NEWLINE: ClassVar[int] = 77

    CONTROL_CHAR_THRESHOLD: ClassVar[int] = 0x20
    ASCII_MAX_CHAR: ClassVar[int] = 0x7F
    ALLOWED_CONTROL_CHARS: ClassVar[str] = "\t\n\r"

    MATCHING_RULE_TO_RFC: ClassVar[dict[str, str]] = {}
    SYNTAX_OID_TO_RFC: ClassVar[dict[str, str]] = {}
    BOOLEAN_CONVERSION: ClassVar[dict[str, str]] = {}
    BOOLEAN_DENORMALIZATION: ClassVar[dict[str, str]] = {}
    ATTRIBUTE_CASE_MAP: ClassVar[dict[str, str]] = {}
    ATTRIBUTE_NAME_TO_RFC: ClassVar[dict[str, str]] = {}
    ATTRIBUTE_NAME_FROM_RFC: ClassVar[dict[str, str]] = {}
    BOOLEAN_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset()

    ACL_PREFIX_DN: ClassVar[str] = "dn:"
    ACL_PREFIX_VERSION: ClassVar[str] = "version 3.0"
    ACL_PREFIX_LDAP_URL: ClassVar[str] = "ldap:///"
    ACL_DEFAULT_VERSION: ClassVar[str] = "version 3.0"

    ACL_SELF_SUBJECT: ClassVar[str] = "ldap:///self"
    ACL_ANONYMOUS_SUBJECT: ClassVar[str] = "ldap:///anyone"
