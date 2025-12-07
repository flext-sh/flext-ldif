"""RFC 4512 Compliant Server Quirks - Base LDAP Schema/ACL/Entry Implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides RFC-compliant baseline implementations for LDAP directory operations.
All server-specific quirks (OID, OUD, OpenLDAP, etc.) extend this RFC base.

Architecture:
    - RFC baseline: Strict RFC 2849/4512 compliance
    - Server quirks: Extend RFC with server-specific enhancements
    - No cross-server dependencies: Each server is isolated
    - Generic conversions: All via RFC intermediate format

References:
    - RFC 2849: LDIF Format Specification
    - RFC 4512: LDAP Directory Information Models

"""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

from flext_core import FlextLogger

from flext_ldif.constants import c
from flext_ldif.servers._base import FlextLdifServersBaseConstants

logger = FlextLogger(__name__)


class FlextLdifServersRfcConstants(FlextLdifServersBaseConstants):
    """RFC baseline constants (RFC 4512 compliant). Inherited by all servers."""

    SERVER_TYPE: ClassVar[c.Ldif.LiteralTypes.ServerTypeLiteral] = "rfc"
    PRIORITY: ClassVar[int] = 100

    # LDAP Connection Defaults (RFC 4511 §4.1 - Standard LDAP ports)
    DEFAULT_PORT: ClassVar[int] = 389  # Standard LDAP port
    DEFAULT_SSL_PORT: ClassVar[int] = 636  # Standard LDAPS port (LDAP over SSL/TLS)
    DEFAULT_PAGE_SIZE: ClassVar[int] = 1000  # RFC 2696 Simple Paged Results default

    CANONICAL_NAME: ClassVar[str] = c.Ldif.ServerTypes.RFC
    ALIASES: ClassVar[frozenset[str]] = frozenset([
        c.Ldif.ServerTypes.RFC,
        c.Ldif.ServerTypes.GENERIC,
    ])

    # Conversion capabilities
    CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset([
        c.Ldif.ServerTypes.RFC,
    ])
    CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset([
        c.Ldif.ServerTypes.RFC,
    ])

    # ACL configuration
    ACL_FORMAT: ClassVar[str] = "rfc_generic"
    ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"  # RFC 4876 ACI attribute (generic)

    # ACL metadata keys (standardized for bidirectional conversion)
    ACL_METADATA_KEY_FILTER: ClassVar[str] = "filter"
    ACL_METADATA_KEY_CONSTRAINT: ClassVar[str] = "added_object_constraint"
    ACL_METADATA_KEY_ORIGINAL_FORMAT: ClassVar[str] = (
        c.Ldif.MetadataKeys.ACL_ORIGINAL_FORMAT
    )

    # ACL permission names (RFC 4876)
    PERMISSION_READ: ClassVar[str] = "read"
    PERMISSION_WRITE: ClassVar[str] = "write"
    PERMISSION_ADD: ClassVar[str] = "add"
    PERMISSION_DELETE: ClassVar[str] = "delete"
    PERMISSION_SEARCH: ClassVar[str] = "search"
    PERMISSION_COMPARE: ClassVar[str] = "compare"

    # Supported permissions
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

    # Schema configuration (RFC 4512)
    SCHEMA_DN: ClassVar[str] = "cn=schema"

    SCHEMA_SUP_SEPARATOR: ClassVar[str] = "$"  # RFC 4512 standard SUP separator

    ATTRIBUTE_FIELDS: ClassVar[frozenset[str]] = frozenset([])

    # ObjectClass requirements
    OBJECTCLASS_REQUIREMENTS: ClassVar[Mapping[str, bool]] = {
        "requires_sup_for_auxiliary": True,
        "allows_multiple_sup": False,
        "requires_explicit_structural": False,
    }

    ATTRIBUTE_ALIASES: ClassVar[Mapping[str, list[str]]] = {}

    # Operational attributes
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

    # Categorization rules
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

    # Detection patterns
    DETECTION_OID_PATTERN: ClassVar[str] = r".*"
    DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset([])
    DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset([])
    DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset([])

    # Encoding constants
    ENCODING_UTF8: ClassVar[str] = "utf-8"
    ENCODING_UTF16LE: ClassVar[str] = "utf-16-le"
    ENCODING_ASCII: ClassVar[str] = "ascii"
    ENCODING_LATIN1: ClassVar[str] = "latin-1"

    ENCODING_ERROR_REPLACE: ClassVar[str] = "replace"
    ENCODING_ERROR_IGNORE: ClassVar[str] = "ignore"
    ENCODING_ERROR_STRICT: ClassVar[str] = "strict"

    # LDIF format constants (RFC 2849)
    LDIF_DN_PREFIX: ClassVar[str] = "dn: "
    LDIF_ATTR_SEPARATOR: ClassVar[str] = ": "
    LDIF_NEWLINE: ClassVar[str] = "\n"
    LDIF_ENTRY_SEPARATOR: ClassVar[str] = "\n\n"
    LDIF_COMMENT_PREFIX: ClassVar[str] = "# "
    LDIF_VERSION_PREFIX: ClassVar[str] = "version: "
    LDIF_CHANGETYPE_PREFIX: ClassVar[str] = "changetype: "
    LDIF_BASE64_PREFIX: ClassVar[str] = ": "  # RFC 2849 base64 marker

    LDIF_LINE_LENGTH_LIMIT: ClassVar[int] = 76
    LDIF_LINE_LENGTH_WITH_NEWLINE: ClassVar[int] = 77

    CONTROL_CHAR_THRESHOLD: ClassVar[int] = 0x20
    ASCII_MAX_CHAR: ClassVar[int] = 0x7F  # RFC 2849: Non-ASCII boundary
    ALLOWED_CONTROL_CHARS: ClassVar[str] = "\t\n\r"

    # Hook-related mappings (servers override as needed)
    MATCHING_RULE_TO_RFC: ClassVar[dict[str, str]] = {}
    SYNTAX_OID_TO_RFC: ClassVar[dict[str, str]] = {}
    BOOLEAN_CONVERSION: ClassVar[dict[str, str]] = {}
    BOOLEAN_DENORMALIZATION: ClassVar[dict[str, str]] = {}
    ATTRIBUTE_CASE_MAP: ClassVar[dict[str, str]] = {}
    ATTRIBUTE_NAME_TO_RFC: ClassVar[dict[str, str]] = {}
    ATTRIBUTE_NAME_FROM_RFC: ClassVar[dict[str, str]] = {}
    BOOLEAN_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset()

    # ACL prefix constants
    ACL_PREFIX_DN: ClassVar[str] = "dn:"
    ACL_PREFIX_VERSION: ClassVar[str] = "version 3.0"
    ACL_PREFIX_LDAP_URL: ClassVar[str] = "ldap:///"
    ACL_DEFAULT_VERSION: ClassVar[str] = "version 3.0"

    ACL_SELF_SUBJECT: ClassVar[str] = "ldap:///self"
    ACL_ANONYMOUS_SUBJECT: ClassVar[str] = "ldap:///anyone"
