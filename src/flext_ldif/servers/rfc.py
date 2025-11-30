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

import base64
import re
from collections.abc import Mapping
from typing import ClassVar, Self, overload

from flext_core import FlextLogger, FlextResult, FlextRuntime

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities

logger = FlextLogger(__name__)


# TypedDicts moved to typings.py - import from there


class FlextLdifServersRfc(FlextLdifServersBase):
    r"""RFC-Compliant LDAP Server Implementation - STRICT Baseline.

    Implements STRICT RFC-compliant LDIF processing based on:
    - RFC 2849: LDIF Data Interchange Format (entry/change records)
    - RFC 4512: LDAP Directory Information Models (schema)
    - RFC 4514: String Representation of Distinguished Names
    - RFC 4517: LDAP Syntaxes and Matching Rules
    - RFC 2820: Access Control Requirements (ACL concepts)

    RFC 4512 Schema ABNF Grammar:
    =============================
    AttributeTypeDescription = LPAREN WSP
        numericoid                         ; Rfc.SYNTAX_OID
        [ SP "NAME" SP qdescrs ]           ; Rfc.SCHEMA_KW_NAME
        [ SP "DESC" SP qdstring ]          ; Rfc.SCHEMA_KW_DESC
        [ SP "OBSOLETE" ]                  ; Rfc.SCHEMA_KW_OBSOLETE
        [ SP "SUP" SP oid ]                ; Rfc.SCHEMA_KW_SUP
        [ SP "EQUALITY" SP oid ]           ; Rfc.SCHEMA_KW_EQUALITY
        [ SP "ORDERING" SP oid ]           ; Rfc.SCHEMA_KW_ORDERING
        [ SP "SUBSTR" SP oid ]             ; Rfc.SCHEMA_KW_SUBSTR
        [ SP "SYNTAX" SP noidlen ]         ; Rfc.SCHEMA_KW_SYNTAX
        [ SP "SINGLE-VALUE" ]              ; Rfc.SCHEMA_KW_SINGLE_VALUE
        [ SP "COLLECTIVE" ]                ; Rfc.SCHEMA_KW_COLLECTIVE
        [ SP "NO-USER-MODIFICATION" ]      ; Rfc.SCHEMA_KW_NO_USER_MODIFICATION
        [ SP "USAGE" SP usage ]            ; Rfc.SCHEMA_KW_USAGE
        extensions WSP RPAREN              ; Rfc.SCHEMA_EXTENSION_PREFIX

    ObjectClassDescription = LPAREN WSP
        numericoid
        [ SP "NAME" SP qdescrs ]
        [ SP "DESC" SP qdstring ]
        [ SP "OBSOLETE" ]
        [ SP "SUP" SP oids ]
        [ SP kind ]                        ; Rfc.SCHEMA_KINDS
        [ SP "MUST" SP oids ]              ; Rfc.SCHEMA_KW_MUST
        [ SP "MAY" SP oids ]               ; Rfc.SCHEMA_KW_MAY
        extensions WSP RPAREN

    usage = "userApplications" /           ; Rfc.SCHEMA_USAGE_*
            "directoryOperation" /
            "distributedOperation" /
            "dSAOperation"

    kind = "ABSTRACT" / "STRUCTURAL" / "AUXILIARY"  ; Rfc.SCHEMA_KIND_*

    ABNF Syntax (FlextLdifConstants.Rfc):
    =====================================
    WSP    = 0*SPACE                       ; Rfc.SCHEMA_WSP
    SP     = 1*SPACE
    LPAREN = %x28                          ; Rfc.SCHEMA_LPAREN
    RPAREN = %x29                          ; Rfc.SCHEMA_RPAREN
    SQUOTE = %x27                          ; Rfc.SCHEMA_SQUOTE
    DQUOTE = %x22                          ; Rfc.SCHEMA_DQUOTE
    DOLLAR = %x24                          ; Rfc.SCHEMA_DOLLAR

    Key RFC Standards Implemented:
    ==============================
    RFC 2849 - LDIF Format:
        - Line folding at 76 bytes (Rfc.LINE_FOLD_WIDTH)
        - Base64 encoding for non-safe characters (Rfc.BASE64_CHARS)
        - Change types: Rfc.CHANGETYPES (add, delete, modify, modrdn/moddn)
        - Modify ops: Rfc.MODIFY_OPERATIONS (add, delete, replace)

    RFC 4512 - Schema:
        - Schema keywords: Rfc.SCHEMA_KW_*
        - Usage values: Rfc.SCHEMA_USAGE_VALUES
        - Kind values: Rfc.SCHEMA_KINDS

    RFC 4514 - Distinguished Names:
        - Escape chars: Rfc.DN_ESCAPE_CHARS, DN_ESCAPE_AT_START, DN_ESCAPE_AT_END
        - Character classes: Rfc.DN_LUTF1_EXCLUDE, DN_TUTF1_EXCLUDE, DN_SUTF1_EXCLUDE
        - Separators: Rfc.DN_RDN_SEPARATOR, DN_MULTIVALUE_SEPARATOR

    Metadata Keys (FlextLdifConstants.Rfc):
    =======================================
    - META_RFC_*: Entry/LDIF metadata
    - META_SCHEMA_*: Schema parsing metadata
    - META_DN_*: DN transformation metadata
    - META_TRANSFORMATION_*: Cross-server conversion tracking

    Architecture:
    =============
    RFC Server provides complete RFC baseline. Server-specific quirks extend
    by overriding hook methods (see Entry.Acl classes for hook patterns).

    """

    class Constants:
        """RFC baseline constants (RFC 4512 compliant). Inherited by all servers."""

        SERVER_TYPE: ClassVar[FlextLdifConstants.LiteralTypes.ServerTypeLiteral] = (
            FlextLdifConstants.ServerTypes.RFC
        )
        PRIORITY: ClassVar[int] = 100

        # LDAP Connection Defaults (RFC 4511 §4.1 - Standard LDAP ports)
        DEFAULT_PORT: ClassVar[int] = 389  # Standard LDAP port
        DEFAULT_SSL_PORT: ClassVar[int] = 636  # Standard LDAPS port (LDAP over SSL/TLS)
        DEFAULT_PAGE_SIZE: ClassVar[int] = 1000  # RFC 2696 Simple Paged Results default

        CANONICAL_NAME: ClassVar[str] = FlextLdifConstants.ServerTypes.RFC
        ALIASES: ClassVar[frozenset[str]] = frozenset([
            FlextLdifConstants.ServerTypes.RFC,
        ])

        # Conversion capabilities
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset([
            FlextLdifConstants.ServerTypes.RFC,
        ])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset([
            FlextLdifConstants.ServerTypes.RFC,
        ])

        # ACL configuration
        ACL_FORMAT: ClassVar[str] = "rfc_generic"
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"  # RFC 4876 ACI attribute (generic)

        # ACL metadata keys (standardized for bidirectional conversion)
        ACL_METADATA_KEY_FILTER: ClassVar[str] = "filter"
        ACL_METADATA_KEY_CONSTRAINT: ClassVar[str] = "added_object_constraint"
        ACL_METADATA_KEY_ORIGINAL_FORMAT: ClassVar[str] = (
            FlextLdifConstants.MetadataKeys.ACL_ORIGINAL_FORMAT
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

    def _handle_parse_operation(
        self,
        ldif_text: str,
    ) -> FlextResult[FlextLdifModels.Entry | str]:
        """Handle parse operation for main quirk.

        Delegates to base class implementation.
        """
        return super()._handle_parse_operation(ldif_text)

    def _handle_write_operation(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[FlextLdifModels.Entry | str]:
        """Handle write operation for main quirk.

        Delegates to base class implementation.
        """
        return super()._handle_write_operation(entries)

    def _route_model_to_write(
        self,
        model: FlextLdifTypes.ConvertibleModel,
    ) -> FlextResult[str]:
        """Route a single model to appropriate write method.

        Delegates to base class implementation.
        """
        return super()._route_model_to_write(model)

    class Schema(FlextLdifServersBase.Schema):
        """RFC 4512 Compliant Schema Quirk - STRICT Implementation.

        RFC 4512 ABNF Grammar (Section 4.1):
        ====================================

        AttributeTypeDescription (Section 4.1.2):
        -----------------------------------------
        AttributeTypeDescription = LPAREN WSP
            numericoid                    ; object identifier
            [ SP "NAME" SP qdescrs ]      ; short names (e.g., 'cn', 'mail')
            [ SP "DESC" SP qdstring ]     ; description
            [ SP "OBSOLETE" ]             ; not active
            [ SP "SUP" SP oid ]           ; supertype
            [ SP "EQUALITY" SP oid ]      ; equality matching rule
            [ SP "ORDERING" SP oid ]      ; ordering matching rule
            [ SP "SUBSTR" SP oid ]        ; substring matching rule
            [ SP "SYNTAX" SP noidlen ]    ; value syntax (OID{len})
            [ SP "SINGLE-VALUE" ]         ; single-value constraint
            [ SP "COLLECTIVE" ]           ; collective attribute
            [ SP "NO-USER-MODIFICATION" ] ; not user modifiable
            [ SP "USAGE" SP usage ]       ; usage classification
            extensions WSP RPAREN

        ObjectClassDescription (Section 4.1.1):
        ---------------------------------------
        ObjectClassDescription = LPAREN WSP
            numericoid                 ; object identifier
            [ SP "NAME" SP qdescrs ]   ; short names
            [ SP "DESC" SP qdstring ]  ; description
            [ SP "OBSOLETE" ]          ; not active
            [ SP "SUP" SP oids ]       ; superior classes
            [ SP kind ]                ; ABSTRACT / STRUCTURAL / AUXILIARY
            [ SP "MUST" SP oids ]      ; required attributes
            [ SP "MAY" SP oids ]       ; allowed attributes
            extensions WSP RPAREN

        Common Productions:
        -------------------
        numericoid = number 1*( DOT number )
        oid = descr / numericoid
        oids = oid / ( LPAREN WSP oidlist WSP RPAREN )
        qdescrs = qdescr / ( LPAREN WSP qdescrlist WSP RPAREN )
        qdescr = SQUOTE descr SQUOTE
        noidlen = numericoid [ LCURLY len RCURLY ]
        usage = "userApplications" / "directoryOperation" /
                "distributedOperation" / "dSAOperation"
        kind = "ABSTRACT" / "STRUCTURAL" / "AUXILIARY"

        Valid Usage Values (FlextLdifConstants.Rfc.SCHEMA_USAGE_VALUES):
        - userApplications     (default for user attributes)
        - directoryOperation   (operational attributes)
        - distributedOperation (distributed across DSAs)
        - dSAOperation         (DSA-specific attributes)

        Valid ObjectClass Kinds (FlextLdifConstants.Rfc.SCHEMA_KINDS):
        - ABSTRACT    (cannot be instantiated directly)
        - STRUCTURAL  (can be instantiated, single per entry)
        - AUXILIARY   (can be added to entries with structural)
        """

        def __init__(
            self,
            schema_service: FlextLdifTypes.Services.SchemaService | None = None,
            _parent_quirk: FlextLdifServersBase | None = None,
            **kwargs: str | float | bool | None,
        ) -> None:
            """Initialize RFC schema quirk service.

            Args:
                schema_service: Injected FlextLdifSchema service (optional)
                _parent_quirk: Reference to parent FlextLdifServersBase (optional)
                **kwargs: Passed to parent class

            """
            # Pass schema_service and _parent_quirk to parent explicitly
            # Base class stores as self._schema_service
            super().__init__(
                schema_service=schema_service,
                _parent_quirk=_parent_quirk,
                **kwargs,
            )

        def can_handle_attribute(
            self,
            attr_definition: str | FlextLdifModels.SchemaAttribute,
        ) -> bool:
            """Check if RFC quirk can handle attribute definitions (abstract impl).

            Accepts raw string or SchemaAttribute model.
            """
            _ = attr_definition
            return True

        def can_handle_objectclass(
            self,
            oc_definition: str | FlextLdifModels.SchemaObjectClass,
        ) -> bool:
            """Check if RFC quirk can handle objectClass definitions (abstract impl).

            Accepts raw string or SchemaObjectClass model.
            """
            _ = oc_definition
            return True

        def should_filter_out_attribute(
            self,
            _attribute: FlextLdifModels.SchemaAttribute,
        ) -> bool:
            """RFC quirk does not filter attributes.

            Args:
                _attribute: SchemaAttribute model (unused)

            Returns:
                False

            """
            return False

        def should_filter_out_objectclass(
            self,
            _objectclass: FlextLdifModels.SchemaObjectClass,
        ) -> bool:
            """RFC quirk does not filter objectClasses.

            Args:
                _objectclass: SchemaObjectClass model (unused)

            Returns:
                False

            """
            return False

        # ===== HELPER METHODS FOR RFC SCHEMA PARSING =====

        @staticmethod
        def _build_attribute_metadata(
            attr_definition: str,
            syntax: str | None,
            syntax_validation_error: str | None,
            attribute_oid: str | None = None,
            equality_oid: str | None = None,
            ordering_oid: str | None = None,
            substr_oid: str | None = None,
            sup_oid: str | None = None,
            _server_type: str | None = None,
        ) -> FlextLdifModels.QuirkMetadata | None:
            """Build metadata for attribute including extensions and OID validation.

            Delegates to base implementation with RFC server type.

            Args:
                attr_definition: Original attribute definition
                syntax: Syntax OID (optional)
                syntax_validation_error: Validation error for syntax OID if any
                attribute_oid: Attribute OID (optional, for validation tracking)
                equality_oid: Equality matching rule OID (optional)
                ordering_oid: Ordering matching rule OID (optional)
                substr_oid: Substring matching rule OID (optional)
                sup_oid: SUP OID (optional)
                _server_type: Server type identifier (unused, always RFC)

            Returns:
                QuirkMetadata or None

            """
            return FlextLdifServersBase.Schema.build_attribute_metadata(
                attr_definition,
                syntax,
                syntax_validation_error,
                attribute_oid=attribute_oid,
                equality_oid=equality_oid,
                ordering_oid=ordering_oid,
                substr_oid=substr_oid,
                sup_oid=sup_oid,
                server_type=FlextLdifConstants.ServerTypes.RFC,
            )

        # ===== RFC 4512 PARSING METHODS =====

        def _parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse RFC 4512 attribute definition using generalized parser.

            Args:
                attr_definition: RFC 4512 attribute definition string

            Returns:
                FlextResult with parsed SchemaAttribute model

            """
            # Get server type (fast-fail if not available)
            server_type = self._get_server_type()

            # Wrap method to match ParseCoreHook protocol
            def parse_core_hook(
                definition: str,
            ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
                return self._parse_attribute_core(definition)

            parse_result = FlextLdifUtilities.Parsers.Attribute.parse(
                attr_definition,
                server_type,
                parse_core_hook,
            )

            # Invoke post-parse hook for server-specific customization
            if parse_result.is_failure:
                return parse_result

            return self._hook_post_parse_attribute(parse_result.unwrap())

        def _parse_attribute_core(
            self,
            attr_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Core RFC 4512 attribute parsing per Section 4.1.2.

            RFC 4512 ABNF (AttributeTypeDescription):
            =========================================
            AttributeTypeDescription = LPAREN WSP
                numericoid                    ; object identifier
                [ SP "NAME" SP qdescrs ]      ; short names
                [ SP "DESC" SP qdstring ]     ; description
                [ SP "OBSOLETE" ]             ; not active
                [ SP "SUP" SP oid ]           ; supertype
                [ SP "EQUALITY" SP oid ]      ; equality matching rule
                [ SP "ORDERING" SP oid ]      ; ordering matching rule
                [ SP "SUBSTR" SP oid ]        ; substring matching rule
                [ SP "SYNTAX" SP noidlen ]    ; value syntax
                [ SP "SINGLE-VALUE" ]         ; single-value constraint
                [ SP "COLLECTIVE" ]           ; collective attribute
                [ SP "NO-USER-MODIFICATION" ] ; not user modifiable
                [ SP "USAGE" SP usage ]       ; usage classification
                extensions WSP RPAREN

            Delegates parsing to FlextLdifUtilitiesSchema.parse_attribute()
            for SRP compliance and code reuse.

            Args:
                attr_definition: RFC 4512 attribute definition string

            Returns:
                FlextResult with parsed SchemaAttribute model

            """
            try:
                # Delegate parsing to centralized utility (SRP)
                parsed = FlextLdifUtilities.Schema.parse_attribute(attr_definition)

                # Extract syntax validation error from parsed result
                syntax_validation_error: str | None = None
                syntax_validation = parsed.get("syntax_validation")
                if syntax_validation and isinstance(syntax_validation, dict):
                    error_value = syntax_validation.get(
                        FlextLdifConstants.MetadataKeys.SYNTAX_VALIDATION_ERROR,
                    )
                    if isinstance(error_value, str):
                        syntax_validation_error = error_value

                # Type-safe extraction with narrowing for _build_attribute_metadata call
                # Track all OIDs: attribute, syntax, matching rules (equality, ordering, substr), and SUP
                syntax_val = parsed.get("syntax")
                syntax_for_meta: str | None = (
                    syntax_val if isinstance(syntax_val, str | type(None)) else None
                )

                oid_val = parsed.get("oid")
                oid_for_meta: str | None = (
                    oid_val if isinstance(oid_val, str | type(None)) else None
                )

                eq_val = parsed.get("equality")
                eq_for_meta: str | None = (
                    eq_val if isinstance(eq_val, str | type(None)) else None
                )

                ord_val = parsed.get("ordering")
                ord_for_meta: str | None = (
                    ord_val if isinstance(ord_val, str | type(None)) else None
                )

                sub_val = parsed.get("substr")
                sub_for_meta: str | None = (
                    sub_val if isinstance(sub_val, str | type(None)) else None
                )

                sup_val = parsed.get("sup")
                sup_for_meta: str | None = (
                    sup_val if isinstance(sup_val, str | type(None)) else None
                )

                metadata = self._build_attribute_metadata(
                    attr_definition,
                    syntax_for_meta,
                    syntax_validation_error,
                    attribute_oid=oid_for_meta,
                    equality_oid=eq_for_meta,
                    ordering_oid=ord_for_meta,
                    substr_oid=sub_for_meta,
                    sup_oid=sup_for_meta,
                )

                # Type-safe extraction with narrowing
                oid_value = parsed["oid"]
                oid: str = (
                    oid_value if isinstance(oid_value, str) else str(oid_value or "")
                )

                name_value = parsed["name"]
                name: str = (
                    name_value
                    if isinstance(name_value, str)
                    else (str(name_value) if name_value else "")
                )

                desc_value = parsed["desc"]
                desc: str | None = (
                    desc_value
                    if isinstance(desc_value, str)
                    else (
                        str(desc_value)
                        if desc_value and desc_value is not True
                        else None
                    )
                )

                syntax_value = parsed["syntax"]
                syntax: str | None = (
                    syntax_value
                    if isinstance(syntax_value, str)
                    else (
                        str(syntax_value)
                        if syntax_value and syntax_value is not True
                        else None
                    )
                )

                length_value = parsed["length"]
                if isinstance(length_value, int):
                    length: int | None = length_value
                elif isinstance(length_value, str) and length_value:
                    length = int(length_value)
                else:
                    length = None

                equality_value = parsed["equality"]
                equality: str | None = (
                    equality_value
                    if isinstance(equality_value, str)
                    else (
                        str(equality_value)
                        if equality_value and equality_value is not True
                        else None
                    )
                )

                ordering_value = parsed["ordering"]
                ordering: str | None = (
                    ordering_value
                    if isinstance(ordering_value, str)
                    else (
                        str(ordering_value)
                        if ordering_value and ordering_value is not True
                        else None
                    )
                )

                substr_value = parsed["substr"]
                substr: str | None = (
                    substr_value
                    if isinstance(substr_value, str)
                    else (
                        str(substr_value)
                        if substr_value and substr_value is not True
                        else None
                    )
                )

                single_value_value = parsed["single_value"]
                single_value: bool = (
                    isinstance(single_value_value, bool) and single_value_value
                )

                no_user_mod_value = parsed["no_user_modification"]
                no_user_modification: bool = (
                    isinstance(no_user_mod_value, bool) and no_user_mod_value
                )

                sup_value = parsed["sup"]
                sup: str | None = (
                    sup_value
                    if isinstance(sup_value, str)
                    else (
                        str(sup_value) if sup_value and sup_value is not True else None
                    )
                )

                usage_value = parsed["usage"]
                usage: str | None = (
                    usage_value
                    if isinstance(usage_value, str)
                    else (
                        str(usage_value)
                        if usage_value and usage_value is not True
                        else None
                    )
                )

                attribute = FlextLdifModels.SchemaAttribute(
                    oid=oid,
                    name=name,
                    desc=desc,
                    syntax=syntax,
                    length=length,
                    equality=equality,
                    ordering=ordering,
                    substr=substr,
                    single_value=single_value,
                    no_user_modification=no_user_modification,
                    sup=sup,
                    usage=usage,
                    metadata=metadata,
                    x_origin=None,
                    x_file_ref=None,
                    x_name=None,
                    x_alias=None,
                    x_oid=None,
                )

                return FlextResult[FlextLdifModels.SchemaAttribute].ok(attribute)

            except (ValueError, TypeError, AttributeError) as e:
                logger.exception("RFC attribute parsing exception")
                return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                    f"RFC attribute parsing failed: {e}",
                )

        def _parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse RFC 4512 objectClass definition using generalized parser.

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                FlextResult with parsed SchemaObjectClass model

            """
            # Get server type (fast-fail if not available)
            server_type = self._get_server_type()

            # Wrap method to match ParseCoreHook protocol
            def parse_core_hook(
                definition: str,
            ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
                return self._parse_objectclass_core(definition)

            parse_result = FlextLdifUtilities.Parsers.ObjectClass.parse(
                oc_definition,
                server_type,
                parse_core_hook,
            )

            # Invoke post-parse hook for server-specific customization
            if parse_result.is_failure:
                return parse_result

            return self._hook_post_parse_objectclass(parse_result.unwrap())

        def _validate_oid_list(
            self,
            oids: list[str] | None,
            oid_type: str,
            metadata_extensions: dict[str, list[str] | str | bool | None],
        ) -> None:
            """Validate OID list and track in metadata."""
            if not oids or not FlextRuntime.is_list_like(oids):
                return
            for idx, oid in enumerate(oids):
                if oid and isinstance(oid, str):
                    FlextLdifServersBase.Schema.validate_and_track_oid(
                        metadata_extensions,
                        oid,
                        f"objectClass {oid_type}[{idx}]",
                    )

        def _build_objectclass_metadata(
            self,
            oc_definition: str,
            metadata_extensions: dict[str, list[str] | str | bool | None],
        ) -> FlextLdifModels.QuirkMetadata:
            """Build objectClass metadata with extensions."""
            server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral = (
                FlextLdifConstants.ServerTypes.RFC
            )
            metadata = FlextLdifModels.QuirkMetadata(
                quirk_type=server_type,
                extensions=FlextLdifModels.DynamicMetadata(**metadata_extensions)
                if metadata_extensions
                else FlextLdifModels.DynamicMetadata(),
            )
            FlextLdifUtilities.Metadata.preserve_schema_formatting(
                metadata,
                oc_definition,
            )
            return metadata

        def _parse_objectclass_core(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Core RFC 4512 objectClass parsing per Section 4.1.1.

            Delegates parsing to FlextLdifUtilitiesSchema.parse_objectclass()
            for SRP compliance and code reuse.

            """
            try:
                parsed = FlextLdifUtilities.Schema.parse_objectclass(oc_definition)

                metadata_extensions_raw = parsed["metadata_extensions"]
                metadata_extensions: dict[str, list[str] | str | bool | None] = (
                    metadata_extensions_raw
                    if isinstance(metadata_extensions_raw, dict)
                    else {}
                )
                metadata_extensions[FlextLdifConstants.MetadataKeys.ORIGINAL_FORMAT] = (
                    oc_definition.strip()
                )
                metadata_extensions[
                    FlextLdifConstants.MetadataKeys.SCHEMA_ORIGINAL_STRING_COMPLETE
                ] = oc_definition

                objectclass_oid = parsed.get("oid")
                if objectclass_oid is None or isinstance(objectclass_oid, str):
                    FlextLdifServersBase.Schema.validate_and_track_oid(
                        metadata_extensions,
                        objectclass_oid,
                        "objectClass",
                    )

                objectclass_sup_oid = parsed.get("sup")
                if objectclass_sup_oid is None or isinstance(objectclass_sup_oid, str):
                    FlextLdifServersBase.Schema.validate_and_track_oid(
                        metadata_extensions,
                        objectclass_sup_oid,
                        "objectClass SUP",
                    )

                # Narrow must and may lists before passing to _validate_oid_list
                must_val = parsed.get("must")
                must_list: list[str] | None = (
                    must_val if isinstance(must_val, list) else None
                )
                self._validate_oid_list(must_list, "MUST", metadata_extensions)

                may_val = parsed.get("may")
                may_list: list[str] | None = (
                    may_val if isinstance(may_val, list) else None
                )
                self._validate_oid_list(may_list, "MAY", metadata_extensions)

                metadata = self._build_objectclass_metadata(
                    oc_definition,
                    metadata_extensions,
                )

                # Type-safe extraction with narrowing for SchemaObjectClass
                oc_oid_value = parsed["oid"]
                oc_oid: str = (
                    oc_oid_value
                    if isinstance(oc_oid_value, str)
                    else str(oc_oid_value or "")
                )

                oc_name_value = parsed["name"]
                oc_name: str = (
                    oc_name_value
                    if isinstance(oc_name_value, str)
                    else (str(oc_name_value) if oc_name_value else "")
                )

                oc_desc_value = parsed["desc"]
                oc_desc: str | None = (
                    oc_desc_value
                    if isinstance(oc_desc_value, str)
                    else (
                        str(oc_desc_value)
                        if oc_desc_value and oc_desc_value is not True
                        else None
                    )
                )

                oc_sup_value = parsed["sup"]
                if isinstance(oc_sup_value, str):
                    oc_sup: str | list[str] | None = oc_sup_value
                elif isinstance(oc_sup_value, list):
                    oc_sup = oc_sup_value
                else:
                    oc_sup = None

                oc_kind_value = parsed["kind"]
                oc_kind: str = (
                    oc_kind_value
                    if isinstance(oc_kind_value, str)
                    else str(oc_kind_value or "STRUCTURAL")
                )

                oc_must_value = parsed["must"]
                oc_must: list[str] | None = (
                    oc_must_value if isinstance(oc_must_value, list) else None
                )

                oc_may_value = parsed["may"]
                oc_may: list[str] | None = (
                    oc_may_value if isinstance(oc_may_value, list) else None
                )

                objectclass = FlextLdifModels.SchemaObjectClass(
                    oid=oc_oid,
                    name=oc_name,
                    desc=oc_desc,
                    sup=oc_sup,
                    kind=oc_kind,
                    must=oc_must,
                    may=oc_may,
                    metadata=metadata,
                )

                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(objectclass)

            except (ValueError, TypeError, AttributeError) as e:
                logger.exception("RFC objectClass parsing exception")
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    f"RFC objectClass parsing failed: {e}",
                )

        # Schema conversion methods eliminated - use universal parse/write pipeline

        def _transform_objectclass_for_write(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextLdifModels.SchemaObjectClass:
            """Hook for subclasses to transform objectClass before writing."""
            return oc_data

        def _post_write_objectclass(self, written_str: str) -> str:
            """Hook for subclasses to transform written objectClass string."""
            return written_str

        def _transform_attribute_for_write(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextLdifModels.SchemaAttribute:
            """Hook for subclasses to transform attribute before writing."""
            return attr_data

        def _post_write_attribute(self, written_str: str) -> str:
            """Hook for subclasses to transform written attribute string."""
            return written_str

        def _build_attribute_parts(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> list[str]:
            """Build RFC attribute definition parts.

            Delegates to FlextLdifUtilities.Schema.build_attribute_parts_with_metadata()
            for SRP compliance. Restores original formatting from metadata when
            available for zero data loss (perfect round-trip).

            Args:
                attr_data: SchemaAttribute model to serialize

            Returns:
                List of RFC-compliant attribute definition parts

            """
            return FlextLdifUtilities.Schema.build_attribute_parts_with_metadata(
                attr_data,
                restore_original=True,
            )

        def _build_objectclass_parts(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
        ) -> list[str]:
            """Build RFC objectClass definition parts.

            Delegates to FlextLdifUtilities.Schema.build_objectclass_parts_with_metadata()
            for SRP compliance. Restores original formatting from metadata when
            available for zero data loss (perfect round-trip).

            Args:
                oc_data: SchemaObjectClass model to serialize

            Returns:
                List of RFC-compliant objectClass definition parts

            """
            return FlextLdifUtilities.Schema.build_objectclass_parts_with_metadata(
                oc_data,
                restore_original=True,
            )

        def _ensure_x_origin(
            self,
            output_str: str,
            metadata: FlextLdifModels.QuirkMetadata | None,
        ) -> str:
            """Ensure X-ORIGIN extension is present if in metadata.

            Inserts X-ORIGIN before closing paren if not already present.
            Consolidated helper for both attribute and objectClass writing.
            """
            if not metadata or not metadata.extensions:
                return output_str
            x_origin_raw = metadata.extensions.get(
                FlextLdifConstants.MetadataKeys.X_ORIGIN,
            )
            if not isinstance(x_origin_raw, str):
                return output_str
            if ")" not in output_str or "X-ORIGIN" in output_str:
                return output_str
            x_origin_str = f" X-ORIGIN '{x_origin_raw}'"
            return output_str.rstrip(")") + x_origin_str + ")"

        def _write_schema_item(
            self,
            data: FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[str]:
            """Write schema item (attribute or objectClass) to RFC-compliant format.

            Auto-detects type using isinstance for proper type narrowing.

            Args:
                data: Schema item (attribute or objectClass)

            Returns:
                FlextResult with RFC-compliant string

            """
            try:
                # Use isinstance for proper type narrowing
                if isinstance(data, FlextLdifModels.SchemaAttribute):
                    attr_transformed = self._transform_attribute_for_write(data)
                    if not attr_transformed.oid:
                        return FlextResult[str].fail(
                            "RFC attribute writing failed: missing OID",
                        )
                    parts = self._build_attribute_parts(attr_transformed)
                    written_str = " ".join(parts)
                    transformed_str = self._post_write_attribute(written_str)

                    # Restore original case from metadata (attribute only)
                    if attr_transformed.metadata:
                        fmt = attr_transformed.metadata.schema_format_details
                        if fmt:
                            attr_case = getattr(
                                fmt,
                                "attribute_case",
                                FlextLdifConstants.SchemaFields.ATTRIBUTE_TYPES,
                            )
                            attr_types_lower = (
                                FlextLdifConstants.SchemaFields.ATTRIBUTE_TYPES.lower()
                            )
                            if attr_types_lower in transformed_str.lower():
                                transformed_str = re.sub(
                                    rf"{attr_types_lower}:",
                                    f"{attr_case}:",
                                    transformed_str,
                                    flags=re.IGNORECASE,
                                )
                    return FlextResult[str].ok(
                        self._ensure_x_origin(
                            transformed_str,
                            attr_transformed.metadata,
                        ),
                    )

                # data is SchemaObjectClass
                oc_transformed = self._transform_objectclass_for_write(data)
                if not oc_transformed.oid:
                    return FlextResult[str].fail(
                        "RFC objectclass writing failed: missing OID",
                    )
                parts = self._build_objectclass_parts(oc_transformed)
                written_str = " ".join(parts)
                transformed_str = self._post_write_objectclass(written_str)

                return FlextResult[str].ok(
                    self._ensure_x_origin(transformed_str, oc_transformed.metadata),
                )

            except (ValueError, TypeError, AttributeError) as e:
                item_type = (
                    "attribute"
                    if isinstance(data, FlextLdifModels.SchemaAttribute)
                    else "objectclass"
                )
                logger.exception("RFC %s writing exception", item_type, exception=e)
                return FlextResult[str].fail(f"RFC {item_type} writing failed: {e}")

        def _write_attribute(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[str]:
            """Write attribute to RFC-compliant string format (internal)."""
            if not isinstance(attr_data, FlextLdifModels.SchemaAttribute):
                return FlextResult[str].fail(
                    f"Invalid attribute type: expected SchemaAttribute, "
                    f"got {type(attr_data).__name__}",
                )
            return self._write_schema_item(attr_data)

        def _write_objectclass(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[str]:
            """Write objectClass to RFC-compliant string format (internal)."""
            if not isinstance(oc_data, FlextLdifModels.SchemaObjectClass):
                return FlextResult[str].fail(
                    f"Invalid objectClass type: expected SchemaObjectClass, "
                    f"got {type(oc_data).__name__}",
                )
            return self._write_schema_item(oc_data)

        # parse(), write(), _route_parse() are now in base.py
        # This class only provides RFC-specific implementations of:
        # - _parse_attribute(), _parse_objectclass()
        # - _write_attribute(), _write_objectclass()
        # - can_handle_attribute(), can_handle_objectclass()

        @overload
        def __call__(
            self,
            attr_definition: str,
            *,
            oc_definition: None = None,
            attr_model: None = None,
            oc_model: None = None,
            operation: FlextLdifConstants.LiteralTypes.ParseOperationLiteral
            | None = None,
        ) -> FlextLdifTypes.SchemaModel: ...

        @overload
        def __call__(
            self,
            *,
            attr_definition: None = None,
            oc_definition: str,
            attr_model: None = None,
            oc_model: None = None,
            operation: FlextLdifConstants.LiteralTypes.ParseOperationLiteral
            | None = None,
        ) -> FlextLdifTypes.SchemaModel: ...

        @overload
        def __call__(
            self,
            *,
            attr_definition: None = None,
            oc_definition: None = None,
            attr_model: FlextLdifModels.SchemaAttribute,
            oc_model: None = None,
            operation: FlextLdifConstants.LiteralTypes.WriteOperationLiteral
            | None = None,
        ) -> str: ...

        @overload
        def __call__(
            self,
            *,
            attr_definition: None = None,
            oc_definition: None = None,
            attr_model: None = None,
            oc_model: FlextLdifModels.SchemaObjectClass,
            operation: FlextLdifConstants.LiteralTypes.WriteOperationLiteral
            | None = None,
        ) -> str: ...

        @overload
        def __call__(
            self,
            attr_definition: str | None = None,
            oc_definition: str | None = None,
            attr_model: FlextLdifModels.SchemaAttribute | None = None,
            oc_model: FlextLdifModels.SchemaObjectClass | None = None,
            operation: FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral
            | None = None,
        ) -> FlextLdifTypes.SchemaModelOrString: ...

        def __call__(
            self,
            attr_definition: str | None = None,
            oc_definition: str | None = None,
            attr_model: FlextLdifModels.SchemaAttribute | None = None,
            oc_model: FlextLdifModels.SchemaObjectClass | None = None,
            operation: FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral
            | None = None,
        ) -> FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str:
            """Callable interface - automatic polymorphic processor.

            Pass definition string for parsing or model for writing.
            Returns concrete model instances (SchemaAttribute/SchemaObjectClass)
            or strings, which satisfy the Protocol contracts.
            """
            # Schema.execute() expects a single 'data' parameter, not separate parameters
            # For __call__, we need to handle multiple parameters differently
            # If attr_definition is provided, use it; otherwise use oc_definition
            # If attr_model is provided, use it; otherwise use oc_model
            data: (
                str
                | FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | None
            ) = None
            if attr_definition is not None:
                data = attr_definition
            elif oc_definition is not None:
                data = oc_definition
            elif attr_model is not None:
                data = attr_model
            elif oc_model is not None:
                data = oc_model

            result = self.execute(data=data, operation=operation)
            return result.unwrap()

        def __new__(
            cls,
            schema_service: FlextLdifTypes.Services.SchemaService | None = None,
            **kwargs: FlextLdifTypes.FlexibleKwargsMutable,
        ) -> Self:
            """Override __new__ to support auto-execute and processor instantiation."""
            # Use object.__new__ to avoid calling parent's __new__ which also checks auto_execute
            # This prevents recursion when child class has auto_execute=True
            instance = object.__new__(cls)
            # Remove auto-execute kwargs before passing to __init__
            # Filter out auto-execute kwargs AND _parent_quirk (internal, not for Pydantic)
            filtered_kwargs = {
                "attr_definition",
                "oc_definition",
                "attr_model",
                "oc_model",
                "operation",
                "_parent_quirk",  # Internal attribute, not for Pydantic
            }
            init_kwargs = {k: v for k, v in kwargs.items() if k not in filtered_kwargs}
            # Initialize instance using proper type - Schema.__init__ accepts schema_service
            # Type narrowing: instance is Self (Schema subclass)
            # Guard clause: should always pass for valid Schema subclasses
            if not isinstance(instance, FlextLdifServersRfc.Schema):
                # Unreachable for valid Schema subclasses, but needed for type safety
                error_msg = f"Invalid instance type: {type(instance)}"
                raise TypeError(error_msg)
            schema_instance: Self = instance  # Now properly narrowed
            # Initialize using super() to avoid mypy error about accessing __init__ on instance
            # Use FlextLdifServersBase.Schema as the base class for super()
            if schema_service is not None:
                super(FlextLdifServersBase.Schema, schema_instance).__init__(
                    schema_service=schema_service,
                    parent_quirk=None,
                    **init_kwargs,
                )
            else:
                super(FlextLdifServersBase.Schema, schema_instance).__init__(
                    parent_quirk=None,
                    **init_kwargs,
                )

            if cls.auto_execute:
                # Type-safe extraction of kwargs with isinstance checks
                attr_def_raw = kwargs.get("attr_definition")
                attr_def: str | None = (
                    attr_def_raw if isinstance(attr_def_raw, str) else None
                )
                oc_def_raw = kwargs.get("oc_definition")
                oc_def: str | None = oc_def_raw if isinstance(oc_def_raw, str) else None
                attr_mod_raw = kwargs.get("attr_model")
                attr_mod: FlextLdifModels.SchemaAttribute | None = (
                    attr_mod_raw
                    if isinstance(attr_mod_raw, FlextLdifModels.SchemaAttribute)
                    else None
                )
                oc_mod_raw = kwargs.get("oc_model")
                oc_mod: FlextLdifModels.SchemaObjectClass | None = (
                    oc_mod_raw
                    if isinstance(oc_mod_raw, FlextLdifModels.SchemaObjectClass)
                    else None
                )
                op_raw = kwargs.get("operation")
                op: FlextLdifConstants.LiteralTypes.ParseOperationLiteral | None = (
                    "parse" if op_raw == "parse" else None
                )
                # Schema.execute() expects a single 'data' parameter
                data: (
                    str
                    | FlextLdifModels.SchemaAttribute
                    | FlextLdifModels.SchemaObjectClass
                    | None
                ) = None
                if attr_def is not None:
                    data = attr_def
                elif oc_def is not None:
                    data = oc_def
                elif attr_mod is not None:
                    data = attr_mod
                elif oc_mod is not None:
                    data = oc_mod
                # Type narrowing: instance is Self (Schema subclass)
                # Use schema_instance from above
                result = schema_instance.execute(data=data, operation=op)
                # Unwrap and return the result of auto-execute
                unwrapped = result.unwrap()
                if isinstance(unwrapped, cls):
                    return unwrapped
                return instance

            return instance

        def create_metadata(
            self,
            original_format: str,
            extensions: dict[str, object] | None = None,
        ) -> FlextLdifModels.QuirkMetadata:
            """Create quirk metadata with consistent server-specific extensions.

            Helper method to consolidate metadata creation across server quirks.
            Reduces code duplication in server-specific parse_attribute/parse_objectclass methods.

            Args:
                original_format: Original text format of the parsed element
                extensions: Optional dict of server-specific extensions/metadata

            Returns:
                FlextLdifModels.QuirkMetadata with quirk_type from Constants of parent server class

            Note:
                server_type is retrieved from Constants of the parent server class dynamically.
                This ensures all nested classes (Schema, Acl, Entry) use the same Constants
                from their parent server class (e.g., FlextLdifServersRfc.Constants,
                FlextLdifServersOid.Constants).

            """
            # Find parent server class that has Constants
            # Iterate through MRO to find the server class (not nested Schema/Acl/Entry)
            server_type_value: FlextLdifConstants.LiteralTypes.ServerTypeLiteral = (
                "generic"
            )
            for cls in type(self).__mro__:
                # Check if this class has a Constants nested class
                if hasattr(cls, "Constants") and hasattr(cls.Constants, "SERVER_TYPE"):
                    server_type_value = cls.Constants.SERVER_TYPE.value
                    break

            # Build extensions with original_format
            all_extensions: dict[str, object] = {
                FlextLdifConstants.MetadataKeys.ACL_ORIGINAL_FORMAT: original_format,
            }
            if extensions:
                all_extensions.update(extensions)

            return FlextLdifModels.QuirkMetadata(
                quirk_type=server_type_value,
                extensions=FlextLdifModels.DynamicMetadata(**all_extensions)
                if all_extensions
                else FlextLdifModels.DynamicMetadata(),
            )

        def extract_schemas_from_ldif(
            self,
            ldif_content: str,
            *,
            validate_dependencies: bool = False,
        ) -> FlextResult[dict[str, object]]:
            """Extract schema definitions from LDIF using FlextLdifUtilities.

            Args:
                ldif_content: Raw LDIF content with schema definitions
                validate_dependencies: If True, validate attrs before objectClass extraction

            Returns:
                FlextResult with ATTRIBUTES and OBJECTCLASS lists

            """
            try:
                # PHASE 1: Extract all attributeTypes using FlextLdifUtilities
                attributes_parsed = (
                    FlextLdifUtilities.Schema.extract_attributes_from_lines(
                        ldif_content,
                        self.parse_attribute,
                    )
                )

                # PHASE 2: Build available attributes set (if validation requested)
                if validate_dependencies:
                    available_attrs = (
                        FlextLdifUtilities.Schema.build_available_attributes_set(
                            attributes_parsed,
                        )
                    )

                    # Call server-specific validation hook
                    validation_result = self._hook_validate_attributes(
                        attributes_parsed,
                        available_attrs,
                    )
                    if not validation_result.is_success:
                        return FlextResult[dict[str, object]].fail(
                            f"Attribute validation failed: {validation_result.error}",
                        )

                # PHASE 3: Extract objectClasses using FlextLdifUtilities
                objectclasses_parsed = (
                    FlextLdifUtilities.Schema.extract_objectclasses_from_lines(
                        ldif_content,
                        self.parse_objectclass,
                    )
                )

                # Return combined result
                dk = FlextLdifConstants.DictKeys
                schema_dict: dict[str, object] = {
                    dk.ATTRIBUTES: attributes_parsed,
                    dk.OBJECTCLASS: objectclasses_parsed,
                }
                return FlextResult[dict[str, object]].ok(schema_dict)

            except Exception as e:
                logger.exception(
                    "Schema extraction failed",
                )
                return FlextResult[dict[str, object]].fail(
                    f"Schema extraction failed: {e}",
                )

    class Acl(FlextLdifServersBase.Acl):
        r"""LDAP ACL Quirk - Base Implementation.

        Note: LDAP Access Control is NOT standardized in a single RFC.
        RFC 2820 defines requirements, but implementations vary by vendor:
        - OpenLDAP: Uses "olcAccess" with complex syntax
        - Oracle OID: Uses "orclaci" attribute
        - Oracle OUD: Uses "aci" attribute with OpenDS/DSEE syntax
        - Active Directory: Uses ACE/ACL security descriptors

        This base implementation provides common ACL parsing primitives
        that server-specific quirks can extend with vendor-specific parsing.

        Common ACL Concepts (RFC 2820 Requirements):
        =============================================
        - Subject: Who the ACL applies to (user, group, role)
        - Target: What resource is being protected (entry, attribute)
        - Permissions: What operations are allowed/denied (read, write, etc.)

        """

        def can_handle_acl(self, acl_line: FlextLdifTypes.AclOrString) -> bool:
            """Check if this quirk can handle the ACL definition.

            RFC quirk handles all ACLs as it's the baseline implementation.

            Args:
                acl_line: ACL definition line string or Acl model

            Returns:
                True (RFC handles all ACLs)

            """
            _ = acl_line  # Unused - RFC handles all ACLs
            return True

        def _supports_feature(self, feature_id: str) -> bool:
            """Check if this server supports a specific feature.

            Delegates to base class implementation.
            """
            return super()._supports_feature(feature_id)

        def _normalize_permission(
            self,
            permission: str,
            _metadata: dict[str, object],
        ) -> tuple[str, str | None]:
            """Normalize a server-specific permission to RFC standard.

            Override to convert server-specific permissions to RFC equivalents.
            Returns (rfc_permission, feature_id) where feature_id is set for
            vendor-specific permissions that need metadata preservation.

            Args:
                permission: Server-specific permission string
                _metadata: Metadata dict to store original value (unused in base)

            Returns:
                Tuple of (normalized_permission, feature_id or None)

            """
            # RFC implementation: permissions are already RFC-compliant
            return permission, None

        def _denormalize_permission(
            self,
            permission: str,
            _feature_id: str | None,
            _metadata: dict[str, object],
        ) -> str:
            """Convert RFC permission back to server-specific format.

            Override to convert RFC permissions to server-specific equivalents.
            Uses feature_id and metadata to restore original vendor values.

            Args:
                permission: RFC-normalized permission
                _feature_id: Feature ID if vendor-specific (unused in base)
                _metadata: Metadata dict with original values (unused in base)

            Returns:
                Server-specific permission string.

            """
            # RFC implementation: keep RFC permission as-is
            return permission

        def _get_feature_fallback(self, feature_id: str) -> str | None:
            """Get RFC fallback value for unsupported vendor feature.

            Delegates to base class implementation.
            """
            return super()._get_feature_fallback(feature_id)

        def _preserve_unsupported_feature(
            self,
            feature_id: str,
            original_value: str,
            metadata: dict[str, object],
        ) -> None:
            """Preserve unsupported feature in metadata for round-trip.

            Called when a feature cannot be translated. Stores the original
            value in metadata so it can be restored if converting back.

            Args:
                feature_id: Feature ID that couldn't be translated
                original_value: Original server-specific value
                metadata: Metadata dict to store preservation info

            """
            meta_key = FlextLdifConstants.FeatureCapabilities.META_UNSUPPORTED_FEATURES
            if meta_key not in metadata:
                metadata[meta_key] = {}
            unsupported = metadata[meta_key]
            if isinstance(unsupported, dict):
                unsupported[feature_id] = original_value

        def _parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse RFC-compliant ACL line (implements abstract method).

            Args:
                acl_line: The raw ACL string from the LDIF.

            Returns:
                A FlextResult containing the Acl model.

            """
            # Type guard: ensure acl_line is a string
            if not isinstance(acl_line, str):
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"ACL line must be a string, got {type(acl_line).__name__}",
                )
            if not acl_line or not acl_line.strip():
                return FlextResult.fail("ACL line must be a non-empty string.")

            # Get server type from the actual server class (not hardcoded "rfc")
            server_type_value = self._get_server_type()

            # RFC passthrough: store the raw line in the model.
            # server_type_value is already the correct type from _get_server_type()
            acl_model = FlextLdifModels.Acl(
                raw_acl=acl_line,
                server_type=server_type_value,
                metadata=FlextLdifModels.QuirkMetadata(
                    quirk_type=server_type_value,
                    extensions=FlextLdifModels.DynamicMetadata(**{
                        FlextLdifConstants.MetadataKeys.ACL_ORIGINAL_FORMAT: acl_line,
                    }),
                ),
            )
            return FlextResult.ok(acl_model)

        # parse_acl() method is redundant - parse() already delegates to _parse_acl()
        # Removed to use base.py.parse() which already handles this

        # create_metadata(), convert_rfc_acl_to_aci(), format_acl_value()
        # are now in base.py - these methods delegate to parent without RFC-specific logic

        def _write_acl(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write ACL to RFC-compliant string format (internal).

            RFC implementation of ACL writing using raw_acl or name fallback.
            """
            # Use raw_acl if available and non-empty
            if (
                acl_data.raw_acl
                and isinstance(acl_data.raw_acl, str)
                and acl_data.raw_acl.strip()
            ):
                return FlextResult[str].ok(acl_data.raw_acl)
            # If raw_acl is empty but name exists, return minimal ACL with name
            if (
                acl_data.name
                and isinstance(acl_data.name, str)
                and acl_data.name.strip()
            ):
                return FlextResult[str].ok(f"{acl_data.name}:")
            # No valid data to write
            return FlextResult[str].fail("ACL has no raw_acl or name to write")

        def can_handle_attribute(
            self,
            attribute: FlextLdifModels.SchemaAttribute,
        ) -> bool:
            """Check if quirk handles schema attributes.

            ACL quirks don't handle schema attributes - that's handled by Schema quirks.

            Args:
                attribute: SchemaAttribute model

            Returns:
                False - ACL quirks don't handle attributes

            """
            _ = attribute  # Unused - ACL doesn't handle attributes
            return False

        def can_handle_objectclass(
            self,
            objectclass: FlextLdifModels.SchemaObjectClass,
        ) -> bool:
            """Check if quirk handles objectclasses.

            ACL quirks don't handle objectclasses - that's handled by Schema quirks.

            Args:
                objectclass: SchemaObjectClass model

            Returns:
                False - ACL quirks don't handle objectclasses

            """
            _ = objectclass  # Unused - ACL doesn't handle objectclasses
            return False

        # execute() is now in base.py (via parent FlextService)
        # This class only provides RFC-specific implementations of:
        # - _parse_acl(), _write_acl()

        @overload
        def __call__(
            self,
            data: str,
            *,
            operation: FlextLdifConstants.LiteralTypes.ParseOperationLiteral
            | None = None,
        ) -> FlextLdifModels.Acl: ...

        @overload
        def __call__(
            self,
            data: FlextLdifModels.Acl,
            *,
            operation: FlextLdifConstants.LiteralTypes.WriteOperationLiteral
            | None = None,
        ) -> str: ...

        @overload
        def __call__(
            self,
            data: str | FlextLdifModels.Acl | None = None,
            *,
            operation: FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral
            | None = None,
        ) -> FlextLdifModels.Acl | str: ...

        def __call__(
            self,
            data: str | FlextLdifModels.Acl | None = None,
            *,
            operation: FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral
            | None = None,
        ) -> FlextLdifModels.Acl | str:
            """Callable interface - automatic polymorphic processor.

            Pass ACL line string for parsing or Acl model for writing.
            Type auto-detection handles routing automatically.
            """
            result = self.execute(data=data, operation=operation)
            return result.unwrap()

        def __new__(
            cls,
            acl_service: FlextLdifTypes.Services.AclService | None = None,
            **kwargs: FlextLdifTypes.FlexibleKwargsMutable,
        ) -> Self:
            """Override __new__ to support auto-execute and processor instantiation."""
            instance = super().__new__(cls)
            # Remove auto-execute kwargs before passing to __init__
            auto_execute_kwargs = {"data", "operation"}
            init_kwargs = {
                k: v for k, v in kwargs.items() if k not in auto_execute_kwargs
            }
            # Use explicit type cast for __init__ call to avoid type checker issues
            # with dynamic class instantiation
            instance_type = type(instance)
            if hasattr(instance_type, "__init__"):
                instance_type.__init__(
                    instance,
                    acl_service=acl_service,
                    parent_quirk=None,
                    **init_kwargs,
                )

            if cls.auto_execute:
                # Type-safe extraction of kwargs
                data_raw = kwargs.get("data")
                data: str | FlextLdifModels.Acl | None = None
                if isinstance(data_raw, (str, FlextLdifModels.Acl)):
                    data = data_raw
                op_raw = kwargs.get("operation")
                op: (
                    FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral | None
                ) = None
                if op_raw == "parse":
                    op = "parse"
                elif op_raw == "write":
                    op = "write"
                result = instance.execute(data=data, operation=op)
                unwrapped: FlextLdifModels.Acl | str = result.unwrap()
                if isinstance(unwrapped, cls):
                    return unwrapped
                return instance

            return instance

        # parse() method inherited from base.py.Acl - delegates to _parse_acl()

        # write() method inherited from base.py.Acl - delegates to _write_acl()

    class Entry(FlextLdifServersBase.Entry):
        r"""RFC 2849 Compliant Entry Quirk - Base Implementation.

        RFC 2849 ABNF Grammar (LDIF Format):
        =====================================
        ldif-file           = ldif-content / ldif-changes
        ldif-content        = version-spec 1*(1*SEP ldif-attrval-record)
        ldif-changes        = version-spec 1*(1*SEP ldif-change-record)
        version-spec        = "version:" FILL version-number
        version-number      = 1*DIGIT

        ldif-attrval-record = dn-spec SEP 1*attrval-spec
        ldif-change-record  = dn-spec SEP *control changerecord

        dn-spec             = "dn:" (FILL distinguishedName /
                              ":" FILL base64-distinguishedName)
        attrval-spec        = AttributeDescription value-spec SEP
        value-spec          = ":" (FILL 0*1(SAFE-STRING) /
                              ":" FILL (BASE64-STRING) /
                              "<" FILL url)

        changerecord        = "changetype:" FILL (change-add / change-delete /
                              change-modify / change-moddn)
        change-add          = "add" SEP 1*attrval-spec
        change-delete       = "delete" SEP
        change-modify       = "modify" SEP *mod-spec
        change-moddn        = ("modrdn" / "moddn") SEP
                              "newrdn:" (FILL rdn / ":" FILL base64-rdn) SEP
                              "deleteoldrdn:" FILL ("0" / "1") SEP
                              0*1("newsuperior:" (FILL dn / ":" FILL base64-dn) SEP)

        mod-spec            = ("add:" / "delete:" / "replace:")
                              FILL AttributeDescription SEP *attrval-spec "-" SEP

        control             = "control:" FILL ldap-oid 0*1(1*SPACE ("true"/"false"))
                              0*1(value-spec) SEP

        Character Classes (FlextLdifConstants.Rfc):
        ============================================
        FILL           = *SPACE
        SEP            = (CR LF / LF)  ; Rfc.LINE_SEPARATOR
        SPACE          = %x20          ; Rfc.SCHEMA_SPACE
        SAFE-CHAR      = %x01-09 / %x0B-0C / %x0E-7F  ; Rfc.SAFE_CHAR_*
        SAFE-INIT-CHAR = %x01-09 / %x0B-0C / %x0E-1F / %x21-39 / %x3B / %x3D-7F
                         ; Rfc.SAFE_INIT_CHAR_EXCLUDE
        SAFE-STRING    = [SAFE-INIT-CHAR *SAFE-CHAR]
        BASE64-CHAR    = %x2B / %x2F / %x30-39 / %x3D / %x41-5A / %x61-7A
                         ; Rfc.BASE64_CHARS

        Hook Methods for Server Override:
        ==================================
        - _normalize_entry(entry, metadata) → (normalized_entry, metadata)
        - _denormalize_entry(entry, metadata) → denormalized_entry
        - _supports_changetype(changetype) → bool
        - _get_entry_metadata_keys() → frozenset[str]  ; Rfc.META_RFC_*

        """

        def can_handle(
            self,
            entry_dn: str,
            attributes: FlextLdifTypes.CommonDict.AttributeDictGeneric,
        ) -> bool:
            """Check if this quirk can handle the entry.

            RFC quirk can handle any entry.

            Args:
                entry_dn: Entry distinguished name
                attributes: Entry attributes mapping

            Returns:
                True - RFC quirk handles all entries as baseline

            """
            _ = entry_dn  # Unused - RFC handles all entries
            _ = attributes  # Unused - RFC handles all entries
            return True

        def can_handle_attribute(
            self,
            attribute: FlextLdifModels.SchemaAttribute,
        ) -> bool:
            """Check if quirk handles schema attributes.

            Entry quirks don't handle schema attributes - that's handled by Schema quirks.

            Args:
                attribute: SchemaAttribute model

            Returns:
                False - Entry quirks don't handle attributes

            """
            _ = attribute  # Unused - Entry doesn't handle attributes
            return False

        def can_handle_objectclass(
            self,
            objectclass: FlextLdifModels.SchemaObjectClass,
        ) -> bool:
            """Check if quirk handles objectclasses.

            Entry quirks don't handle objectclasses - that's handled by Schema quirks.

            Args:
                objectclass: SchemaObjectClass model

            Returns:
                False - Entry quirks don't handle objectclasses

            """
            _ = objectclass  # Unused - Entry doesn't handle objectclasses
            return False

        def can_handle_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> bool:
            """Check if entry is RFC-compliant.

            Validates RFC 2849 and RFC 4514 compliance:
            - DN must be properly formatted (RFC 4514)
            - Entry must have objectClass attribute (LDAP requirement)
            - Attributes must be non-empty

            RFC quirk acts as the baseline handler since all LDAP entries
            must be RFC-compliant before server-specific quirks can extend them.

            Args:
                entry: Entry model to validate

            Returns:
                True if entry meets RFC baseline requirements

            """
            # RFC 4514: DN must not be empty
            if not entry.dn or not entry.dn.value:
                return False

            # RFC 2849: Attributes must be present
            if not entry.attributes or not entry.attributes.attributes:
                return False

            # LDAP requirement: Every entry must have objectClass attribute
            # Use Entry model method to check for objectClass
            return entry.has_attribute(FlextLdifConstants.DictKeys.OBJECTCLASS)

        # write() is now in base.py
        # This class only provides RFC-specific implementations of:
        # - _parse_content(), _write_entry()

        def _normalize_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextLdifModels.Entry:
            """Normalize entry to RFC format with metadata tracking.

            RFC Implementation: Returns entry as-is (already RFC-compliant).
            Delegates to base implementation.

            Args:
                entry: Entry to normalize

            Returns:
                Normalized entry (RFC quirk returns unchanged)

            """
            return super()._normalize_entry(entry)

        def _denormalize_entry(
            self,
            entry: FlextLdifModels.Entry,
            target_server: str | None = None,
        ) -> FlextLdifModels.Entry:
            """Denormalize entry from RFC format to target server format.

            RFC Implementation: Returns entry as-is (RFC is the canonical format).
            Delegates to base implementation.

            Args:
                entry: RFC-normalized entry
                target_server: Target server type (optional hint)

            Returns:
                Denormalized entry for target server (RFC quirk returns unchanged)

            """
            return super()._denormalize_entry(entry, target_server)

        def _hook_transform_entry_raw(
            self,
            dn: str,
            attrs: dict[str, list[str | bytes]],
        ) -> FlextResult[tuple[str, dict[str, list[str | bytes]]]]:
            """Hook to transform raw entry before parsing.

            RFC Implementation: Returns DN and attributes unchanged (no transformation).

            Args:
                dn: Raw DN string
                attrs: Raw attributes dict

            Returns:
                FlextResult with tuple of (transformed_dn, transformed_attrs)

            """
            return FlextResult.ok((dn, attrs))

        def _hook_build_entry_metadata(
            self,
            _entry: FlextLdifModels.Entry,
        ) -> dict[str, object] | None:
            """Hook to add server-specific metadata extensions.

            RFC Implementation: Returns None (no additional metadata).

            Args:
                _entry: Parsed entry (unused in RFC baseline).

            Returns:
                Dict of metadata extensions or None

            """
            return None

        def _hook_normalize_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Hook to normalize entry after parsing.

            RFC Implementation: Returns entry unchanged (already RFC-compliant).

            Args:
                entry: Parsed entry

            Returns:
                FlextResult with normalized entry

            """
            return FlextResult.ok(entry)

        def _hook_finalize_entry_parse(
            self,
            entry: FlextLdifModels.Entry,
            original_dn: str,
            original_attrs: Mapping[str, object],
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Hook to finalize entry parsing with original context.

            RFC Implementation: Returns entry unchanged.

            Args:
                entry: Parsed entry
                original_dn: Original DN before transformation
                original_attrs: Original attributes before parsing

            Returns:
                FlextResult with finalized entry

            """
            _ = original_dn
            _ = original_attrs
            return FlextResult.ok(entry)

        def _supports_changetype(self, changetype: str) -> bool:
            """Check if server supports a specific changetype.

            RFC 2849 §5.7 defines changetypes: add, delete, modify, moddn, modrdn.
            Override in server quirks if server has limited changetype support.

            Args:
                changetype: The changetype to check (add/delete/modify/moddn/modrdn)

            Returns:
                True if changetype is supported

            """
            # RFC supports all standard changetypes
            supported = {"add", "delete", "modify", "moddn", "modrdn"}
            return changetype.lower() in supported

        def _get_entry_metadata_keys(self) -> frozenset[str]:
            """Get metadata keys used by this server for entry processing.

            Returns the set of FlextLdifConstants.Rfc.META_* keys that this
            server uses for entry metadata tracking. Used for serialization
            and round-trip conversion.

            Returns:
                Frozenset of metadata key strings

            """
            return frozenset({
                FlextLdifConstants.Rfc.META_RFC_VERSION,
                FlextLdifConstants.Rfc.META_RFC_LINE_FOLDING,
                FlextLdifConstants.Rfc.META_RFC_BASE64_ENCODED,
                FlextLdifConstants.Rfc.META_RFC_URL_REFERENCE,
                FlextLdifConstants.Rfc.META_RFC_CHANGETYPE,
                FlextLdifConstants.Rfc.META_RFC_CONTROLS,
                FlextLdifConstants.Rfc.META_DN_ORIGINAL,
                FlextLdifConstants.Rfc.META_DN_WAS_BASE64,
                FlextLdifConstants.Rfc.META_DN_ESCAPES_APPLIED,
                FlextLdifConstants.Rfc.META_TRANSFORMATION_SOURCE,
                FlextLdifConstants.Rfc.META_TRANSFORMATION_TARGET,
                FlextLdifConstants.Rfc.META_TRANSFORMATION_TIMESTAMP,
            })

        def _validate_entry_rfc_compliance(
            self,
            entry: FlextLdifModels.Entry,
            *,
            strict: bool = True,
        ) -> tuple[bool, list[str]]:
            """Validate entry for RFC 2849/4514 compliance.

            Validates:
            - DN format per RFC 4514
            - Attribute values per RFC 2849 SAFE-STRING grammar
            - Required objectClass per LDAP specification

            Args:
                entry: Entry to validate
                strict: If True, enforce strict RFC compliance

            Returns:
                Tuple of (is_valid, list_of_violations)

            """
            violations: list[str] = []

            # Validate DN using utility
            if entry.dn and entry.dn.value:
                is_valid_dn, dn_errors = FlextLdifUtilities.DN.is_valid_dn_string(
                    entry.dn.value,
                    strict=strict,
                )
                if not is_valid_dn:
                    violations.extend(dn_errors)
            else:
                violations.append("RFC 2849 §2: DN is required")

            # Validate attributes present
            if not entry.attributes or not entry.attributes.attributes:
                violations.append("RFC 2849 §2: Entry must have attributes")

            # Validate objectClass if strict
            if strict and not entry.has_attribute(
                FlextLdifConstants.DictKeys.OBJECTCLASS,
            ):
                violations.append("LDAP: Every entry must have objectClass attribute")

            # Validate attribute values for RFC 2849 compliance
            if entry.attributes:
                for attr_name, attr_values in entry.attributes.attributes.items():
                    for value in attr_values:
                        str_value = str(value) if value is not None else ""
                        # Check if value is valid SAFE-STRING (doesn't need base64)
                        if not FlextLdifUtilities.Writer.is_valid_safe_string(
                            str_value,
                        ):
                            # Not a violation if we can base64 encode it
                            # Only a violation if strict and contains control chars
                            # RFC 2849: Control chars are < 0x20 except TAB (0x09), LF (0x0A), CR (0x0D)
                            # Use Constants for parametrization (servers can override)
                            control_char_threshold = (
                                FlextLdifServersRfc.Constants.CONTROL_CHAR_THRESHOLD
                            )
                            allowed_control_chars = (
                                FlextLdifServersRfc.Constants.ALLOWED_CONTROL_CHARS
                            )
                            if strict and any(
                                ord(c) < control_char_threshold
                                and c not in allowed_control_chars
                                for c in str_value
                            ):
                                violations.append(
                                    f"RFC 2849: Attribute {attr_name} contains "
                                    f"invalid control characters",
                                )

            return len(violations) == 0, violations

        def _format_aci_attributes(
            self,
            entry: FlextLdifModels.Entry,
            *,
            use_original_format_as_name: bool = False,
        ) -> FlextLdifModels.Entry:
            """Format ACI attributes in entry using original ACL format as name.

            Delegates ACL formatting to the Acl quirk's format_acl_value() method,
            following SRP by handling ACL-specific formatting in Entry quirk
            rather than in Writer service.

            Args:
                entry: Entry containing ACI attributes to format.
                use_original_format_as_name: If True, replace acl "name" in ACI values
                    with the sanitized original format from metadata.

            Returns:
                Entry with formatted ACI attribute values if applicable,
                otherwise unchanged entry.

            Example:
                >>> formatted_entry = entry_quirk._format_aci_attributes(
                ...     entry, use_original_format_as_name=True
                ... )

            """
            # Early return if option not enabled
            if not use_original_format_as_name:
                return entry

            # Check if entry has aci attribute
            aci_attr_name = FlextLdifConstants.AclKeys.ACI
            if not entry.attributes or aci_attr_name not in entry.attributes.attributes:
                return entry

            # Extract ACL metadata from entry metadata
            # Convert DynamicMetadata to dict for from_extensions
            extensions_dict: dict[str, object] | None = None
            if entry.metadata and entry.metadata.extensions:
                extensions_dict = entry.metadata.extensions.model_dump()
            acl_metadata = FlextLdifModels.AclWriteMetadata.from_extensions(
                extensions_dict,
            )

            # Early return if no original format available
            if not acl_metadata.has_original_format():
                return entry

            # Create ACL quirk instance for formatting
            # self is already FlextLdifServersBase (RFC extends it)
            acl_quirk = FlextLdifServersRfc.Acl(
                parent_quirk=self,
            )

            # Format all ACI values
            aci_values = entry.attributes.attributes[aci_attr_name]
            new_aci_values: list[str] = []

            for aci_value in aci_values:
                result = acl_quirk.format_acl_value(
                    aci_value,
                    acl_metadata,
                    use_original_format_as_name=True,
                )
                if result.is_success:
                    new_aci_values.append(result.unwrap())
                else:
                    # Keep original value on format failure
                    new_aci_values.append(aci_value)

            # Update entry with formatted aci values
            new_attrs = dict(entry.attributes.attributes)
            new_attrs[aci_attr_name] = new_aci_values

            return entry.model_copy(
                update={
                    "attributes": FlextLdifModels.LdifAttributes(attributes=new_attrs),
                },
            )

        def _extract_write_options(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextLdifModels.WriteFormatOptions | None:
            """Extract write options from entry metadata.

            Args:
                entry_data: Entry with optional metadata.write_options.

            Returns:
                WriteFormatOptions if found, None otherwise.

            """
            if not entry_data.metadata or not entry_data.metadata.write_options:
                return None
            # Access dynamic fields - handle both dict and Pydantic model
            write_opts = entry_data.metadata.write_options
            key = FlextLdifConstants.MetadataKeys.WRITE_OPTIONS
            # Check if write_opts is a Pydantic model or a plain dict
            if hasattr(write_opts, "model_extra"):
                extras = write_opts.model_extra or {}
            elif isinstance(write_opts, dict):
                extras = write_opts
            else:
                return None
            if key not in extras:
                return None
            opt = extras.get(key)
            if isinstance(opt, FlextLdifModels.WriteFormatOptions):
                return opt
            return None

        def _apply_pre_write_hook(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Apply pre-write hook if available.

            Args:
                entry_data: Entry to process.

            Returns:
                FlextResult with processed entry.

            """
            pre_write_hook = getattr(self, "_hook_pre_write_entry", None)
            if not pre_write_hook:
                return FlextResult.ok(entry_data)
            pre_write_result = pre_write_hook(entry_data)
            if pre_write_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(
                    pre_write_result.error or "Pre-write processing failed",
                )
            return FlextResult.ok(pre_write_result.unwrap())

        def _apply_acl_formatting(
            self,
            entry_data: FlextLdifModels.Entry,
            write_options: FlextLdifModels.WriteFormatOptions | None,
        ) -> FlextLdifModels.Entry:
            """Apply ACL formatting if write_options enables it.

            Args:
                entry_data: Entry to format.
                write_options: Optional write options.

            Returns:
                Formatted entry (or original if no formatting needed).

            """
            if not write_options or not write_options.use_original_acl_format_as_name:
                return entry_data
            return self._format_aci_attributes(
                entry_data,
                use_original_format_as_name=True,
            )

        def _apply_rfc_attribute_ordering(
            self,
            attrs_dict: dict[str, list[str]],
            write_options: FlextLdifModels.WriteFormatOptions | None,
        ) -> dict[str, list[str]]:
            """Apply RFC 2849 attribute ordering if write_options enables it.

            Uses FlextLdifUtilities.Writer.order_attribute_names for ordering.

            Args:
                attrs_dict: Attributes dictionary.
                write_options: Optional write options.

            Returns:
                Ordered attributes dictionary.

            """
            if not write_options:
                return attrs_dict
            if (
                not write_options.sort_attributes
                or not write_options.use_rfc_attribute_order
            ):
                return attrs_dict
            priority_attrs = write_options.rfc_order_priority_attributes or [
                "objectClass",
            ]
            # Use utility for ordering, then build ordered dict
            ordered_names = FlextLdifUtilities.Writer.order_attribute_names(
                list(attrs_dict.keys()),
                use_rfc_order=True,
                priority_attrs=priority_attrs,
            )
            return {name: attrs_dict[name] for name in ordered_names}

        def _apply_objectclass_value_sorting(
            self,
            attrs_dict: dict[str, list[str]],
            write_options: FlextLdifModels.WriteFormatOptions | None,
        ) -> dict[str, list[str]]:
            """Sort objectClass values with 'top' first if enabled.

            Ensures proper objectClass hierarchy ordering in LDIF output.
            'top' is the root abstract objectClass and should appear first.

            Args:
                attrs_dict: Attributes dictionary.
                write_options: Optional write options.

            Returns:
                Attributes dictionary with sorted objectClass values.

            """
            if not write_options or not write_options.sort_objectclass_values:
                return attrs_dict

            # Find objectClass attribute (case-insensitive)
            oc_key = None
            for key in attrs_dict:
                if key.lower() == "objectclass":
                    oc_key = key
                    break

            if not oc_key or not attrs_dict[oc_key]:
                return attrs_dict

            # Sort objectClass values: 'top' first, then alphabetically
            oc_values = attrs_dict[oc_key]
            top_values = [v for v in oc_values if v.lower() == "top"]
            other_values = sorted(
                [v for v in oc_values if v.lower() != "top"],
                key=str.lower,
            )
            sorted_values = top_values + other_values

            # Create new dict with sorted objectClass values
            result = dict(attrs_dict)
            result[oc_key] = sorted_values
            return result

        def _prepare_entry_for_write(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Validate and prepare entry for writing."""
            if not entry_data:
                return FlextResult[FlextLdifModels.Entry].fail("Entry is None")
            if not entry_data.dn or not entry_data.dn.value:
                return FlextResult[FlextLdifModels.Entry].fail("Entry DN is empty")

            pre_result = self._apply_pre_write_hook(entry_data)
            if pre_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(
                    pre_result.error or "Pre-write failed",
                )
            entry_data = self._denormalize_entry(pre_result.unwrap())
            return FlextResult[FlextLdifModels.Entry].ok(entry_data)

        def _add_server_comments(
            self,
            ldif_lines: list[str],
            entry_data: FlextLdifModels.Entry,
            write_options: FlextLdifModels.WriteFormatOptions | None,
        ) -> None:
            """Add server-specific comments after DN line."""
            generate_comments = getattr(self, "generate_entry_comments", None)
            if not generate_comments:
                return
            server_comments_str = generate_comments(entry_data, write_options)
            if server_comments_str:
                ldif_lines.extend(server_comments_str.strip().split("\n"))

        def _write_entry(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextResult[str]:
            r"""Write Entry model to RFC 2849 compliant LDIF string."""
            prep_result = self._prepare_entry_for_write(entry_data)
            if prep_result.is_failure:
                return FlextResult[str].fail(prep_result.error or "Preparation failed")
            entry_data = prep_result.unwrap()

            write_options = self._extract_write_options(entry_data)

            if write_options and write_options.ldif_changetype == "modify":
                return self._write_entry_modify_format(entry_data, write_options)

            entry_data = self._apply_acl_formatting(entry_data, write_options)
            restored_entry = self._restore_entry_from_metadata(entry_data)
            dn_value = restored_entry.dn.value if restored_entry.dn else ""
            attrs_dict: dict[str, list[str]] = (
                restored_entry.attributes.attributes
                if restored_entry.attributes
                else {}
            )
            hidden_attrs = self._get_hidden_attributes(entry_data, write_options)

            attrs_dict = self._apply_rfc_attribute_ordering(attrs_dict, write_options)
            attrs_dict = self._apply_objectclass_value_sorting(
                attrs_dict,
                write_options,
            )

            if (
                write_options
                and write_options.sort_objectclass_values
                and restored_entry.attributes
            ):
                for key in restored_entry.attributes.attributes:
                    if key.lower() == "objectclass" and key in attrs_dict:
                        restored_entry.attributes.attributes[key] = attrs_dict[key]
                        break

            ldif_lines: list[str] = []
            if write_options:
                self._write_entry_comments_dn(ldif_lines, restored_entry, write_options)

            ldif_lines.append(f"dn: {dn_value}")

            if write_options:
                self._write_entry_comments_metadata(
                    ldif_lines,
                    restored_entry,
                    write_options,
                )

            self._add_server_comments(ldif_lines, entry_data, write_options)

            if attrs_dict:
                self._write_entry_process_attributes(
                    ldif_lines,
                    restored_entry,
                    hidden_attrs,
                    write_options,
                )
            else:
                ldif_lines.append("")

            ldif_str = FlextLdifUtilities.Writer.finalize_ldif_text(ldif_lines)
            return FlextResult[str].ok(ldif_str)

        def _write_entry_add_format(
            self,
            entry_data: FlextLdifModels.Entry,
            write_options: FlextLdifModels.WriteFormatOptions | None,
        ) -> FlextResult[str]:
            """Write Entry in standard ADD format (default RFC 2849 format).

            Uses FlextLdifUtilities.Writer for DRY consolidation.

            Args:
                entry_data: Entry model to write
                write_options: Optional formatting options

            Returns:
                FlextResult with LDIF string in ADD format

            """
            # DN validation
            if not (entry_data.dn and entry_data.dn.value):
                return FlextResult[str].fail("Entry DN is required for LDIF output")

            # Get attributes dict (empty dict if None)
            attrs_dict: dict[str, list[str]] = (
                entry_data.attributes.attributes if entry_data.attributes else {}
            )

            # Build LDIF lines using generalized utility
            include_changetype = bool(
                write_options and getattr(write_options, "include_changetype", False),
            )
            changetype_value = (
                write_options.ldif_changetype
                if write_options and hasattr(write_options, "ldif_changetype")
                else "add"
            )

            ldif_lines = FlextLdifUtilities.Writer.build_entry_lines(
                dn_value=entry_data.dn.value,
                attributes=attrs_dict,
                format_type="add",
                include_changetype=include_changetype,
                changetype_value=changetype_value,
            )

            return FlextResult[str].ok(
                FlextLdifUtilities.Writer.finalize_ldif_text(ldif_lines),
            )

        # NOTE: _parse_content inherited from FlextLdifServersBase.Entry
        # The generic implementation in base.py calls self._parse_entry()
        # which is implemented below.

        def _normalize_attribute_name(self, attr_name: str) -> str:
            """Normalize attribute name to RFC 2849 canonical form.

            RFC 2849: Attribute names are case-insensitive.
            This method normalizes to canonical form for consistent matching.

            Key rule: objectclass (any case) → objectClass (canonical)
            All other attributes: preserved as-is (most are already lowercase)

            Args:
                attr_name: Attribute name from LDIF (any case)

            Returns:
                Canonical form of the attribute name

            """
            return super()._normalize_attribute_name(attr_name)

        # ===== _parse_entry HELPER METHODS (DRY refactoring) =====

        def _convert_raw_attributes(
            self,
            entry_attrs: dict[str, list[str | bytes]],
        ) -> dict[str, list[str]]:
            """Convert raw LDIF attributes to dict[str, list[str]] format.

            Handles bytes values from ldif3 parser and normalizes attribute names.

            Args:
                entry_attrs: Raw attributes mapping from LDIF parser

            Returns:
                Converted attributes with normalized names and string values

            """
            return super()._convert_raw_attributes(entry_attrs)

        def _extract_original_lines(
            self,
            converted_attrs: dict[str, list[str]],
        ) -> tuple[str | None, list[str], bool]:
            """Extract original lines from converted attributes.

            Pops internal keys (_base64_dn, _original_dn_line, _original_lines)
            from converted_attrs and returns the extracted values.

            Args:
                converted_attrs: Converted attributes dict (will be modified)

            Returns:
                Tuple of (original_dn_line, original_attr_lines, dn_was_base64)

            """
            # Check if DN was base64-encoded
            dn_was_base64 = converted_attrs.pop("_base64_dn", None) is not None

            # Extract original DN line with type-safe conversion
            original_dn_line: str | None = None
            if "_original_dn_line" in converted_attrs:
                original_dn_lines = converted_attrs.pop("_original_dn_line", [])
                if original_dn_lines and FlextRuntime.is_list_like(original_dn_lines):
                    original_dn_lines_list = [str(item) for item in original_dn_lines]
                    original_dn_line = (
                        original_dn_lines_list[0] if original_dn_lines_list else None
                    )

            # Extract original attribute lines with type-safe conversion
            original_attr_lines: list[str] = []
            if "_original_lines" in converted_attrs:
                original_lines = converted_attrs.pop("_original_lines", [])
                if original_lines and FlextRuntime.is_list_like(original_lines):
                    original_attr_lines = [str(item) for item in original_lines]

            return original_dn_line, original_attr_lines, dn_was_base64

        def _analyze_entry_differences(
            self,
            entry_attrs: FlextLdifTypes.CommonDict.AttributeDictGeneric,
            converted_attrs: dict[str, list[str]],
            original_entry_dn: str,
            cleaned_dn: str,
        ) -> tuple[
            dict[str, object],
            dict[str, dict[str, object]],
            dict[str, object],
            dict[str, str],
        ]:
            """Analyze DN and attribute differences for round-trip support (DRY wrapper)."""
            return FlextLdifUtilities.Entry.analyze_differences(
                entry_attrs=entry_attrs,
                converted_attrs=converted_attrs,
                original_dn=original_entry_dn,
                cleaned_dn=cleaned_dn,
                normalize_attr_fn=self._normalize_attribute_name,
            )

        def _build_parse_entry_metadata(
            self,
            context: FlextLdifTypes.ModelMetadata.EntryParsingContext,
        ) -> FlextLdifModels.QuirkMetadata:
            """Build QuirkMetadata with format details AND track differences (DRY wrapper)."""
            # Type narrowing for context.get() calls
            original_entry_dn_val = context.get("original_entry_dn", "")
            original_entry_dn: str = (
                original_entry_dn_val if isinstance(original_entry_dn_val, str) else ""
            )

            cleaned_dn_raw = context.get(
                "cleaned_dn",
                context.get("original_entry_dn", ""),
            )
            cleaned_dn: str = cleaned_dn_raw if isinstance(cleaned_dn_raw, str) else ""

            original_dn_line_val = context.get("original_dn_line")
            original_dn_line: str | None = (
                original_dn_line_val if isinstance(original_dn_line_val, str) else None
            )

            original_attr_lines_val = context.get("original_attr_lines", [])
            original_attr_lines: list[str] | None = (
                original_attr_lines_val
                if isinstance(original_attr_lines_val, list)
                else None
            )

            dn_was_base64_val = context.get("dn_was_base64", False)
            dn_was_base64: bool = (
                isinstance(dn_was_base64_val, bool) and dn_was_base64_val
            )

            original_attribute_case_val = context.get("original_attribute_case", {})
            original_attribute_case: dict[str, str] | None = (
                original_attribute_case_val
                if isinstance(original_attribute_case_val, dict)
                else None
            )

            dn_differences_val = context.get("dn_differences", {})
            dn_differences: dict[str, object] | None = (
                dn_differences_val if isinstance(dn_differences_val, dict) else None
            )

            attribute_differences_val = context.get("attribute_differences", {})
            attribute_differences: dict[str, object] | None = (
                attribute_differences_val
                if isinstance(attribute_differences_val, dict)
                else None
            )

            original_attributes_complete_val = context.get(
                "original_attributes_complete",
                {},
            )
            original_attributes_complete: dict[str, object] | None = (
                original_attributes_complete_val
                if isinstance(original_attributes_complete_val, dict)
                else None
            )

            return FlextLdifUtilities.Metadata.build_entry_parse_metadata(
                quirk_type=self._get_server_type(),
                original_entry_dn=original_entry_dn,
                cleaned_dn=cleaned_dn,
                original_dn_line=original_dn_line,
                original_attr_lines=original_attr_lines,
                dn_was_base64=dn_was_base64,
                original_attribute_case=original_attribute_case,
                dn_differences=dn_differences,
                attribute_differences=attribute_differences,
                original_attributes_complete=original_attributes_complete,
            )

        def _parse_entry(
            self,
            entry_dn: str,
            entry_attrs: dict[str, list[str | bytes]],
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Parse raw LDIF entry data into Entry model per RFC 2849 §4.

            RFC 2849 ABNF Grammar (Section 4):
            ==================================
            ldif-attrval-record = dn-spec SEP 1*attrval-spec

            dn-spec = "dn:" (FILL distinguishedName /
                            ":" FILL base64-distinguishedName)

            attrval-spec = AttributeDescription value-spec SEP

            value-spec = ":" (FILL 0*1(SAFE-STRING) /
                             ":" FILL (BASE64-STRING) /
                             "<" FILL url)

            AttributeDescription = AttributeType options
            AttributeType = descr / numericoid
            options = *( ";" option )
            option = 1*keychar

            CRITICAL: Preserves ALL original data (DN, attributes, formatting)
            in metadata BEFORE any normalization or conversion for zero data loss.

            RFC 2849 Compliance:
            - Attribute names are case-insensitive (normalized to canonical form)
            - Base64 values (::) are decoded and marked in metadata
            - URL references (:<) are preserved
            - Original line formatting stored for round-trip

            Args:
                entry_dn: Raw DN string from LDIF parser (PRESERVED EXACTLY as-is)
                entry_attrs: Raw attributes mapping from LDIF parser (may contain bytes)

            Returns:
                FlextResult with parsed Entry model including complete metadata

            """
            logger.debug(
                "Parsing RFC entry",
                entry_dn=entry_dn[:50] if entry_dn else None,
                attributes_count=len(entry_attrs),
            )

            try:
                # HOOK: Validate raw entry before parsing
                validation_result = self._hook_validate_entry_raw(
                    entry_dn,
                    entry_attrs,
                )
                if validation_result.is_failure:
                    return FlextResult[FlextLdifModels.Entry].fail(
                        validation_result.error or "Entry validation failed",
                    )

                # HOOK: Transform raw DN and attributes (server-specific normalization)
                # This enables OID to normalize "cn=subschemasubentry" → "cn=schema"
                transform_result = self._hook_transform_entry_raw(
                    entry_dn,
                    entry_attrs,
                )
                if transform_result.is_failure:
                    return FlextResult[FlextLdifModels.Entry].fail(
                        transform_result.error or "Entry transformation failed",
                    )
                transformed_dn, transformed_attrs = transform_result.unwrap()

                # Use transformed values for parsing
                # Original entry_dn preserved separately for metadata
                working_dn = transformed_dn
                working_attrs = transformed_attrs

                # Clean/normalize DN using DN utility
                cleaned_dn = FlextLdifUtilities.DN.clean_dn(working_dn)

                # Convert raw attributes using helper (DRY refactoring)
                # Use working_attrs (potentially transformed by hook)
                converted_attrs = self._convert_raw_attributes(working_attrs)

                # Extract original lines using helper (DRY refactoring)
                original_dn_line, original_attr_lines_complete, dn_was_base64 = (
                    self._extract_original_lines(converted_attrs)
                )

                # CRITICAL: Preserve original entry_dn EXACTLY as-is
                original_entry_dn_complete = entry_dn

                # Create LdifAttributes directly from converted_attrs
                # converted_attrs now has normalized attribute names (_base64_dn, _original_* removed)
                ldif_attrs = FlextLdifModels.LdifAttributes(attributes=converted_attrs)

                # Create DistinguishedName with metadata if it was base64-encoded
                # Entry.create accepts Union[str, DistinguishedName]
                dn_value: str | FlextLdifModels.DistinguishedName
                if dn_was_base64:
                    # Preserve RFC 2849 base64 indicator for round-trip
                    metadata_dict: dict[str, object] = {
                        FlextLdifConstants.MetadataKeys.ORIGINAL_FORMAT: "base64",
                        FlextLdifConstants.Rfc.META_RFC_BASE64_ENCODED: True,
                    }
                    dn_value = FlextLdifModels.DistinguishedName(
                        value=cleaned_dn,
                        metadata=metadata_dict,
                    )
                else:
                    # Entry.create will coerce string to DistinguishedName
                    dn_value = cleaned_dn

                # Create Entry model using Entry.create factory method
                # This ensures proper validation and model construction
                entry_result = FlextLdifModels.Entry.create(
                    dn=dn_value,
                    attributes=ldif_attrs,
                )

                if entry_result.is_failure:
                    return FlextResult[FlextLdifModels.Entry].fail(
                        f"Failed to create Entry model: {entry_result.error}",
                    )

                # Get the Entry model - no additional processing needed
                # Entry model is already in RFC format with proper metadata
                entry_model = entry_result.unwrap()

                # Analyze differences using helper (DRY refactoring)
                (
                    dn_differences,
                    attribute_differences,
                    original_attributes_complete,
                    original_attribute_case,
                ) = self._analyze_entry_differences(
                    entry_attrs,
                    converted_attrs,
                    original_entry_dn_complete,
                    cleaned_dn,
                )

                # Build metadata with consolidated difference tracking (DRY)
                parsing_context: FlextLdifTypes.ModelMetadata.EntryParsingContext = {
                    "original_entry_dn": original_entry_dn_complete,
                    "cleaned_dn": cleaned_dn,
                    "original_dn_line": original_dn_line,
                    "original_attr_lines": original_attr_lines_complete,
                    "dn_was_base64": dn_was_base64,
                    "original_attribute_case": original_attribute_case,
                    "dn_differences": dn_differences,
                    "attribute_differences": attribute_differences,
                    "original_attributes_complete": original_attributes_complete,
                }
                # Metadata creation + difference tracking consolidated in helper
                entry_model.metadata = self._build_parse_entry_metadata(parsing_context)

                # HOOK: Add server-specific metadata extensions
                server_metadata = self._hook_build_entry_metadata(entry_model)
                if server_metadata and entry_model.metadata:
                    current_extensions = dict(entry_model.metadata.extensions or {})
                    current_extensions.update(server_metadata)
                    entry_model.metadata = entry_model.metadata.model_copy(
                        update={"extensions": current_extensions},
                    )

                # HOOK: Normalize entry (server-specific normalization)
                normalize_result = self._hook_normalize_entry(entry_model)
                if normalize_result.is_failure:
                    return FlextResult[FlextLdifModels.Entry].fail(
                        normalize_result.error or "Entry normalization failed",
                    )
                entry_model = normalize_result.unwrap()

                # HOOK: Post-parse processing
                post_parse_result = self._hook_post_parse_entry(entry_model)
                if post_parse_result.is_failure:
                    return FlextResult[FlextLdifModels.Entry].fail(
                        post_parse_result.error or "Post-parse processing failed",
                    )
                entry_model = post_parse_result.unwrap()

                # HOOK: Finalize entry with full original context
                # Passes original_dn and entry_attrs for server-specific
                # metadata assembly (e.g., OID ACL transformation detection)
                finalize_result = self._hook_finalize_entry_parse(
                    entry_model,
                    entry_dn,  # Original DN before transformation
                    entry_attrs,  # Original attributes before parsing
                )
                if finalize_result.is_failure:
                    return FlextResult[FlextLdifModels.Entry].fail(
                        finalize_result.error or "Entry finalization failed",
                    )
                return finalize_result

            except Exception as e:
                logger.exception(
                    "Failed to parse RFC entry",
                    entry_dn=entry_dn[:50] if entry_dn else None,
                    error=str(e),
                )
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to parse entry: {e}",
                )

        def _add_conditional_comments(
            self,
            ldif_lines: list[str],
            entries: dict[str, object],
            header: str | None = None,
        ) -> None:
            """Add conditional comments based on key-value pairs.

            Args:
                ldif_lines: List to append comments to
                entries: Dict of {label: value} to add as comments (skip if value is falsy)
                header: Optional header comment to add before entries

            """
            # Filter and add only truthy values
            has_values = any(v for v in entries.values())
            if not has_values:
                return

            if header:
                ldif_lines.append(header)
            for label, value in entries.items():
                if value:
                    ldif_lines.append(f"# {label}: {value}")

        def _write_entry_comments_dn(
            self,
            ldif_lines: list[str],
            entry_data: FlextLdifModels.Entry,
            write_options: FlextLdifModels.WriteFormatOptions,
        ) -> None:
            """Add DN comment if requested."""
            if write_options.include_dn_comments:
                dn_value = entry_data.dn.value if entry_data.dn else ""
                self._add_conditional_comments(
                    ldif_lines,
                    {"Complex DN": dn_value},
                )

        def _write_entry_comments_metadata(
            self,
            ldif_lines: list[str],
            entry_data: FlextLdifModels.Entry,
            write_options: FlextLdifModels.WriteFormatOptions,
        ) -> None:
            """Add metadata comments if requested."""
            if not (write_options.write_metadata_as_comments and entry_data.metadata):
                return

            # Build entries dict with conditional values
            entries = {
                "Server Type": entry_data.metadata.extensions.get(
                    FlextLdifConstants.QuirkMetadataKeys.SERVER_TYPE,
                ),
                "Parsed": entry_data.metadata.extensions.get(
                    FlextLdifConstants.MetadataKeys.PARSED_TIMESTAMP,
                ),
                "Source File": (
                    entry_data.metadata.extensions.get(
                        FlextLdifConstants.MetadataKeys.SOURCE_FILE,
                    )
                    if entry_data.metadata.extensions
                    else None
                ),
                "Quirk Type": entry_data.metadata.quirk_type,
            }
            self._add_conditional_comments(
                ldif_lines,
                entries,
                header="# Entry Metadata:",
            )

        def _write_entry_hidden_attrs(
            self,
            ldif_lines: list[str],
            attr_name: str,
            attr_values: list[str] | str,
            hidden_attrs: set[str],
        ) -> bool:
            """Write hidden attributes as comments if in hidden set. Returns True if written."""
            if attr_name not in hidden_attrs:
                return False
            if FlextRuntime.is_list_like(attr_values):
                ldif_lines.extend(f"# {attr_name}: {value}" for value in attr_values)
            else:
                ldif_lines.append(f"# {attr_name}: {attr_values}")
            return True

        def _get_hidden_attributes(
            self,
            entry_data: FlextLdifModels.Entry,
            write_options: FlextLdifModels.WriteFormatOptions | None,
        ) -> set[str]:
            """Extract hidden attributes from metadata if requested."""
            if (
                not write_options
                or not write_options.write_hidden_attributes_as_comments
                or not entry_data.metadata
            ):
                return set()
            # extensions has default_factory=dict, so it should never be None
            if not entry_data.metadata.extensions:
                return set()
            # Note: "hidden_attributes" is a display/processing flag, not a standard metadata key
            # It's used to mark attributes that should be written as comments
            hidden_list = entry_data.metadata.extensions.get(
                FlextLdifConstants.MetadataKeys.HIDDEN_ATTRIBUTES,
            )
            if FlextRuntime.is_list_like(hidden_list):
                return {str(item) for item in hidden_list}
            return set()

        def _write_entry_attribute_value(
            self,
            ldif_lines: list[str],
            attr_name: str,
            value: str,
            write_options: FlextLdifModels.WriteFormatOptions | None = None,
        ) -> None:
            """Write a single attribute value, handling RFC 2849 base64 encoding.

            Implements automatic base64 encoding detection per RFC 2849 section 3.
            Values are base64-encoded if they contain unsafe characters AND
            base64_encode_binary option is enabled (default: True).
            """
            # Handle pre-encoded base64 values (from parsing with __BASE64__ marker)
            if value.startswith("__BASE64__:"):
                base64_value = value[11:]  # Remove "__BASE64__:" marker
                ldif_lines.append(f"{attr_name}:: {base64_value}")
                return

            # Check if base64 encoding is enabled (default: True if not specified)
            base64_enabled = (
                write_options.base64_encode_binary
                if write_options and hasattr(write_options, "base64_encode_binary")
                else True
            )

            # Only apply base64 encoding if enabled AND value needs it
            if base64_enabled and FlextLdifUtilities.Writer.needs_base64_encoding(
                value,
            ):
                # Encode to base64
                encoded_value = base64.b64encode(value.encode("utf-8")).decode("ascii")
                ldif_lines.append(f"{attr_name}:: {encoded_value}")
            # Safe value or encoding disabled - write as plain text
            # Handle multiline values: preserve newlines with proper LDIF continuation
            elif "\n" in value:
                # Multiline value: first line with attr_name, continuation lines with space prefix
                lines = value.split("\n")
                ldif_lines.append(f"{attr_name}: {lines[0]}")
                # Continuation lines: prefix with space (RFC 2849 continuation)
                ldif_lines.extend(
                    f" {continuation_line}" for continuation_line in lines[1:]
                )
            else:
                # Single line value
                ldif_lines.append(f"{attr_name}: {value}")

        def _write_entry_process_attributes(
            self,
            ldif_lines: list[str],
            entry_data: FlextLdifModels.Entry,
            hidden_attrs: set[str],
            write_options: FlextLdifModels.WriteFormatOptions | None = None,
        ) -> None:
            """Process and write all entry attributes.

            ZERO DATA LOSS: If original attribute lines are available in metadata,
            uses them to preserve exact formatting. Otherwise, writes standard format.
            """
            if not (entry_data.attributes and entry_data.attributes.attributes):
                return

            # Get original attribute lines using utility (consolidated)
            original_attr_lines_complete = (
                FlextLdifUtilities.Metadata.get_original_attr_lines_from_metadata(
                    entry_data.metadata,
                )
            )

            # Get minimal differences using utility (consolidated)
            minimal_differences_attrs = (
                FlextLdifUtilities.Metadata.get_minimal_differences_from_metadata(
                    entry_data.metadata,
                )
            )

            if original_attr_lines_complete:
                # Write original lines using helper (DRY refactoring)
                self._write_original_attr_lines(
                    ldif_lines,
                    entry_data,
                    original_attr_lines_complete,
                    write_options,
                )
            else:
                # Write fallback using helper (DRY refactoring)
                self._write_fallback_attr_lines(
                    ldif_lines,
                    entry_data,
                    hidden_attrs,
                    minimal_differences_attrs,
                    write_options,
                )

        # ===== _write_entry_process_attributes HELPER METHODS (DRY refactoring) =====
        # NOTE: _get_original_attr_lines_from_metadata REMOVED - use FlextLdifUtilities.Metadata.get_original_attr_lines_from_metadata
        # NOTE: _get_minimal_differences_from_metadata REMOVED - use FlextLdifUtilities.Metadata.get_minimal_differences_from_metadata

        def _write_original_attr_lines(
            self,
            ldif_lines: list[str],
            entry_data: FlextLdifModels.Entry,
            original_attr_lines_complete: list[str],
            write_options: FlextLdifModels.WriteFormatOptions | None,
        ) -> None:
            """Write original attribute lines preserving exact formatting.

            Args:
                ldif_lines: Output lines list
                entry_data: Entry data
                original_attr_lines_complete: Original attribute lines
                write_options: Write format options

            """
            # Get set of current attribute names (lowercase) for filtering
            current_attrs = set()
            if entry_data.attributes and entry_data.attributes.attributes:
                current_attrs = {
                    attr_name.lower() for attr_name in entry_data.attributes.attributes
                }

            for original_line in original_attr_lines_complete:
                # Skip DN line if it appears in original lines
                if original_line.lower().startswith("dn:"):
                    continue
                # Skip comments unless write_metadata_as_comments is True
                if original_line.strip().startswith("#") and not (
                    write_options
                    and getattr(write_options, "write_metadata_as_comments", False)
                ):
                    continue

                # Only restore lines for attributes that still exist
                if ":" in original_line:
                    attr_name_part = original_line.split(":", 1)[0].strip().lower()
                    attr_name_part = attr_name_part.removesuffix(":")
                    attr_name_part = attr_name_part.removeprefix("<")
                    if current_attrs and attr_name_part not in current_attrs:
                        continue

                ldif_lines.append(original_line)

            logger.debug(
                "Restored original attribute lines from metadata",
                entry_dn=entry_data.dn.value[:50] if entry_data.dn else None,
                original_lines_count=len(original_attr_lines_complete),
            )

        def _determine_attribute_order(
            self,
            attr_names: list[str],
            write_options: FlextLdifModels.WriteFormatOptions | None,
        ) -> list[str]:
            """Determine the order in which attributes should be written.

            Delegates to FlextLdifUtilities.Writer.order_attribute_names for SRP.

            Args:
                attr_names: List of attribute names
                write_options: Write format options

            Returns:
                Ordered list of attribute names

            """
            return FlextLdifUtilities.Writer.order_attribute_names(
                attr_names,
                use_rfc_order=bool(
                    write_options and write_options.use_rfc_attribute_order,
                ),
                sort_alphabetical=bool(write_options and write_options.sort_attributes),
                priority_attrs=(
                    write_options.rfc_order_priority_attributes
                    if write_options and write_options.rfc_order_priority_attributes
                    else None
                ),
            )

        def _write_single_attribute(
            self,
            ldif_lines: list[str],
            context: FlextLdifTypes.ModelMetadata.AttributeWriteContext,
        ) -> None:
            """Write a single attribute to LDIF lines (DRY wrapper).

            Uses FlextLdifUtilities.Writer for generic operations.
            """
            attr_name = context.get("attr_name", "")
            attr_values = context.get("attr_values")
            minimal_differences_attrs = context.get("minimal_differences_attrs", {})
            hidden_attrs = context.get("hidden_attrs", set())
            write_options = context.get("write_options")

            # DRY: Check minimal differences and restore original if needed
            if FlextLdifUtilities.Writer.check_minimal_differences_restore(
                ldif_lines,
                attr_name,
                minimal_differences_attrs,
            ):
                return

            # DRY: Type-safe extraction of attr_values
            typed_attr_values = FlextLdifUtilities.Writer.extract_typed_attr_values(
                attr_values,
            )

            # Write hidden attributes as comments if requested
            if self._write_entry_hidden_attrs(
                ldif_lines,
                attr_name,
                typed_attr_values,
                hidden_attrs,
            ):
                return

            # Write normal attributes
            if isinstance(typed_attr_values, list):
                for value in typed_attr_values:
                    self._write_entry_attribute_value(
                        ldif_lines,
                        attr_name,
                        value,
                        write_options,
                    )
            elif typed_attr_values:
                self._write_entry_attribute_value(
                    ldif_lines,
                    attr_name,
                    typed_attr_values,
                    write_options,
                )

        def _write_fallback_attr_lines(
            self,
            ldif_lines: list[str],
            entry_data: FlextLdifModels.Entry,
            hidden_attrs: set[str],
            minimal_differences_attrs: dict[str, object],
            write_options: FlextLdifModels.WriteFormatOptions | None,
        ) -> None:
            """Write attributes with fallback to standard format.

            Args:
                ldif_lines: Output lines list
                entry_data: Entry data
                hidden_attrs: Hidden attributes set
                minimal_differences_attrs: Minimal differences dictionary
                write_options: Write format options

            """
            if not (entry_data.attributes and entry_data.attributes.attributes):
                return

            # Determine attribute order based on write options
            # Note: servers convert EVERYTHING - writer.py decides what to show/hide/comment
            attr_names = list(entry_data.attributes.attributes.keys())
            ordered_attr_names = self._determine_attribute_order(
                attr_names,
                write_options,
            )

            # Write attributes in determined order
            for attr_name in ordered_attr_names:
                attr_values = entry_data.attributes.attributes[attr_name]
                write_context: FlextLdifTypes.ModelMetadata.AttributeWriteContext = {
                    "attr_name": attr_name,
                    "attr_values": attr_values,
                    "minimal_differences_attrs": minimal_differences_attrs,
                    "hidden_attrs": hidden_attrs,
                    "write_options": write_options,
                }
                self._write_single_attribute(ldif_lines, write_context)

        # ===== _write_entry HELPER METHODS (DRY refactoring) =====

        def _restore_original_dn(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextLdifModels.Entry:
            """Restore original DN from metadata for round-trip support.

            Args:
                entry_data: Entry model to restore

            Returns:
                Entry with restored original DN if available

            """
            mk = FlextLdifConstants.MetadataKeys
            if not (
                entry_data.metadata and entry_data.metadata.extensions and entry_data.dn
            ):
                return entry_data

            original_dn = entry_data.metadata.extensions.get(
                FlextLdifConstants.MetadataKeys.ORIGINAL_DN_COMPLETE,
            )
            if not (original_dn and isinstance(original_dn, str)):
                return entry_data

            dn_differences = entry_data.metadata.extensions.get(
                FlextLdifConstants.MetadataKeys.MINIMAL_DIFFERENCES_DN,
                {},
            )
            if not (
                FlextRuntime.is_dict_like(dn_differences)
                and dn_differences.get(mk.HAS_DIFFERENCES)
            ):
                return entry_data

            logger.debug(
                "Restored original DN from metadata",
                original_dn=original_dn,
                current_dn=str(entry_data.dn),
            )
            return entry_data.model_copy(
                update={"dn": FlextLdifModels.DistinguishedName(value=original_dn)},
            )

        def _restore_original_attributes(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextLdifModels.Entry:
            """Restore original attributes from metadata for round-trip support.

            Args:
                entry_data: Entry model to restore

            Returns:
                Entry with restored original attributes if available

            """
            if not (
                entry_data.metadata
                and entry_data.metadata.extensions
                and entry_data.attributes
            ):
                return entry_data

            original_attrs = entry_data.metadata.extensions.get(
                FlextLdifConstants.MetadataKeys.ORIGINAL_ATTRIBUTES_COMPLETE,
            )
            if not (original_attrs and FlextRuntime.is_dict_like(original_attrs)):
                return entry_data

            attr_differences = entry_data.metadata.extensions.get(
                FlextLdifConstants.MetadataKeys.MINIMAL_DIFFERENCES_ATTRIBUTES,
                {},
            )
            if not (
                FlextRuntime.is_dict_like(attr_differences)
                and len(attr_differences) > 0
            ):
                return entry_data

            if not entry_data.metadata.original_attribute_case:
                return entry_data

            restored_attrs: dict[str, list[str]] = {}
            for attr_name, attr_values in entry_data.attributes.attributes.items():
                original_case_raw = entry_data.metadata.original_attribute_case.get(
                    attr_name.lower(),
                    attr_name,
                )
                original_case: str = (
                    original_case_raw
                    if isinstance(original_case_raw, str)
                    else attr_name
                )
                if original_case in original_attrs:
                    original_val = original_attrs[original_case]
                    if FlextRuntime.is_list_like(original_val):
                        restored_attrs[original_case] = [str(v) for v in original_val]
                    else:
                        restored_attrs[original_case] = [str(original_val)]
                else:
                    restored_attrs[original_case] = attr_values

            if restored_attrs:
                return entry_data.model_copy(
                    update={
                        "attributes": FlextLdifModels.LdifAttributes(
                            attributes=restored_attrs,
                            attribute_metadata=entry_data.attributes.attribute_metadata,
                            metadata=entry_data.attributes.metadata,
                        ),
                    },
                )
            return entry_data

        def _restore_boolean_values(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextLdifModels.Entry:
            """Restore original boolean values from metadata.

            Args:
                entry_data: Entry model to restore

            Returns:
                Entry with restored boolean values if available

            """
            if not (entry_data.metadata and entry_data.metadata.boolean_conversions):
                return entry_data

            restored_attrs = (
                dict(entry_data.attributes.attributes) if entry_data.attributes else {}
            )
            for (
                attr_name,
                conversion,
            ) in entry_data.metadata.boolean_conversions.items():
                if attr_name in restored_attrs:
                    original_val = conversion.get("original", "")
                    if original_val:
                        restored_attrs[attr_name] = [original_val]
                        logger.debug(
                            "Restoring original boolean value from metadata",
                            operation="_write_entry",
                            attribute_name=attr_name,
                            original_value=original_val,
                        )

            current_attrs = (
                entry_data.attributes.attributes if entry_data.attributes else {}
            )
            if restored_attrs != current_attrs:
                return entry_data.model_copy(
                    update={
                        "attributes": FlextLdifModels.LdifAttributes(
                            attributes=restored_attrs,
                            attribute_metadata=entry_data.attributes.attribute_metadata
                            if entry_data.attributes
                            else {},
                            metadata=entry_data.attributes.metadata
                            if entry_data.attributes
                            else {},
                        ),
                    },
                )
            return entry_data

        def _restore_entry_from_metadata(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextLdifModels.Entry:
            """Restore original DN, attributes, and booleans from metadata (consolidated).

            Consolidates _restore_original_dn, _restore_original_attributes, and
            _restore_boolean_values into a single call for cleaner code.
            Follows OUD pattern for consistency.
            """
            return self._restore_boolean_values(
                self._restore_original_attributes(
                    self._restore_original_dn(entry_data),
                ),
            )

        @staticmethod
        def extract_conversion_metadata_from_entry(
            entry: FlextLdifModels.Entry,
            converted_attrs_key: str | None = None,
            boolean_conversions_key: str | None = None,
        ) -> tuple[set[str], dict[str, dict[str, list[str]]]]:
            """Extract conversion metadata from entry.metadata.extensions (shared helper).

            Safely extracts typed conversion data from metadata extensions.
            This helper is shared across RFC, OID, OUD and other server implementations.

            Uses FlextLdifConstants.MetadataKeys for standardized metadata keys.

            Args:
                entry: Entry with metadata extensions
                converted_attrs_key: Key for converted attributes set (defaults to CONVERTED_ATTRIBUTES)
                boolean_conversions_key: Key for boolean conversions dict (defaults to standard key)

            Returns:
                Tuple of (converted_attrs set, boolean_conversions dict)

            """
            # Use constants for default keys if not provided
            if converted_attrs_key is None:
                converted_attrs_key = (
                    FlextLdifConstants.MetadataKeys.CONVERTED_ATTRIBUTES
                )
            if boolean_conversions_key is None:
                # Note: boolean_conversions is stored in metadata.boolean_conversions dict
                # This key is for extensions lookup if needed
                boolean_conversions_key = (
                    "boolean_conversions"  # Legacy key, kept for compatibility
                )

            converted_attrs: set[str] = set()
            boolean_conversions: dict[str, dict[str, str | list[str]]] = {}

            if entry.metadata and entry.metadata.extensions:
                converted_attrs_obj = entry.metadata.extensions.get(
                    converted_attrs_key,
                    [],
                )
                if isinstance(converted_attrs_obj, list):
                    converted_attrs = set(converted_attrs_obj)

                boolean_conversions_obj = entry.metadata.extensions.get(
                    boolean_conversions_key,
                    {},
                )
                if isinstance(boolean_conversions_obj, dict):
                    boolean_conversions = boolean_conversions_obj

            return converted_attrs, boolean_conversions

        def _parse_content(
            self,
            ldif_content: str,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Parse raw LDIF content string into Entry models (internal).

            PRIMARY parsing entry point - called by framework with raw LDIF.

            Uses FlextLdifUtilities.Parsers.Content.parse for RFC-compliant parsing.

            Args:
                ldif_content: Raw LDIF content as string

            Returns:
                FlextResult with list[Entry] on success or fail(message)

            """

            # Use FlextLdifUtilities.Parsers.Content.parse for RFC-compliant parsing
            # Adapt _parse_entry signature to match Content.parse expectations
            def adapted_parse_entry(
                dn: str,
                attrs: Mapping[str, list[str]],
            ) -> FlextResult[FlextLdifModels.Entry]:
                # Convert Mapping[str, list[str]] to Mapping[str, object] for _parse_entry
                attrs_obj: Mapping[str, object] = attrs
                return self._parse_entry(dn, attrs_obj)

            return FlextLdifUtilities.Parsers.Content.parse(
                ldif_content,
                self._get_server_type(),
                adapted_parse_entry,
            )

        def normalize_entry_dn(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextLdifModels.Entry:
            """Normalize DN formatting to RFC 4514 standard with metadata tracking.

            Normalizes DN according to RFC 4514 §2 and tracks the transformation
            in metadata for round-trip conversion support.

            Uses FlextLdifConstants.Rfc.META_DN_* for metadata keys.

            Args:
                entry: Entry with DN to normalize

            Returns:
                Entry with normalized DN and metadata tracking

            """
            if not entry.dn:
                return entry

            original_dn_str = str(entry.dn.value)
            norm_result = FlextLdifUtilities.DN.norm(original_dn_str)

            if not norm_result.is_success:
                normalized_str = FlextLdifUtilities.DN.clean_dn(original_dn_str)
            else:
                normalized_str = norm_result.unwrap()

            # Check if normalization actually changed the DN
            if normalized_str == original_dn_str:
                return entry  # No change, no metadata update needed

            # Create normalized DN
            normalized_dn = FlextLdifModels.DistinguishedName(value=normalized_str)

            # Update metadata to track the DN transformation
            metadata = entry.metadata.model_copy(deep=True)
            metadata.track_dn_transformation(
                original_dn=original_dn_str,
                transformed_dn=normalized_str,
                transformation_type="normalized",
            )

            return entry.model_copy(update={"dn": normalized_dn, "metadata": metadata})

        def filter_operational_attributes(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextLdifModels.Entry:
            """Filter out operational attributes from entry.

            Args:
                entry: Entry to filter

            Returns:
                Entry with operational attributes removed

            """
            if not entry.attributes:
                return entry

            is_schema_entry = FlextLdifUtilities.Entry.is_schema_entry(
                entry,
                strict=False,
            )

            operational_attrs = {
                attr.lower()
                for attr in FlextLdifConstants.OperationalAttributes.FILTER_FROM_ALL_ENTRIES
            }

            if not is_schema_entry:
                schema_operational_attrs = {
                    attr.lower()
                    for attr in FlextLdifConstants.OperationalAttributes.FILTER_FROM_NON_SCHEMA_ENTRIES
                }
                operational_attrs.update(schema_operational_attrs)

            filtered_attrs = {
                attr_name: attr_value
                for attr_name, attr_value in entry.attributes.attributes.items()
                if attr_name.lower() not in operational_attrs
            }

            return entry.model_copy(
                update={
                    "attributes": FlextLdifModels.LdifAttributes(
                        attributes=filtered_attrs,
                        attribute_metadata=entry.attributes.attribute_metadata,
                        metadata=entry.attributes.metadata,
                    ),
                },
            )

        def _add_transformation_comments(
            self,
            comment_lines: list[str],
            entry: FlextLdifModels.Entry,
            format_options: FlextLdifModels.WriteFormatOptions | None = None,
        ) -> None:
            """Add transformation comments for attribute changes.

            Uses generic utilities with hooks/parameters for extensibility.
            Attributes are sorted using the same ordering logic as normal attributes.

            Args:
                comment_lines: List to append comments to
                entry: Entry with transformation metadata
                format_options: Write format options for attribute ordering

            """
            if not entry.metadata:
                return

            # Process attribute_transformations (primary source)
            processed_attrs: set[str] = set()
            if entry.metadata.attribute_transformations:
                # Collect attribute names and sort them using the same logic as normal attributes
                attr_names = list(entry.metadata.attribute_transformations.keys())
                ordered_attr_names = self._determine_attribute_order(
                    attr_names,
                    format_options,
                )

                # Iterate over sorted attribute names instead of dictionary directly
                for attr_name in ordered_attr_names:
                    transformation = entry.metadata.attribute_transformations[attr_name]
                    transformation_type = transformation.transformation_type.upper()
                    # Map types: MODIFIED → TRANSFORMED for comments
                    comment_type = (
                        "TRANSFORMED"
                        if transformation_type in {"MODIFIED", "TRANSFORMED"}
                        else transformation_type
                    )
                    self._add_attribute_transformation_comments(
                        comment_lines,
                        attr_name,
                        transformation,
                        comment_type,
                    )
                    processed_attrs.add(attr_name.lower())

            # Also check removed_attributes field for legacy compatibility
            # This ensures all removed attributes are shown, even if not tracked as transformations
            if (
                format_options
                and format_options.write_removed_attributes_as_comments
                and entry.metadata.removed_attributes
            ):
                removed_attr_names = list(entry.metadata.removed_attributes.keys())
                ordered_removed_attrs = self._determine_attribute_order(
                    removed_attr_names,
                    format_options,
                )

                for attr_name in ordered_removed_attrs:
                    # Skip if already processed as transformation
                    if attr_name.lower() in processed_attrs:
                        continue

                    removed_values = entry.metadata.removed_attributes[attr_name]
                    if isinstance(removed_values, list):
                        comment_lines.extend(
                            f"# [REMOVED] {attr_name}: {value}"
                            for value in removed_values
                        )
                    else:
                        comment_lines.append(
                            f"# [REMOVED] {attr_name}: {removed_values}",
                        )

            if comment_lines:
                comment_lines.append("")  # Separator

        def _format_transformation_comment(
            self,
            transformation_type: str,
            attr_name: str,
            transformation: FlextLdifModels.AttributeTransformation,
        ) -> list[str]:
            """Format transformation comments generically.

            Consolidates logic for REMOVED, RENAMED, and TRANSFORMED types.

            Args:
                transformation_type: Type of transformation (REMOVED, RENAMED, TRANSFORMED)
                attr_name: Attribute name
                transformation: Transformation metadata

            Returns:
                List of formatted comment lines

            """
            lines: list[str] = []

            if transformation_type == "REMOVED":
                lines.extend(
                    f"# [REMOVED] {attr_name}: {value}"
                    for value in transformation.original_values
                )
            elif transformation_type == "RENAMED":
                target_name = transformation.target_name or "unknown"
                lines.extend(
                    f"# [RENAMED] {attr_name} -> {target_name}: {value}"
                    for value in transformation.original_values
                )
            elif transformation_type == "TRANSFORMED":
                orig_values = transformation.original_values
                target_values = transformation.target_values or []
                max_len = max(len(orig_values), len(target_values))
                for i in range(max_len):
                    orig_val = orig_values[i] if i < len(orig_values) else "?"
                    target_val = target_values[i] if i < len(target_values) else "?"
                    lines.append(
                        f"# [TRANSFORMED] {attr_name}: {orig_val} -> {target_val}",
                    )

            return lines

        def _add_attribute_transformation_comments(
            self,
            comment_lines: list[str],
            attr_name: str,
            transformation: FlextLdifModels.AttributeTransformation,
            transformation_type: str = "REMOVED",
        ) -> None:
            """Add generic transformation comments (REMOVED, RENAMED, TRANSFORMED).

            Args:
                comment_lines: List to append comments to
                attr_name: Attribute name
                transformation: Transformation metadata
                transformation_type: Type of transformation ("REMOVED", "RENAMED", "TRANSFORMED")

            """
            lines = self._format_transformation_comment(
                transformation_type,
                attr_name,
                transformation,
            )
            comment_lines.extend(lines)

        def _add_rejection_reason_comments(
            self,
            comment_lines: list[str],
            entry: FlextLdifModels.Entry,
        ) -> None:
            """Add rejection reason comments if entry was rejected.

            Args:
                comment_lines: List to append comments to
                entry: Entry with processing stats

            """
            if not (
                entry.metadata
                and entry.metadata.processing_stats
                and entry.metadata.processing_stats.rejection_reason
            ):
                return

            rejection_reason = entry.metadata.processing_stats.rejection_reason
            comment_lines.extend(
                [
                    FlextLdifConstants.CommentFormats.SEPARATOR_DOUBLE,
                    FlextLdifConstants.CommentFormats.HEADER_REJECTION_REASON,
                    FlextLdifConstants.CommentFormats.SEPARATOR_DOUBLE,
                    f"{FlextLdifConstants.CommentFormats.PREFIX_COMMENT}{rejection_reason}",
                    FlextLdifConstants.CommentFormats.SEPARATOR_EMPTY,
                ],
            )

        def generate_entry_comments(
            self,
            entry: FlextLdifModels.Entry,
            format_options: FlextLdifModels.WriteFormatOptions | None = None,
        ) -> str:
            """Generate LDIF comments for transformations, removed attributes, and rejection reasons.

            Comments are written BEFORE the entry to document:
            - Attribute transformations ([REMOVED], [RENAMED], [TRANSFORMED])
            - Attributes that were removed during migration (legacy format)
            - Rejection reasons if entry was rejected

            Args:
                entry: Entry to generate comments for
                format_options: Write format options controlling comment generation (optional)

            Returns:
                String containing comment lines (with trailing newline if non-empty)

            """
            comment_lines: list[str] = []

            # Add transformation comments if enabled (NEW FORMAT)
            if format_options and format_options.write_transformation_comments:
                self._add_transformation_comments(comment_lines, entry, format_options)

            # Add rejection reason comments if enabled
            if format_options and format_options.write_rejection_reasons:
                self._add_rejection_reason_comments(comment_lines, entry)

            return "\n".join(comment_lines) + "\n" if comment_lines else ""

        def format_entry_for_write(
            self,
            entry: FlextLdifModels.Entry,
            format_options: FlextLdifModels.WriteFormatOptions | None = None,
        ) -> FlextLdifModels.Entry:
            """Format entry for writing using quirk-specific logic.

            This method applies server-specific formatting/normalization
            before the entry is written. Delegates to quirks for all
            transformations.

            Args:
                entry: Entry to format
                format_options: Write format options (optional)

            Returns:
                Formatted entry ready for writing

            """
            # RFC base: Only normalize attribute names if requested
            if not format_options or not format_options.normalize_attribute_names:
                return entry

            if not entry.attributes:
                return entry

            # Normalize attribute names to lowercase
            new_attrs = {
                attr_name.lower(): attr_values
                for attr_name, attr_values in entry.attributes.attributes.items()
            }

            return entry.model_copy(
                update={
                    "attributes": FlextLdifModels.LdifAttributes(attributes=new_attrs),
                },
            )

        def _route_parse(
            self,
            ldif_text: str,
        ) -> FlextResult[
            FlextLdifModels.Entry
            | FlextLdifModels.SchemaAttribute
            | FlextLdifModels.SchemaObjectClass
            | FlextLdifModels.Acl
            | list[FlextLdifModels.Entry]
        ]:
            """Route LDIF parsing to appropriate handler.

            Detects content type and routes to Entry, Schema, or Acl parser:
            - Multiline/DN-based → Entry.parse()
            - attributetypes: or objectclasses: → Schema.route_parse()
            - (target=...) or acl syntax → Acl.parse()

            Args:
                ldif_text: LDIF content string.

            Returns:
                FlextResult with parsed model(s).

            """
            # Strip and check content type
            text_lower = ldif_text.lower().strip()

            # Detect schema definitions (attributetypes: or objectclasses:)
            if "attributetypes:" in text_lower or "objectclasses:" in text_lower:
                # Access Schema via parent's class (RFC is the parent class containing Schema)
                schema_quirk = FlextLdifServersRfc.Schema(parent_quirk=self)
                return schema_quirk.route_parse(ldif_text)

            # Detect ACL (parentheses-based syntax)
            if text_lower.startswith("(") and "target=" in text_lower:
                # Access Acl via parent's class (RFC is the parent class containing Acl)
                # self is already FlextLdifServersBase (RFC extends it)
                acl_quirk = FlextLdifServersRfc.Acl(
                    parent_quirk=self,
                )
                return acl_quirk.parse(ldif_text)

            # Default to Entry parsing
            return self.parse(ldif_text)

        def _route_write(
            self,
            model: (
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | FlextLdifModels.Acl
                | FlextLdifModels.Entry
                | str
            ),
        ) -> FlextResult[str]:
            """Route model writing to appropriate handler.

            Detects model type and routes to Entry, Schema, or Acl writer:
            - Entry → Entry.write()
            - SchemaAttribute/SchemaObjectClass → Schema.write()
            - Acl → Acl.write()

            Args:
                model: Model instance to write.

            Returns:
                FlextResult with RFC-compliant string.

            """
            if isinstance(model, FlextLdifModels.Entry):
                return self.write(model)

            if isinstance(
                model,
                (FlextLdifModels.SchemaAttribute, FlextLdifModels.SchemaObjectClass),
            ):
                schema_quirk = FlextLdifServersRfc.Schema(parent_quirk=self)
                return schema_quirk.write(model)

            if isinstance(model, FlextLdifModels.Acl):
                # self is already FlextLdifServersBase (RFC extends it)
                acl_quirk = FlextLdifServersRfc.Acl(
                    parent_quirk=self,
                )
                return acl_quirk.write(model)

            return FlextResult[str].fail(
                f"Unknown model type for writing: {type(model).__name__}",
            )

        def _route_write_many(
            self,
            items: list[object],
        ) -> FlextResult[str]:
            """Route multiple items writing (entries, schemas, acls).

            Writes each item and combines results.

            Args:
                items: List of models (Entry, SchemaAttribute, SchemaObjectClass, Acl).

            Returns:
                FlextResult with combined RFC string.

            """
            ldif_lines: list[str] = []
            for item in items:
                result = self._route_write(item)
                if result.is_failure:
                    return result
                ldif_lines.append(result.unwrap())
            ldif_text = "\n".join(ldif_lines)
            if ldif_text and not ldif_text.endswith("\n"):
                ldif_text += "\n"
            return FlextResult.ok(ldif_text)

        def _handle_parse_entry(
            self,
            ldif_text: str,
        ) -> FlextResult[FlextLdifModels.Entry | str]:
            """Handle parse operation for entry quirk."""
            parse_result = self.parse(ldif_text)
            if parse_result.is_success:
                parsed_entries: list[FlextLdifModels.Entry] = parse_result.unwrap()
                # Return first entry or empty string (matching base class behavior)
                if len(parsed_entries) == 1:
                    return FlextResult[FlextLdifModels.Entry | str].ok(
                        parsed_entries[0],
                    )
                if len(parsed_entries) == 0:
                    return FlextResult[FlextLdifModels.Entry | str].ok("")
                # Multiple entries: return first one
                return FlextResult[FlextLdifModels.Entry | str].ok(
                    parsed_entries[0],
                )
            error_msg: str = parse_result.error or "Parse failed"
            return FlextResult[FlextLdifModels.Entry | str].fail(error_msg)

        def _handle_write_entry(
            self,
            entries_to_write: list[FlextLdifModels.Entry],
        ) -> FlextResult[FlextLdifModels.Entry | str]:
            """Handle write operation for entry quirk."""
            write_result = self._route_write_many(list(entries_to_write))
            if write_result.is_success:
                written_text: str = write_result.unwrap()
                return FlextResult[FlextLdifModels.Entry | str].ok(written_text)
            error_msg: str = write_result.error or "Write failed"
            return FlextResult[FlextLdifModels.Entry | str].fail(error_msg)

        def _auto_detect_entry_operation(
            self,
            data: str | list[FlextLdifModels.Entry],
            operation: FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral
            | None,
        ) -> FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral:
            """Auto-detect entry operation from data type.

            If operation is forced (not None), uses it. Otherwise detects from type:
            - str -> "parse"
            - list[Entry] -> "write"
            - else -> error

            """
            if operation is not None:
                return operation

            if isinstance(data, str):
                return "parse"

            # data is list[Entry] at this point (type checker narrowed from Union[str, list[Entry]])
            if not data:
                return "write"

            # Validate that all items in list are Entry models
            for item in data:
                if not isinstance(item, FlextLdifModels.Entry):
                    # Invalid data type - will be handled by caller
                    return "write"  # Default to write, caller will handle error

            return "write"

        def _route_parse_operation(
            self,
            data: str,
        ) -> FlextResult[FlextLdifModels.Entry | str]:
            """Route to parse handler and convert result."""
            parse_result = self._handle_parse_entry(data)
            if parse_result.is_failure:
                return FlextResult[FlextLdifModels.Entry | str].fail(
                    parse_result.error or "Unknown error",
                )

            parse_value = parse_result.unwrap()
            if FlextRuntime.is_list_like(parse_value):
                first_item = parse_value[0] if parse_value else ""
                if isinstance(first_item, FlextLdifModels.Entry):
                    return FlextResult[FlextLdifModels.Entry | str].ok(first_item)
                return FlextResult[FlextLdifModels.Entry | str].ok(
                    str(first_item) if first_item else "",
                )
            if isinstance(parse_value, FlextLdifModels.Entry | str):
                return FlextResult[FlextLdifModels.Entry | str].ok(parse_value)
            return FlextResult[FlextLdifModels.Entry | str].ok("")

        def _route_write_operation(
            self,
            data: list[FlextLdifModels.Entry],
        ) -> FlextResult[FlextLdifModels.Entry | str]:
            """Route to write handler and convert result."""
            entries_list: list[FlextLdifModels.Entry] = [
                item for item in data if isinstance(item, FlextLdifModels.Entry)
            ]
            write_result = self._handle_write_entry(entries_list)
            if write_result.is_failure:
                return FlextResult[FlextLdifModels.Entry | str].fail(
                    write_result.error or "Unknown error",
                )
            write_value = write_result.unwrap()
            if isinstance(write_value, str):
                return FlextResult[FlextLdifModels.Entry | str].ok(write_value)
            return FlextResult[FlextLdifModels.Entry | str].ok("")

        def _route_entry_operation(
            self,
            data: str | list[FlextLdifModels.Entry],
            operation: FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral,
        ) -> FlextResult[FlextLdifModels.Entry | str]:
            """Route entry data to appropriate parse or write handler."""
            if operation == "parse":
                if not isinstance(data, str):
                    return FlextResult[FlextLdifModels.Entry | str].fail(
                        f"parse requires str, got {type(data).__name__}",
                    )
                return self._route_parse_operation(data)

            if operation == "write":
                if not FlextRuntime.is_list_like(data):
                    return FlextResult[FlextLdifModels.Entry | str].fail(
                        f"write requires list[Entry], got {type(data).__name__}",
                    )
                return self._route_write_operation(data)

            msg = f"Unknown operation: {operation}"
            raise AssertionError(msg)

        def _handle_explicit_parse_operation(
            self,
            typed_data: str | list[FlextLdifModels.Entry],
        ) -> FlextResult[FlextLdifModels.Entry | str]:
            """Handle explicit parse operation with result conversion.

            Args:
                typed_data: Data to parse (must be str)

            Returns:
                FlextResult with first Entry or empty string

            """
            if not isinstance(typed_data, str):
                return FlextResult.fail(
                    f"parse operation requires str, got {type(typed_data).__name__}",
                )
            parse_result = self.parse(typed_data)
            if parse_result.is_success:
                entries = parse_result.unwrap()
                return FlextResult.ok(entries[0] if entries else "")
            return FlextResult.fail(parse_result.error or "Unknown error")

        def _convert_route_result_to_output(
            self,
            route_result: FlextResult[FlextLdifModels.Entry | str],
            _detected_operation: FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral,
        ) -> FlextResult[FlextLdifModels.Entry | str]:
            """Convert/validate route operation result.

            Pass-through helper that ensures type safety. _route_entry_operation
            already converts to Union[Entry, str], so we just propagate the result.

            Reusable across all server implementations (rfc, oid, oud).

            Args:
                route_result: Result from _route_entry_operation (already typed)
                _detected_operation: Operation type (for future extensibility)

            Returns:
                FlextResult[FlextLdifModels.Entry | str] unchanged

            """
            return route_result

        def _validate_execute_params(
            self,
            data: str | list[object] | object | None,
            operation: str | None,
        ) -> FlextResult[object]:
            """Validate parameters for execute method."""
            # Type check data parameter
            if data is not None:
                if not isinstance(data, (str, list)) and data is not None:
                    return FlextResult.fail(
                        f"data must be str, list, or None, got {type(data)}",
                    )
                if isinstance(data, list) and not all(
                    isinstance(item, FlextLdifModels.Entry) for item in data
                ):
                    return FlextResult.fail("data list must contain only Entry objects")

            # Type check operation parameter
            if operation is not None and operation not in {"parse", "write"}:
                return FlextResult.fail(
                    f"operation must be 'parse', 'write', or None, got {operation}",
                )

            return FlextResult.ok(True)

        def execute(
            self,
            **kwargs: str | float | bool | None,
        ) -> FlextResult[FlextLdifModels.Entry | str]:
            r"""Execute entry quirk operation with automatic type detection and routing.

            Fully automatic polymorphic dispatch based on data type:
            - str (LDIF content) -> parse_content() -> list[Entry]
            - list[Entry] (models) -> write_entry() for each -> str (LDIF)
            - None -> health check

            **V2 Usage as Processor - Maximum Automation:**
                >>> entry = FlextLdifServersRfc.Entry()
                >>> # Parse: pass LDIF string
                >>> entries = entry.execute(data="dn: cn=test\n...")
                >>> # Write: pass Entry list
                >>> ldif = entry.execute(data=[entry1, entry2])
                >>> # Or use as callable processor
                >>> entries = entry("dn: cn=test\n...")  # Parse
                >>> ldif = entry([entry1, entry2])  # Write

            Args:
                data: LDIF content string OR list of Entry models
                operation: Force operation type (overrides auto-detection)

            Returns:
                FlextResult[FlextLdifModels.Entry | str] depending on operation
                - When operation="parse": returns Entry (first entry) or str (empty)
                - When operation="write": returns str
                - When operation=None: auto-detects and returns appropriate type

            Raises:
                Returns fail() if data type is unknown or operation fails

            """
            # Extract parameters from kwargs with type-safe conversion
            data = kwargs.get("data")
            operation_raw = kwargs.get("operation")
            operation: str | None = (
                operation_raw if isinstance(operation_raw, str) else None
            )

            # Validate input parameters
            validation_result = self._validate_execute_params(data, operation)
            if validation_result.is_failure:
                error_msg = validation_result.error or "Validation failed"
                return FlextResult[FlextLdifModels.Entry | str].fail(error_msg)

            # Type-safe data extraction using isinstance
            typed_data: str | (list[FlextLdifModels.Entry] | None) = None
            if isinstance(data, (str, list)):
                typed_data = data

            # Type-safe operation extraction with explicit Literal check
            typed_operation: (
                FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral | None
            ) = None
            if operation == "parse":
                typed_operation = "parse"
            elif operation == "write":
                typed_operation = "write"

            # Health check: no data provided
            if typed_data is None:
                return FlextResult.ok("")

            # Auto-detect operation from data type
            detected_operation = self._auto_detect_entry_operation(
                typed_data,
                typed_operation,
            )

            # Handle explicit parse operation with dedicated helper
            if detected_operation == "parse" and typed_operation == "parse":
                return self._handle_explicit_parse_operation(typed_data)

            # Route to appropriate handler and convert result to output type
            route_result = self._route_entry_operation(typed_data, detected_operation)
            return self._convert_route_result_to_output(
                route_result,
                detected_operation,
            )

        @overload
        def __call__(
            self,
            data: str,
            *,
            operation: FlextLdifConstants.LiteralTypes.ParseOperationLiteral
            | None = None,
        ) -> FlextLdifTypes.EntryOrString: ...

        @overload
        def __call__(
            self,
            data: list[FlextLdifModels.Entry],
            *,
            operation: FlextLdifConstants.LiteralTypes.WriteOperationLiteral
            | None = None,
        ) -> str: ...

        @overload
        def __call__(
            self,
            data: str | (list[FlextLdifModels.Entry] | None) = None,
            *,
            operation: FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral
            | None = None,
        ) -> FlextLdifTypes.EntryOrString: ...

        def __call__(
            self,
            data: str | (list[FlextLdifModels.Entry] | None) = None,
            *,
            operation: FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral
            | None = None,
        ) -> FlextLdifTypes.EntryOrString:
            """Callable interface - automatic polymorphic processor.

            Pass LDIF string for parsing or Entry list for writing.
            Type auto-detection handles routing automatically.
            """
            result = self.execute(data=data, operation=operation)
            return result.unwrap()  # Already correct type

        def __new__(
            cls,
            entry_service: FlextLdifTypes.Services.EntryService | None = None,
            **kwargs: str | float | bool | None,
        ) -> Self:
            """Override __new__ to support auto-execute and processor instantiation."""
            instance = super().__new__(cls)
            # Remove auto-execute kwargs before passing to __init__
            auto_execute_kwargs = {"ldif_text", "entry", "entries", "operation"}
            init_kwargs = {
                k: v for k, v in kwargs.items() if k not in auto_execute_kwargs
            }
            # Use explicit type cast for __init__ call to avoid type checker issues
            # with dynamic class instantiation
            instance_type = type(instance)
            if hasattr(instance_type, "__init__"):
                instance_type.__init__(
                    instance,
                    entry_service=entry_service,
                    parent_quirk=None,
                    **init_kwargs,
                )

            # Note: auto_execute pattern is disabled to maintain type safety
            # Use entry.execute() method instead of auto_execute in __new__

            return instance

        def parse_entry(
            self,
            entry_dn: str,
            entry_attrs: (
                Mapping[str, list[str] | str] | dict[str, list[str] | str] | str
            ),
        ) -> FlextResult[FlextLdifModels.Entry]:
            """🔴 REQUIRED: Parse individual LDIF entry into Entry model (internal).

            Called by _parse_content() for each (dn, attrs) pair from ldif3.

            **You must:**
            1. Normalize DN (server-specific format)
            2. Convert raw attributes (handle bytes vs str)
            3. Create Entry model
            4. Return FlextResult.ok(entry)

            **IMPORTANT**: Do NOT call _hook_post_parse_entry() here!
            That hook is called by _parse_content() after you return.

            **Edge cases:**
            - Null DN -> return fail("DN is None")
            - Empty DN string -> return fail("DN is empty")
            - Null attributes -> return fail("Attributes is None")
            - Empty attributes dict -> return ok(entry) (valid!)
            - Bytes in attributes -> convert to str
            - Non-string values -> convert with str()

            Args:
                entry_dn: Raw DN string from LDIF parser
                entry_attrs: Raw attributes mapping (may contain bytes like {b'mail': [b'user@example.com']})

            Returns:
                FlextResult with Entry model or fail(message)

            """
            # Default RFC-compliant implementation
            # Servers can override for server-specific parsing logic
            if not entry_dn:
                return FlextResult.fail("DN is None or empty")

            # Type check: entry_attrs should be a mapping
            if not isinstance(entry_attrs, Mapping):
                return FlextResult.fail(
                    f"entry_attrs must be a Mapping, got {type(entry_attrs)}",
                )

            # Convert attributes to FlextLdifModels.LdifAttributes
            attrs_result = FlextLdifModels.LdifAttributes.create(dict(entry_attrs))
            if not attrs_result.is_success:
                return FlextResult.fail(
                    f"Failed to create LdifAttributes: {attrs_result.error}",
                )
            converted_attrs = attrs_result.unwrap()

            # Create DistinguishedName object from DN string
            dn_value: str | FlextLdifModels.DistinguishedName = (
                FlextLdifModels.DistinguishedName(value=entry_dn)
            )

            # Create Entry model with defaults - entry_dn is already validated as str
            entry_result = FlextLdifModels.Entry.create(
                dn=dn_value,
                attributes=converted_attrs,
            )
            if entry_result.is_failure:
                error = entry_result.error or "Unknown error"
                return FlextResult.fail(
                    f"Failed to create Entry: {error}",
                )

            return FlextResult[FlextLdifModels.Entry].ok(entry_result.unwrap())

        def _get_dn_line_for_write(self, entry_data: FlextLdifModels.Entry) -> str:
            """Get DN line from metadata or generate standard format (DRY helper)."""
            if entry_data.metadata:
                # Try metadata locations in priority order
                for getter, key in [
                    (entry_data.metadata.original_format_details, "original_dn_line"),
                    (
                        entry_data.metadata.extensions,
                        FlextLdifConstants.MetadataKeys.ORIGINAL_DN_LINE_COMPLETE,
                    ),
                ]:
                    if getter and isinstance(val := getter.get(key), str):
                        return val
                # Try original_strings with prefix
                if entry_data.metadata.original_strings:
                    dn_orig = entry_data.metadata.original_strings.get(
                        FlextLdifConstants.Rfc.META_DN_ORIGINAL,
                    )
                    if isinstance(dn_orig, str):
                        return f"dn: {dn_orig}"
            return f"dn: {entry_data.dn.value}" if entry_data.dn else "dn: "

        def _write_entry_modify_format(
            self,
            entry_data: FlextLdifModels.Entry,
            write_options: FlextLdifModels.WriteFormatOptions,
        ) -> FlextResult[str]:
            """Write Entry in LDIF modify format (RFC 2849 § 4 - Change Records).

            Uses FlextLdifUtilities.Writer for DRY consolidation.
            For schema entries, filters and orders attributes correctly.

            Args:
                entry_data: Entry model to write
                write_options: Formatting options with ldif_modify_operation

            Returns:
                FlextResult with LDIF string in modify format

            """
            # DN validation
            if not (entry_data.dn and entry_data.dn.value):
                return FlextResult[str].fail("Entry DN is required for LDIF output")

            # Restore original formatting from metadata for round-trip support
            # This ensures we have the correct attribute order from the original entry
            restored_entry = self._restore_entry_from_metadata(entry_data)

            # Get attributes dict (empty dict if None)
            attrs_dict: dict[str, list[str]] = (
                restored_entry.attributes.attributes
                if restored_entry.attributes
                else {}
            )

            # Check if this is a schema entry
            is_schema = FlextLdifUtilities.Entry.is_schema_entry(
                restored_entry,
                strict=False,
            )

            # For schema entries, filter and order attributes correctly
            if is_schema:
                # Schema attribute order (RFC 4512 standard order)
                # Using both uppercase and lowercase variants for compatibility
                schema_order = [
                    "attributetypes",
                    "attributeTypes",
                    "objectclasses",
                    "objectClasses",
                    "ldapsyntaxes",
                    "ldapSyntaxes",
                    "matchingrules",
                    "matchingRules",
                    "matchingruleuse",
                    "matchingRuleUse",
                    "ditcontentrules",
                    "dITContentRules",
                    "ditstructurerules",
                    "dITStructureRules",
                    "namesforms",
                    "nameforms",
                    "nameForms",
                ]
                # Filter out objectClass (should not appear in modify format for schema)
                # and order schema attributes correctly
                filtered_attrs: dict[str, list[str]] = {}

                # Normalize attribute names to lowercase for comparison
                attrs_dict_normalized: dict[str, tuple[str, list[str]]] = {
                    attr_name.lower(): (attr_name, attr_values)
                    for attr_name, attr_values in attrs_dict.items()
                }

                # First, add schema attributes in correct order (using lowercase for lookup)
                schema_order_lower = [attr.lower() for attr in schema_order]
                seen_schema_attrs = set()
                for schema_attr_lower in schema_order_lower:
                    if (
                        schema_attr_lower in attrs_dict_normalized
                        and schema_attr_lower not in seen_schema_attrs
                    ):
                        orig_name, orig_values = attrs_dict_normalized[
                            schema_attr_lower
                        ]
                        filtered_attrs[orig_name] = orig_values
                        seen_schema_attrs.add(schema_attr_lower)

                # For schema modify format, ONLY include schema attributes
                # Do NOT include other attributes like cn, orclnormdn, aci, etc.
                # These are entry-level attributes, not schema definitions
                attrs_dict = filtered_attrs

            # Build LDIF lines using generalized utility
            modify_op = write_options.ldif_modify_operation if write_options else "add"
            ldif_lines = FlextLdifUtilities.Writer.build_entry_lines(
                dn_value=restored_entry.dn.value
                if restored_entry.dn
                else entry_data.dn.value,
                attributes=attrs_dict,
                format_type="modify",
                modify_operation=modify_op,
            )

            return FlextResult[str].ok(
                FlextLdifUtilities.Writer.finalize_ldif_text(ldif_lines),
            )


# Pydantic v2 automatically resolves forward references when classes are defined
# No manual model_rebuild() calls needed

__all__ = [
    "FlextLdifServersRfc",
]
