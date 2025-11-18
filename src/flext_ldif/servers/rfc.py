"""RFC 4512 Compliant Server Quirks - Base LDAP Schema/ACL/Entry Implementation.

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
from typing import ClassVar, Literal, Self, cast, overload

from flext_core import FlextLogger, FlextResult

# ===== TYPE ALIASES (Python 3.13 semantic types) =====
# These document the semantic purpose of constants without formal definitions
# Used in docstrings and type hints for better code clarity
#
# type PermissionSet = frozenset[str]  # Set of ACL permissions
# type AttributeSet = frozenset[str]   # Set of LDAP attribute names
# type PatternSet = frozenset[str]     # Set of regex/match patterns
# type ReplacementMap = Mapping[str, str]  # Mapping for substitutions/normalization
# type DetectionConfig = Mapping[str, str | int | frozenset[str]]  # Detection config
# type AclConfig = Mapping[str, str | int | frozenset[str]]  # ACL format config
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities

logger = FlextLogger(__name__)

# Import for type checking in __new__ method


class FlextLdifServersRfc(FlextLdifServersBase):
    """RFC 4512 Compliant Server Quirks - Base Implementation.

    LDAP Schema/ACL/Entry Parsing.

    Transforms RFC 4512 utility parsers into concrete quirks classes extending
    FlextLdifServersBase with nested Schema, Acl, and Entry quirk implementations.
    Provides RFC-compliant implementations for use as a foundation layer that
    server-specific quirks can extend.

    Architecture:
        RFC Server provides complete RFC 4512 baseline:
        - Schema: Uses AttributeParser/ObjectClassParser for strict RFC parsing
        - Acl: RFC 4516 ACL baseline implementation
        - Entry: RFC 2849 LDIF entry handling

        Server-specific quirks extend this to add server-specific features:
        - Override can_handle_attribute/objectclass() for server-specific selection
        - Override parse_attribute/parse_objectclass() for enhanced parsing
        - Override convert_*() methods for server-specific transformations

    Design Benefits:
        - Single source of truth: RFC parsers in one module
        - Composable: Server quirks extend RFC base
        - Testable: RFC quirk is independently testable
        - Maintainable: RFC updates automatically propagate to all servers

    Inheritance Hierarchy:
        FlextLdifServersBase (abstract base)
        └── FlextLdifServersRfc (RFC 4512 baseline - concrete with all quirks)
            ├── FlextLdifServersOid (Oracle OID - extends RFC)
            ├── FlextLdifServersOud (Oracle OUD - extends RFC)
            ├── FlextLdifServersOpenLDAP (OpenLDAP - extends RFC)
            └── Other servers...

    Example:
        from flext_ldif.servers.rfc import FlextLdifServersRfc

        rfc_server = FlextLdifServersRfc()
        schema = rfc_server.Schema()

        # RFC quirk handles all RFC-compliant attributes/objectClasses
        if schema.can_handle_attribute(attr_def):
            result = schema.parse_attribute(attr_def)
            if result.is_success:
                parsed_attr = result.unwrap()
                # Use parsed attribute...

        # Parse objectClass
        result = RfcObjectClassParser.parse_common(oc_definition)

    """

    # =========================================================================
    # STANDARDIZED CONSTANTS FOR AUTO-DISCOVERY
    # =========================================================================
    class Constants:
        r"""Server configuration constants for RFC baseline (RFC 4512 compliant).

        This class provides standardized configuration constants used by all
        server-specific Constants classes, eliminating duplication across all
        server implementations.

        **Python 3.13 Design Patterns:**
        - Type aliases using `type` keyword for semantic constants
        - Frozen sets and mappings for immutable configuration
        - Advanced mapping protocols for zero-cost abstractions
        - ClassVar annotations for explicit class-level state

        **Note**: SERVER_TYPE and PRIORITY are now at class level (not in Constants).
        These are set once per server implementation for initialization
        via __init_subclass__.

        **Standard Fields** (inherited by all servers):
        - CANONICAL_NAME: Canonical name for display
        - ALIASES: Alternative names for server detection
        - CAN_NORMALIZE_FROM: Server types this can normalize from
        - CAN_DENORMALIZE_TO: Server types this can denormalize to
        - ACL_FORMAT: ACL format identifier (e.g., "orclaci", "rfc_generic")
        - ACL_ATTRIBUTE_NAME: LDAP attribute name for ACLs
        - SCHEMA_SUP_SEPARATOR: Character used to separate SUP fields (RFC standard)
        - DETECTION_OID_PATTERN: Regex pattern for server OID detection
        - DETECTION_ATTRIBUTE_PREFIXES: Attribute name prefixes to detect server
        - DETECTION_OBJECTCLASS_NAMES: ObjectClass names to detect server
        - DETECTION_DN_MARKERS: DN patterns to detect server

        **RFC baseline** - Universal intermediate format for all conversions.
        """

        # =====================================================================
        # CORE IDENTITY - Server identification and metadata
        # =====================================================================
        SERVER_TYPE: ClassVar[str] = FlextLdifConstants.ServerTypes.RFC
        PRIORITY: ClassVar[int] = 100

        # LDAP Connection Defaults (RFC 4511 §4.1 - Standard LDAP ports)
        DEFAULT_PORT: ClassVar[int] = 389  # Standard LDAP port
        DEFAULT_SSL_PORT: ClassVar[int] = 636  # Standard LDAPS port (LDAP over SSL/TLS)
        DEFAULT_PAGE_SIZE: ClassVar[int] = 1000  # RFC 2696 Simple Paged Results default

        CANONICAL_NAME: ClassVar[str] = "rfc"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["rfc", "generic"])

        # =====================================================================
        # CONVERSION CAPABILITIES - Server transformation support
        # =====================================================================
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["rfc"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["rfc"])

        # =====================================================================
        # ACL CONFIGURATION - Access control list settings
        # =====================================================================
        ACL_FORMAT: ClassVar[str] = "rfc_generic"  # RFC generic ACL format
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"  # RFC 4876 ACI attribute (generic)

        # === ACL PERMISSION NAMES (RFC 4876 Standard) ===
        # Standard LDAP permission names (RFC baseline)
        # Servers inherit these and can add their own (e.g., PERMISSION_PROXY)
        PERMISSION_READ: ClassVar[str] = "read"
        PERMISSION_WRITE: ClassVar[str] = "write"
        PERMISSION_ADD: ClassVar[str] = "add"
        PERMISSION_DELETE: ClassVar[str] = "delete"
        PERMISSION_SEARCH: ClassVar[str] = "search"
        PERMISSION_COMPARE: ClassVar[str] = "compare"

        # === ACL SUPPORTED PERMISSIONS (Python 3.13 frozenset) ===
        # Permissions that RFC supports
        # (migrated from FlextLdifConstants.AclPermissionCompatibility)
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

        # =====================================================================
        # SCHEMA CONFIGURATION - Schema parsing and validation
        # =====================================================================
        # RFC 4512 § 4.2 Subschema Subentries - Standard schema DN
        # The subschema subentry for a server is conventionally named "cn=schema"
        # or "cn=subschema". This is the RFC-compliant canonical form.
        SCHEMA_DN: ClassVar[str] = "cn=schema"  # RFC 4512 standard schema DN

        SCHEMA_SUP_SEPARATOR: ClassVar[str] = "$"  # RFC 4512 standard SUP separator

        # Schema attribute fields that are server-specific
        # (RFC is canonical - no special fields)
        ATTRIBUTE_FIELDS: ClassVar[frozenset[str]] = frozenset([])

        # === OBJECTCLASS REQUIREMENTS (Python 3.13 mapping) ===
        # ObjectClass requirements for RFC (migrated from FlextLdifConstants.SchemaConversionMappings)
        OBJECTCLASS_REQUIREMENTS: ClassVar[Mapping[str, bool]] = {
            "requires_sup_for_auxiliary": True,
            "allows_multiple_sup": False,
            "requires_explicit_structural": False,
        }

        # === RFC ATTRIBUTE ALIASES (Python 3.13 mapping) ===
        # RFC has no attribute aliases (canonical format)
        # Subclasses can override with their own mappings
        ATTRIBUTE_ALIASES: ClassVar[Mapping[str, list[str]]] = {}

        # =====================================================================
        # OPERATIONAL ATTRIBUTES - System-managed attributes
        # =====================================================================
        # RFC operational attributes (generic baseline)
        # Using ClassVar[frozenset] to allow subclasses to extend with their own
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

        # === PRESERVE ON MIGRATION (Python 3.13 frozenset) ===
        # Operational attributes to preserve during migration FROM RFC
        PRESERVE_ON_MIGRATION: ClassVar[frozenset[str]] = frozenset(
            [
                "createTimestamp",
                "modifyTimestamp",
            ],
        )

        # =====================================================================
        # CATEGORIZATION RULES - Entry categorization for filtering
        # =====================================================================
        # Category priority order (RFC baseline - standard LDAP)
        CATEGORIZATION_PRIORITY: ClassVar[list[str]] = [
            "users",  # User accounts (person, inetOrgPerson)
            "hierarchy",  # Structural containers (organizationalUnit, organization)
            "groups",  # Group entries (groupOfNames, groupOfUniqueNames)
            "acl",  # ACL entries
        ]

        # ObjectClasses defining each category (RFC baseline - standard LDAP objectClasses)
        CATEGORY_OBJECTCLASSES: ClassVar[dict[str, frozenset[str]]] = {
            "users": frozenset([
                "person",
                "inetOrgPerson",
                "organizationalPerson",
                "residentialPerson",
            ]),
            "hierarchy": frozenset([
                "organizationalUnit",
                "organization",
                "locality",
                "country",
            ]),
            "groups": frozenset([
                "groupOfNames",
                "groupOfUniqueNames",
                "posixGroup",
            ]),
        }

        # ACL attributes for categorization (RFC 4876 + generic)
        CATEGORIZATION_ACL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset([
            "aci",  # RFC 4876 ACI attribute
            "acl",  # Generic ACL attribute (common in various LDAP servers)
        ])

        # =====================================================================
        # DETECTION PATTERNS - Server type detection rules
        # =====================================================================
        # Detection patterns (all server-specific, define in subclasses)
        DETECTION_OID_PATTERN: ClassVar[str] = r".*"  # Match any OID by default
        DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset([])
        DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset([])
        DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset([])

        # =====================================================================
        # ENCODING CONSTANTS - DRY (shared across all servers)
        # =====================================================================
        # Character encodings used in LDIF processing (RFC baseline)
        ENCODING_UTF8: ClassVar[str] = "utf-8"
        ENCODING_UTF16LE: ClassVar[str] = "utf-16-le"
        ENCODING_ASCII: ClassVar[str] = "ascii"
        ENCODING_LATIN1: ClassVar[str] = "latin-1"

        # Error handling strategies for encoding/decoding
        ENCODING_ERROR_REPLACE: ClassVar[str] = "replace"
        ENCODING_ERROR_IGNORE: ClassVar[str] = "ignore"
        ENCODING_ERROR_STRICT: ClassVar[str] = "strict"

        # =====================================================================
        # LDIF FORMAT CONSTANTS - DRY (shared across all servers)
        # =====================================================================
        # RFC 2849 LDIF format specifications
        LDIF_DN_PREFIX: ClassVar[str] = "dn: "
        LDIF_ATTR_SEPARATOR: ClassVar[str] = ": "
        LDIF_NEWLINE: ClassVar[str] = "\n"
        LDIF_ENTRY_SEPARATOR: ClassVar[str] = "\n\n"
        LDIF_COMMENT_PREFIX: ClassVar[str] = "# "
        LDIF_VERSION_PREFIX: ClassVar[str] = "version: "
        LDIF_CHANGETYPE_PREFIX: ClassVar[str] = "changetype: "
        LDIF_BASE64_PREFIX: ClassVar[str] = ": "  # RFC 2849 base64 marker

        # LDIF line length constraints (RFC 2849)
        LDIF_LINE_LENGTH_LIMIT: ClassVar[int] = 76
        LDIF_LINE_LENGTH_WITH_NEWLINE: ClassVar[int] = 77

        # =====================================================================
        # ACL PREFIX CONSTANTS - DRY (shared across all servers)
        # =====================================================================
        # Common ACL line prefixes used in parsing
        ACL_PREFIX_DN: ClassVar[str] = "dn:"
        ACL_PREFIX_VERSION: ClassVar[str] = "version 3.0"
        ACL_PREFIX_LDAP_URL: ClassVar[str] = "ldap:///"
        ACL_DEFAULT_VERSION: ClassVar[str] = "version 3.0"

        # ACL subject constants
        ACL_SELF_SUBJECT: ClassVar[str] = "ldap:///self"
        ACL_ANONYMOUS_SUBJECT: ClassVar[str] = "ldap:///anyone"

    # =========================================================================
    # Server identification - accessed via Constants via properties in base.py
    # =========================================================================
    # NOTE: server_type and priority are accessed via properties in base.py
    # which read from Constants.SERVER_TYPE and Constants.PRIORITY

    # NOTE: AttributeParser, ObjectClassParser, AttributeWriter, ObjectClassWriter
    # have been moved to FlextLdifUtilities.Parser and FlextLdifUtilities.Writer
    # Use: FlextLdifUtilities.Parser.parse_rfc_attribute() / parse_rfc_objectclass()
    # Use: FlextLdifUtilities.Writer.write_rfc_attribute() / write_rfc_objectclass()

    # =========================================================================
    # Main Quirk Operation Handlers - Concrete implementations moved from base.py
    # =========================================================================

    def _handle_parse_operation(
        self,
        ldif_text: str,
    ) -> FlextResult[FlextLdifTypes.EntryOrString]:
        """Handle parse operation for main quirk."""
        parse_result = self.parse(ldif_text)
        if parse_result.is_success:
            parse_response = parse_result.unwrap()
            entries = parse_response.entries
            if isinstance(entries, list):
                if entries and len(entries) > 0:
                    return FlextResult[FlextLdifTypes.EntryOrString].ok(
                        cast("FlextLdifTypes.EntryOrString", entries[0]),
                    )
                return FlextResult[FlextLdifTypes.EntryOrString].ok("")
            if isinstance(entries, FlextLdifModels.Entry):
                return FlextResult[FlextLdifTypes.EntryOrString].ok(
                    cast("FlextLdifTypes.EntryOrString", entries),
                )
            return FlextResult[FlextLdifTypes.EntryOrString].ok("")
        error_msg: str = parse_result.error or "Parse failed"
        return FlextResult[FlextLdifTypes.EntryOrString].fail(error_msg)

    def _handle_write_operation(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[FlextLdifTypes.EntryOrString]:
        """Handle write operation for main quirk."""
        write_result = self.write(entries)
        if write_result.is_success:
            written_text: str = write_result.unwrap()
            return FlextResult[FlextLdifTypes.EntryOrString].ok(written_text)
        error_msg: str = write_result.error or "Write failed"
        return FlextResult[FlextLdifTypes.EntryOrString].fail(error_msg)

    # =========================================================================
    # Automatic Routing Methods - Concrete implementations moved from base.py
    # =========================================================================

    def _detect_model_type(self, model: object) -> str:
        """Detect model type for automatic routing using functional type mapping.

        Args:
            model: Model instance to detect type for.

        Returns:
            Model type name: "entry", "schema_attribute",
            "schema_objectclass", or "acl".

        """
        # Functional type mapping with pattern matching
        type_mappings = {
            FlextLdifModels.Entry: "entry",
            FlextLdifModels.SchemaAttribute: "schema_attribute",
            FlextLdifModels.SchemaObjectClass: "schema_objectclass",
            FlextLdifModels.Acl: "acl",
        }

        # Find first matching type using functional composition
        for model_type, type_name in type_mappings.items():
            if isinstance(model, model_type):
                return type_name

        return "unknown"

    def _get_for_model(self, model: object) -> object | None:
        """Get appropriate quirk instance for a model type using functional routing.

        Args:
            model: Model instance to get quirk for.

        Returns:
            Appropriate quirk instance (Schema, Acl, or Entry) or None if not found.

        """
        # Functional routing mapping: model_type -> quirk_class_name
        routing_map = {
            "entry": "Entry",
            "schema_attribute": "Schema",
            "schema_objectclass": "Schema",
            "acl": "Acl",
        }

        def get_quirk_instance(class_name: str) -> object | None:
            """Get quirk instance by class name using reflection."""
            quirk_class = getattr(type(self), class_name, None)
            return quirk_class() if quirk_class else None

        # Compose detection and routing using functional approach
        model_type = self._detect_model_type(model)
        quirk_class_name = routing_map.get(model_type)

        return get_quirk_instance(quirk_class_name) if quirk_class_name else None

    def _route_model_to_write(self, model: object) -> FlextResult[str]:
        """Route a single model to appropriate write method.

        Automatically detects model type and routes to correct quirk write method.

        Args:
            model: Model instance to write (Entry, SchemaAttribute, SchemaObjectClass, or Acl).

        Returns:
            FlextResult with LDIF string representation.

        """
        if isinstance(model, FlextLdifModels.Entry):
            entry_class = getattr(type(self), "Entry", None)
            if not entry_class:
                return FlextResult.fail("Entry nested class not available")
            quirk = entry_class()
            result: FlextResult[str] = quirk.write(model)
            return result
        if isinstance(model, FlextLdifModels.SchemaAttribute):
            schema_class = getattr(type(self), "Schema", None)
            if not schema_class:
                return FlextResult.fail("Schema nested class not available")
            quirk = schema_class()
            result2: FlextResult[str] = quirk.write_attribute(model)
            return result2
        if isinstance(model, FlextLdifModels.SchemaObjectClass):
            schema_class = getattr(type(self), "Schema", None)
            if not schema_class:
                return FlextResult.fail("Schema nested class not available")
            quirk = schema_class()
            result3: FlextResult[str] = quirk.write_objectclass(model)
            return result3
        if isinstance(model, FlextLdifModels.Acl):
            acl_class = getattr(type(self), "Acl", None)
            if not acl_class:
                return FlextResult.fail("Acl nested class not available")
            quirk = acl_class()
            result4: FlextResult[str] = quirk.write(model)
            return result4
        return FlextResult.fail(f"Unknown model type: {type(model).__name__}")

    def _route_models_to_write(self, models: list[object]) -> FlextResult[list[str]]:
        """Route multiple models to appropriate write methods.

        Processes each model individually and routes to correct quirk.

        Args:
            models: List of model instances to write.

        Returns:
            FlextResult with list of LDIF string representations.

        """
        ldif_lines: list[str] = []
        for model in models:
            result = self._route_model_to_write(model)
            if result.is_failure:
                return FlextResult.fail(result.error or "Unknown error")
            text = result.unwrap()
            ldif_lines.extend(text.splitlines(keepends=False))
            if text and not text.endswith("\n"):
                ldif_lines.append("")  # Add blank line between entries
        return FlextResult.ok(ldif_lines)

    # =========================================================================
    # Validation Methods - Concrete implementations moved from base.py
    # =========================================================================

    def _validate_ldif_text(self, ldif_text: str) -> FlextResult[bool]:
        """Validate LDIF text before parsing - handles edge cases.

        Edge cases handled:
        - None/empty string -> returns ok (will result in empty entry list)
        - Whitespace only -> returns ok (will result in empty entry list)
        - Encoding issues -> any decoding happens in parse_content

        Args:
            ldif_text: LDIF content to validate

        Returns:
            FlextResult[bool] with True if valid, fail() if invalid

        """
        # Empty or whitespace-only is valid (will parse to empty list)
        if not ldif_text or not ldif_text.strip():
            return FlextResult[bool].ok(True)
        return FlextResult[bool].ok(True)

    def _validate_entries(
        self,
        entries: list[FlextLdifModels.Entry] | None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Validate entry list before writing - handles edge cases.

        Edge cases handled:
        - None -> returns empty list
        - Empty list -> returns empty list
        - Invalid entries -> returns fail

        Args:
            entries: Entry list to validate

        Returns:
            FlextResult with validated entry list

        """
        if entries is None:
            return FlextResult.ok([])
        if not entries:
            return FlextResult.ok([])
        # Validate that all entries are Entry models
        for entry in entries:
            if not isinstance(entry, FlextLdifModels.Entry):
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Invalid entry type: expected Entry, got {type(entry).__name__}",
                )
        return FlextResult.ok(entries)

    class Schema(FlextLdifServersBase.Schema):
        """RFC 4512 Compliant Schema Quirk - Base Implementation."""

        def __init__(
            self,
            schema_service: object | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize RFC schema quirk service.

            Args:
                schema_service: Injected FlextLdifSchema service (optional)
                **kwargs: Passed to parent class

            """
            super().__init__(schema_service=schema_service, **kwargs)

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
        def _validate_syntax_oid(syntax: str | None) -> str | None:
            """Validate syntax OID format.

            Args:
                syntax: Syntax OID to validate

            Returns:
                Error message if validation fails, None otherwise

            """
            if syntax is None or not syntax.strip():
                return None

            from flext_ldif._utilities.oid import FlextLdifUtilitiesOID

            validate_result = FlextLdifUtilitiesOID.validate_format(syntax)
            if validate_result.is_failure:
                return f"Syntax OID validation failed: {validate_result.error}"
            if not validate_result.unwrap():
                return f"Invalid syntax OID format: {syntax}"

            return None

        @staticmethod
        def _build_attribute_metadata(
            attr_definition: str,
            syntax: str | None,
            syntax_validation_error: str | None,
        ) -> FlextLdifModels.QuirkMetadata | None:
            """Build metadata for attribute including extensions.

            Args:
                attr_definition: Original attribute definition
                syntax: Syntax OID
                syntax_validation_error: Validation error if any

            Returns:
                QuirkMetadata or None

            """
            from flext_ldif._utilities.parser import FlextLdifUtilitiesParser

            metadata_extensions = FlextLdifUtilitiesParser.extract_extensions(
                attr_definition,
            )

            if syntax:
                metadata_extensions[
                    FlextLdifConstants.MetadataKeys.SYNTAX_OID_VALID
                ] = syntax_validation_error is None
                if syntax_validation_error:
                    metadata_extensions[
                        FlextLdifConstants.MetadataKeys.SYNTAX_VALIDATION_ERROR
                    ] = syntax_validation_error

            metadata_extensions[FlextLdifConstants.MetadataKeys.ORIGINAL_FORMAT] = (
                attr_definition.strip()
            )

            return (
                FlextLdifModels.QuirkMetadata(
                    quirk_type="rfc",
                    extensions=metadata_extensions,
                )
                if metadata_extensions
                else None
            )

        # ===== RFC 4512 PARSING METHODS =====

        def _parse_attribute(
            self,
            attr_definition: str,
            *,
            case_insensitive: bool = False,
            allow_syntax_quotes: bool = False,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse RFC 4512 attribute definition (implements abstract method).

            Args:
                attr_definition: RFC 4512 attribute definition string
                case_insensitive: Whether to use case-insensitive pattern matching
                allow_syntax_quotes: Whether to allow quoted syntax values (for lenient parsing)

            Returns:
                FlextResult with parsed SchemaAttribute model

            """
            try:
                oid_match = re.match(
                    FlextLdifConstants.LdifPatterns.SCHEMA_OID_EXTRACTION,
                    attr_definition,
                )
                if not oid_match:
                    return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                        "RFC attribute parsing failed: missing an OID",
                    )
                oid = oid_match.group(1)

                # Extract all string fields using helper
                name = FlextLdifUtilities.Parser._extract_regex_field(
                    attr_definition,
                    FlextLdifConstants.LdifPatterns.SCHEMA_NAME,
                    default=oid,
                )
                desc = FlextLdifUtilities.Parser._extract_regex_field(
                    attr_definition,
                    FlextLdifConstants.LdifPatterns.SCHEMA_DESC,
                )
                equality = FlextLdifUtilities.Parser._extract_regex_field(
                    attr_definition,
                    FlextLdifConstants.LdifPatterns.SCHEMA_EQUALITY,
                )
                substr = FlextLdifUtilities.Parser._extract_regex_field(
                    attr_definition,
                    FlextLdifConstants.LdifPatterns.SCHEMA_SUBSTR,
                )
                ordering = FlextLdifUtilities.Parser._extract_regex_field(
                    attr_definition,
                    FlextLdifConstants.LdifPatterns.SCHEMA_ORDERING,
                )
                sup = FlextLdifUtilities.Parser._extract_regex_field(
                    attr_definition,
                    FlextLdifConstants.LdifPatterns.SCHEMA_SUP,
                )
                usage = FlextLdifUtilities.Parser._extract_regex_field(
                    attr_definition,
                    FlextLdifConstants.LdifPatterns.SCHEMA_USAGE,
                )

                # Extract syntax and length using helper
                syntax, length = FlextLdifUtilities.Parser._extract_syntax_and_length(
                    attr_definition,
                    allow_syntax_quotes=allow_syntax_quotes,
                )

                # Validate syntax using helper
                syntax_validation_error = self._validate_syntax_oid(syntax)

                # Extract boolean flags
                single_value = (
                    re.search(
                        FlextLdifConstants.LdifPatterns.SCHEMA_SINGLE_VALUE,
                        attr_definition,
                    )
                    is not None
                )

                no_user_modification = False
                if case_insensitive:
                    no_user_modification = (
                        re.search(
                            FlextLdifConstants.LdifPatterns.SCHEMA_NO_USER_MODIFICATION,
                            attr_definition,
                        )
                        is not None
                    )

                # Build metadata using helper
                metadata = self._build_attribute_metadata(
                    attr_definition,
                    syntax,
                    syntax_validation_error,
                )

                attribute = FlextLdifModels.SchemaAttribute(
                    oid=oid,
                    name=name or oid,
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
            """Parse RFC 4512 objectClass definition (implements abstract method).

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                FlextResult with parsed SchemaObjectClass model

            """
            try:
                oid_match = re.match(
                    FlextLdifConstants.LdifPatterns.SCHEMA_OID_EXTRACTION,
                    oc_definition,
                )
                if not oid_match:
                    return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                        "RFC objectClass parsing failed: missing an OID",
                    )
                oid = oid_match.group(1)

                name_match = re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_NAME,
                    oc_definition,
                )
                name = name_match.group(1) if name_match else oid

                desc_match = re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_DESC,
                    oc_definition,
                )
                desc = desc_match.group(1) if desc_match else None

                sup = None
                sup_match = re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_OBJECTCLASS_SUP,
                    oc_definition,
                )
                if sup_match:
                    sup_value = sup_match.group(1) or sup_match.group(2)
                    sup_value = sup_value.strip()
                    if "$" in sup_value:
                        sup = next(s.strip() for s in sup_value.split("$"))
                    else:
                        sup = sup_value

                kind_match = re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_OBJECTCLASS_KIND,
                    oc_definition,
                    re.IGNORECASE,
                )
                if kind_match:
                    kind = kind_match.group(1).upper()
                else:
                    kind = FlextLdifConstants.Schema.STRUCTURAL

                must = None
                must_match = re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_OBJECTCLASS_MUST,
                    oc_definition,
                )
                if must_match:
                    must_value = must_match.group(1) or must_match.group(2)
                    must_value = must_value.strip()
                    if "$" in must_value:
                        must = [m.strip() for m in must_value.split("$")]
                    else:
                        must = [must_value]

                may = None
                may_match = re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_OBJECTCLASS_MAY,
                    oc_definition,
                )
                if may_match:
                    may_value = may_match.group(1) or may_match.group(2)
                    may_value = may_value.strip()
                    if "$" in may_value:
                        may = [m.strip() for m in may_value.split("$")]
                    else:
                        may = [may_value]

                from flext_ldif._utilities.parser import FlextLdifUtilitiesParser

                metadata_extensions = FlextLdifUtilitiesParser.extract_extensions(
                    oc_definition,
                )

                metadata_extensions[FlextLdifConstants.MetadataKeys.ORIGINAL_FORMAT] = (
                    oc_definition.strip()
                )

                metadata = (
                    FlextLdifModels.QuirkMetadata(
                        quirk_type="rfc",
                        extensions=metadata_extensions,
                    )
                    if metadata_extensions
                    else None
                )

                objectclass = FlextLdifModels.SchemaObjectClass(
                    oid=oid,
                    name=name,
                    desc=desc,
                    sup=sup,
                    kind=kind,
                    must=must,
                    may=may,
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

        # RFC 4512 Writing Helper Methods (Phase 5: Moved from _utilities/writer.py)
        # These methods implement RFC-compliant schema attribute and objectClass writing

        def _add_attribute_matching_rules(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
            parts: list[str],
        ) -> None:
            """Add matching rules to attribute parts list.

            Args:
                attr_data: SchemaAttribute model with matching rules
                parts: List to append matching rule strings to

            """
            if attr_data.equality:
                parts.append(f"EQUALITY {attr_data.equality}")
            if attr_data.ordering:
                parts.append(f"ORDERING {attr_data.ordering}")
            if attr_data.substr:
                parts.append(f"SUBSTR {attr_data.substr}")

        def _add_attribute_syntax(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
            parts: list[str],
        ) -> None:
            """Add syntax and length to attribute parts list.

            ARCHITECTURE: Writer ONLY formats data, does NOT transform
            Quirks are responsible for ensuring correct syntax format:
            - RFC/OUD quirks: ensure syntax has no quotes before calling writer
            - Writer preserves syntax value from model as-is

            Args:
                attr_data: SchemaAttribute model with syntax information
                parts: List to append syntax string to

            """
            if attr_data.syntax:
                # Format syntax as-is from model (quirks ensure correct format)
                syntax_str = str(attr_data.syntax)
                if attr_data.length is not None:
                    syntax_str += f"{{{attr_data.length}}}"
                parts.append(f"SYNTAX {syntax_str}")

        def _add_attribute_flags(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
            parts: list[str],
        ) -> None:
            """Add flags to attribute parts list.

            Args:
                attr_data: SchemaAttribute model with flags
                parts: List to append flag strings to

            """
            if attr_data.single_value:
                parts.append("SINGLE-VALUE")
            if attr_data.metadata and attr_data.metadata.extensions.get(
                FlextLdifConstants.MetadataKeys.COLLECTIVE,
            ):
                parts.append("COLLECTIVE")
            if attr_data.no_user_modification:
                parts.append("NO-USER-MODIFICATION")

        def _add_conditional_parts(
            self,
            parts: list[str],
            data: object,
            *,
            field_configs: list[tuple[str, str, str | None]],
        ) -> None:
            """Add conditional parts to list using DRY pattern (Python 3.13 optimized).

            Generic helper for reducing if-append duplication across schema builders.

            Args:
                parts: List to append formatted strings to
                data: Data object (SchemaAttribute or SchemaObjectClass)
                field_configs: List of (attr_name, keyword, quote) tuples
                    - attr_name: Attribute name on data object
                    - keyword: RFC keyword (e.g., "NAME", "DESC", "SUP")
                    - quote: Quote character ("'" for strings, None for no quotes)

            Example:
                self._add_conditional_parts(
                    parts,
                    attr_data,
                    field_configs=[
                        ("name", "NAME", "'"),
                        ("desc", "DESC", "'"),
                        ("sup", "SUP", None),
                    ],
                )

            """
            for attr_name, keyword, quote in field_configs:
                value = getattr(data, attr_name, None)
                if value:
                    if quote:
                        parts.append(f"{keyword} {quote}{value}{quote}")
                    else:
                        parts.append(f"{keyword} {value}")

        def _build_attribute_parts(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> list[str]:
            """Build RFC attribute definition parts.

            Args:
                attr_data: SchemaAttribute model to serialize

            Returns:
                List of RFC-compliant attribute definition parts

            """
            parts: list[str] = [f"( {attr_data.oid}"]

            # Add standard fields using DRY helper (Python 3.13 optimized)
            self._add_conditional_parts(
                parts,
                attr_data,
                field_configs=[
                    ("name", "NAME", "'"),
                    ("desc", "DESC", "'"),
                    ("sup", "SUP", None),
                    ("usage", "USAGE", None),
                ],
            )

            # Add OBSOLETE flag if present
            if attr_data.metadata and attr_data.metadata.extensions.get(
                FlextLdifConstants.MetadataKeys.OBSOLETE,
            ):
                parts.append("OBSOLETE")

            # Add matching rules, syntax, and flags
            self._add_attribute_matching_rules(attr_data, parts)
            self._add_attribute_syntax(attr_data, parts)
            self._add_attribute_flags(attr_data, parts)

            # Add X-ORIGIN extension if present
            if attr_data.metadata and attr_data.metadata.extensions.get("x_origin"):
                parts.append(
                    f"X-ORIGIN '{attr_data.metadata.extensions.get('x_origin')}'",
                )

            parts.append(")")
            return parts

        def _add_oc_must_may(
            self,
            parts: list[str],
            attr_list: str | list[str] | None,
            keyword: str,
        ) -> None:
            """Add MUST or MAY clause to objectClass definition parts.

            RFC-compliant implementation - passes attribute names as-is from Entry model.
            Server-specific normalization should happen in quirks layer during parsing.

            Args:
                parts: List to append MUST/MAY clause to
                attr_list: Single attribute name or list of attribute names
                keyword: Either "MUST" or "MAY"

            """
            if not attr_list:
                return

            if isinstance(attr_list, list):
                if len(attr_list) == 1:
                    parts.append(f"{keyword} {attr_list[0]}")
                else:
                    attrs_str = " $ ".join(attr_list)
                    parts.append(f"{keyword} ( {attrs_str} )")
            else:
                parts.append(f"{keyword} {attr_list}")

        def _build_objectclass_parts(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
        ) -> list[str]:
            """Build RFC objectClass definition parts.

            Args:
                oc_data: SchemaObjectClass model to serialize

            Returns:
                List of RFC-compliant objectClass definition parts

            """
            parts: list[str] = [f"( {oc_data.oid}"]

            # Add standard fields using DRY helper (Python 3.13 optimized)
            self._add_conditional_parts(
                parts,
                oc_data,
                field_configs=[
                    ("name", "NAME", "'"),
                    ("desc", "DESC", "'"),
                ],
            )

            # Add OBSOLETE flag if present
            if oc_data.metadata and oc_data.metadata.extensions.get(
                FlextLdifConstants.MetadataKeys.OBSOLETE,
            ):
                parts.append("OBSOLETE")

            # Handle SUP - can be single string or list (for multiple inheritance)
            if oc_data.sup:
                if isinstance(oc_data.sup, list):
                    # Multiple SUP values: format as ( value1 $ value2 $ ... )
                    sup_str = " $ ".join(oc_data.sup)
                    parts.append(f"SUP ( {sup_str} )")
                else:
                    # Single SUP value
                    parts.append(f"SUP {oc_data.sup}")

            kind = oc_data.kind or FlextLdifConstants.Schema.STRUCTURAL
            parts.append(str(kind))

            self._add_oc_must_may(parts, oc_data.must, "MUST")
            self._add_oc_must_may(parts, oc_data.may, "MAY")

            if oc_data.metadata and oc_data.metadata.extensions.get("x_origin"):
                parts.append(
                    f"X-ORIGIN '{oc_data.metadata.extensions.get('x_origin')}'",
                )

            parts.append(")")

            return parts

        def _write_attribute(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[str]:
            """Write attribute to RFC-compliant string format (internal).

            Args:
                attr_data: SchemaAttribute model

            Returns:
                FlextResult with RFC-compliant attribute string

            """
            # Validate input type
            if not isinstance(attr_data, FlextLdifModels.SchemaAttribute):
                return FlextResult[str].fail(
                    f"Invalid attribute type: expected SchemaAttribute, got {type(attr_data).__name__}",
                )

            # Check for original format in metadata (for perfect round-trip)
            if attr_data.metadata and attr_data.metadata.extensions.get(
                "original_format",
            ):
                original_str = cast(
                    "str",
                    attr_data.metadata.extensions.get("original_format", ""),
                )
                # If x_origin is in metadata but not in original_format, add it
                if (
                    attr_data.metadata.extensions.get("x_origin")
                    and ")" in original_str
                    and "X-ORIGIN" not in original_str
                ):
                    x_origin_str = (
                        f" X-ORIGIN '{attr_data.metadata.extensions.get('x_origin')}'"
                    )
                    original_str = original_str.rstrip(")") + x_origin_str + ")"
                return FlextResult[str].ok(original_str)

            # Transform attribute data using subclass hooks
            transformed_attr = self._transform_attribute_for_write(attr_data)

            # Write to RFC format using newly added helper methods (Phase 5)
            try:
                if not transformed_attr.oid:
                    return FlextResult[str].fail(
                        "RFC attribute writing failed: missing OID",
                    )

                parts = self._build_attribute_parts(transformed_attr)
                result = FlextResult[str].ok(" ".join(parts))
            except (ValueError, TypeError, AttributeError) as e:
                logger.exception("RFC attribute writing exception")
                return FlextResult[str].fail(f"RFC attribute writing failed: {e}")

            # Apply post-write transformations
            if result.is_success:
                written_str = result.unwrap()
                transformed_str = self._post_write_attribute(written_str)

                # Include extended attributes from metadata
                # Note: write_rfc_attribute already includes X-ORIGIN via _build_attribute_parts,
                # but we ensure it's present if metadata has x_origin and closing paren exists
                if (
                    transformed_attr.metadata
                    and transformed_attr.metadata.extensions.get("x_origin")
                    and ")" in transformed_str
                    and "X-ORIGIN" not in transformed_str
                ):
                    # Insert X-ORIGIN before closing paren if not already present
                    x_origin_str = f" X-ORIGIN '{transformed_attr.metadata.extensions.get('x_origin')}'"
                    transformed_str = transformed_str.rstrip(")") + x_origin_str + ")"

                return FlextResult[str].ok(transformed_str)

            return result

        def _write_objectclass(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[str]:
            """Write objectClass to RFC-compliant string format (internal).

            Args:
                oc_data: SchemaObjectClass model

            Returns:
                FlextResult with RFC-compliant objectClass string

            """
            # Validate input type
            if not isinstance(oc_data, FlextLdifModels.SchemaObjectClass):
                return FlextResult[str].fail(
                    f"Invalid objectClass type: expected SchemaObjectClass, got {type(oc_data).__name__}",
                )

            # Check for original format in metadata (for perfect round-trip)
            if oc_data.metadata and oc_data.metadata.extensions.get("original_format"):
                original_str = cast(
                    "str",
                    oc_data.metadata.extensions.get("original_format", ""),
                )
                # If x_origin is in metadata but not in original_format, add it
                # Support both field access (metadata.x_origin) and dict access (metadata.extensions["x_origin"])
                x_origin_value = None
                if hasattr(oc_data.metadata, "x_origin") and oc_data.metadata.x_origin:
                    x_origin_value = oc_data.metadata.x_origin
                elif oc_data.metadata.extensions.get("x_origin"):
                    x_origin_value = oc_data.metadata.extensions.get("x_origin")

                if (
                    x_origin_value
                    and ")" in original_str
                    and "X-ORIGIN" not in original_str
                ):
                    x_origin_str = f" X-ORIGIN '{x_origin_value}'"
                    original_str = original_str.rstrip(")") + x_origin_str + ")"
                return FlextResult[str].ok(original_str)

            # Transform objectClass data using subclass hooks
            transformed_oc = self._transform_objectclass_for_write(oc_data)

            # Write to RFC format using newly added helper methods (Phase 5)
            try:
                if not transformed_oc.oid:
                    return FlextResult[str].fail(
                        "RFC objectClass writing failed: missing OID",
                    )

                parts = self._build_objectclass_parts(transformed_oc)
                result = FlextResult[str].ok(" ".join(parts))
            except (ValueError, TypeError, AttributeError) as e:
                logger.exception("RFC objectClass writing exception")
                return FlextResult[str].fail(f"RFC objectClass writing failed: {e}")

            # Apply post-write transformations
            if result.is_success:
                written_str = result.unwrap()
                transformed_str = self._post_write_objectclass(written_str)

                # Include extended attributes from metadata
                # Support both field access (metadata.x_origin) and dict access (metadata.extensions["x_origin"])
                x_origin_value = None
                if transformed_oc.metadata:
                    # Try field access first (direct attribute)
                    if (
                        hasattr(transformed_oc.metadata, "x_origin")
                        and transformed_oc.metadata.x_origin
                    ):
                        x_origin_value = transformed_oc.metadata.x_origin
                    # Then try dict access (extensions)
                    elif transformed_oc.metadata.extensions.get("x_origin"):
                        x_origin_value = transformed_oc.metadata.extensions.get(
                            "x_origin"
                        )

                if x_origin_value and ")" in transformed_str:
                    # Insert X-ORIGIN before closing paren
                    x_origin_str = f" X-ORIGIN '{x_origin_value}'"
                    transformed_str = transformed_str.rstrip(")") + x_origin_str + ")"

                return FlextResult[str].ok(transformed_str)

            return result

        # =========================================================================
        # Automatic Routing Methods - Concrete implementations moved from base.py
        # =========================================================================

        def _detect_schema_type(
            self,
            definition: (
                str
                | FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
            ),
        ) -> str:
            """Detect schema type (attribute or objectclass) for automatic routing.

            Args:
                definition: Schema definition string or model.

            Returns:
                "attribute" or "objectclass".

            """
            if isinstance(definition, FlextLdifModels.SchemaAttribute):
                return "attribute"
            if isinstance(definition, FlextLdifModels.SchemaObjectClass):
                return "objectclass"
            # Try to detect from string content (definition is str at this point)
            definition_str = str(definition)
            definition_lower = definition_str.lower()

            # Check for objectClass-specific keywords (RFC 4512)
            # ObjectClasses have: STRUCTURAL, AUXILIARY, ABSTRACT, MUST, MAY
            # (Note: SUP is valid for both attributes and objectClasses, so excluded)
            # Attributes have: EQUALITY, SUBSTR, ORDERING, SYNTAX, USAGE, SINGLE-VALUE, NO-USER-MODIFICATION
            objectclass_only_keywords = [
                " structural",
                " auxiliary",
                " abstract",
                " must (",
                " may (",
            ]
            for keyword in objectclass_only_keywords:
                if keyword in definition_lower:
                    return "objectclass"

            # Check for attribute-specific keywords (more accurate detection)
            # These keywords ONLY appear in attribute definitions
            attribute_only_keywords = [
                " equality ",
                " substr ",
                " ordering ",
                " syntax ",
                " usage ",
                " single-value",
                " no-user-modification",
            ]
            for keyword in attribute_only_keywords:
                if keyword in definition_lower:
                    return "attribute"

            # Legacy check for explicit objectclass keyword
            if "objectclass" in definition_lower or "oclass" in definition_lower:
                return "objectclass"

            # Default to attribute if ambiguous
            return "attribute"

        def _route_parse(
            self,
            definition: str,
        ) -> (
            FlextResult[FlextLdifModels.SchemaAttribute]
            | FlextResult[FlextLdifModels.SchemaObjectClass]
        ):
            """Route schema definition to appropriate parse method.

            Automatically detects if definition is attribute or objectclass.

            Args:
                definition: Schema definition string.

            Returns:
                FlextResult with SchemaAttribute or SchemaObjectClass.

            """
            schema_type = self._detect_schema_type(definition)
            if schema_type == "objectclass":
                return self._parse_objectclass(definition)
            return self._parse_attribute(definition)

        def parse(
            self,
            definition: str,
        ) -> (
            FlextResult[FlextLdifModels.SchemaAttribute]
            | FlextResult[FlextLdifModels.SchemaObjectClass]
        ):
            """Parse schema definition (attribute or objectClass).

            Automatically routes to parse_attribute() or parse_objectclass() based on content.

            Args:
                definition: Schema definition string (attribute or objectClass)

            Returns:
                FlextResult with SchemaAttribute or SchemaObjectClass model

            """
            return self._route_parse(definition)

        def write(
            self,
            model: FlextLdifTypes.SchemaModel,
        ) -> FlextResult[str]:
            """Write schema model to RFC-compliant string.

            Automatically routes to _write_attribute() or _write_objectclass() based on model type.

            Args:
                model: SchemaAttribute or SchemaObjectClass model

            Returns:
                FlextResult with RFC-compliant definition string

            """
            if isinstance(model, FlextLdifModels.SchemaAttribute):
                return self._write_attribute(model)
            # isinstance narrowed to SchemaObjectClass by type checker
            return self._write_objectclass(model)

        def _route_write(
            self,
            model: FlextLdifTypes.SchemaModel,
        ) -> FlextResult[str]:
            """Route schema model to appropriate write method.

            Automatically detects model type and routes to correct write method.

            Args:
                model: SchemaAttribute or SchemaObjectClass model.

            Returns:
                FlextResult with string representation.

            """
            if isinstance(model, FlextLdifModels.SchemaAttribute):
                return self.write_attribute(model)
            # isinstance narrowed to SchemaObjectClass by type checker
            return self.write_objectclass(model)

        def _route_can_handle(
            self,
            definition: (
                str
                | FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
            ),
        ) -> bool:
            """Route can_handle check to appropriate method.

            Automatically detects type and routes to correct can_handle method.

            Args:
                definition: Schema definition string or model.

            Returns:
                True if quirk can handle this definition.

            """
            if isinstance(definition, FlextLdifModels.SchemaAttribute):
                return self.can_handle_attribute(definition)
            if isinstance(definition, FlextLdifModels.SchemaObjectClass):
                return self.can_handle_objectclass(definition)
            # For string definitions, try both methods
            schema_type = self._detect_schema_type(definition)
            if schema_type == "objectclass":
                return self.can_handle_objectclass(definition)
            return self.can_handle_attribute(definition)

        def _handle_parse_operation(
            self,
            attr_definition: str | None,
            oc_definition: str | None,
        ) -> FlextResult[FlextLdifTypes.SchemaModelOrString]:
            """Handle parse operation for schema quirk."""
            if attr_definition:
                attr_result = self.parse_attribute(attr_definition)
                if attr_result.is_success:
                    parsed_attr: FlextLdifModels.SchemaAttribute = attr_result.unwrap()
                    return FlextResult[
                        FlextLdifModels.SchemaAttribute
                        | FlextLdifModels.SchemaObjectClass
                        | str
                    ].ok(parsed_attr)
                error_msg: str = attr_result.error or "Parse attribute failed"
                return FlextResult[
                    FlextLdifModels.SchemaAttribute
                    | FlextLdifModels.SchemaObjectClass
                    | str
                ].fail(error_msg)
            if oc_definition:
                oc_result = self.parse_objectclass(oc_definition)
                if oc_result.is_success:
                    parsed_oc: FlextLdifModels.SchemaObjectClass = oc_result.unwrap()
                    return FlextResult[
                        FlextLdifModels.SchemaAttribute
                        | FlextLdifModels.SchemaObjectClass
                        | str
                    ].ok(parsed_oc)
                error_msg = oc_result.error or "Parse objectclass failed"
                return FlextResult[
                    FlextLdifModels.SchemaAttribute
                    | FlextLdifModels.SchemaObjectClass
                    | str
                ].fail(error_msg)
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].fail("No parse parameter provided")

        def _handle_write_operation(
            self,
            attr_model: FlextLdifModels.SchemaAttribute | None,
            oc_model: FlextLdifModels.SchemaObjectClass | None,
        ) -> FlextResult[FlextLdifTypes.SchemaModelOrString]:
            """Handle write operation for schema quirk."""
            if attr_model:
                write_result = self.write_attribute(attr_model)
                if write_result.is_success:
                    written_text: str = write_result.unwrap()
                    return FlextResult[
                        FlextLdifModels.SchemaAttribute
                        | FlextLdifModels.SchemaObjectClass
                        | str
                    ].ok(written_text)
                error_msg: str = write_result.error or "Write attribute failed"
                return FlextResult[
                    FlextLdifModels.SchemaAttribute
                    | FlextLdifModels.SchemaObjectClass
                    | str
                ].fail(error_msg)
            if oc_model:
                write_oc_result = self.write_objectclass(oc_model)
                if write_oc_result.is_success:
                    written_text = write_oc_result.unwrap()
                    return FlextResult[
                        FlextLdifModels.SchemaAttribute
                        | FlextLdifModels.SchemaObjectClass
                        | str
                    ].ok(written_text)
                error_msg = write_oc_result.error or "Write objectclass failed"
                return FlextResult[
                    FlextLdifModels.SchemaAttribute
                    | FlextLdifModels.SchemaObjectClass
                    | str
                ].fail(error_msg)
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].fail("No write parameter provided")

        def _auto_detect_operation(
            self,
            data: (
                str
                | FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | None
            ),
            operation: Literal["parse", "write"] | None,
        ) -> (
            Literal["parse", "write"]
            | FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ]
        ):
            """Auto-detect operation from data type. Returns operation or error result."""
            if operation is not None:
                return operation

            if isinstance(data, str):
                return "parse"
            if isinstance(
                data,
                (
                    FlextLdifModels.SchemaAttribute,
                    FlextLdifModels.SchemaObjectClass,
                ),
            ):
                return "write"

            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].fail(
                f"Unknown data type: {type(data).__name__}. Expected str, SchemaAttribute, or SchemaObjectClass",
            )

        def _route_operation(
            self,
            data: (
                str
                | FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
            ),
            operation: Literal["parse", "write"],
        ) -> FlextResult[FlextLdifTypes.SchemaModelOrString]:
            """Route data to appropriate parse or write handler."""
            if operation == "parse":
                if not isinstance(data, str):
                    return FlextResult[
                        FlextLdifModels.SchemaAttribute
                        | FlextLdifModels.SchemaObjectClass
                        | str
                    ].fail(f"parse operation requires str, got {type(data).__name__}")
                if self._detect_schema_type(data) == "objectclass":
                    return self._handle_parse_operation(
                        attr_definition=None,
                        oc_definition=data,
                    )
                return self._handle_parse_operation(
                    attr_definition=data,
                    oc_definition=None,
                )

            if operation == "write":
                if isinstance(data, FlextLdifModels.SchemaAttribute):
                    return self._handle_write_operation(attr_model=data, oc_model=None)
                if isinstance(data, FlextLdifModels.SchemaObjectClass):
                    return self._handle_write_operation(attr_model=None, oc_model=data)
                return FlextResult[
                    FlextLdifModels.SchemaAttribute
                    | FlextLdifModels.SchemaObjectClass
                    | str
                ].fail(
                    f"write operation requires SchemaAttribute or SchemaObjectClass, got {type(data).__name__}",
                )

            # Should not reach here (Literal type ensures only parse or write)
            msg = f"Unknown operation: {operation}"
            raise AssertionError(msg)

        def execute(
            self,
            data: (
                str
                | FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | None
            ) = None,
            operation: Literal["parse", "write"] | None = None,
            **_kwargs: object,
        ) -> FlextResult[FlextLdifTypes.SchemaModelOrString]:
            """Execute schema quirk operation with automatic type detection and routing.

            Fully automatic polymorphic dispatch based on data type:
            - str (schema definition) -> parse_attribute() OR parse_objectclass() -> SchemaAttribute OR SchemaObjectClass
            - SchemaAttribute (model) -> write_attribute() -> str
            - SchemaObjectClass (model) -> write_objectclass() -> str
            - None -> health check

            **V2 Usage - Maximum Automation:**
                >>> schema = FlextLdifServersRfc.Schema()
                >>> # Parse: pass schema definition string
                >>> attr = schema.execute(
                ...     "( 2.5.4.3 NAME 'cn' ...)"
                ... )  # -> SchemaAttribute
                >>> # Write: pass model
                >>> text = schema.execute(attr)  # -> str
                >>> # Auto-detect which type of schema definition
                >>> attr_or_oc = schema.execute("( 2.5.6.6 ... )")  # Detects & parses

            Args:
                data: Schema definition string OR SchemaAttribute OR SchemaObjectClass model
                      (operation auto-detected from type)
                operation: Force operation type (overrides auto-detection)

            Returns:
                FlextResult[SchemaAttribute | SchemaObjectClass | str] depending on operation

            """
            # Health check: no data provided
            if data is None:
                empty_str: str = ""
                return FlextResult[
                    FlextLdifModels.SchemaAttribute
                    | FlextLdifModels.SchemaObjectClass
                    | str
                ].ok(empty_str)

            # Auto-detect or validate operation
            detected_op = self._auto_detect_operation(data, operation)
            if isinstance(detected_op, FlextResult):
                return detected_op

            # Route to appropriate handler
            return self._route_operation(data, detected_op)

        @overload
        def __call__(
            self,
            attr_definition: str,
            *,
            oc_definition: None = None,
            attr_model: None = None,
            oc_model: None = None,
            operation: Literal["parse"] | None = None,
        ) -> FlextLdifTypes.SchemaModel: ...

        @overload
        def __call__(
            self,
            *,
            attr_definition: None = None,
            oc_definition: str,
            attr_model: None = None,
            oc_model: None = None,
            operation: Literal["parse"] | None = None,
        ) -> FlextLdifTypes.SchemaModel: ...

        @overload
        def __call__(
            self,
            *,
            attr_definition: None = None,
            oc_definition: None = None,
            attr_model: FlextLdifModels.SchemaAttribute,
            oc_model: None = None,
            operation: Literal["write"] | None = None,
        ) -> str: ...

        @overload
        def __call__(
            self,
            *,
            attr_definition: None = None,
            oc_definition: None = None,
            attr_model: None = None,
            oc_model: FlextLdifModels.SchemaObjectClass,
            operation: Literal["write"] | None = None,
        ) -> str: ...

        @overload
        def __call__(
            self,
            attr_definition: str | None = None,
            oc_definition: str | None = None,
            attr_model: FlextLdifModels.SchemaAttribute | None = None,
            oc_model: FlextLdifModels.SchemaObjectClass | None = None,
            operation: Literal["parse", "write"] | None = None,
        ) -> FlextLdifTypes.SchemaModelOrString: ...

        def __call__(
            self,
            attr_definition: str | None = None,
            oc_definition: str | None = None,
            attr_model: FlextLdifModels.SchemaAttribute | None = None,
            oc_model: FlextLdifModels.SchemaObjectClass | None = None,
            operation: Literal["parse", "write"] | None = None,
        ) -> FlextLdifTypes.SchemaModelOrString:
            """Callable interface - use as processor.

            Enables direct usage as processor:
                >>> schema = FlextLdifServersRfc.Schema()
                >>> attr = schema(attr_definition="( 2.5.4.3 NAME 'cn' ...)")  # Parse
                >>> text = schema(attr_model=attr)  # Write

            Args:
                attr_definition: Attribute definition to parse
                oc_definition: ObjectClass definition to parse
                attr_model: Attribute model to write
                oc_model: ObjectClass model to write
                operation: Explicit operation type

            Returns:
                Unwrapped result (SchemaAttribute, SchemaObjectClass, or str).

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
            schema_service: object | None = None,
            **kwargs: object,
        ) -> Self:
            """Override __new__ to support auto-execute and processor instantiation."""
            # Use object.__new__ to avoid calling parent's __new__ which also checks auto_execute
            # This prevents recursion when child class has auto_execute=True
            instance = object.__new__(cls)
            # Remove auto-execute kwargs before passing to __init__
            auto_execute_kwargs = {
                "attr_definition",
                "oc_definition",
                "attr_model",
                "oc_model",
                "operation",
            }
            init_kwargs = {
                k: v for k, v in kwargs.items() if k not in auto_execute_kwargs
            }
            # Initialize instance using proper type - Schema.__init__ accepts schema_service
            # Type narrowing: instance is Self (Schema subclass)
            schema_instance = cast("Self", instance)
            if schema_service is not None:
                schema_instance.__init__(schema_service=schema_service, **init_kwargs)
            else:
                schema_instance.__init__(**init_kwargs)

            if cls.auto_execute:
                attr_def = (
                    cast("str | None", kwargs.get("attr_definition"))
                    if "attr_definition" in kwargs
                    else None
                )
                oc_def = (
                    cast("str | None", kwargs.get("oc_definition"))
                    if "oc_definition" in kwargs
                    else None
                )
                attr_mod = (
                    cast(
                        "FlextLdifModels.SchemaAttribute | None",
                        kwargs.get("attr_model"),
                    )
                    if "attr_model" in kwargs
                    else None
                )
                oc_mod = (
                    cast(
                        "FlextLdifModels.SchemaObjectClass | None",
                        kwargs.get("oc_model"),
                    )
                    if "oc_model" in kwargs
                    else None
                )
                op = (
                    cast("Literal['parse'] | None", kwargs.get("operation"))
                    if "operation" in kwargs
                    else None
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
                schema_instance = cast("Self", instance)
                result = schema_instance.execute(data=data, operation=op)
                unwrapped: (
                    FlextLdifModels.SchemaAttribute
                    | FlextLdifModels.SchemaObjectClass
                    | str
                ) = result.unwrap()
                return cast("Self", unwrapped)

            return cast("Self", instance)

        def parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse attribute definition (public API).

            Delegates to _parse_attribute() for server-specific implementation.

            Args:
                attr_definition: Attribute definition string

            Returns:
                FlextResult with parsed SchemaAttribute model

            """
            return self._parse_attribute(attr_definition)

        def parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse objectClass definition (public API).

            Delegates to _parse_objectclass() for server-specific implementation.

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                FlextResult with parsed SchemaObjectClass model

            """
            return self._parse_objectclass(oc_definition)

        def write_attribute(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[str]:
            """Write attribute to RFC-compliant string format (public API).

            Delegates to _write_attribute() for server-specific implementation.

            Args:
                attr_data: SchemaAttribute model

            Returns:
                FlextResult with RFC-compliant attribute string

            """
            return self._write_attribute(attr_data)

        def write_objectclass(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[str]:
            """Write objectClass to RFC-compliant string format (public API).

            Delegates to _write_objectclass() for server-specific implementation.

            Args:
                oc_data: SchemaObjectClass model

            Returns:
                FlextResult with RFC-compliant objectClass string

            """
            return self._write_objectclass(oc_data)

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
            server_type = FlextLdifConstants.ServerTypes.GENERIC
            for cls in type(self).__mro__:
                # Check if this class has a Constants nested class
                if hasattr(cls, "Constants") and hasattr(cls.Constants, "SERVER_TYPE"):
                    server_type = cls.Constants.SERVER_TYPE
                    break

            # Build extensions with original_format
            all_extensions: dict[str, object] = {"original_format": original_format}
            if extensions:
                all_extensions.update(extensions)

            return FlextLdifModels.QuirkMetadata(
                quirk_type=server_type,
                extensions=all_extensions,
            )

        def extract_schemas_from_ldif(
            self,
            ldif_content: str,
            *,
            validate_dependencies: bool = False,
        ) -> FlextResult[dict[str, object]]:
            """Extract and parse all schema definitions from LDIF content (template method).

            Generic template method that consolidates schema extraction logic across all servers.
            Uses FlextLdifUtilities for parsing and provides hook for server-specific validation.

            This template method provides unified schema extraction logic,
            replacing duplicated implementations across multiple server quirk classes.

            Process:
                1. Extract attributes using FlextLdifUtilities.Schema
                2. If validate_dependencies: build available_attrs set and call validation hook
                3. Extract objectClasses using FlextLdifUtilities.Schema
                4. Return combined result

            Args:
                ldif_content: Raw LDIF content containing schema definitions
                validate_dependencies: If True, validate attribute dependencies before
                                     objectClass extraction (used by OUD for dep checking)

            Returns:
                FlextResult with dict containing:
                    - ATTRIBUTES: list[SchemaAttribute]
                    - OBJECTCLASS: list[SchemaObjectClass]

            Example Usage (OID - simple):
                result = self.extract_schemas_from_ldif(ldif_content)

            Example Usage (OUD - with validation):
                result = self.extract_schemas_from_ldif(
                    ldif_content,
                    validate_dependencies=True
                )

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
                return FlextResult[dict[str, object]].fail(
                    f"Schema extraction failed: {e}",
                )

        def _hook_validate_attributes(
            self,
            attributes: list[FlextLdifModels.SchemaAttribute],
            available_attrs: set[str],
        ) -> FlextResult[bool]:
            """Hook for server-specific attribute validation during schema extraction.

            Subclasses can override this to perform validation of attribute dependencies
            before objectClass extraction. This is called only when validate_dependencies=True.

            Default implementation: No validation (pass-through).

            Args:
                attributes: List of parsed SchemaAttribute models
                available_attrs: Set of lowercase attribute names available

            Returns:
                FlextResult[bool] with True on success, fail() on failure

            Example Override (in OUD):
                def _hook_validate_attributes(self, attributes, available_attrs):
                    # OUD-specific validation logic
                    for attr in attributes:
                        if attr.requires_dependency not in available_attrs:
                            return FlextResult.fail("Missing dependency")
                    return FlextResult.ok(True)

            """
            # Default: No validation needed
            _ = attributes
            _ = available_attrs
            return FlextResult[bool].ok(True)

    class Acl(FlextLdifServersBase.Acl):
        """RFC 4516 Compliant ACL Quirk - Base Implementation."""

        def __init__(self, acl_service: object | None = None, **kwargs: object) -> None:
            """Initialize RFC ACL quirk service.

            Args:
                acl_service: Injected FlextLdifAcl service (optional)
                **kwargs: Passed to parent class

            """
            super().__init__(acl_service=acl_service, **kwargs)

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

        def can_handle(self, acl_line: FlextLdifTypes.AclOrString) -> bool:
            """Check if this ACL is RFC-compliant.

            The RFC quirk assumes any ACL that has been successfully parsed into
            the Acl model is handleable.

            Args:
                acl_line: The ACL string or Acl model to check.

            Returns:
                True, as any parsed ACL is considered handleable.

            """
            _ = acl_line  # Unused - RFC handles all ACLs
            return True

        def can_handle_attribute(
            self,
            attribute: FlextLdifModels.SchemaAttribute,
        ) -> bool:
            """RFC ACL quirk does not handle attributes.

            Args:
                attribute: SchemaAttribute model (unused)

            Returns:
                False

            """
            _ = attribute  # Unused - ACL quirk doesn't handle attributes
            return False

        def can_handle_objectclass(
            self,
            objectclass: FlextLdifModels.SchemaObjectClass,
        ) -> bool:
            """RFC ACL quirk does not handle objectClasses.

            Args:
                objectclass: SchemaObjectClass model (unused)

            Returns:
                False

            """
            _ = objectclass  # Unused - ACL quirk doesn't handle objectClasses
            return False

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
                    f"ACL line must be a string, got {type(acl_line).__name__}"
                )
            if not acl_line or not acl_line.strip():
                return FlextResult.fail("ACL line must be a non-empty string.")

            # Get server type from the actual server class (not hardcoded "rfc")
            server_type_value = self._get_server_type()

            # RFC passthrough: store the raw line in the model.
            acl_model = FlextLdifModels.Acl(
                raw_acl=acl_line,
                server_type=cast(
                    "FlextLdifConstants.LiteralTypes.ServerType",
                    server_type_value,
                ),
                metadata=FlextLdifModels.QuirkMetadata(
                    quirk_type=server_type_value,
                    extensions={"original_format": acl_line},
                ),
            )
            return FlextResult.ok(acl_model)

        def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse RFC-compliant ACL line.

            Args:
                acl_line: The raw ACL string from the LDIF.

            Returns:
                A FlextResult containing the Acl model.

            """
            return self._parse_acl(acl_line)

        def create_metadata(
            self,
            original_format: str,
            extensions: dict[str, object] | None = None,
        ) -> FlextLdifModels.QuirkMetadata:
            """Create ACL quirk metadata."""
            all_extensions: dict[str, object] = {"original_format": original_format}
            if extensions:
                all_extensions.update(extensions)
            return FlextLdifModels.QuirkMetadata(
                quirk_type=self._get_server_type(),
                extensions=all_extensions,
            )

        # Nested Acl conversion methods eliminated - use universal parse/write pipeline

        def convert_rfc_acl_to_aci(
            self,
            rfc_acl_attrs: dict[str, list[str]],
            target_server: str,  # noqa: ARG002
        ) -> FlextResult[dict[str, list[str]]]:
            """Convert RFC ACL format to server-specific ACI format.

            RFC implementation: Pass-through (RFC ACLs are already in RFC format).

            Args:
                rfc_acl_attrs: ACL attributes in RFC format
                target_server: Target server type identifier (unused in RFC)

            Returns:
                FlextResult with same RFC ACL attributes (no conversion needed)

            """
            return FlextResult.ok(rfc_acl_attrs)

        def _write_acl(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write ACL to RFC-compliant string format (internal)."""
            # Use raw_acl if available and non-empty
            # Type guard: ensure raw_acl is a string
            if (
                acl_data.raw_acl
                and isinstance(acl_data.raw_acl, str)
                and acl_data.raw_acl.strip()
            ):
                return FlextResult[str].ok(acl_data.raw_acl)
            # If raw_acl is empty but name exists, return minimal ACL with name
            # Type guard: ensure name is a string
            if (
                acl_data.name
                and isinstance(acl_data.name, str)
                and acl_data.name.strip()
            ):
                return FlextResult[str].ok(f"{acl_data.name}:")
            # No valid data to write
            return FlextResult[str].fail("ACL has no raw_acl or name to write")

        # =====================================================================
        # Automatic Routing Methods - Concrete implementations moved from base.py
        # =====================================================================

        def _route_parse(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Route ACL parsing to parse method.

            Simplified wrapper for automatic routing.

            Args:
                acl_line: ACL line string.

            Returns:
                FlextResult with Acl model.

            """
            return self.parse(acl_line)

        def _route_write(self, acl_model: FlextLdifModels.Acl) -> FlextResult[str]:
            """Route ACL writing to write method.

            Simplified wrapper for automatic routing.

            Args:
                acl_model: Acl model.

            Returns:
                FlextResult with string representation.

            """
            return self.write(acl_model)

        def _handle_parse_acl(
            self,
            acl_line: str,
        ) -> FlextResult[FlextLdifModels.Acl | str]:
            """Handle parse operation for ACL quirk."""
            parse_acl_result = self._route_parse(acl_line)
            if parse_acl_result.is_success:
                parsed_acl: FlextLdifModels.Acl = parse_acl_result.unwrap()
                return FlextResult[FlextLdifModels.Acl | str].ok(parsed_acl)
            error_msg: str = parse_acl_result.error or "Parse ACL failed"
            return FlextResult[FlextLdifModels.Acl | str].fail(error_msg)

        def _handle_write_acl(
            self,
            acl_model: FlextLdifModels.Acl,
        ) -> FlextResult[FlextLdifModels.Acl | str]:
            """Handle write operation for ACL quirk."""
            write_result = self._route_write(acl_model)
            if write_result.is_success:
                written_text: str = write_result.unwrap()
                return FlextResult[FlextLdifModels.Acl | str].ok(written_text)
            error_msg: str = write_result.error or "Write ACL failed"
            return FlextResult[FlextLdifModels.Acl | str].fail(error_msg)

        def execute(
            self,
            data: str | FlextLdifModels.Acl | None = None,
            operation: Literal["parse", "write"] | None = None,
            **_kwargs: object,
        ) -> FlextResult[FlextLdifModels.Acl | str]:
            """Execute ACL quirk operation with automatic type detection and routing.

            Fully automatic polymorphic dispatch based on data type:
            - str (ACL line) -> parse_acl() -> Acl
            - Acl (model) -> write_acl() -> str
            - None -> health check

            **V2 Usage - Maximum Automation:**
                >>> acl = FlextLdifServersRfc.Acl()
                >>> # Parse: pass ACL line string
                >>> acl_model = acl.execute("(target=...)")  # -> Acl
                >>> # Write: pass model
                >>> acl_text = acl.execute(acl_model)  # -> str
                >>> # Or use as callable processor
                >>> acl_model = acl("(target=...)")  # Parse
                >>> acl_text = acl(acl_model)  # Write

            Args:
                data: ACL line string OR Acl model
                      (operation auto-detected from type)
                operation: Force operation type (overrides auto-detection)

            Returns:
                FlextResult[Acl | str] depending on operation

            """
            # Health check: no data provided
            if data is None:
                empty_acl: FlextLdifModels.Acl = FlextLdifModels.Acl()
                return FlextResult[FlextLdifModels.Acl | str].ok(empty_acl)

            # Auto-detect operation from data type, unless overridden
            detected_operation: Literal["parse", "write"] | None = operation

            if detected_operation is None:
                # Type-based auto-detection
                detected_operation = "parse" if isinstance(data, str) else "write"

            # Execute based on detected/forced operation
            if detected_operation == "parse":
                if not isinstance(data, str):
                    return FlextResult[FlextLdifModels.Acl | str].fail(
                        f"parse operation requires str, got {type(data).__name__}",
                    )
                # Route to parse_acl -> Acl
                return self._handle_parse_acl(data)

            # detected_operation == "write"
            if not isinstance(data, FlextLdifModels.Acl):
                return FlextResult[FlextLdifModels.Acl | str].fail(
                    f"write operation requires Acl, got {type(data).__name__}",
                )
            # Route to write_acl -> str
            return self._handle_write_acl(data)

        @overload
        def __call__(
            self,
            data: str,
            *,
            operation: Literal["parse"] | None = None,
        ) -> FlextLdifModels.Acl: ...

        @overload
        def __call__(
            self,
            data: FlextLdifModels.Acl,
            *,
            operation: Literal["write"] | None = None,
        ) -> str: ...

        @overload
        def __call__(
            self,
            data: str | FlextLdifModels.Acl | None = None,
            *,
            operation: Literal["parse", "write"] | None = None,
        ) -> FlextLdifModels.Acl | str: ...

        def __call__(
            self,
            data: str | FlextLdifModels.Acl | None = None,
            *,
            operation: Literal["parse", "write"] | None = None,
        ) -> FlextLdifModels.Acl | str:
            """Callable interface - automatic polymorphic processor.

            Pass ACL line string for parsing or Acl model for writing.
            Type auto-detection handles routing automatically.
            """
            result = self.execute(data=data, operation=operation)
            return result.unwrap()

        def __new__(cls, acl_service: object | None = None, **kwargs: object) -> Self:
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
                instance_type.__init__(instance, acl_service=acl_service, **init_kwargs)

            if cls.auto_execute:
                data = (
                    cast("str | FlextLdifModels.Acl | None", kwargs.get("data"))
                    if "data" in kwargs
                    else None
                )
                op = (
                    cast("Literal['parse', 'write'] | None", kwargs.get("operation"))
                    if "operation" in kwargs
                    else None
                )
                result = instance.execute(data=data, operation=op)
                unwrapped: FlextLdifModels.Acl | str = result.unwrap()
                return cast("Self", unwrapped)

            return instance

        def parse(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse ACL definition line.

            Routes to _parse_acl() internally.

            Args:
                acl_line: ACL definition string

            Returns:
                FlextResult with Acl model

            """
            return self._parse_acl(acl_line)

        def write(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write ACL data to RFC-compliant string format.

            Routes to _write_acl() internally.

            Args:
                acl_data: Acl model

            Returns:
                FlextResult with RFC-compliant ACL string

            """
            return self._write_acl(acl_data)

    class Entry(FlextLdifServersBase.Entry):
        """RFC 2849 Compliant Entry Quirk - Base Implementation."""

        def __init__(
            self,
            entry_service: object | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize RFC entry quirk service.

            Args:
                entry_service: Injected FlextLdifEntry service (optional)
                **kwargs: Passed to parent class

            """
            super().__init__(entry_service=entry_service, **kwargs)

        def _needs_base64_encoding(self, value: str) -> bool:
            """Check if a value needs base64 encoding per RFC 2849.

            RFC 2849 requires base64 encoding for values that:
            - Start with space, colon, or less-than
            - End with space
            - Contain control characters (< 0x20) except LF
            - Contain non-ASCII characters (>= 0x80)

            Args:
                value: Attribute value to check

            Returns:
                True if value needs base64 encoding, False otherwise

            """
            if not value:
                return False

            # Check first character (space, colon, less-than)
            if value[0] in (" ", ":", "<"):
                return True

            # Check last character (space)
            if value.endswith(" "):
                return True

            # Check for control characters (< 0x20) and non-ASCII (>= 0x80)
            for char in value:
                char_ord = ord(char)
                # Control characters (except LF which is 0x0A)
                if char_ord < 0x20 and char_ord != 0x0A:
                    return True
                # Non-ASCII
                if char_ord >= 0x80:
                    return True

            return False

        def can_handle(
            self,
            entry_dn: str,
            attributes: Mapping[str, object],
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
            """Check if this Entry quirk has special handling for an attribute definition.

            Entry processing doesn't change based on schema.

            Args:
                attribute: The SchemaAttribute model to check.

            Returns:
                False - RFC entry quirk doesn't have attribute-specific logic

            """
            _ = attribute  # Unused - Entry doesn't have attribute-specific logic
            return False

        def can_handle_objectclass(
            self,
            objectclass: FlextLdifModels.SchemaObjectClass,
        ) -> bool:
            """Check if this Entry quirk has special handling for an objectClass definition.

            Entry processing doesn't change based on objectClass.

            Args:
                objectclass: The SchemaObjectClass model to check.

            Returns:
                False - RFC entry quirk doesn't have objectClass-specific logic

            """
            _ = objectclass  # Unused - Entry doesn't have objectClass-specific logic
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

        def _parse_content(
            self,
            ldif_content: str,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Parse raw LDIF content string (implements abstract method)."""
            """Parse raw LDIF content string into Entry models.

            This is the PRIMARY interface - parser.py calls this with raw LDIF content.
            This method internally uses ldif3 to iterate and parse all entries.

            Implementation:
            1. Use ldif3.LDIFParser to parse LDIF content
            2. For each (dn, attrs) pair from ldif3:
               - Call parse_entry() to transform into Entry model
            3. Return list of all parsed entries

            Args:
                ldif_content: Raw LDIF content as string

            Returns:
                FlextResult with list of parsed Entry objects

            """
            try:
                entries: list[FlextLdifModels.Entry] = []

                # Handle empty/whitespace-only content gracefully
                if not ldif_content.strip():
                    return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

                # Use shared RFC 2849-compliant LDIF parser from FlextLdifUtilities
                parsed_entries = FlextLdifUtilities.Parser.parse_ldif_lines(
                    ldif_content,
                )

                # Convert parsed (dn, attrs) tuples to Entry models
                for dn, attrs in parsed_entries:
                    entry_result = self._parse_entry(dn, attrs)
                    if entry_result.is_success:
                        entries.append(entry_result.unwrap())

                return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

            except (ValueError, TypeError, AttributeError, OSError, Exception) as e:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Failed to parse LDIF content: {e}",
                )

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
            if not attr_name:
                return attr_name
            # Normalize objectclass variants to canonical objectClass
            if attr_name.lower() == "objectclass":
                return FlextLdifConstants.DictKeys.OBJECTCLASS
            # Other attributes: preserve as-is (cn, mail, uid, etc.)
            return attr_name

        def _parse_entry(
            self,
            entry_dn: str,
            entry_attrs: Mapping[str, object],
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Parse raw LDIF entry data into Entry model (internal).

            Converts raw LDIF parser output (dict with bytes values) into
            an Entry model with string attributes. This is the boundary method
            that converts raw parser data to Entry models - all subsequent
            processing uses Entry models.

            RFC 2849 Compliance: Attribute names are normalized to canonical form
            to ensure case-insensitive matching works correctly.

            Args:
                entry_dn: Raw DN string from LDIF parser
                entry_attrs: Raw attributes mapping from LDIF parser (may contain bytes values)

            Returns:
                FlextResult with parsed Entry model (ready for process_entry)

            """
            try:
                # Clean/normalize DN using DN utility
                cleaned_dn = FlextLdifUtilities.DN.clean_dn(entry_dn)

                # Convert raw attributes to dict[str, list[str]] format
                # Handle bytes values from ldif3 parser
                # RFC 2849 COMPLIANCE: Normalize attribute names to canonical form
                converted_attrs: dict[str, list[str]] = {}
                for attr_name, attr_values in entry_attrs.items():
                    # Normalize attribute name to canonical case (RFC 2849 case-insensitive)
                    canonical_attr_name = self._normalize_attribute_name(attr_name)

                    # Convert values to strings
                    string_values: list[str] = []
                    if isinstance(attr_values, list):
                        string_values = [
                            (
                                value.decode("utf-8", errors="replace")
                                if isinstance(value, bytes)
                                else str(value)
                            )
                            for value in attr_values
                        ]
                    elif isinstance(attr_values, bytes):
                        string_values = [
                            attr_values.decode("utf-8", errors="replace"),
                        ]
                    else:
                        string_values = [str(attr_values)]

                    # RFC 2849: If attribute already exists (case-insensitive), append values
                    # This handles cases where LDIF has both "objectclass: top" and "objectClass: person"
                    if canonical_attr_name in converted_attrs:
                        converted_attrs[canonical_attr_name].extend(string_values)
                    else:
                        converted_attrs[canonical_attr_name] = string_values

                # Check if DN was base64-encoded (parser sets _base64_dn flag)
                dn_was_base64 = converted_attrs.pop("_base64_dn", None) is not None

                # Create LdifAttributes directly from converted_attrs
                # converted_attrs now has normalized attribute names (_base64_dn removed)
                ldif_attrs = FlextLdifModels.LdifAttributes(attributes=converted_attrs)

                # Create DistinguishedName with metadata if it was base64-encoded
                if dn_was_base64:
                    # Preserve RFC 2849 base64 indicator for round-trip
                    dn_obj = FlextLdifModels.DistinguishedName(
                        value=cleaned_dn,
                        metadata={"original_format": "base64"},
                    )
                else:
                    # Entry.create will coerce string to DistinguishedName
                    dn_obj = cast("FlextLdifModels.DistinguishedName", cleaned_dn)

                # Create Entry model using Entry.create factory method
                # This ensures proper validation and model construction
                # dn_obj is DistinguishedName which is compatible with str | DistinguishedName
                entry_result = FlextLdifModels.Entry.create(
                    dn=cast("str | FlextLdifModels.DistinguishedName", dn_obj),
                    attributes=ldif_attrs,
                )

                if entry_result.is_failure:
                    return FlextResult[FlextLdifModels.Entry].fail(
                        f"Failed to create Entry model: {entry_result.error}",
                    )

                # Get the Entry model - no additional processing needed
                # Entry model is already in RFC format with proper metadata
                entry_model = entry_result.unwrap()
                return FlextResult[FlextLdifModels.Entry].ok(
                    cast("FlextLdifModels.Entry", entry_model),
                )

            except Exception as e:
                _ = logger.exception("RFC entry parsing exception")
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to parse entry: {e}",
                )

        def _write_entry_comments_dn(
            self,
            ldif_lines: list[str],
            entry_data: FlextLdifModels.Entry,
            write_options: FlextLdifModels.WriteFormatOptions,
        ) -> None:
            """Add DN comment if requested."""
            if write_options.include_dn_comments:
                dn_value = entry_data.dn.value if entry_data.dn else ""
                ldif_lines.append(f"# Complex DN: {dn_value}")

        def _write_entry_comments_metadata(
            self,
            ldif_lines: list[str],
            entry_data: FlextLdifModels.Entry,
            write_options: FlextLdifModels.WriteFormatOptions,
        ) -> None:
            """Add metadata comments if requested."""
            if not (write_options.write_metadata_as_comments and entry_data.metadata):
                return
            ldif_lines.append("# Entry Metadata:")

            # Add server type
            if entry_data.metadata.extensions.get("server_type"):
                ldif_lines.append(
                    f"# Server Type: {entry_data.metadata.extensions.get('server_type')}",
                )

            # Add parsed timestamp
            if entry_data.metadata.extensions.get("parsed_timestamp"):
                ldif_lines.append(
                    f"# Parsed: {entry_data.metadata.extensions.get('parsed_timestamp')}",
                )

            # Add source file if available in extensions
            # extensions has default_factory=dict, so it should never be None
            if entry_data.metadata.extensions and (
                source_file := entry_data.metadata.extensions.get("source_file")
            ):
                ldif_lines.append(f"# Source File: {source_file}")

            # Add quirk type if available
            if entry_data.metadata.quirk_type:
                ldif_lines.append(
                    f"# Quirk Type: {entry_data.metadata.quirk_type}",
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
            if isinstance(attr_values, list):
                ldif_lines.extend(f"# {attr_name}: {value}" for value in attr_values)
            else:
                ldif_lines.append(f"# {attr_name}: {attr_values}")
            return True

        def _get_hidden_attributes(
            self,
            entry_data: FlextLdifModels.Entry,
            write_options: FlextLdifModels.WriteFormatOptions,
        ) -> set[str]:
            """Extract hidden attributes from metadata if requested."""
            if (
                not write_options.write_hidden_attributes_as_comments
                or not entry_data.metadata
            ):
                return set()
            # extensions has default_factory=dict, so it should never be None
            if not entry_data.metadata.extensions:
                return set()
            hidden_list = entry_data.metadata.extensions.get("hidden_attributes")
            return set(hidden_list) if isinstance(hidden_list, list) else set()

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
            if base64_enabled and FlextLdifUtilities.Writer.needs_base64_encoding(value):
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
            """Process and write all entry attributes."""
            if not (entry_data.attributes and entry_data.attributes.attributes):
                return
            for attr_name, attr_values in entry_data.attributes.attributes.items():
                # Write hidden attributes as comments if requested
                if self._write_entry_hidden_attrs(
                    ldif_lines,
                    attr_name,
                    attr_values,
                    hidden_attrs,
                ):
                    continue

                # Write normal attributes
                if isinstance(attr_values, list):
                    for value in attr_values:
                        self._write_entry_attribute_value(
                            ldif_lines,
                            attr_name,
                            value,
                            write_options,
                        )
                elif attr_values:
                    # Single non-list value
                    # CORRECT: Ensure value is string for RFC 2849 compliance
                    str_value = (
                        str(attr_values)
                        if not isinstance(attr_values, str)
                        else attr_values
                    )
                    # Use _write_entry_attribute_value to ensure proper RFC 2849 encoding
                    self._write_entry_attribute_value(
                        ldif_lines,
                        attr_name,
                        str_value,
                        write_options,
                    )

        def _write_entry(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextResult[str]:
            """Write Entry model to RFC-compliant LDIF string format (internal).

            Converts Entry model to LDIF format per RFC 2849, with support for
            WriteFormatOptions stored in entry_metadata["_write_options"].

            Supports LDIF modify format when ldif_changetype="modify" is specified
            in WriteFormatOptions (RFC 2849 § 4 - Change Records).

            Args:
                entry_data: Entry model to write

            Returns:
                FlextResult with RFC-compliant LDIF string

            """
            try:
                # RFC Compliance: Extract WriteFormatOptions from metadata.write_options
                write_options: FlextLdifModels.WriteFormatOptions | None = None
                if entry_data.metadata.write_options:
                    write_options_obj = entry_data.metadata.write_options.get(
                        "_write_options"
                    )
                    if isinstance(
                        write_options_obj,
                        FlextLdifModels.WriteFormatOptions,
                    ):
                        write_options = write_options_obj

                # Check if LDIF modify format requested
                # Also use modify format if entry has no attributes (RFC 2849 § 4)
                use_modify_format = (
                    write_options and write_options.ldif_changetype == "modify"
                ) or (not entry_data.attributes or not entry_data.attributes.attributes)

                if use_modify_format:
                    # Create default write_options if not provided
                    if write_options is None:
                        write_options = FlextLdifModels.WriteFormatOptions()
                    return self._write_entry_modify_format(entry_data, write_options)

                # Standard ADD format (RFC 2849 § 3)
                return self._write_entry_add_format(entry_data, write_options)

            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult[str].fail(
                    f"Failed to write entry to LDIF: {e}",
                )

        # =====================================================================
        # Automatic Routing Methods - Concrete implementations moved from base.py
        # =====================================================================

        def parse(self, ldif_text: str) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Parse LDIF content string to Entry models.

            Routes to _parse_content() internally.

            Args:
                ldif_text: LDIF content string

            Returns:
                FlextResult with list of Entry models

            """
            return self._parse_content(ldif_text)

        def normalize_entry_dn(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextLdifModels.Entry:
            """Normalize DN formatting to RFC 4514 standard.

            Args:
                entry: Entry with DN to normalize

            Returns:
                Entry with normalized DN

            """
            if not entry.dn:
                return entry

            dn_str = str(entry.dn.value)
            norm_result = FlextLdifUtilities.DN.norm(dn_str)

            if not norm_result.is_success:
                normalized_str = FlextLdifUtilities.DN.clean_dn(dn_str)
            else:
                normalized_str = norm_result.unwrap()

            normalized_dn = FlextLdifModels.DistinguishedName(value=normalized_str)
            return entry.model_copy(update={"dn": normalized_dn})

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
                entry, strict=False
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
                    )
                }
            )

        def generate_entry_comments(
            self,
            entry: FlextLdifModels.Entry,
            format_options: FlextLdifModels.WriteFormatOptions,
        ) -> str:
            """Generate LDIF comments for removed attributes and rejection reasons.

            Comments are written BEFORE the entry to document:
            - Attributes that were removed during migration (with original values)
            - Rejection reasons if entry was rejected

            Args:
                entry: Entry to generate comments for
                format_options: Write format options controlling comment generation

            Returns:
                String containing comment lines (with trailing newline if non-empty)

            """
            comment_lines: list[str] = []

            # Add rejection reason comments if enabled
            if (
                format_options.write_rejection_reasons
                and entry.metadata.processing_stats
            ):
                rejection_reason = entry.metadata.processing_stats.rejection_reason
                if rejection_reason:
                    comment_lines.extend([
                        FlextLdifConstants.CommentFormats.SEPARATOR_DOUBLE,
                        FlextLdifConstants.CommentFormats.HEADER_REJECTION_REASON,
                        FlextLdifConstants.CommentFormats.SEPARATOR_DOUBLE,
                        f"{FlextLdifConstants.CommentFormats.PREFIX_COMMENT}{rejection_reason}",
                        FlextLdifConstants.CommentFormats.SEPARATOR_EMPTY,
                    ])

            # Add removed attributes comments if enabled
            if (
                format_options.write_removed_attributes_as_comments
                and entry.metadata.removed_attributes
            ):
                removed_attrs = entry.metadata.removed_attributes
                if removed_attrs and isinstance(removed_attrs, dict):
                    if comment_lines:
                        comment_lines.append(
                            FlextLdifConstants.CommentFormats.SEPARATOR_EMPTY,
                        )
                    comment_lines.extend([
                        FlextLdifConstants.CommentFormats.SEPARATOR_SINGLE,
                        FlextLdifConstants.CommentFormats.HEADER_REMOVED_ATTRIBUTES,
                        FlextLdifConstants.CommentFormats.SEPARATOR_SINGLE,
                    ])
                    # Python 3.13: Optimize with nested list comprehension
                    comment_lines.extend([
                        f"{FlextLdifConstants.CommentFormats.PREFIX_COMMENT}{attr_name}: {value}"
                        for attr_name, attr_values in removed_attrs.items()
                        for value in (
                            attr_values
                            if isinstance(attr_values, list)
                            else [attr_values]
                        )
                    ])
                    comment_lines.append(
                        FlextLdifConstants.CommentFormats.SEPARATOR_EMPTY,
                    )

            return "\n".join(comment_lines) + "\n" if comment_lines else ""

        def format_entry_for_write(
            self,
            entry: FlextLdifModels.Entry,
            format_options: FlextLdifModels.WriteFormatOptions,
        ) -> FlextLdifModels.Entry:
            """Format entry for writing using quirk-specific logic.

            This method applies server-specific formatting/normalization
            before the entry is written. Delegates to quirks for all
            transformations.

            Args:
                entry: Entry to format
                format_options: Write format options

            Returns:
                Formatted entry ready for writing

            """
            # RFC base: Only normalize attribute names if requested
            if not format_options.normalize_attribute_names:
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
                    "attributes": FlextLdifModels.LdifAttributes(attributes=new_attrs)
                }
            )

        def write(self, entry: FlextLdifModels.Entry) -> FlextResult[str]:
            """Write single Entry model to LDIF string.

            Routes to _write_entry() internally.

            Args:
                entry: Entry model to write

            Returns:
                FlextResult with LDIF string

            """
            return self._write_entry(entry)

        def _route_parse(
            self,
            ldif_text: str,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Route LDIF parsing to parse method.

            Simplified wrapper for automatic routing.

            Args:
                ldif_text: LDIF content string.

            Returns:
                FlextResult with list of Entry models.

            """
            return self.parse(ldif_text)

        def _route_write(self, entry: FlextLdifModels.Entry) -> FlextResult[str]:
            """Route entry writing to write method.

            Simplified wrapper for automatic routing.

            Args:
                entry: Entry model.

            Returns:
                FlextResult with string representation.

            """
            return self.write(entry)

        def _route_write_many(
            self,
            entries: list[FlextLdifModels.Entry],
        ) -> FlextResult[str]:
            """Route multiple entries writing.

            Writes each entry and combines results.

            Args:
                entries: List of Entry models.

            Returns:
                FlextResult with combined LDIF string.

            """
            ldif_lines: list[str] = []
            for entry in entries:
                result = self._route_write(entry)
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
        ) -> FlextResult[FlextLdifModels.Entry | str | list[FlextLdifModels.Entry]]:
            """Handle parse operation for entry quirk."""
            parse_result = self._route_parse(ldif_text)
            if parse_result.is_success:
                parsed_entries: list[FlextLdifModels.Entry] = parse_result.unwrap()
                if len(parsed_entries) == 1:
                    return FlextResult[
                        FlextLdifModels.Entry | str | list[FlextLdifModels.Entry]
                    ].ok(parsed_entries[0])
                if len(parsed_entries) == 0:
                    return FlextResult[
                        FlextLdifModels.Entry | str | list[FlextLdifModels.Entry]
                    ].ok("")
                return FlextResult[
                    FlextLdifModels.Entry | str | list[FlextLdifModels.Entry]
                ].ok(parsed_entries)
            error_msg: str = parse_result.error or "Parse failed"
            return FlextResult[
                FlextLdifModels.Entry | str | list[FlextLdifModels.Entry]
            ].fail(error_msg)

        def _handle_write_entry(
            self,
            entries_to_write: list[FlextLdifModels.Entry],
        ) -> FlextResult[FlextLdifModels.Entry | str | list[FlextLdifModels.Entry]]:
            """Handle write operation for entry quirk."""
            write_result = self._route_write_many(entries_to_write)
            if write_result.is_success:
                written_text: str = write_result.unwrap()
                return FlextResult[
                    FlextLdifModels.Entry | str | list[FlextLdifModels.Entry]
                ].ok(written_text)
            error_msg: str = write_result.error or "Write failed"
            return FlextResult[
                FlextLdifModels.Entry | str | list[FlextLdifModels.Entry]
            ].fail(error_msg)

        def _auto_detect_entry_operation(
            self,
            data: str | list[FlextLdifModels.Entry],
            operation: Literal["parse", "write"] | None,
        ) -> (
            Literal["parse", "write"]
            | FlextResult[FlextLdifModels.Entry | str | list[FlextLdifModels.Entry]]
        ):
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

            # data is list[Entry] at this point (type checker narrowed from str | list[Entry])
            if not data:
                return "write"

            # Validate that all items in list are Entry models
            for item in data:
                if not isinstance(item, FlextLdifModels.Entry):
                    return FlextResult[
                        FlextLdifModels.Entry | str | list[FlextLdifModels.Entry]
                    ].fail(
                        f"list contains unknown types, not Entry models: {[type(item).__name__ for item in data[:3]]}",
                    )

            return "write"

        def _route_entry_operation(
            self,
            data: str | list[FlextLdifModels.Entry],
            operation: Literal["parse", "write"],
        ) -> FlextResult[FlextLdifModels.Entry | str | list[FlextLdifModels.Entry]]:
            """Route entry data to appropriate parse or write handler.

            Validates data type matches operation, then delegates to handler.

            """
            if operation == "parse":
                if not isinstance(data, str):
                    return FlextResult[
                        FlextLdifModels.Entry | str | list[FlextLdifModels.Entry]
                    ].fail(
                        f"parse operation requires str, got {type(data).__name__}",
                    )
                return self._handle_parse_entry(data)

            if operation == "write":
                if not isinstance(data, list):
                    return FlextResult[
                        FlextLdifModels.Entry | str | list[FlextLdifModels.Entry]
                    ].fail(
                        f"write operation requires list[Entry], got {type(data).__name__}",
                    )
                return self._handle_write_entry(data)

            # Should not reach here (Literal type ensures only parse or write)
            msg = f"Unknown operation: {operation}"
            raise AssertionError(msg)

        # NOTE: This method extends FlextService.execute() with parameters for entry operations.
        # It is NOT an override - it's a method extension that supports polymorphic dispatch
        # for entry quirks. The base FlextService.execute() has no parameters, but entry quirks
        # need parameters for parse/write operations. This is an architectural extension.
        # Do NOT use @override decorator as this is an extension, not an override.
        def execute(
            self,
            data: str | list[FlextLdifModels.Entry] | None = None,
            operation: Literal["parse", "write"] | None = None,
            **_kwargs: object,
        ) -> FlextResult[FlextLdifModels.Entry | str | list[FlextLdifModels.Entry]]:
            r"""Execute entry quirk operation with automatic type detection and routing.

            Fully automatic polymorphic dispatch based on data type:
            - str (LDIF content) -> parse_content() -> list[Entry]
            - list[Entry] (models) -> write_entry() for each -> str (LDIF)
            - None -> health check

            **V2 Usage as Processor - Maximum Automation:**
                >>> entry = FlextLdifServersRfc.Entry()
                >>> # Parse: pass LDIF string
                >>> entries = entry.execute("dn: cn=test\n...")
                >>> # Write: pass Entry list
                >>> ldif = entry.execute([entry1, entry2])
                >>> # Or use as callable processor
                >>> entries = entry("dn: cn=test\n...")  # Parse
                >>> ldif = entry([entry1, entry2])  # Write

            Args:
                data: LDIF content string OR list of Entry models
                      (operation auto-detected from type)
                operation: Force operation type (overrides auto-detection)

            Returns:
                FlextResult[list[Entry] | str] depending on operation
                - When operation="parse": returns list[Entry]
                - When operation="write": returns str
                - When operation=None: auto-detects and returns appropriate type

            Raises:
                Returns fail() if data type is unknown or operation fails

            """
            # Health check: no data provided
            if data is None:
                return FlextResult[
                    FlextLdifModels.Entry | str | list[FlextLdifModels.Entry]
                ].ok("")

            # Auto-detect operation from data type
            detected_operation = self._auto_detect_entry_operation(data, operation)
            if isinstance(detected_operation, FlextResult):
                return detected_operation

            # When operation="parse" is explicitly specified, return list directly
            if detected_operation == "parse" and operation == "parse":
                if not isinstance(data, str):
                    return FlextResult[
                        FlextLdifModels.Entry | str | list[FlextLdifModels.Entry]
                    ].fail(
                        f"parse operation requires str, got {type(data).__name__}",
                    )
                parse_result = self._route_parse(data)
                if parse_result.is_success:
                    return FlextResult[
                        FlextLdifModels.Entry | str | list[FlextLdifModels.Entry]
                    ].ok(parse_result.unwrap())
                # Convert failure result to match return type
                return FlextResult[
                    FlextLdifModels.Entry | str | list[FlextLdifModels.Entry]
                ].fail(parse_result.error or "Unknown error")

            # Route to appropriate handler
            return self._route_entry_operation(data, detected_operation)

        @overload
        def __call__(
            self,
            data: str,
            *,
            operation: Literal["parse"] | None = None,
        ) -> FlextLdifTypes.EntryOrString: ...

        @overload
        def __call__(
            self,
            data: list[FlextLdifModels.Entry],
            *,
            operation: Literal["write"] | None = None,
        ) -> str: ...

        @overload
        def __call__(
            self,
            data: str | list[FlextLdifModels.Entry] | None = None,
            *,
            operation: Literal["parse", "write"] | None = None,
        ) -> FlextLdifTypes.EntryOrString: ...

        def __call__(
            self,
            data: str | list[FlextLdifModels.Entry] | None = None,
            *,
            operation: Literal["parse", "write"] | None = None,
        ) -> FlextLdifTypes.EntryOrString:
            """Callable interface - automatic polymorphic processor.

            Pass LDIF string for parsing or Entry list for writing.
            Type auto-detection handles routing automatically.
            """
            result = self.execute(data=data, operation=operation)
            return result.unwrap()

        def __new__(cls, entry_service: object | None = None, **kwargs: object) -> Self:
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
                    instance, entry_service=entry_service, **init_kwargs
                )

            if cls.auto_execute:
                ldif_txt = (
                    cast("str | None", kwargs.get("ldif_text"))
                    if "ldif_text" in kwargs
                    else None
                )
                ent = (
                    cast("FlextLdifModels.Entry | None", kwargs.get("entry"))
                    if "entry" in kwargs
                    else None
                )
                ents = (
                    cast("list[FlextLdifModels.Entry] | None", kwargs.get("entries"))
                    if "entries" in kwargs
                    else None
                )
                op = (
                    cast("Literal['parse', 'write'] | None", kwargs.get("operation"))
                    if "operation" in kwargs
                    else None
                )
                # Entry.execute() expects 'data' parameter (str | list[Entry] | None)
                data: str | list[FlextLdifModels.Entry] | None = None
                if ldif_txt is not None:
                    data = ldif_txt
                elif ents is not None:
                    data = ents
                elif ent is not None:
                    data = [ent]
                result = instance.execute(data=data, operation=op)
                unwrapped: FlextLdifTypes.EntryOrString = result.unwrap()
                return cast("Self", unwrapped)

            return instance

        def parse_entry(
            self,
            entry_dn: str,
            entry_attrs: Mapping[str, object],
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
                return FlextResult[FlextLdifModels.Entry].fail("DN is None or empty")

            # Convert attributes to FlextLdifModels.LdifAttributes
            attrs_result = FlextLdifModels.LdifAttributes.create(dict(entry_attrs))
            if not attrs_result.is_success:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to create LdifAttributes: {attrs_result.error}",
                )
            converted_attrs = attrs_result.unwrap()

            # Create DistinguishedName object from DN string
            dn_obj = FlextLdifModels.DistinguishedName(value=entry_dn)

            # Create Entry model with defaults
            # dn_obj is DistinguishedName which is compatible with str | DistinguishedName
            entry_result = FlextLdifModels.Entry.create(
                dn=cast("str | FlextLdifModels.DistinguishedName", dn_obj),
                attributes=converted_attrs,
            )
            if entry_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to create Entry: {entry_result.error}",
                )
            entry = entry_result.unwrap()

            return FlextResult[FlextLdifModels.Entry].ok(
                cast("FlextLdifModels.Entry", entry),
            )

        def _write_entry_add_format(
            self,
            entry_data: FlextLdifModels.Entry,
            write_options: FlextLdifModels.WriteFormatOptions | None,
        ) -> FlextResult[str]:
            """Write Entry in standard ADD format (default RFC 2849 format).

            Args:
                entry_data: Entry model to write
                write_options: Optional formatting options

            Returns:
                FlextResult with LDIF string in ADD format

            """
            # Build LDIF string from Entry model
            ldif_lines: list[str] = []

            # Add DN comment if requested
            if write_options:
                self._write_entry_comments_dn(ldif_lines, entry_data, write_options)

            # DN line (required)
            if not (entry_data.dn and entry_data.dn.value):
                return FlextResult[str].fail("Entry DN is required for LDIF output")
            ldif_lines.append(f"dn: {entry_data.dn.value}")

            # RFC 2849: Only include changetype if entry has it
            # Content records (no changetype) vs Change records (with changetype)
            if (
                entry_data.attributes
                and "changetype" in entry_data.attributes.attributes
            ):
                changetype_values = entry_data.attributes.attributes["changetype"]
                if changetype_values:
                    ldif_lines.append(f"changetype: {changetype_values[0]}")

            # Add metadata comments if requested
            if write_options:
                self._write_entry_comments_metadata(
                    ldif_lines,
                    entry_data,
                    write_options,
                )

            # Get hidden attributes if needed
            hidden_attrs = (
                self._get_hidden_attributes(entry_data, write_options)
                if write_options
                else set()
            )

            # RFC 2849: changetype is not a regular attribute - hide it from attribute processing
            # It was already written above if present
            hidden_attrs.add("changetype")

            # Process attributes
            self._write_entry_process_attributes(
                ldif_lines,
                entry_data,
                hidden_attrs,
                write_options,
            )

            # Join with newlines and ensure proper LDIF formatting
            ldif_text = "\n".join(ldif_lines)
            if ldif_text and not ldif_text.endswith("\n"):
                ldif_text += "\n"

            return FlextResult[str].ok(ldif_text)

        def _write_entry_modify_format(
            self,
            entry_data: FlextLdifModels.Entry,
            _write_options: FlextLdifModels.WriteFormatOptions,
        ) -> FlextResult[str]:
            """Write Entry in LDIF modify format (RFC 2849 § 4 - Change Records).

            Generates LDIF with changetype: modify and operation directives.
            For ACL entries, generates one replace: aci block per ACI attribute value.

            Example output:
            ```
            dn: cn=OracleContext
            changetype: modify
            replace: aci
            aci: access to entry by group="cn=Admins" (browse,add,delete)
            -
            replace: aci
            aci: access to entry filter=(objectclass=person) by * (browse)
            -
            ```

            Args:
                entry_data: Entry model to write
                _write_options: Formatting options (reserved for future use)

            Returns:
                FlextResult with LDIF string in modify format

            """
            ldif_lines: list[str] = []

            # DN line (required)
            if not (entry_data.dn and entry_data.dn.value):
                return FlextResult[str].fail("Entry DN is required for LDIF output")
            ldif_lines.extend([
                f"dn: {entry_data.dn.value}",
                "changetype: modify",
            ])

            # Get attributes to process
            if not entry_data.attributes or not entry_data.attributes.attributes:
                # No attributes to process
                ldif_text = "\n".join(ldif_lines) + "\n"
                return FlextResult[str].ok(ldif_text)

            attrs_dict = entry_data.attributes.attributes
            first_attr = True

            # For modify format: generate replace operation for each attribute
            # For ACL entries, each ACI value gets its own replace block
            for attr_name, values in attrs_dict.items():
                if not values:
                    continue

                # Generate replace operation for each value in this attribute
                value: bytes | str
                for value in values:
                    # Add separator between replace blocks (not before first)
                    if not first_attr:
                        ldif_lines.append("-")
                    first_attr = False

                    # Add replace directive
                    ldif_lines.append(f"replace: {attr_name}")

                    # Add attribute value(s) - handle bytes or str
                    # Use _write_entry_attribute_value for proper base64 encoding
                    if isinstance(value, bytes):
                        # Convert bytes to base64-encoded string
                        encoded_value = base64.b64encode(value).decode("ascii")
                        ldif_lines.append(f"{attr_name}:: {encoded_value}")
                    else:
                        # CORRECT: Ensure value is str and valid UTF-8 for RFC 2849 compliance
                        str_value = str(value) if not isinstance(value, str) else value

                        # CORRECT: Ensure valid UTF-8 encoding (RFC 2849 requirement)
                        try:
                            str_value.encode("utf-8")
                        except UnicodeEncodeError:
                            # Invalid UTF-8 - encode with error handling
                            str_value = str_value.encode(
                                "utf-8",
                                errors="replace",
                            ).decode("utf-8", errors="replace")
                            original_preview = (
                                value[:100] if len(value) > 100 else value
                            )
                            corrected_preview = (
                                str_value[:100] if len(str_value) > 100 else str_value
                            )
                            logger.debug(
                                f"RFC quirks: Corrected invalid UTF-8 in attribute: attribute_name={attr_name}, original_value_preview={original_preview}, corrected_value_preview={corrected_preview}, value_length={len(value)}, correction_type=utf8_encoding_fix"
                            )

                        # Check if attribute is a known binary attribute (RFC 4522)
                        # Binary attributes should always be base64-encoded
                        is_binary_attr = (
                            attr_name.lower()
                            in FlextLdifConstants.RfcBinaryAttributes.BINARY_ATTRIBUTE_NAMES
                        )
                        # Check if value needs base64 encoding per RFC 2849
                        needs_base64 = is_binary_attr or FlextLdifUtilities.Writer.needs_base64_encoding(
                            str_value,
                        )
                        if needs_base64:
                            encoded_value = base64.b64encode(
                                str_value.encode("utf-8"),
                            ).decode("ascii")
                            ldif_lines.append(f"{attr_name}:: {encoded_value}")
                        else:
                            ldif_lines.append(f"{attr_name}: {str_value}")

            # Final separator
            if ldif_lines[-1] != "-":
                ldif_lines.append("-")

            # Join with newlines and ensure proper LDIF formatting
            ldif_text = "\n".join(ldif_lines)
            if ldif_text and not ldif_text.endswith("\n"):
                ldif_text += "\n"

            return FlextResult[str].ok(ldif_text)


__all__ = [
    "FlextLdifServersRfc",
]
