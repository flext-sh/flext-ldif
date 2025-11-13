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
from collections.abc import Mapping
from typing import ClassVar, cast

from flext_core import FlextLogger, FlextResult

# ===== TYPE ALIASES (Python 3.13 semantic types) =====
# These document the semantic purpose of constants without formal definitions
# Used in docstrings and type hints for better code clarity
#
# type PermissionSet = frozenset[str]  # Set of ACL permissions
# type AttributeSet = frozenset[str]   # Set of LDAP attribute names
# type PatternSet = frozenset[str]     # Set of regex/match patterns
# type ReplacementMap = Mapping[str, str]  # Mapping for substitutions/normalization
# type DetectionConfig = Mapping[str, str | int | frozenset[str]]  # Server detection config
# type AclConfig = Mapping[str, str | int | frozenset[str]]  # ACL format config
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities

logger = FlextLogger(__name__)


class FlextLdifServersRfc(FlextLdifServersBase):
    """RFC 4512 Compliant Server Quirks - Base Implementation for LDAP Schema/ACL/Entry Parsing.

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
        These are set once per server implementation for initialization via __init_subclass__.

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
        PRIORITY: ClassVar[int] = 100  # Lowest priority - fallback only

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
        # Permissions that RFC supports (migrated from FlextLdifConstants.AclPermissionCompatibility)
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

        # Schema attribute fields that are server-specific (RFC is canonical - no special fields)
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

    class Schema(FlextLdifServersBase.Schema):
        """RFC 4512 Compliant Schema Quirk - Base Implementation."""

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

        def _parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse RFC 4512 attribute definition (implements abstract method)."""
            return FlextLdifUtilities.Parser.parse_rfc_attribute(
                attr_definition=attr_definition,
                case_insensitive=False,
                allow_syntax_quotes=False,
            )

        def _parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse RFC-compliant objectClass definition (implements abstract method)."""
            return FlextLdifUtilities.Parser.parse_rfc_objectclass(
                oc_definition=oc_definition,
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
            # Type check - ensure we got a proper model object
            if not isinstance(attr_data, FlextLdifModels.SchemaAttribute):
                return FlextResult[str].fail(
                    "write_attribute_to_rfc requires SchemaAttribute model, got "
                    f"{type(attr_data).__name__}",
                )

            # Check for original format in metadata (for perfect round-trip)
            if attr_data.metadata and attr_data.metadata.extensions.get(
                "original_format"
            ):
                return FlextResult[str].ok(
                    cast(
                        "str", attr_data.metadata.extensions.get("original_format", "")
                    )
                )

            # Transform attribute data using subclass hooks
            transformed_attr = self._transform_attribute_for_write(attr_data)

            # Write to RFC format (writer now accepts model directly)
            result = FlextLdifUtilities.Writer.write_rfc_attribute(transformed_attr)

            # Apply post-write transformations
            if result.is_success:
                written_str = result.unwrap()
                transformed_str = self._post_write_attribute(written_str)

                # Include attribute flags and extended attributes
                extras = []

                # Add attribute flags
                if transformed_attr.no_user_modification:
                    extras.append("NO-USER-MODIFICATION")
                if transformed_attr.single_value:
                    extras.append("SINGLE-VALUE")

                # Add X-ORIGIN from metadata if available
                if (
                    transformed_attr.metadata
                    and transformed_attr.metadata.extensions.get("x_origin")
                ):
                    extras.append(
                        f"X-ORIGIN '{transformed_attr.metadata.extensions.get('x_origin')}'"
                    )

                # Insert all extras before closing paren
                if extras and ")" in transformed_str:
                    extras_str = " " + " ".join(extras)
                    transformed_str = transformed_str.rstrip(")") + extras_str + ")"

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
            # Type check - ensure we got a proper model object
            if not isinstance(oc_data, FlextLdifModels.SchemaObjectClass):
                return FlextResult[str].fail(
                    "write_objectclass_to_rfc requires SchemaObjectClass model, got "
                    f"{type(oc_data).__name__}",
                )

            # Check for original format in metadata (for perfect round-trip)
            if oc_data.metadata and oc_data.metadata.extensions.get("original_format"):
                return FlextResult[str].ok(
                    cast("str", oc_data.metadata.extensions.get("original_format", ""))
                )

            # Transform objectClass data using subclass hooks
            transformed_oc = self._transform_objectclass_for_write(oc_data)

            # Write to RFC format (call static method)
            result = FlextLdifUtilities.Writer.write_rfc_objectclass(transformed_oc)

            # Apply post-write transformations
            if result.is_success:
                written_str = result.unwrap()
                transformed_str = self._post_write_objectclass(written_str)

                # Include extended attributes from metadata
                if (
                    transformed_oc.metadata
                    and transformed_oc.metadata.extensions.get("x_origin")
                    and ")" in transformed_str
                ):
                    # Insert X-ORIGIN before closing paren
                    x_origin_str = f" X-ORIGIN '{transformed_oc.metadata.extensions.get('x_origin')}'"
                    transformed_str = transformed_str.rstrip(")") + x_origin_str + ")"

                return FlextResult[str].ok(transformed_str)

            return result

    class Acl(FlextLdifServersBase.Acl):
        """RFC 4516 Compliant ACL Quirk - Base Implementation."""

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
            if not acl_line or not isinstance(acl_line, str) or not acl_line.strip():
                return FlextResult.fail("ACL line must be a non-empty string.")

            # Get server type from the actual server class (not hardcoded "rfc")
            server_type_value = self._get_server_type()

            # RFC passthrough: store the raw line in the model.
            acl_model = FlextLdifModels.Acl(
                raw_acl=acl_line,
                server_type=cast(
                    "FlextLdifConstants.LiteralTypes.ServerType", server_type_value
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
            if acl_data.raw_acl and acl_data.raw_acl.strip():
                return FlextResult[str].ok(acl_data.raw_acl)
            # If raw_acl is empty but name exists, return minimal ACL with name
            if acl_data.name and acl_data.name.strip():
                return FlextResult[str].ok(f"{acl_data.name}:")
            # No valid data to write
            return FlextResult[str].fail("ACL has no raw_acl or name to write")

    class Entry(FlextLdifServersBase.Entry):
        """RFC 2849 Compliant Entry Quirk - Base Implementation."""

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
                entry_result = FlextLdifModels.Entry.create(
                    dn=dn_obj,  # type: ignore[arg-type]
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
                    cast("FlextLdifModels.Entry", entry_model)
                )

            except Exception as e:
                logger.exception("RFC entry parsing exception")
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
            extensions = entry_data.metadata.extensions or {}
            if source_file := extensions.get("source_file"):
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
            extensions = entry_data.metadata.extensions or {}
            hidden_list = extensions.get("hidden_attributes")
            return set(hidden_list) if isinstance(hidden_list, list) else set()

        @staticmethod
        def _needs_base64_encoding(value: str) -> bool:
            """Check if value needs base64 encoding per RFC 2849.

            RFC 2849 section 3 requires base64 encoding for values that:
            - Start with space ' ', colon ':', or less-than '<'
            - End with space ' '
            - Contain null bytes or control characters (< 0x20, > 0x7E)

            Args:
                value: The attribute value to check

            Returns:
                True if value needs base64 encoding, False otherwise

            """
            if not value:
                return False

            # RFC 2849 unsafe start characters
            unsafe_start_chars = {" ", ":", "<"}

            # Check if starts with unsafe characters (space, colon, less-than)
            if value[0] in unsafe_start_chars:
                return True

            # Check if ends with space
            if value[-1] == " ":
                return True

            # RFC 2849 control character boundaries
            min_printable = 0x20  # Space (first printable ASCII)
            max_printable = 0x7E  # Tilde (last printable ASCII)

            # Check for control characters or non-printable ASCII
            for char in value:
                byte_val = ord(char)
                # Control chars (< 0x20) or non-ASCII (> 0x7E) require base64
                if byte_val < min_printable or byte_val > max_printable:
                    return True

            return False

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
            if isinstance(value, str) and value.startswith("__BASE64__:"):
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
            if base64_enabled and self._needs_base64_encoding(value):
                # Encode to base64
                encoded_value = base64.b64encode(value.encode("utf-8")).decode("ascii")
                ldif_lines.append(f"{attr_name}:: {encoded_value}")
            else:
                # Safe value or encoding disabled - write as plain text
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
                    ldif_lines.append(f"{attr_name}: {attr_values}")

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
                # Extract WriteFormatOptions if available (passed by writer)
                write_options: FlextLdifModels.WriteFormatOptions | None = None
                if entry_data.entry_metadata:
                    write_options_obj = entry_data.entry_metadata.get("_write_options")
                    if isinstance(
                        write_options_obj, FlextLdifModels.WriteFormatOptions
                    ):
                        write_options = write_options_obj

                # Check if LDIF modify format requested
                if write_options and write_options.ldif_changetype == "modify":
                    return self._write_entry_modify_format(entry_data, write_options)

                # Standard ADD format (RFC 2849 § 3)
                return self._write_entry_add_format(entry_data, write_options)

            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult[str].fail(
                    f"Failed to write entry to LDIF: {e}",
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
                    if isinstance(value, bytes):
                        encoded_value = base64.b64encode(value).decode("ascii")
                        ldif_lines.append(f"{attr_name}:: {encoded_value}")
                    else:
                        # Ensure value is str for type checker
                        str_value = str(value)
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
