"""Shared utilities for LDAP server quirks implementations.

This module provides reusable components for server-specific LDIF processing,
reducing code duplication across quirks implementations following FLEXT pattern:
one utilities class per module.

Advanced Features:
- Hook-based ACL conversion system for extensible server-to-server transformations
- Polymorphic permission mapping with fallback strategies
- Zero-data-loss conversion with comprehensive comment preservation
- Metadata-driven transformation pipeline with pluggable processors
"""

import logging
import re
from collections.abc import Callable
from typing import Any, ClassVar, cast

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels

logger = logging.getLogger(__name__)

# Type aliases for hook system
type AclConversionHook = Callable[
    [FlextLdifModels.Acl, str, str], FlextResult[FlextLdifModels.Acl]
]
type PermissionConversionHook = Callable[
    [list[str], str, str], tuple[list[str], list[str]]
]
type SubjectTransformHook = Callable[[str, str, str], tuple[str, str]]
type CommentGeneratorHook = Callable[[dict[str, Any], str, str], list[str]]


class FlextLdifUtilities:
    """Unified utilities for LDIF processing across LDAP server implementations.

    Provides reusable validation, fixing, and transformation methods to reduce
    code duplication across server-specific quirks. Follows FLEXT pattern of
    one utilities class per module.
    """

    @staticmethod
    def normalize_server_type(server_type: str) -> str:
        """Normalize server type aliases to canonical form.

        Converts aliases like 'oracle_oid' → 'oid', 'oracle_oud' → 'oud'
        This reduces conditional checks throughout the codebase.

        Args:
            server_type: Server type string (may be alias)

        Returns:
            Canonical server type

        """
        # Server type alias mappings
        aliases = {
            "oracle_oid": "oid",
            "oracle_oud": "oud",
            "openldap2": "openldap",
            "389ds": "389ds",
            "active_directory": "ad",
        }
        return aliases.get(server_type, server_type)

    @staticmethod
    def matches_server_type(server_type: str, *canonical_types: str) -> bool:
        """Check if server_type matches any of the canonical types (handles aliases).

        Args:
            server_type: Server type to check
            *canonical_types: Canonical type(s) to match against

        Returns:
            True if server_type (or its canonical form) matches any canonical_type

        """
        normalized = FlextLdifUtilities.normalize_server_type(server_type)
        return normalized in canonical_types or server_type in canonical_types

    class ObjectClassValidator:
        """Generic ObjectClass validation and transformation utilities.

        Provides methods for validating and fixing ObjectClass definitions
        according to RFC standards without server-specific assumptions.
        """

        @staticmethod
        def ensure_sup_for_auxiliary(
            schema_oc: FlextLdifModels.SchemaObjectClass,
            default_sup: str = "top",
        ) -> None:
            """Ensure AUXILIARY objectClasses have a SUP clause.

            RFC 4512 requires AUXILIARY classes to have explicit SUP.
            If missing, adds the specified default SUP value.

            Args:
                schema_oc: ObjectClass model to potentially fix
                default_sup: Default SUP value to add if missing (default: "top")

            Returns:
                None - modifies schema_oc in place

            """
            if (
                not schema_oc.sup
                and schema_oc.kind == FlextLdifConstants.Schema.AUXILIARY
            ):
                schema_oc.sup = default_sup

        @staticmethod
        def ensure_sup_for_kind(
            schema_oc: FlextLdifModels.SchemaObjectClass,
            required_for_kinds: set[str] | None = None,
            default_sup: str = "top",
        ) -> None:
            """Ensure objectClasses of specified kinds have a SUP clause.

            Generic method to add SUP to objectClasses of specified kinds
            that are missing SUP (e.g., AUXILIARY classes require SUP per RFC 4512).

            Args:
                schema_oc: ObjectClass model to potentially fix
                required_for_kinds: Set of class kinds requiring SUP
                    (default: {AUXILIARY})
                default_sup: Default SUP value to add if missing (default: "top")

            Returns:
                None - modifies schema_oc in place

            """
            if required_for_kinds is None:
                required_for_kinds = {FlextLdifConstants.Schema.AUXILIARY}

            if not schema_oc.sup and schema_oc.kind in required_for_kinds:
                schema_oc.sup = default_sup

        @staticmethod
        def fix_missing_sup(
            schema_oc: FlextLdifModels.SchemaObjectClass,
            server_type: str = "oid",
        ) -> None:
            """Fix missing SUP for AUXILIARY objectClasses.

            AUXILIARY classes that require an explicit SUP clause are fixed by adding
            "top" as the superior class. This is required for OUD compatibility.

            Args:
                schema_oc: ObjectClass model to potentially fix
                server_type: Server type hint for logging (e.g., "oid", "oud")

            Returns:
                None - modifies schema_oc in place

            """
            # Only fix AUXILIARY classes without SUP
            if schema_oc.sup or schema_oc.kind != FlextLdifConstants.Schema.AUXILIARY:
                return

            # Known AUXILIARY classes from OID that are missing SUP top
            auxiliary_without_sup = {
                "orcldAsAttrCategory",  # orclDASAttrCategory
                "orcldasattrcategory",
            }
            name_lower = str(schema_oc.name).lower() if schema_oc.name else ""

            if name_lower in auxiliary_without_sup:
                schema_oc.sup = "top"
                logger.debug(
                    f"[{server_type}] Adding missing SUP top to AUXILIARY class {schema_oc.name}",
                )

        @staticmethod
        def fix_kind_mismatch(
            schema_oc: FlextLdifModels.SchemaObjectClass,
            server_type: str = "oid",
        ) -> None:
            """Fix objectClass kind mismatches with superior classes.

            Some ObjectClasses have kind mismatches with their superior classes
            (e.g., AUXILIARY class with STRUCTURAL superior). This method fixes
            such mismatches by aligning the kind with the superior class.

            Args:
                schema_oc: ObjectClass model to potentially fix
                server_type: Server type hint for logging (e.g., "oid", "oud")

            Returns:
                None - modifies schema_oc in place

            """
            # Only fix if both SUP and kind are present
            if not schema_oc.sup or not schema_oc.kind:
                return

            # Known STRUCTURAL superior classes that cause conflicts
            structural_superiors = {
                "orclpwdverifierprofile",
                "orclapplicationentity",
                "tombstone",
            }
            # Known AUXILIARY superior classes that cause conflicts
            auxiliary_superiors = {"javanamingref", "javanamingReference"}

            sup_lower = (
                str(schema_oc.sup).lower() if isinstance(schema_oc.sup, str) else ""
            )

            # If SUP is STRUCTURAL but objectClass is AUXILIARY, change to STRUCTURAL
            if (
                sup_lower in structural_superiors
                and schema_oc.kind == FlextLdifConstants.Schema.AUXILIARY
            ):
                logger.debug(
                    f"[{server_type}] Changing {schema_oc.name} from AUXILIARY to STRUCTURAL "
                    f"to match superior class {schema_oc.sup}",
                )
                schema_oc.kind = FlextLdifConstants.Schema.STRUCTURAL

            # If SUP is AUXILIARY but objectClass is STRUCTURAL, change to AUXILIARY
            elif (
                sup_lower in auxiliary_superiors
                and schema_oc.kind == FlextLdifConstants.Schema.STRUCTURAL
            ):
                logger.debug(
                    f"[{server_type}] Changing {schema_oc.name} from STRUCTURAL to AUXILIARY "
                    f"to match superior class {schema_oc.sup}",
                )
                schema_oc.kind = FlextLdifConstants.Schema.AUXILIARY

        @staticmethod
        def align_kind_with_superior(
            schema_oc: FlextLdifModels.SchemaObjectClass,
            superior_kind: str | None,
        ) -> None:
            """Align ObjectClass kind with its superior class kind.

            If the ObjectClass kind conflicts with the superior's kind,
            aligns them for RFC compliance.

            Args:
                schema_oc: ObjectClass model to potentially fix
                superior_kind: Kind of the superior ObjectClass

            Returns:
                None - modifies schema_oc in place

            """
            if not schema_oc.sup or not schema_oc.kind or not superior_kind:
                return

            if (
                superior_kind == FlextLdifConstants.Schema.STRUCTURAL
                and schema_oc.kind == FlextLdifConstants.Schema.AUXILIARY
            ):
                schema_oc.kind = FlextLdifConstants.Schema.STRUCTURAL
            elif (
                superior_kind == FlextLdifConstants.Schema.AUXILIARY
                and schema_oc.kind == FlextLdifConstants.Schema.STRUCTURAL
            ):
                schema_oc.kind = FlextLdifConstants.Schema.AUXILIARY

        @staticmethod
        def align_kind_with_mapping(
            schema_oc: FlextLdifModels.SchemaObjectClass,
            superior_kind: str | None,
            kind_mappings: dict[tuple[str, str], str] | None = None,
        ) -> None:
            """Generically align ObjectClass kind based on superior class kind.

            Uses configurable mappings to determine how to resolve kind conflicts
            between a class and its superior class.

            Args:
                schema_oc: ObjectClass model to potentially fix
                superior_kind: Kind of the superior ObjectClass
                kind_mappings: Dict mapping (own_kind, superior_kind) tuples to
                    the corrected kind. Example: {
                        ("AUXILIARY", "STRUCTURAL"): "STRUCTURAL",
                        ("STRUCTURAL", "AUXILIARY"): "AUXILIARY",
                    }

            Returns:
                None - modifies schema_oc in place

            """
            if not schema_oc.sup or not schema_oc.kind or not superior_kind:
                return

            if kind_mappings is None:
                kind_mappings = {
                    (
                        FlextLdifConstants.Schema.AUXILIARY,
                        FlextLdifConstants.Schema.STRUCTURAL,
                    ): FlextLdifConstants.Schema.STRUCTURAL,
                    (
                        FlextLdifConstants.Schema.STRUCTURAL,
                        FlextLdifConstants.Schema.AUXILIARY,
                    ): FlextLdifConstants.Schema.AUXILIARY,
                }

            mapping_key = (schema_oc.kind, superior_kind)
            if mapping_key in kind_mappings:
                schema_oc.kind = kind_mappings[mapping_key]

    class AttributeFixer:
        """Generic attribute definition normalization utilities.

        Provides methods for normalizing attribute definitions to RFC
        standards without server-specific assumptions.
        """

        # Standard matching rule normalizations
        @staticmethod
        def normalize_name(
            name_value: str | None,
            suffixes_to_remove: list[str] | None = None,
            char_replacements: dict[str, str] | None = None,
        ) -> str | None:
            """Normalize attribute NAME field.

            Applies generic transformations:
            - Remove specified suffixes
            - Apply character/substring replacements

            Args:
                name_value: NAME field value to normalize
                suffixes_to_remove: List of suffixes to strip from NAME
                    (default: [";binary"])
                char_replacements: Dict mapping characters/strings to replace
                    (default: {"_": "-"})

            Returns:
                Normalized NAME value or original if no changes needed

            """
            if not name_value or not isinstance(name_value, str):
                return name_value

            result = name_value

            # Use defaults if not provided
            if suffixes_to_remove is None:
                suffixes_to_remove = [";binary"]
            if char_replacements is None:
                char_replacements = {"_": "-"}

            # Remove specified suffixes
            for suffix in suffixes_to_remove:
                if suffix in result:
                    result = result.replace(suffix, "")

            # Apply character replacements
            for old, new in char_replacements.items():
                if old in result:
                    result = result.replace(old, new)

            return result

        @staticmethod
        def fix_name_quirks(
            name_value: str | None,
            server_type: str = "oid",
        ) -> str | None:
            """Fix NAME field for server-specific quirks.

            Handles common NAME issues like:
            - Removal of ;binary suffix (OID)
            - Underscore to dash conversion (OID)

            Args:
                name_value: NAME field value to fix
                server_type: Server type hint for logging

            Returns:
                Fixed NAME value or original if no fixes needed

            """
            if not name_value or not isinstance(name_value, str):
                return name_value

            result = name_value

            # Remove ;binary suffix
            if ";binary" in result:
                result = result.replace(";binary", "")
                logger.debug(
                    f"[{server_type}] Removed ;binary from NAME: {name_value}",
                )

            # Replace underscores with dashes
            if "_" in result:
                result = result.replace("_", "-")
                logger.debug(
                    f"[{server_type}] Replaced _ with - in NAME: {name_value}",
                )

            return result

        @staticmethod
        def normalize_matching_rules(
            equality_value: str | None,
            substr_value: str | None,
            substr_rules_in_equality: dict[str, str] | None = None,
            rule_replacements: dict[str, str] | None = None,
            normalized_substr_values: dict[str, str] | None = None,
        ) -> tuple[str | None, str | None]:
            """Normalize EQUALITY and SUBSTR matching rules.

            Applies generic matching rule corrections:
            - Move SUBSTR rules used in EQUALITY to correct field
            - Apply standard matching rule normalizations
            - Normalize SUBSTR case variants

            Args:
                equality_value: EQUALITY matching rule
                substr_value: SUBSTR matching rule
                substr_rules_in_equality: Dict mapping SUBSTR rules found in EQUALITY
                    to their corrected EQUALITY rule (e.g.,
                    {"caseIgnoreSubstringsMatch": "caseIgnoreMatch"})
                rule_replacements: Dict mapping old matching rules to new ones
                    (applied after substr detection)
                normalized_substr_values: Dict mapping case variants to normalized
                    SUBSTR values (e.g., {"caseIgnoreSubStringsMatch": "caseIgnoreSubstringsMatch"})

            Returns:
                Tuple of (normalized_equality, normalized_substr)

            """
            if not equality_value or not isinstance(equality_value, str):
                return equality_value, substr_value

            result_equality = equality_value
            result_substr = substr_value

            # Use defaults if not provided
            if substr_rules_in_equality is None:
                substr_rules_in_equality = {
                    "caseIgnoreSubstringsMatch": "caseIgnoreMatch",
                    "caseIgnoreSubStringsMatch": "caseIgnoreMatch",
                }
            if rule_replacements is None:
                rule_replacements = FlextLdifConstants.SchemaConversionMappings.MATCHING_RULE_NORMALIZATIONS

            # Detect SUBSTR rule misused in EQUALITY position
            if equality_value in substr_rules_in_equality:
                # Move to correct position
                result_equality = substr_rules_in_equality[equality_value]
                # Use normalized SUBSTR value if provided, otherwise use original
                if (
                    normalized_substr_values
                    and equality_value in normalized_substr_values
                ):
                    result_substr = normalized_substr_values[equality_value]
                else:
                    result_substr = equality_value
            elif equality_value in rule_replacements:
                # Apply standard normalization
                result_equality = rule_replacements[equality_value]

            return result_equality, result_substr

        @staticmethod
        def fix_syntax_quirks(
            syntax_value: str | None,
            _server_type: str = "oid",
        ) -> str | None:
            """Fix SYNTAX field for server-specific quirks.

            Handles common SYNTAX issues like OID truncation or normalization.

            Args:
                syntax_value: SYNTAX field value to fix
                _server_type: Server type hint for logging

            Returns:
                Fixed SYNTAX value or original if no fixes needed

            """
            if not syntax_value or not isinstance(syntax_value, str):
                return syntax_value

            # Add server-specific syntax fixes here as needed
            logger.debug(
                f"[{_server_type}] Processing SYNTAX: {syntax_value}",
            )
            return syntax_value

    class LdifParser:
        """Universal LDIF parsing utilities with server-driven configuration.

        Server quirks provide their specific parsing configurations as parameters.
        This class provides the universal RFC 2849-compliant parsing algorithm.
        """

        @staticmethod
        def parse_ldif_lines(
            ldif_content: str,
            *,
            # Server Configuration (optional - servers can override defaults)
            encoding: str = "utf-8",
            handle_base64: bool = True,
            preserve_line_breaks: bool = True,
            skip_comments: bool = True,
            case_sensitive_attrs: bool = True,
            # Processing Hooks
            pre_parse_hook: Any | None = None,
            post_parse_hook: Any | None = None,
            attribute_hook: Any | None = None,
            dn_hook: Any | None = None,
        ) -> list[tuple[str, dict[str, list[str]]]]:
            """Parse LDIF content with server-provided configuration.

            Server quirks can customize behavior through parameters and hooks.

            Args:
                ldif_content: Raw LDIF content string
                encoding: Character encoding for decoding
                handle_base64: Whether to decode base64 values
                preserve_line_breaks: Whether to preserve line breaks in values
                skip_comments: Whether to skip comment lines
                case_sensitive_attrs: Whether attribute names are case-sensitive
                pre_parse_hook: Called before parsing starts
                post_parse_hook: Called after parsing completes
                attribute_hook: Called for each attribute (name, value) -> (name, value)
                dn_hook: Called for each DN value

            Returns:
                List of (dn, attributes_dict) tuples

            """
            # Apply pre-parse hook if provided
            if pre_parse_hook:
                ldif_content = pre_parse_hook(ldif_content)

            entries: list[tuple[str, dict[str, list[str]]]] = []
            lines = ldif_content.split("\n")
            current_dn: str | None = None
            current_attrs: dict[str, list[str]] = {}
            i = 0

            while i < len(lines):
                line = lines[i]

                # Skip comments and empty lines (configurable)
                if skip_comments and (not line.strip() or line.strip().startswith("#")):
                    i += 1
                    continue

                # Handle line continuation (RFC 2849: space at start = continuation)
                full_line = line
                while i + 1 < len(lines) and lines[i + 1].startswith(" "):
                    i += 1
                    continuation = lines[i][1:]
                    # Preserve spaces that were at the wrap point
                    if full_line and continuation and not full_line[-1].isspace():
                        if continuation[0] not in ",=:":
                            full_line += " "
                    full_line += continuation

                # Parse the line
                if ":" not in full_line:
                    i += 1
                    continue

                attr_name, _, attr_value = full_line.partition(":")
                attr_name = attr_name.strip()
                attr_value = attr_value.strip()

                # Handle base64-encoded values (configurable)
                if handle_base64 and attr_value.startswith(":"):
                    import base64

                    try:
                        decoded_bytes = base64.b64decode(attr_value[1:].strip())
                        attr_value = decoded_bytes.decode(encoding)
                    except (ValueError, UnicodeDecodeError):
                        # Keep as base64 string for binary data
                        attr_value = attr_value[1:].strip()

                # Apply attribute hook if provided (server can transform attribute name/value)
                if attribute_hook:
                    attr_name, attr_value = attribute_hook(attr_name, attr_value)

                # DN line starts a new entry
                if attr_name.lower() == "dn":
                    # Save previous entry if exists
                    if current_dn is not None:
                        entries.append((current_dn, current_attrs))

                    # Apply DN hook if provided (server can transform DN)
                    current_dn = dn_hook(attr_value) if dn_hook else attr_value
                    current_attrs = {}
                # Add attribute to current entry
                elif current_dn is not None:
                    # Normalize attribute name case if configured
                    if not case_sensitive_attrs:
                        attr_name = attr_name.lower()

                    if attr_name not in current_attrs:
                        current_attrs[attr_name] = []
                    current_attrs[attr_name].append(attr_value)

                i += 1

            # Save last entry
            if current_dn is not None:
                entries.append((current_dn, current_attrs))

            # Apply post-parse hook if provided (server can process all entries)
            if post_parse_hook:
                entries = post_parse_hook(entries)

            return entries

        @staticmethod
        def parse_schema_attribute(
            attr_definition: str,
            *,
            # Server Configuration
            server_type: str = "rfc",
            case_insensitive: bool = False,
            allow_syntax_quotes: bool = False,
            required_fields: list[str] | None = None,
            optional_fields: list[str] | None = None,
            # Field Transformations (server provides)
            oid_extractor: Any | None = None,
            name_extractor: Any | None = None,
            syntax_normalizer: Any | None = None,
            # Processing Hooks
            pre_parse_hook: Any | None = None,
            post_parse_hook: Any | None = None,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Universal schema attribute parser with server-driven configuration.

            Servers provide their specific parsing rules as parameters.
            This eliminates code duplication across 12 server implementations.

            Args:
                attr_definition: Attribute definition string
                server_type: Server type for metadata
                case_insensitive: Whether NAME matching is case-insensitive
                allow_syntax_quotes: Whether SYNTAX can have quotes
                required_fields: Fields that must be present
                optional_fields: Fields to extract if present
                oid_extractor: Custom OID extraction function
                name_extractor: Custom NAME extraction function
                syntax_normalizer: Custom SYNTAX normalization function
                pre_parse_hook: Transform definition before parsing
                post_parse_hook: Transform parsed attribute after parsing

            Returns:
                FlextResult with SchemaAttribute or error

            """
            try:
                # Apply pre-parse hook if server provides one
                if pre_parse_hook:
                    attr_definition = pre_parse_hook(attr_definition)

                # Use FlextLdifConstants for standard patterns
                # Extract OID (required)
                if oid_extractor:
                    oid = oid_extractor(attr_definition)
                else:
                    oid_match = re.match(
                        FlextLdifConstants.LdifPatterns.SCHEMA_OID_EXTRACTION,
                        attr_definition,
                    )
                    if not oid_match:
                        return FlextResult.fail(
                            "Schema attribute parsing failed: missing OID"
                        )
                    oid = oid_match.group(1)

                # Extract NAME (use OID as fallback)
                if name_extractor:
                    name = name_extractor(attr_definition)
                else:
                    name_match = re.search(
                        FlextLdifConstants.LdifPatterns.SCHEMA_NAME,
                        attr_definition,
                        re.IGNORECASE if case_insensitive else 0,
                    )
                    name = name_match.group(1) if name_match else oid

                # Extract other standard fields using constants
                desc_match = re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_DESC, attr_definition
                )
                desc = desc_match.group(1) if desc_match else None

                syntax_match = re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_SYNTAX_LENGTH,
                    attr_definition,
                )
                syntax = syntax_match.group(1) if syntax_match else None
                length = (
                    int(syntax_match.group(2))
                    if syntax_match and syntax_match.group(2)
                    else None
                )

                # Apply syntax normalizer if server provides one
                if syntax_normalizer and syntax:
                    syntax = syntax_normalizer(syntax)

                # Extract matching rules
                equality_match = re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_EQUALITY, attr_definition
                )
                equality = equality_match.group(1) if equality_match else None

                substr_match = re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_SUBSTR, attr_definition
                )
                substr = substr_match.group(1) if substr_match else None

                ordering_match = re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_ORDERING, attr_definition
                )
                ordering = ordering_match.group(1) if ordering_match else None

                # Extract additional fields
                sup_match = re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_SUP, attr_definition
                )
                sup = sup_match.group(1) if sup_match else None

                usage_match = re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_USAGE, attr_definition
                )
                usage = usage_match.group(1) if usage_match else None

                # Extract flags
                single_value = bool(
                    re.search(
                        FlextLdifConstants.LdifPatterns.SCHEMA_SINGLE_VALUE,
                        attr_definition,
                    )
                )
                collective = bool(
                    re.search(
                        FlextLdifConstants.LdifPatterns.SCHEMA_COLLECTIVE,
                        attr_definition,
                    )
                )
                no_user_mod = bool(
                    re.search(
                        FlextLdifConstants.LdifPatterns.SCHEMA_NO_USER_MODIFICATION,
                        attr_definition,
                    )
                )

                # Extract extensions using shared utility
                metadata_extensions = FlextLdifUtilities.LdifParser.extract_extensions(
                    attr_definition
                )
                metadata_extensions[FlextLdifConstants.MetadataKeys.ORIGINAL_FORMAT] = (
                    attr_definition.strip()
                )

                # Build metadata
                metadata = FlextLdifModels.QuirkMetadata(
                    quirk_type=server_type,
                    server_type=server_type,
                    original_format=attr_definition.strip(),
                    extensions=metadata_extensions,
                )

                # Build attribute model
                attribute = FlextLdifModels.SchemaAttribute(
                    oid=oid,
                    name=name,
                    desc=desc,
                    syntax=syntax,
                    length=length,
                    equality=equality,
                    substr=substr,
                    ordering=ordering,
                    sup=sup,
                    usage=usage,
                    single_value=single_value,
                    collective=collective,
                    no_user_modification=no_user_mod,
                    metadata=metadata,
                )

                # Apply post-parse hook if server provides one
                if post_parse_hook:
                    attribute = post_parse_hook(attribute)

                return FlextResult.ok(attribute)

            except Exception as e:
                return FlextResult.fail(f"Schema attribute parsing failed: {e}")

        @staticmethod
        def extract_extensions(definition: str) -> dict[str, object]:
            """Extract schema extensions (X-ORIGIN, OBSOLETE, etc.) from definitions.

            Reusable for both attribute and objectClass definitions.

            Args:
                definition: Schema definition string

            Returns:
                Dictionary of extension key-value pairs

            """
            extensions: dict[str, object] = {}

            if re.search(FlextLdifConstants.LdifPatterns.SCHEMA_OBSOLETE, definition):
                extensions[FlextLdifConstants.MetadataKeys.OBSOLETE] = True

            if re.search(FlextLdifConstants.LdifPatterns.SCHEMA_COLLECTIVE, definition):
                extensions[FlextLdifConstants.MetadataKeys.COLLECTIVE] = True

            x_origin_match = re.search(
                FlextLdifConstants.LdifPatterns.SCHEMA_X_ORIGIN, definition
            )
            if x_origin_match:
                extensions[FlextLdifConstants.MetadataKeys.X_ORIGIN] = (
                    x_origin_match.group(1)
                )

            return extensions

    class AclConverter:
        """Advanced ACL conversion utilities with hook-based extensibility.

        Provides zero-data-loss ACL conversion between LDAP server formats using:
        - Hook-based permission mapping for extensible conversions
        - Metadata-driven transformation with comment preservation
        - Polymorphic subject transformation with fallback strategies
        - Server-agnostic constraint and filter analysis
        """

        # Registry for conversion hooks - can be extended by server quirks
        _conversion_hooks: ClassVar[dict[tuple[str, str], list[AclConversionHook]]] = {}
        _permission_hooks: ClassVar[
            dict[tuple[str, str], list[PermissionConversionHook]]
        ] = {}
        _subject_hooks: ClassVar[dict[tuple[str, str], list[SubjectTransformHook]]] = {}
        _comment_hooks: ClassVar[dict[tuple[str, str], list[CommentGeneratorHook]]] = {}

        @classmethod
        def register_conversion_hook(
            cls, source_server: str, target_server: str, hook: AclConversionHook
        ) -> None:
            """Register a conversion hook for specific server pair."""
            key = (source_server, target_server)
            if key not in cls._conversion_hooks:
                cls._conversion_hooks[key] = []
            cls._conversion_hooks[key].append(hook)

        @classmethod
        def register_permission_hook(
            cls, source_server: str, target_server: str, hook: PermissionConversionHook
        ) -> None:
            """Register a permission conversion hook for specific server pair."""
            key = (source_server, target_server)
            if key not in cls._permission_hooks:
                cls._permission_hooks[key] = []
            cls._permission_hooks[key].append(hook)

        @classmethod
        def register_comment_hook(
            cls, source_server: str, target_server: str, hook: CommentGeneratorHook
        ) -> None:
            """Register a comment generation hook for specific server pair."""
            key = (source_server, target_server)
            if key not in cls._comment_hooks:
                cls._comment_hooks[key] = []
            cls._comment_hooks[key].append(hook)

        @classmethod
        def register_subject_hook(
            cls,
            source_server: str,
            target_server: str,
            hook: Any,  # SubjectTransformHook
        ) -> None:
            """Register a subject transformation hook for specific server pair."""
            key = (source_server, target_server)
            if key not in cls._subject_hooks:
                cls._subject_hooks[key] = []
            cls._subject_hooks[key].append(hook)

        @classmethod
        def convert_acl_with_hooks(
            cls, acl: FlextLdifModels.Acl, source_server: str, target_server: str
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Convert ACL using registered hooks with fallback to built-in conversion."""
            # Try registered hooks first
            key = (source_server, target_server)
            if key in cls._conversion_hooks:
                for hook in cls._conversion_hooks[key]:
                    result = hook(acl, source_server, target_server)
                    if result.is_success:
                        return result

            # Fallback to built-in conversion
            return cls._convert_acl_builtin(acl, source_server, target_server)

        @classmethod
        def _convert_acl_builtin(
            cls, acl: FlextLdifModels.Acl, source_server: str, target_server: str
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Built-in ACL conversion with comprehensive metadata preservation."""
            try:
                # Extract metadata for conversion decision-making
                metadata_info = cls.extract_conversion_metadata(acl)

                # Generate conversion comments
                comments = cls.generate_conversion_comments(
                    metadata_info, source_server, target_server
                )

                # Convert permissions using advanced mapping
                converted_permissions = (
                    cls.convert_permissions_advanced(
                        acl.permissions, source_server, target_server
                    )
                    if acl.permissions
                    else None
                )

                # Transform subject using built-in logic
                transformed_subject = (
                    cls.transform_subject_advanced(
                        acl.subject, source_server, target_server
                    )
                    if acl.subject
                    else None
                )

                # Build converted metadata
                converted_metadata = FlextLdifModels.QuirkMetadata(
                    original_format=acl.metadata.original_format
                    if acl.metadata
                    else "",
                    quirk_type=target_server,
                    server_type=target_server,
                    extensions={
                        "converted_from": source_server,
                        "conversion_comments": comments,
                        "original_metadata": metadata_info,
                        "preservation_strategy": "comments_and_metadata",
                    },
                )

                # Build final converted ACL
                # Use model_copy to preserve type safety
                converted_acl = acl.model_copy(
                    update={
                        "name": f"Converted from {source_server}: {acl.name}",
                        "subject": transformed_subject,
                        "permissions": converted_permissions,
                        "server_type": target_server,  # Keep as string for flexibility
                        "metadata": converted_metadata,
                    }
                )

                return FlextResult.ok(converted_acl)

            except Exception as e:
                return FlextResult.fail(f"ACL conversion failed: {e}")

        @classmethod
        def extract_conversion_metadata(
            cls, acl: FlextLdifModels.Acl
        ) -> dict[str, Any]:
            """Extract comprehensive metadata for conversion decisions."""
            metadata_info = {
                "source_server": acl.server_type,
                "has_metadata": acl.metadata is not None,
                "original_format": "",
                "extensions": {},
                "special_features": [],
            }

            if acl.metadata:
                metadata_info["original_format"] = acl.metadata.original_format or ""
                if hasattr(acl.metadata, "extensions") and acl.metadata.extensions:
                    metadata_info["extensions"] = dict(acl.metadata.extensions)

                    # Identify special features from extensions
                    for key, value in acl.metadata.extensions.items():
                        if (
                            key
                            in {
                                "filter_clause",
                                "added_object_constraint",
                                "oid_specific_permissions",
                            }
                            and value
                        ):  # Has non-empty value
                            metadata_info["special_features"].append(key)

            return metadata_info

        @classmethod
        def generate_conversion_comments(
            cls, metadata_info: dict[str, Any], source_server: str, target_server: str
        ) -> list[str]:
            """Generate comprehensive conversion comments using hooks."""
            comments = []

            # Try registered comment hooks first
            key = (source_server, target_server)
            if key in cls._comment_hooks:
                for hook in cls._comment_hooks[key]:
                    hook_comments = hook(metadata_info, source_server, target_server)
                    comments.extend(hook_comments)

            # Add built-in conversion comments
            comments.extend(
                cls._generate_builtin_comments(
                    metadata_info, source_server, target_server
                )
            )

            return comments

        @classmethod
        def _generate_builtin_comments(
            cls, metadata_info: dict[str, Any], source_server: str, target_server: str
        ) -> list[str]:
            """Generate built-in conversion comments."""
            comments = []

            # Header comment
            comments.append(f"# ACL converted from {source_server} to {target_server}")

            # Original format comment
            if metadata_info.get("original_format"):
                original_format = metadata_info["original_format"][:100]
                comments.append(f"# Original format: {original_format}...")

            # Special features comments
            special_features = metadata_info.get("special_features", [])
            if special_features:
                comments.append(
                    f"# Special features detected: {', '.join(special_features)}"
                )

            return comments

        @classmethod
        def convert_permissions_advanced(
            cls,
            permissions: FlextLdifModels.AclPermissions | None,
            source_server: str,
            target_server: str,
        ) -> FlextLdifModels.AclPermissions | None:
            """Convert permissions using advanced mapping with server-specific rules."""
            if not permissions:
                return None

            # Use PermissionMapper for advanced conversion
            mapper = FlextLdifUtilities.PermissionMapper

            # Extract permission list from model
            permission_list = [
                perm_name
                for perm_name in [
                    "read",
                    "write",
                    "add",
                    "delete",
                    "search",
                    "compare",
                    "self_write",
                    "proxy",
                ]
                if getattr(permissions, perm_name, False)
            ]

            # Check compatibility and convert
            converted_perms = {
                "read": False,
                "write": False,
                "add": False,
                "delete": False,
                "search": False,
                "compare": False,
                "self_write": False,
                "proxy": False,
            }

            for perm in permission_list:
                if mapper.is_permission_supported(perm, target_server):
                    converted_perms[perm] = True
                else:
                    # Use alternatives for unsupported permissions
                    alternatives = mapper.suggest_permission_alternatives(
                        perm, target_server
                    )
                    for alt in alternatives:
                        if alt in converted_perms:
                            converted_perms[alt] = True

            return FlextLdifModels.AclPermissions(**converted_perms)

        @classmethod
        def transform_subject_advanced(
            cls,
            subject: FlextLdifModels.AclSubject | None,
            source_server: str,
            target_server: str,
        ) -> FlextLdifModels.AclSubject | None:
            """Transform subject using advanced classification and conversion."""
            if not subject:
                return None

            # Use SubjectTransformer for advanced transformation
            transformer = FlextLdifUtilities.SubjectTransformer

            # Try registered subject hooks first
            key = (source_server, target_server)
            if key in cls._subject_hooks:
                for hook in cls._subject_hooks[key]:
                    subject_type, subject_value = hook(
                        subject.subject_type, subject.subject_value, target_server
                    )
                    if subject_type and subject_value:
                        return FlextLdifModels.AclSubject(
                            subject_type=subject_type, subject_value=subject_value
                        )

            # Fallback to subject transformer with generalized mapping
            classified_type = transformer.classify_subject_type(subject.subject_value)
            extracted_value = transformer.extract_subject_value(
                subject.subject_value, classified_type
            )

            # Use generalized transformation mapping system
            return cls._transform_subject_generic(
                subject, classified_type, extracted_value, source_server, target_server
            )

        # Subject transformation now follows RFC-as-hub strategy
        # Instead of direct mappings, use two-step conversion:
        # 1. source → RFC (via source.normalize_to_rfc)
        # 2. RFC → target (via target.denormalize_from_rfc)
        # This eliminates the need for N×N direct mappings

        @classmethod
        def _transform_subject_generic(
            cls,
            subject: FlextLdifModels.AclSubject,
            classified_type: str,
            extracted_value: str,
            source_server: str,
            target_server: str,
        ) -> FlextLdifModels.AclSubject:
            """Transform subject using RFC-as-hub strategy from FlextLdifConstants.

            **Algorithm** (following FlextLdifConstants.ConversionStrategy):
            1. Transform source → RFC using source server's mappings
            2. Transform RFC → target using target server's mappings
            3. Metadata preserves original for round-trip

            This eliminates N×N direct mappings, using only 2N transformations.
            """
            # Step 1: Normalize to RFC canonical format
            rfc_subject = cls._normalize_subject_to_rfc(
                classified_type, extracted_value, source_server
            )

            # Step 2: Denormalize from RFC to target format
            target_subject = cls._denormalize_subject_from_rfc(
                rfc_subject, target_server
            )

            return (
                target_subject or subject
            )  # Fallback to original if transformation fails

        @classmethod
        def _normalize_subject_to_rfc(
            cls, classified_type: str, value: str, source_server: str
        ) -> FlextLdifModels.AclSubject:
            """Normalize subject from source server to RFC canonical format."""
            # Universal subjects that don't need transformation
            if (
                classified_type
                in FlextLdifConstants.AclSubjectTransformations.UNIVERSAL_SUBJECTS
            ):
                return FlextLdifModels.AclSubject(
                    subject_type=classified_type, subject_value=value
                )

            # Use server-specific normalization mappings (using helper for cleaner code)
            if FlextLdifUtilities.matches_server_type(source_server, "oid"):
                mapping = (
                    FlextLdifConstants.AclSubjectTransformations.OID_TO_RFC_SUBJECTS
                )
            elif FlextLdifUtilities.matches_server_type(source_server, "oud"):
                mapping = (
                    FlextLdifConstants.AclSubjectTransformations.OUD_TO_RFC_SUBJECTS
                )
            elif FlextLdifUtilities.matches_server_type(source_server, "389ds"):
                mapping = (
                    FlextLdifConstants.AclSubjectTransformations.DS389_TO_RFC_SUBJECTS
                )
            else:
                mapping = {}

            if classified_type in mapping:
                rfc_type, template = mapping[classified_type]
                rfc_value = template.format(value=value)
                return FlextLdifModels.AclSubject(
                    subject_type=rfc_type, subject_value=rfc_value
                )

            # Default: assume it's already in RFC format
            return FlextLdifModels.AclSubject(
                subject_type=classified_type, subject_value=value
            )

        @classmethod
        def _denormalize_subject_from_rfc(
            cls, rfc_subject: FlextLdifModels.AclSubject, target_server: str
        ) -> FlextLdifModels.AclSubject | None:
            """Denormalize subject from RFC canonical format to target server format."""
            rfc_type = rfc_subject.subject_type
            rfc_value = rfc_subject.subject_value

            # Universal subjects don't need transformation
            if (
                rfc_type
                in FlextLdifConstants.AclSubjectTransformations.UNIVERSAL_SUBJECTS
            ):
                return rfc_subject

            # Use server-specific denormalization mappings (using helper)
            if FlextLdifUtilities.matches_server_type(target_server, "oud"):
                mapping = (
                    FlextLdifConstants.AclSubjectTransformations.RFC_TO_OUD_SUBJECTS
                )
            elif FlextLdifUtilities.matches_server_type(target_server, "oid"):
                mapping = (
                    FlextLdifConstants.AclSubjectTransformations.RFC_TO_OID_SUBJECTS
                )
            else:
                mapping = {}

            if rfc_type in mapping:
                target_type, template = mapping[rfc_type]
                target_value = template.format(value=rfc_value)
                return FlextLdifModels.AclSubject(
                    subject_type=target_type, subject_value=target_value
                )

            # Default: preserve RFC format
            return rfc_subject

    class PermissionMapper:
        """Advanced permission mapping utilities using FlextLdifConstants.

        All data now centralized in FlextLdifConstants.AclPermissionCompatibility.
        This class provides utility methods that reference the constants.
        """

        @classmethod
        def is_permission_supported(cls, permission: str, server_type: str) -> bool:
            """Check if a permission is supported by a specific server type.

            Uses FlextLdifConstants.AclPermissionCompatibility for single source of truth.
            """
            supported = (
                FlextLdifConstants.AclPermissionCompatibility.SUPPORTED_PERMISSIONS.get(
                    server_type, frozenset()
                )
            )
            return permission.lower() in supported

        @classmethod
        def get_unsupported_permissions(
            cls, permissions: list[str], server_type: str
        ) -> list[str]:
            """Get list of permissions not supported by target server type."""
            return [
                perm
                for perm in permissions
                if not cls.is_permission_supported(perm, server_type)
            ]

        @classmethod
        def suggest_permission_alternatives(
            cls, permission: str, target_server: str
        ) -> list[str]:
            """Suggest alternative permissions for unsupported permissions.

            Uses FlextLdifConstants.AclPermissionCompatibility for single source of truth.
            """
            key = (permission.lower(), target_server)
            return FlextLdifConstants.AclPermissionCompatibility.PERMISSION_ALTERNATIVES.get(
                key, []
            )

        @classmethod
        def transform_permissions_advanced(
            cls, permissions: list[str], source_server: str, target_server: str
        ) -> tuple[list[str], list[str], dict[str, list[str]]]:
            """Advanced permission transformation with detailed mapping tracking.

            Returns:
                Tuple of (allowed_permissions, denied_permissions, transformation_log)

            """
            allowed = []
            denied = []
            transformation_log = {}

            for perm in permissions:
                perm_lower = perm.lower()

                # Check if supported in target server
                if cls.is_permission_supported(perm_lower, target_server):
                    allowed.append(perm_lower)
                    transformation_log[perm_lower] = [perm_lower]  # Direct mapping
                else:
                    # Find transformation
                    alternatives = cls.suggest_permission_alternatives(
                        perm_lower, target_server
                    )
                    if alternatives:
                        allowed.extend(alternatives)
                        transformation_log[perm_lower] = alternatives
                    else:
                        denied.append(perm_lower)
                        transformation_log[perm_lower] = []

            # Remove duplicates while preserving order
            allowed = list(dict.fromkeys(allowed))
            denied = list(dict.fromkeys(denied))

            return allowed, denied, transformation_log

        @classmethod
        def get_server_specific_permissions(cls, server_type: str) -> list[str]:
            """Get list of server-specific permissions not in RFC standard.

            Uses FlextLdifConstants.AclPermissionCompatibility.
            """
            rfc_permissions = (
                FlextLdifConstants.AclPermissionCompatibility.SUPPORTED_PERMISSIONS.get(
                    "rfc", frozenset()
                )
            )
            server_permissions = (
                FlextLdifConstants.AclPermissionCompatibility.SUPPORTED_PERMISSIONS.get(
                    server_type, frozenset()
                )
            )

            specific_permissions = server_permissions - rfc_permissions
            return sorted(specific_permissions)

        @classmethod
        def analyze_permission_compatibility(
            cls, source_server: str, target_server: str
        ) -> dict[str, Any]:
            """Analyze permission compatibility between two servers.

            Uses FlextLdifConstants.AclPermissionCompatibility.
            """
            source_perms = (
                FlextLdifConstants.AclPermissionCompatibility.SUPPORTED_PERMISSIONS.get(
                    source_server, frozenset()
                )
            )
            target_perms = (
                FlextLdifConstants.AclPermissionCompatibility.SUPPORTED_PERMISSIONS.get(
                    target_server, frozenset()
                )
            )

            return {
                "compatible_permissions": sorted(source_perms & target_perms),
                "source_only_permissions": sorted(source_perms - target_perms),
                "target_only_permissions": sorted(target_perms - source_perms),
                "compatibility_score": len(source_perms & target_perms)
                / len(source_perms | target_perms)
                if source_perms | target_perms
                else 0.0,
            }

    class AttributeNameMapper:
        """Advanced attribute name mapping between LDAP server implementations."""

        # Case sensitivity mapping per server
        CASE_SENSITIVE_SERVERS: ClassVar[set[str]] = {
            "active_directory",  # AD is case-insensitive but preserves case
        }

        @classmethod
        def transform_attribute_name(
            cls, attribute_name: str, source_server: str, target_server: str
        ) -> str:
            """Transform attribute name using RFC-as-hub strategy.

            **Algorithm**: source → RFC → target
            1. Normalize to RFC using source server's mapping
            2. Denormalize to target using target server's mapping

            Uses FlextLdifConstants.SchemaConversionMappings.
            """
            attr_lower = attribute_name.lower()

            # Step 1: Normalize to RFC from source server (using helper)
            if FlextLdifUtilities.matches_server_type(source_server, "oid"):
                rfc_name = FlextLdifConstants.SchemaConversionMappings.ATTRIBUTE_TRANSFORMATION_OID_TO_RFC.get(
                    attr_lower, attribute_name
                )
            elif FlextLdifUtilities.matches_server_type(source_server, "oud"):
                rfc_name = FlextLdifConstants.SchemaConversionMappings.ATTRIBUTE_TRANSFORMATION_OUD_TO_RFC.get(
                    attr_lower, attribute_name
                )
            else:
                rfc_name = attribute_name  # Already RFC or unknown

            # Step 2: Denormalize from RFC to target server (using helper)
            if FlextLdifUtilities.matches_server_type(target_server, "oud"):
                target_name = FlextLdifConstants.SchemaConversionMappings.ATTRIBUTE_TRANSFORMATION_RFC_TO_OUD.get(
                    rfc_name.lower(), rfc_name
                )
            elif FlextLdifUtilities.matches_server_type(target_server, "oid"):
                target_name = FlextLdifConstants.SchemaConversionMappings.ATTRIBUTE_TRANSFORMATION_RFC_TO_OID.get(
                    rfc_name.lower(), rfc_name
                )
            else:
                target_name = rfc_name  # Keep RFC format

            # Check aliases in target server
            target_aliases = (
                FlextLdifConstants.SchemaConversionMappings.ATTRIBUTE_ALIASES.get(
                    target_server, {}
                )
            )
            for canonical_name, aliases in target_aliases.items():
                if target_name.lower() in [alias.lower() for alias in aliases]:
                    return canonical_name

            return target_name

        @classmethod
        def get_attribute_aliases(
            cls, attribute_name: str, server_type: str
        ) -> list[str]:
            """Get all known aliases for an attribute in a specific server.

            Uses FlextLdifConstants.SchemaConversionMappings.ATTRIBUTE_ALIASES.
            """
            server_aliases = (
                FlextLdifConstants.SchemaConversionMappings.ATTRIBUTE_ALIASES.get(
                    server_type, {}
                )
            )
            attr_lower = attribute_name.lower()

            # Find the canonical attribute and return its aliases
            for canonical_name, aliases in server_aliases.items():
                if canonical_name.lower() == attr_lower or attr_lower in [
                    alias.lower() for alias in aliases
                ]:
                    return [canonical_name] + aliases

            return [attribute_name]  # Return original if no aliases found

        @classmethod
        def normalize_attribute_case(cls, attribute_name: str, server_type: str) -> str:
            """Normalize attribute name case according to server preferences."""
            # Case-insensitive servers typically use lowercase
            if server_type not in cls.CASE_SENSITIVE_SERVERS:
                return attribute_name.lower()

            # Case-sensitive servers preserve original case
            return attribute_name

        @classmethod
        def analyze_attribute_compatibility(
            cls, attributes: list[str], source_server: str, target_server: str
        ) -> dict[str, Any]:
            """Analyze attribute compatibility between servers."""
            transformable = []
            preserved = []
            potential_issues = []

            for attr in attributes:
                transformed = cls.transform_attribute_name(
                    attr, source_server, target_server
                )

                if transformed != attr:
                    transformable.append({
                        "original": attr,
                        "transformed": transformed,
                        "reason": "server_specific_mapping",
                    })
                elif (
                    attr.lower() != attr
                    and target_server not in cls.CASE_SENSITIVE_SERVERS
                ):
                    potential_issues.append({
                        "attribute": attr,
                        "issue": "case_sensitivity",
                        "suggestion": attr.lower(),
                    })
                    preserved.append(attr)
                else:
                    preserved.append(attr)

            return {
                "transformable_attributes": transformable,
                "preserved_attributes": preserved,
                "potential_issues": potential_issues,
                "compatibility_score": len(preserved) / len(attributes)
                if attributes
                else 1.0,
            }

    class DnTransformer:
        """Advanced Distinguished Name transformation between LDAP servers."""

        # DN format preferences per server
        DN_FORMAT_PREFERENCES: ClassVar[dict[str, dict[str, Any]]] = {
            "oracle_oid": {
                "case_preference": "preserve",
                "space_around_equals": False,
                "space_after_comma": True,
                "quote_special_chars": True,
            },
            "oracle_oud": {
                "case_preference": "lowercase",
                "space_around_equals": False,
                "space_after_comma": True,
                "quote_special_chars": True,
            },
            "active_directory": {
                "case_preference": "preserve",
                "space_around_equals": False,
                "space_after_comma": False,
                "quote_special_chars": False,
            },
            "389ds": {
                "case_preference": "lowercase",
                "space_around_equals": False,
                "space_after_comma": True,
                "quote_special_chars": True,
            },
            "openldap": {
                "case_preference": "lowercase",
                "space_around_equals": False,
                "space_after_comma": True,
                "quote_special_chars": True,
            },
        }

        @classmethod
        def transform_dn(cls, dn: str, source_server: str, target_server: str) -> str:
            """Transform DN format between server types."""
            if not dn or dn.strip() == "":
                return dn

            try:
                # Parse DN into components
                components = cls._parse_dn_components(dn)

                # Transform each component
                transformed_components = []
                for component in components:
                    transformed_comp = cls._transform_dn_component(
                        component, source_server, target_server
                    )
                    transformed_components.append(transformed_comp)

                # Reassemble according to target server preferences
                return cls._assemble_dn(transformed_components, target_server)

            except Exception:
                # If parsing fails, return original DN
                return dn

        @classmethod
        def _parse_dn_components(cls, dn: str) -> list[dict[str, str]]:
            """Parse DN into list of component dictionaries."""
            components = []

            # Simple DN parsing (production would use proper LDAP DN parser)
            parts = dn.split(",")

            for part in parts:
                part = part.strip()
                if "=" in part:
                    attr, value = part.split("=", 1)
                    components.append({
                        "attribute": attr.strip(),
                        "value": value.strip(),
                        "original": part,
                    })

            return components

        @classmethod
        def _transform_dn_component(
            cls, component: dict[str, str], source_server: str, target_server: str
        ) -> dict[str, str]:
            """Transform a single DN component."""
            attr = component["attribute"]
            value = component["value"]

            # Transform attribute name
            attr_mapper = FlextLdifUtilities.AttributeNameMapper
            transformed_attr = attr_mapper.transform_attribute_name(
                attr, source_server, target_server
            )

            # Apply case preferences
            target_prefs = cls.DN_FORMAT_PREFERENCES.get(target_server, {})
            case_pref = target_prefs.get("case_preference", "preserve")

            if case_pref == "lowercase":
                transformed_attr = transformed_attr.lower()
            elif case_pref == "uppercase":
                transformed_attr = transformed_attr.upper()
            # "preserve" keeps original case

            return {
                "attribute": transformed_attr,
                "value": value,  # Value transformation could be added here
                "original": component["original"],
            }

        @classmethod
        def _assemble_dn(
            cls, components: list[dict[str, str]], target_server: str
        ) -> str:
            """Assemble DN components according to target server format."""
            target_prefs = cls.DN_FORMAT_PREFERENCES.get(target_server, {})

            space_around_equals = target_prefs.get("space_around_equals", False)
            space_after_comma = target_prefs.get("space_after_comma", True)

            dn_parts = []
            for comp in components:
                attr = comp["attribute"]
                value = comp["value"]

                part = f"{attr} = {value}" if space_around_equals else f"{attr}={value}"

                dn_parts.append(part)

            if space_after_comma:
                return ", ".join(dn_parts)
            return ",".join(dn_parts)

        @classmethod
        def validate_dn_format(cls, dn: str, server_type: str) -> dict[str, Any]:
            """Validate DN format according to server requirements."""
            issues = []
            suggestions = []

            if not dn:
                return {
                    "valid": False,
                    "issues": ["DN is empty"],
                    "suggestions": ["Provide a valid DN"],
                }

            try:
                components = cls._parse_dn_components(dn)

                if not components:
                    issues.append("DN has no valid components")
                    suggestions.append(
                        "Ensure DN follows format: attr=value,attr=value"
                    )

                # Check format preferences
                prefs = cls.DN_FORMAT_PREFERENCES.get(server_type, {})

                # Check case preferences
                case_pref = prefs.get("case_preference", "preserve")
                if case_pref == "lowercase":
                    for comp in components:
                        if comp["attribute"] != comp["attribute"].lower():
                            issues.append(
                                f"Attribute '{comp['attribute']}' should be lowercase"
                            )
                            suggestions.append(
                                f"Use '{comp['attribute'].lower()}' instead"
                            )

                return {
                    "valid": len(issues) == 0,
                    "issues": issues,
                    "suggestions": suggestions,
                    "components_count": len(components),
                }

            except Exception as e:
                return {
                    "valid": False,
                    "issues": [f"DN parsing failed: {e}"],
                    "suggestions": ["Check DN syntax"],
                }

    class SubjectTransformer:
        """Advanced subject transformation utilities for cross-server compatibility."""

        @classmethod
        def classify_subject_type(cls, subject_str: str) -> str:
            """Classify subject string into standard categories."""
            if not subject_str:
                return "unknown"

            # Standard classifications
            if subject_str == "*":
                return "anonymous"
            if subject_str == "self":
                return "self"
            if subject_str.startswith('group="') and subject_str.endswith('"'):
                return "group_dn"
            if subject_str.startswith('"') and subject_str.endswith('"'):
                return "user_dn"
            if subject_str.startswith("dnattr=(") and subject_str.endswith(")"):
                return "dynamic_group_dnattr"
            if subject_str.startswith("guidattr=(") and subject_str.endswith(")"):
                return "dynamic_group_guidattr"
            if subject_str.startswith("groupattr=(") and subject_str.endswith(")"):
                return "dynamic_group_attr"
            if "userattr=" in subject_str.lower() or "groupdn=" in subject_str.lower():
                return "bind_rules"
            return "user_dn"  # Default assumption

        @classmethod
        def extract_subject_value(cls, subject_str: str, subject_type: str) -> str:
            """Extract the actual value from a subject string based on its type."""
            if subject_type == "group_dn" and subject_str.startswith('group="'):
                return subject_str[7:-1]  # Remove group=" and trailing "
            if subject_type == "user_dn" and subject_str.startswith('"'):
                return subject_str[1:-1]  # Remove surrounding quotes
            if subject_type == "dynamic_group_dnattr":
                return subject_str[8:-1]  # Remove dnattr( and trailing )
            if subject_type == "dynamic_group_guidattr":
                return subject_str[10:-1]  # Remove guidattr( and trailing )
            if subject_type == "dynamic_group_attr":
                return subject_str[11:-1]  # Remove groupattr( and trailing )
            return subject_str  # Return as-is for other types

    class MetadataProcessor:
        """Advanced metadata processing utilities for conversion tracking."""

        @classmethod
        def extract_oid_features(
            cls, metadata: FlextLdifModels.QuirkMetadata | None
        ) -> dict[str, Any]:
            """Extract OID-specific features from metadata."""
            features = {
                "acl_type": "",
                "filter_clause": "",
                "added_object_constraint": "",
                "multi_subjects": [],
                "oid_permissions": [],
                "unconvertible_features": [],
            }

            if (
                not metadata
                or not hasattr(metadata, "extensions")
                or not metadata.extensions
            ):
                return features

            extensions = metadata.extensions
            for key in features:
                if key in extensions:
                    features[key] = extensions[key]

            return features

        @classmethod
        def is_feature_convertible(
            cls, feature_name: str, feature_value: Any, target_server: str
        ) -> bool:
            """Check if a specific feature can be converted to target server format."""
            if not feature_value:
                return True

            # Feature-specific convertibility rules
            if feature_name == "filter_clause":
                return cls._is_filter_convertible(str(feature_value), target_server)
            if feature_name == "added_object_constraint":
                return cls._is_constraint_convertible(str(feature_value), target_server)
            if feature_name == "oid_permissions":
                return cls._are_permissions_convertible(
                    list(feature_value), target_server
                )
            return True  # Unknown features are assumed convertible

        @classmethod
        def _is_filter_convertible(cls, filter_clause: str, target_server: str) -> bool:
            """Check if filter clause is convertible to target server."""
            if not filter_clause:
                return True

            # Simple equality filters are usually convertible
            complex_operators = ["&", "|", "!", ">=", "<=", "~=", "^="]
            has_complex = any(op in filter_clause for op in complex_operators)

            if target_server == FlextLdifConstants.LdapServerType.ORACLE_OUD.value:
                # OUD supports most LDAP filters
                return (
                    not has_complex or len(filter_clause) < 200
                )  # Reasonable complexity limit
            return not has_complex

        @classmethod
        def _is_constraint_convertible(
            cls, constraint: str, target_server: str
        ) -> bool:
            """Check if constraint is convertible to target server."""
            if not constraint:
                return True

            if target_server == FlextLdifConstants.LdapServerType.ORACLE_OUD.value:
                # Simple objectClass constraints convert to targattrfilters
                simple_oc_pattern = r"^objectClass\s*=\s*\w+$"
                return bool(re.match(simple_oc_pattern, constraint.strip()))

            return False  # Conservative approach for unknown servers

        @classmethod
        def _are_permissions_convertible(
            cls, permissions: list[str], target_server: str
        ) -> bool:
            """Check if all permissions are convertible to target server."""
            mapper = FlextLdifUtilities.PermissionMapper
            unsupported = mapper.get_unsupported_permissions(permissions, target_server)
            return len(unsupported) == 0

    class SchemaTransformer:
        """Advanced schema transformation utilities for cross-server migrations."""

        # Schema object class mappings between servers
        OBJECTCLASS_TRANSFORMATION_MAP: ClassVar[dict[tuple[str, str, str], str]] = {
            # === Oracle OID ↔ OUD ===
            ("oracle_oid", "oracle_oud", "orcluser"): "inetOrgPerson",
            ("oracle_oid", "oracle_oud", "orclgroup"): "groupOfNames",
            ("oracle_oid", "oracle_oud", "orclcontainer"): "organizationalUnit",
            ("oracle_oid", "oracle_oud", "orclorganization"): "organization",
            ("oracle_oud", "oracle_oid", "inetOrgPerson"): "orcluser",
            ("oracle_oud", "oracle_oid", "groupOfNames"): "orclgroup",
            # === Active Directory mappings ===
            ("active_directory", "oracle_oud", "user"): "inetOrgPerson",
            ("active_directory", "oracle_oud", "group"): "groupOfNames",
            (
                "active_directory",
                "oracle_oud",
                "organizationalUnit",
            ): "organizationalUnit",
            ("active_directory", "oracle_oud", "container"): "organizationalUnit",
            ("active_directory", "oracle_oud", "computer"): "device",
            ("active_directory", "oracle_oud", "contact"): "organizationalPerson",
            # === 389DS mappings ===
            ("389ds", "oracle_oud", "nsuser"): "inetOrgPerson",
            ("389ds", "oracle_oud", "nsgroup"): "groupOfNames",
            ("389ds", "oracle_oud", "nscontainer"): "organizationalUnit",
            # === OpenLDAP mappings ===
            ("openldap", "oracle_oud", "posixAccount"): "inetOrgPerson",
            ("openldap", "oracle_oud", "posixGroup"): "groupOfNames",
            ("openldap", "oracle_oud", "dcObject"): "domainComponent",
            # === Generic standard mappings ===
            ("*", "*", "person"): "person",
            ("*", "*", "organizationalPerson"): "organizationalPerson",
            ("*", "*", "inetOrgPerson"): "inetOrgPerson",
            ("*", "*", "groupOfNames"): "groupOfNames",
            ("*", "*", "organizationalUnit"): "organizationalUnit",
            ("*", "*", "organization"): "organization",
            ("*", "*", "domainComponent"): "domainComponent",
            ("*", "*", "top"): "top",
        }

        # Required attributes per object class per server
        OBJECTCLASS_REQUIRED_ATTRS: ClassVar[dict[tuple[str, str], list[str]]] = {
            # Oracle OUD requirements
            ("oracle_oud", "inetOrgPerson"): ["cn", "sn"],
            ("oracle_oud", "groupOfNames"): ["cn", "member"],
            ("oracle_oud", "organizationalUnit"): ["ou"],
            ("oracle_oud", "organization"): ["o"],
            ("oracle_oud", "domainComponent"): ["dc"],
            # Oracle OID requirements
            ("oracle_oid", "orcluser"): ["cn", "sn", "orclguid"],
            ("oracle_oid", "orclgroup"): ["cn", "orclguid"],
            ("oracle_oid", "orclcontainer"): ["cn", "orclguid"],
            # Active Directory requirements
            ("active_directory", "user"): ["cn", "sAMAccountName"],
            ("active_directory", "group"): ["cn", "sAMAccountName"],
            ("active_directory", "organizationalUnit"): ["ou"],
            # 389DS requirements
            ("389ds", "nsuser"): ["cn", "sn", "nsUniqueId"],
            ("389ds", "nsgroup"): ["cn", "nsUniqueId"],
        }

        @classmethod
        def transform_objectclass(
            cls, objectclass: str, source_server: str, target_server: str
        ) -> str:
            """Transform object class name between server types."""
            oc_lower = objectclass.lower()

            # Try exact transformation mapping
            key = (source_server, target_server, oc_lower)
            if key in cls.OBJECTCLASS_TRANSFORMATION_MAP:
                return cls.OBJECTCLASS_TRANSFORMATION_MAP[key]

            # Try wildcard mappings
            for wildcard_key in [
                ("*", target_server, oc_lower),
                (source_server, "*", oc_lower),
                ("*", "*", oc_lower),
            ]:
                if wildcard_key in cls.OBJECTCLASS_TRANSFORMATION_MAP:
                    return cls.OBJECTCLASS_TRANSFORMATION_MAP[wildcard_key]

            # Return original if no transformation found
            return objectclass

        @classmethod
        def get_required_attributes(
            cls, objectclass: str, server_type: str
        ) -> list[str]:
            """Get required attributes for an object class on a specific server."""
            oc_lower = objectclass.lower()
            key = (server_type, oc_lower)
            return cls.OBJECTCLASS_REQUIRED_ATTRS.get(key, [])

        @classmethod
        def validate_entry_completeness(
            cls, objectclasses: list[str], attributes: dict[str, Any], server_type: str
        ) -> dict[str, Any]:
            """Validate that entry has all required attributes for its object classes."""
            missing_attrs = []
            warnings = []

            attr_names = {attr.lower() for attr in attributes}

            for oc in objectclasses:
                required = cls.get_required_attributes(oc, server_type)
                missing_attrs.extend(
                    {"objectclass": oc, "missing_attribute": req_attr}
                    for req_attr in required
                    if req_attr.lower() not in attr_names
                )

            return {
                "valid": len(missing_attrs) == 0,
                "missing_attributes": missing_attrs,
                "warnings": warnings,
                "completeness_score": 1.0
                - (len(missing_attrs) / max(1, len(objectclasses))),
            }

        @classmethod
        def suggest_schema_migration_plan(
            cls, entries: list[dict[str, Any]], source_server: str, target_server: str
        ) -> dict[str, Any]:
            """Analyze entries and suggest comprehensive schema migration plan."""
            objectclass_usage = {}
            attribute_usage = {}
            transformation_plan = []
            potential_issues = []

            # Analyze current usage
            for entry in entries:
                objectclasses = entry.get("objectClass", [])
                if isinstance(objectclasses, str):
                    objectclasses = [objectclasses]

                for oc in objectclasses:
                    objectclass_usage[oc] = objectclass_usage.get(oc, 0) + 1

                for attr in entry:
                    if attr != "objectClass":
                        attribute_usage[attr] = attribute_usage.get(attr, 0) + 1

            # Plan object class transformations
            for oc, count in objectclass_usage.items():
                transformed_oc = cls.transform_objectclass(
                    oc, source_server, target_server
                )

                if transformed_oc != oc:
                    transformation_plan.append({
                        "type": "objectclass_transformation",
                        "original": oc,
                        "transformed": transformed_oc,
                        "affected_entries": count,
                    })

                # Check for missing required attributes
                required_attrs = cls.get_required_attributes(
                    transformed_oc, target_server
                )
                potential_issues.extend(
                    {
                        "type": "missing_required_attribute",
                        "objectclass": transformed_oc,
                        "attribute": req_attr,
                        "affected_entries": count,
                    }
                    for req_attr in required_attrs
                    if req_attr not in attribute_usage
                )

            # Plan attribute transformations
            attr_mapper = FlextLdifUtilities.AttributeNameMapper
            for attr, count in attribute_usage.items():
                transformed_attr = attr_mapper.transform_attribute_name(
                    attr, source_server, target_server
                )

                if transformed_attr != attr:
                    transformation_plan.append({
                        "type": "attribute_transformation",
                        "original": attr,
                        "transformed": transformed_attr,
                        "affected_entries": count,
                    })

            return {
                "objectclass_usage": objectclass_usage,
                "attribute_usage": attribute_usage,
                "transformation_plan": transformation_plan,
                "potential_issues": potential_issues,
                "migration_complexity_score": len(transformation_plan)
                + len(potential_issues),
            }

    class OperationalAttributeHandler:
        """Advanced operational attribute handling for server migrations."""

        # Operational attributes per server type
        @classmethod
        def is_operational_attribute(cls, attribute: str, server_type: str) -> bool:
            """Check if attribute is operational for a specific server.

            Uses FlextLdifConstants.OperationalAttributeMappings.OPERATIONAL_ATTRIBUTES.
            """
            operational_attrs = FlextLdifConstants.OperationalAttributeMappings.OPERATIONAL_ATTRIBUTES.get(
                server_type, frozenset()
            )
            return attribute.lower() in {attr.lower() for attr in operational_attrs}

        @classmethod
        def should_preserve_on_migration(cls, attribute: str, server_type: str) -> bool:
            """Check if operational attribute should be preserved during migration.

            Uses FlextLdifConstants.OperationalAttributeMappings.PRESERVE_ON_MIGRATION.
            """
            preserve_attrs = FlextLdifConstants.OperationalAttributeMappings.PRESERVE_ON_MIGRATION.get(
                server_type, frozenset()
            )
            return attribute.lower() in {attr.lower() for attr in preserve_attrs}

        @classmethod
        def filter_operational_attributes(
            cls,
            attributes: dict[str, Any],
            server_type: str,
            preserve_important: bool = True,
        ) -> dict[str, Any]:
            """Filter out operational attributes, optionally preserving important ones."""
            filtered_attrs = {}

            for attr, value in attributes.items():
                if cls.is_operational_attribute(attr, server_type):
                    if preserve_important and cls.should_preserve_on_migration(
                        attr, server_type
                    ):
                        filtered_attrs[attr] = value
                    # Otherwise skip operational attribute
                else:
                    # Keep non-operational attributes
                    filtered_attrs[attr] = value

            return filtered_attrs

        @classmethod
        def transform_operational_attributes(
            cls, attributes: dict[str, Any], source_server: str, target_server: str
        ) -> dict[str, Any]:
            """Transform operational attributes between server types."""
            transformed_attrs = {}
            attr_mapper = FlextLdifUtilities.AttributeNameMapper

            for attr, value in attributes.items():
                # Transform attribute name
                transformed_attr = attr_mapper.transform_attribute_name(
                    attr, source_server, target_server
                )

                # Check if it's operational in source
                if cls.is_operational_attribute(attr, source_server):
                    # Only include if it should be preserved or is operational in target too
                    if cls.should_preserve_on_migration(
                        attr, source_server
                    ) or cls.is_operational_attribute(transformed_attr, target_server):
                        transformed_attrs[transformed_attr] = value
                else:
                    # Non-operational attributes are always included
                    transformed_attrs[transformed_attr] = value

            return transformed_attrs

        @classmethod
        def analyze_operational_compatibility(
            cls, source_server: str, target_server: str
        ) -> dict[str, Any]:
            """Analyze operational attribute compatibility between servers.

            Uses FlextLdifConstants.OperationalAttributeMappings.
            """
            source_ops = FlextLdifConstants.OperationalAttributeMappings.OPERATIONAL_ATTRIBUTES.get(
                source_server, frozenset()
            )
            target_ops = FlextLdifConstants.OperationalAttributeMappings.OPERATIONAL_ATTRIBUTES.get(
                target_server, frozenset()
            )

            compatible = source_ops & target_ops
            source_only = source_ops - target_ops
            target_only = target_ops - source_ops

            # Check which source operational attributes should be preserved
            preserve_source = FlextLdifConstants.OperationalAttributeMappings.PRESERVE_ON_MIGRATION.get(
                source_server, frozenset()
            )
            at_risk = (
                preserve_source & source_only
            )  # Important attrs that won't exist in target

            return {
                "compatible_operational_attrs": sorted(compatible),
                "source_only_operational_attrs": sorted(source_only),
                "target_only_operational_attrs": sorted(target_only),
                "at_risk_important_attrs": sorted(at_risk),
                "compatibility_score": len(compatible) / len(source_ops | target_ops)
                if source_ops | target_ops
                else 1.0,
            }

    class ServerCapabilityMatrix:
        """Advanced server capability analysis for migration planning."""

        # Comprehensive server capability matrix
        SERVER_CAPABILITIES: ClassVar[dict[str, dict[str, Any]]] = {
            "oracle_oid": {
                "max_dn_length": 1000,
                "max_attribute_value_size": 2048,
                "supports_binary_attributes": True,
                "supports_ldapv3": True,
                "supports_ssl_tls": True,
                "supports_sasl": True,
                "supports_virtual_attributes": True,
                "supports_referrals": True,
                "supports_controls": ["persistent_search", "sort", "paged_results"],
                "schema_flexibility": "high",
                "acl_model": "orcl_aci",
                "replication_model": "multimaster",
                "password_policy": "orcl_policy",
                "supported_syntaxes": [
                    "directory_string",
                    "integer",
                    "boolean",
                    "binary",
                    "dn",
                    "guid",
                ],
                "max_concurrent_connections": 10000,
                "performance_tier": "enterprise",
            },
            "oracle_oud": {
                "max_dn_length": 1000,
                "max_attribute_value_size": 4096,
                "supports_binary_attributes": True,
                "supports_ldapv3": True,
                "supports_ssl_tls": True,
                "supports_sasl": True,
                "supports_virtual_attributes": True,
                "supports_referrals": True,
                "supports_controls": [
                    "persistent_search",
                    "sort",
                    "paged_results",
                    "sync_request",
                ],
                "schema_flexibility": "high",
                "acl_model": "rfc_aci",
                "replication_model": "multimaster",
                "password_policy": "rfc_policy",
                "supported_syntaxes": [
                    "directory_string",
                    "integer",
                    "boolean",
                    "binary",
                    "dn",
                    "uuid",
                ],
                "max_concurrent_connections": 20000,
                "performance_tier": "enterprise",
            },
            "active_directory": {
                "max_dn_length": 255,
                "max_attribute_value_size": 1048576,
                "supports_binary_attributes": True,
                "supports_ldapv3": True,
                "supports_ssl_tls": True,
                "supports_sasl": True,
                "supports_virtual_attributes": False,
                "supports_referrals": True,
                "supports_controls": ["paged_results", "sort", "server_sort"],
                "schema_flexibility": "medium",
                "acl_model": "windows_acl",
                "replication_model": "multimaster",
                "password_policy": "windows_policy",
                "supported_syntaxes": [
                    "unicode_string",
                    "integer",
                    "boolean",
                    "binary",
                    "dn",
                    "sid",
                ],
                "max_concurrent_connections": 5000,
                "performance_tier": "enterprise",
            },
            "389ds": {
                "max_dn_length": 512,
                "max_attribute_value_size": 2048,
                "supports_binary_attributes": True,
                "supports_ldapv3": True,
                "supports_ssl_tls": True,
                "supports_sasl": True,
                "supports_virtual_attributes": True,
                "supports_referrals": True,
                "supports_controls": ["persistent_search", "sort", "paged_results"],
                "schema_flexibility": "high",
                "acl_model": "389_aci",
                "replication_model": "multimaster",
                "password_policy": "389_policy",
                "supported_syntaxes": [
                    "directory_string",
                    "integer",
                    "boolean",
                    "binary",
                    "dn",
                ],
                "max_concurrent_connections": 8000,
                "performance_tier": "high",
            },
            "openldap": {
                "max_dn_length": 8192,
                "max_attribute_value_size": 65536,
                "supports_binary_attributes": True,
                "supports_ldapv3": True,
                "supports_ssl_tls": True,
                "supports_sasl": True,
                "supports_virtual_attributes": True,
                "supports_referrals": True,
                "supports_controls": ["sort", "paged_results", "sync_request"],
                "schema_flexibility": "very_high",
                "acl_model": "openldap_acl",
                "replication_model": "configurable",
                "password_policy": "ppolicy",
                "supported_syntaxes": [
                    "directory_string",
                    "integer",
                    "boolean",
                    "binary",
                    "dn",
                    "uuid",
                ],
                "max_concurrent_connections": 4000,
                "performance_tier": "medium",
            },
        }

        @classmethod
        def get_server_capabilities(cls, server_type: str) -> dict[str, Any]:
            """Get comprehensive capability information for a server."""
            return cls.SERVER_CAPABILITIES.get(server_type, {})

        @classmethod
        def analyze_migration_feasibility(
            cls,
            source_server: str,
            target_server: str,
            migration_requirements: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            """Analyze feasibility of migration between servers."""
            source_caps = cls.get_server_capabilities(source_server)
            target_caps = cls.get_server_capabilities(target_server)

            if not source_caps or not target_caps:
                return {"feasible": False, "reason": "Unknown server type capabilities"}

            compatibility_issues = []
            warnings = []
            migration_notes = []

            # Check basic compatibility
            if source_caps.get("max_dn_length", 0) > target_caps.get(
                "max_dn_length", 0
            ):
                compatibility_issues.append({
                    "issue": "DN length limit",
                    "source_limit": source_caps.get("max_dn_length"),
                    "target_limit": target_caps.get("max_dn_length"),
                    "severity": "high",
                })

            if source_caps.get("max_attribute_value_size", 0) > target_caps.get(
                "max_attribute_value_size", 0
            ):
                warnings.append({
                    "warning": "Attribute value size limit",
                    "source_limit": source_caps.get("max_attribute_value_size"),
                    "target_limit": target_caps.get("max_attribute_value_size"),
                    "severity": "medium",
                })

            # Check ACL model compatibility
            source_acl = source_caps.get("acl_model")
            target_acl = target_caps.get("acl_model")
            if source_acl != target_acl:
                migration_notes.append({
                    "note": "ACL model transformation required",
                    "source_model": source_acl,
                    "target_model": target_acl,
                    "complexity": "high" if source_acl == "orcl_aci" else "medium",
                })

            # Check schema flexibility
            source_schema = source_caps.get("schema_flexibility", "medium")
            target_schema = target_caps.get("schema_flexibility", "medium")
            schema_compatibility = cls._compare_flexibility(
                source_schema, target_schema
            )

            if schema_compatibility < 0:
                warnings.append({
                    "warning": "Target server has lower schema flexibility",
                    "source_flexibility": source_schema,
                    "target_flexibility": target_schema,
                    "impact": "May require schema modifications",
                })

            # Calculate overall feasibility score
            feasibility_score = 1.0
            feasibility_score -= len(compatibility_issues) * 0.3
            feasibility_score -= len(warnings) * 0.1
            feasibility_score = max(0.0, feasibility_score)

            return {
                "feasible": len(compatibility_issues) == 0,
                "feasibility_score": feasibility_score,
                "compatibility_issues": compatibility_issues,
                "warnings": warnings,
                "migration_notes": migration_notes,
                "complexity_assessment": cls._assess_migration_complexity(
                    len(compatibility_issues), len(warnings), len(migration_notes)
                ),
            }

        @classmethod
        def _compare_flexibility(cls, source: str, target: str) -> int:
            """Compare schema flexibility levels. Returns: 1 (target higher), 0 (equal), -1 (source higher)."""
            flexibility_order = ["low", "medium", "high", "very_high"]

            try:
                source_idx = flexibility_order.index(source)
                target_idx = flexibility_order.index(target)

                if target_idx > source_idx:
                    return 1
                if target_idx == source_idx:
                    return 0
                return -1
            except ValueError:
                return 0  # Unknown flexibility levels

        @classmethod
        def _assess_migration_complexity(
            cls, issues: int, warnings: int, notes: int
        ) -> str:
            """Assess overall migration complexity."""
            total_complexity = issues * 3 + warnings * 2 + notes * 1

            if total_complexity == 0:
                return "trivial"
            if total_complexity <= 3:
                return "low"
            if total_complexity <= 8:
                return "medium"
            if total_complexity <= 15:
                return "high"
            return "very_high"

        @classmethod
        def recommend_migration_strategy(
            cls,
            source_server: str,
            target_server: str,
            data_volume: str = "medium",  # small, medium, large, enterprise
        ) -> dict[str, Any]:
            """Recommend comprehensive migration strategy."""
            feasibility = cls.analyze_migration_feasibility(
                source_server, target_server
            )

            if not feasibility["feasible"]:
                return {
                    "recommended_strategy": "not_recommended",
                    "reason": "Critical compatibility issues",
                    "issues": feasibility["compatibility_issues"],
                }

            complexity = feasibility["complexity_assessment"]

            # Base strategy recommendations
            strategy_map = {
                "trivial": "direct_migration",
                "low": "phased_migration",
                "medium": "staged_migration_with_validation",
                "high": "gradual_migration_with_fallback",
                "very_high": "custom_migration_with_extensive_testing",
            }

            recommended_strategy = strategy_map.get(
                complexity, "custom_migration_with_extensive_testing"
            )

            # Adjust for data volume
            if data_volume in {"large", "enterprise"}:
                if recommended_strategy == "direct_migration":
                    recommended_strategy = "phased_migration"
                elif recommended_strategy == "phased_migration":
                    recommended_strategy = "staged_migration_with_validation"

            return {
                "recommended_strategy": recommended_strategy,
                "complexity_assessment": complexity,
                "feasibility_score": feasibility["feasibility_score"],
                "estimated_effort": cls._estimate_migration_effort(
                    complexity, data_volume
                ),
                "key_risk_factors": [
                    issue["issue"] for issue in feasibility["compatibility_issues"]
                ],
                "migration_phases": cls._generate_migration_phases(
                    recommended_strategy
                ),
                "required_tools": cls._recommend_migration_tools(
                    source_server, target_server, complexity
                ),
            }

        @classmethod
        def _estimate_migration_effort(
            cls, complexity: str, data_volume: str
        ) -> dict[str, Any]:
            """Estimate migration effort in person-days."""
            base_effort = {
                "trivial": 1,
                "low": 3,
                "medium": 10,
                "high": 30,
                "very_high": 90,
            }

            volume_multiplier = {
                "small": 1.0,
                "medium": 1.5,
                "large": 3.0,
                "enterprise": 5.0,
            }

            base_days = base_effort.get(complexity, 90)
            multiplier = volume_multiplier.get(data_volume, 1.5)

            estimated_days = int(base_days * multiplier)

            return {
                "estimated_person_days": estimated_days,
                "estimated_calendar_weeks": max(1, estimated_days // 5),
                "confidence": "medium" if complexity in {"low", "medium"} else "low",
            }

        @classmethod
        def _generate_migration_phases(cls, strategy: str) -> list[dict[str, Any]]:
            """Generate migration phases based on strategy."""
            phase_templates = {
                "direct_migration": [
                    {
                        "phase": "preparation",
                        "description": "Schema analysis and validation",
                    },
                    {"phase": "migration", "description": "Direct data transfer"},
                    {
                        "phase": "validation",
                        "description": "Data integrity verification",
                    },
                ],
                "phased_migration": [
                    {
                        "phase": "preparation",
                        "description": "Migration planning and tool setup",
                    },
                    {
                        "phase": "pilot",
                        "description": "Small subset migration and testing",
                    },
                    {
                        "phase": "bulk_migration",
                        "description": "Full data migration in batches",
                    },
                    {"phase": "validation", "description": "Comprehensive validation"},
                    {"phase": "cutover", "description": "Production cutover"},
                ],
                "staged_migration_with_validation": [
                    {
                        "phase": "analysis",
                        "description": "Comprehensive compatibility analysis",
                    },
                    {
                        "phase": "preparation",
                        "description": "Environment setup and tool configuration",
                    },
                    {
                        "phase": "stage_1",
                        "description": "Schema and configuration migration",
                    },
                    {
                        "phase": "stage_2",
                        "description": "Data migration with transformation",
                    },
                    {
                        "phase": "validation",
                        "description": "Multi-level validation and testing",
                    },
                    {
                        "phase": "cutover",
                        "description": "Coordinated production cutover",
                    },
                ],
            }

            return phase_templates.get(
                strategy, phase_templates["staged_migration_with_validation"]
            )

        @classmethod
        def _recommend_migration_tools(
            cls, source_server: str, target_server: str, complexity: str
        ) -> list[str]:
            """Recommend migration tools based on server types and complexity."""
            base_tools = ["FlextLdifUtilities", "LDAP Browser", "Schema Validator"]

            server_specific_tools = {
                ("oracle_oid", "oracle_oud"): [
                    "Oracle Directory Integration Platform",
                    "ODSM",
                ],
                ("active_directory", "oracle_oud"): [
                    "Microsoft ADSI",
                    "PowerShell AD Module",
                ],
                ("389ds", "oracle_oud"): ["389 DS Migration Tools"],
                ("openldap", "oracle_oud"): ["OpenLDAP Migration Scripts"],
            }

            complexity_tools = {
                "high": ["Custom Transformation Scripts", "Data Quality Tools"],
                "very_high": ["Professional Services", "Custom Development"],
            }

            recommended = base_tools.copy()

            # Add server-specific tools
            key = (source_server, target_server)
            if key in server_specific_tools:
                recommended.extend(server_specific_tools[key])

            # Add complexity-based tools
            if complexity in complexity_tools:
                recommended.extend(complexity_tools[complexity])

            return recommended

    class Acl:
        """Universal ACL processing utilities with advanced configuration and hooks.

        🚀 **DRY Design**: Single utilities handle ALL LDAP server ACL formats
        🔧 **Parametrizable**: Extensive configuration without complexity
        🪝 **Hook-Based**: Extensible through simple hook functions
        📚 **Server-Driven**: Server classes provide all configuration data
        """

        @classmethod
        def parser(
            cls,
            acl_content: str,
            *,
            # Required Server Configuration (provided by server quirks)
            server_type: str,
            patterns: dict[str, str],
            permissions_map: dict[str, list[str]] | None = None,
            subject_transforms: dict[str, Any] | None = None,
            # Processing Hooks
            pre_parse_hook: Any | None = None,
            post_parse_hook: Any | None = None,
            permission_hook: Any | None = None,
            subject_hook: Any | None = None,
            metadata_hook: Any | None = None,
            # Advanced Options
            extract_metadata: bool = True,
            preserve_original: bool = True,
            normalize_output: bool = True,
            strict_mode: bool = False,
            # Feature Extraction
            extract_filters: bool = True,
            extract_constraints: bool = True,
            extract_multi_subjects: bool = True,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Universal ACL parser with server-provided configuration and hooks.

            **Server-Driven Design:**
            Server quirk classes provide ALL configuration data (patterns, mappings, transforms)
            to this universal parser. No built-in server knowledge, fully configurable.

            **Usage from Server Classes:**
            ```python
            # OID server quirk calls universal parser
            return FlextLdifUtilities.Acl.parser(
                acl_content,
                server_type="oracle_oid",
                patterns=self._get_oid_patterns(),
                permissions_map=self._get_oid_permissions(),
                subject_transforms=self._get_oid_transforms(),
                extract_filters=True,
                extract_constraints=True,
            )
            ```

            **Hook Functions:**
            - pre_parse_hook(content, server_type) -> modified_content
            - post_parse_hook(acl_model, metadata) -> final_acl_model
            - permission_hook(perm_list, server_type) -> processed_permissions
            - subject_hook(subject_str, server_type) -> (type, value)
            - metadata_hook(raw_metadata, server_type) -> processed_metadata

            Args:
                acl_content: Raw ACL string to parse
                server_type: Target server type name
                patterns: Regex patterns for ACL components {component: pattern}
                permissions_map: Permission transformation rules {perm: [mapped_perms]}
                subject_transforms: Subject processing functions {pattern: callable}
                *_hook: Processing hooks for customization
                extract_*: Feature extraction flags
                strict_mode: Fail on any parsing issues

            Returns:
                FlextResult with parsed Acl model or error details

            """
            try:
                # Validate input content
                if not acl_content or not acl_content.strip():
                    return FlextResult.fail(
                        "ACL content cannot be empty or whitespace-only"
                    )

                # Basic format validation - must contain some recognizable ACL structure
                if not any(
                    keyword in acl_content.lower()
                    for keyword in [
                        "access",
                        "allow",
                        "deny",
                        "aci:",
                        "orclaci:",
                        "orclentrylevelaci:",
                    ]
                ):
                    return FlextResult.fail(
                        f"Invalid ACL format: no recognizable ACL keywords found in '{acl_content[:50]}...'"
                    )

                # Apply pre-parse hook
                if pre_parse_hook:
                    acl_content = pre_parse_hook(acl_content, server_type)

                # Use server-provided configuration (required parameters)
                server_patterns = patterns
                server_permissions = permissions_map or {}
                server_transforms = subject_transforms or {}

                # Initialize result containers
                metadata: dict[str, Any] = (
                    {"server_type": server_type, "original_content": acl_content}
                    if extract_metadata
                    else {}
                )

                # Phase 1: Extract ACL type and basic structure
                acl_type = "unknown"
                if "acl_type" in server_patterns:
                    type_match = re.search(server_patterns["acl_type"], acl_content)
                    if type_match:
                        acl_type = (
                            type_match.group(1)
                            if type_match.groups()
                            else type_match.group(0)
                        )
                        if extract_metadata:
                            metadata["acl_type"] = acl_type

                # Phase 2: Extract target specification
                target_dn = "*"
                target_attrs: list[str] = []

                if "target" in server_patterns:
                    target_match = re.search(server_patterns["target"], acl_content)
                    if target_match:
                        # Flexible target extraction based on groups
                        for group in target_match.groups() or []:
                            if group:
                                if "entry" in group.lower():
                                    target_dn = "*"
                                elif "attr" in server_patterns["target"].lower():
                                    target_attrs = [
                                        attr.strip() for attr in group.split(",")
                                    ]
                                else:
                                    target_dn = group
                                break

                # Phase 3: Extract subject with transformations
                subject_type = "anonymous"
                subject_value = "*"

                if "subject" in server_patterns:
                    subject_match = re.search(server_patterns["subject"], acl_content)
                    if subject_match:
                        subject_str = (
                            subject_match.group(1)
                            if subject_match.groups()
                            else subject_match.group(0)
                        )

                        # Apply subject hook or built-in transforms
                        if subject_hook:
                            subject_type, subject_value = subject_hook(
                                subject_str, server_type
                            )
                        else:
                            # Apply server-provided transformations
                            transformed = False
                            for pattern, transform_func in server_transforms.items():
                                if (
                                    pattern in subject_str.lower()
                                    or subject_str.startswith(pattern)
                                ):
                                    if callable(transform_func):
                                        # Extract parameter for transform (e.g., attr from dnattr=(...))
                                        if "=" in subject_str and "(" in subject_str:
                                            param = re.search(
                                                r"=\(([^)]+)\)", subject_str
                                            )
                                            param_value = (
                                                param.group(1) if param else subject_str
                                            )
                                        else:
                                            param_value = subject_str
                                        # Type narrowing: transform_func is callable that returns tuple[str, str]
                                        transform_result = transform_func(param_value)
                                        if (
                                            isinstance(transform_result, tuple)
                                            and len(transform_result) == 2
                                        ):
                                            subject_type, subject_value = (
                                                transform_result
                                            )
                                        else:
                                            # Fallback if transform doesn't return expected tuple
                                            subject_type = "unknown"
                                            subject_value = str(transform_result)
                                        transformed = True
                                        break

                            if not transformed:
                                # Default subject processing
                                if subject_str.startswith('"') and subject_str.endswith(
                                    '"'
                                ):
                                    subject_type, subject_value = (
                                        "user_dn",
                                        subject_str.strip('"'),
                                    )
                                elif "group=" in subject_str:
                                    subject_type, subject_value = (
                                        "group_dn",
                                        subject_str.split('="')[1].rstrip('"'),
                                    )
                                else:
                                    subject_type, subject_value = "user_dn", subject_str

                # Phase 4: Extract and process permissions
                permissions_data = {}
                raw_permissions = []

                if "permissions" in server_patterns:
                    perm_match = re.search(server_patterns["permissions"], acl_content)
                    if perm_match:
                        perm_str = (
                            perm_match.group(1)
                            if perm_match.groups()
                            else perm_match.group(0)
                        )
                        raw_permissions = [p.strip() for p in perm_str.split(",")]

                        # Apply permission hook or server mapping
                        if permission_hook:
                            processed_perms = permission_hook(
                                raw_permissions, server_type
                            )
                            raw_permissions = processed_perms

                        # Map permissions using server-provided rules
                        for perm in raw_permissions:
                            perm_lower = perm.lower()
                            if perm_lower in server_permissions:
                                # Map to multiple permissions if needed
                                for mapped_perm in server_permissions[perm_lower]:
                                    permissions_data[mapped_perm] = True
                            else:
                                # Direct permission
                                permissions_data[perm_lower] = True

                # Phase 5: Advanced feature extraction (if enabled)
                if extract_metadata:
                    # Extract filters
                    if extract_filters and "filter" in server_patterns:
                        filter_match = re.search(server_patterns["filter"], acl_content)
                        if filter_match:
                            filter_clause = filter_match.group(1)
                            metadata["filter_clause"] = filter_clause
                            # Check for complex expressions
                            if any(
                                op in filter_clause
                                for op in ["&", "|", "!", ">=", "<=", "~="]
                            ):
                                if "complex_features" not in metadata:
                                    metadata["complex_features"] = []
                                metadata["complex_features"].append("complex_filter")

                    # Extract constraints
                    if extract_constraints and "constraint" in server_patterns:
                        constraint_match = re.search(
                            server_patterns["constraint"], acl_content
                        )
                        if constraint_match:
                            constraint = constraint_match.group(1)
                            metadata["constraint"] = constraint
                            if "complex_features" not in metadata:
                                metadata["complex_features"] = []
                            metadata["complex_features"].append("constraint")

                    # Extract multi-subjects
                    if extract_multi_subjects and "subject" in server_patterns:
                        all_subjects = re.findall(
                            server_patterns["subject"], acl_content
                        )
                        if len(all_subjects) > 1:
                            metadata["multi_subjects"] = all_subjects
                            if "complex_features" not in metadata:
                                metadata["complex_features"] = []
                            metadata["complex_features"].append("multi_subject")

                # Apply metadata hook
                if metadata_hook and extract_metadata:
                    metadata = metadata_hook(metadata, server_type)

                # Phase 6: Build final ACL model
                # Convert server_type str to ServerType literal
                server_type_literal: FlextLdifConstants.LiteralTypes.ServerType = cast(
                    "FlextLdifConstants.LiteralTypes.ServerType", server_type
                )
                acl_model = FlextLdifModels.Acl(
                    name=f"{server_type.title()} ACL - {acl_type}",
                    target=FlextLdifModels.AclTarget(
                        target_dn=target_dn, attributes=target_attrs
                    ),
                    subject=FlextLdifModels.AclSubject(
                        subject_type=subject_type, subject_value=subject_value
                    ),
                    permissions=FlextLdifModels.AclPermissions(**permissions_data)
                    if permissions_data
                    else None,
                    server_type=server_type_literal,
                    raw_acl=acl_content if preserve_original else "",
                    metadata=FlextLdifModels.QuirkMetadata(
                        server_type=server_type, extensions=metadata
                    )
                    if extract_metadata
                    else None,
                )

                # Apply post-parse hook
                if post_parse_hook:
                    acl_model = post_parse_hook(acl_model, metadata)

                # Normalize output if requested
                if normalize_output:
                    # Ensure required fields are set
                    if not acl_model.permissions:
                        acl_model = acl_model.model_copy(
                            update={"permissions": FlextLdifModels.AclPermissions()}
                        )

                return FlextResult.ok(acl_model)

            except Exception as e:
                error_msg = f"Universal ACL parsing failed for {server_type}: {e}"
                if strict_mode:
                    raise
                return FlextResult.fail(error_msg)


__all__ = ["FlextLdifUtilities"]
