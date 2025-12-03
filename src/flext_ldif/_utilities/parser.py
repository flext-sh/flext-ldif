"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64
import contextlib
import re
from collections.abc import Callable
from typing import TypedDict, cast

from flext_core import FlextLogger, FlextResult, FlextRuntime
from flext_core.typings import t

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif._utilities.oid import FlextLdifUtilitiesOID
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.typings import FlextLdifTypes

logger = FlextLogger(__name__)


# RFC 2849 LDIF format constants - use directly from FlextLdifConstants
# (no local aliases)
# Use FlextLdifConstants.LDIF_BASE64_INDICATOR, LDIF_REGULAR_INDICATOR,
# LDIF_DEFAULT_ENCODING directly


class MetadataDict(TypedDict, total=False):
    """Type-safe dictionary for parsed metadata structures."""

    extensions: FlextLdifTypes.Extensions.ExtensionsDict | None
    # Other metadata fields


type EntryAttributesDict = dict[str, list[str]]
"""Type alias for LDIF entry attributes.

Maps attribute names to lists of values (RFC 2849 format).
Includes dynamic LDAP attribute names (cn, sn, mail, etc.) and
internal metadata fields (_original_dn_line, _original_lines, _base64_dn).
"""

# Type for raw entry dictionaries during parsing (before model conversion)
type RawEntryDict = dict[str, str | list[str] | set[str]]
"""Type alias for raw entry dictionaries during LDIF parsing.

Used internally during parsing before conversion to Entry models.
Values can be strings (single-valued), lists (multi-valued), or sets (base64 tracking).
"""


# Type aliases removed - use types directly from FlextLdifTypes


class FlextLdifUtilitiesParser:
    """Generic LDIF parsing utilities - simple helper functions.

    # LEGACY: Was FlextLdifUtilities.LdifParser
    # Now: Simple pure functions for schema/LDIF parsing
    # Use: parser.py (FlextLdifParser) for full LDIF parsing with quirks
    """

    @staticmethod
    def ext(
        metadata: MetadataDict,
    ) -> FlextLdifTypes.Extensions.ExtensionsDict:
        """Extract extension information from parsed metadata."""
        result = metadata.get("extensions")
        if result is None or not isinstance(result, dict):
            empty: FlextLdifTypes.Extensions.ExtensionsDict = {}
            return empty
        return result

    @staticmethod
    def extract_oid(definition: str) -> str | None:
        """Extract OID from schema definition string.

        Generic method to extract OID (numeric dot-separated) from schema
        definitions. Works for both attribute and objectClass definitions.

        Args:
            definition: Schema definition string (e.g., "( 2.5.4.3 NAME 'cn' ... )")

        Returns:
            Extracted OID string or None if not found

        """
        if not definition or not isinstance(definition, str):
            return None

        # Match OID pattern: opening parenthesis followed by numeric OID
        oid_pattern = re.compile(r"\(\s*([0-9.]+)")
        match = re.match(oid_pattern, definition.strip())
        return match.group(1) if match else None

    @staticmethod
    def extract_optional_field(
        definition: str,
        pattern: re.Pattern[str] | str,
        default: str | None = None,
    ) -> str | None:
        """Extract optional field via regex pattern.

        Generic method to extract optional fields from schema definitions.

        Args:
            definition: Schema definition string
            pattern: Compiled regex pattern or pattern string
            default: Default value if not found

        Returns:
            Extracted value or default

        """
        if not definition:
            return default

        if isinstance(pattern, str):
            pattern = re.compile(pattern)

        match = re.search(pattern, definition)
        return match.group(1) if match else default

    @staticmethod
    def extract_boolean_flag(
        definition: str,
        pattern: re.Pattern[str] | str,
    ) -> bool:
        """Check if boolean flag exists in definition.

        Generic method to check for boolean flags in schema definitions.

        Args:
            definition: Schema definition string
            pattern: Compiled regex pattern or pattern string

        Returns:
            True if flag found, False otherwise

        """
        if not definition:
            return False

        if isinstance(pattern, str):
            pattern = re.compile(pattern)

        return re.search(pattern, definition) is not None

    @staticmethod
    def extract_extensions(
        definition: str,
    ) -> FlextLdifTypes.Extensions.ExtensionsDict:
        """Extract extension information from schema definition string.

        Simple helper to extract X- extensions, DESC, ORDERING, SUBSTR from
        schema attribute/objectClass definitions.

        # LEGACY: Was part of LdifParser.extract_extensions
        """
        if not definition or not isinstance(definition, str):
            return {}

        extensions: FlextLdifTypes.Extensions.ExtensionsDict = {}

        # Extract X- extensions (custom properties)
        x_pattern = re.compile(
            r'X-([A-Z0-9_-]+)\s+["\']?([^"\']*)["\']?(?:\s|$)',
            re.IGNORECASE,
        )
        for match in x_pattern.finditer(definition):
            key = f"X-{match.group(1)}"
            value = match.group(2).strip()
            extensions[key] = value

        # Extract DESC (description) if present
        desc_pattern = re.compile(r"DESC\s+['\"]([^'\"]*)['\"]")
        desc_match = desc_pattern.search(definition)
        if desc_match:
            extensions["DESC"] = desc_match.group(1)

        # Extract ORDERING if present
        ordering_pattern = re.compile(r"ORDERING\s+([A-Za-z0-9_-]+)")
        ordering_match = ordering_pattern.search(definition)
        if ordering_match:
            extensions["ORDERING"] = ordering_match.group(1)

        # Extract SUBSTR if present
        substr_pattern = re.compile(r"SUBSTR\s+([A-Za-z0-9_-]+)")
        substr_match = substr_pattern.search(definition)
        if substr_match:
            extensions["SUBSTR"] = substr_match.group(1)

        return extensions

    @staticmethod
    def unfold_lines(ldif_content: str) -> list[str]:
        """Unfold LDIF lines folded across multiple lines per RFC 2849 §3.

        RFC 2849 §3: Folded lines are created by inserting a line separator
        (CRLF or LF) followed by exactly one space. This function reverses
        that process by joining continuation lines.

        ABNF Grammar (RFC 2849):
            ; Long lines may be folded by inserting:
            ; SEP (CRLF or LF) followed by exactly one SPACE or HTAB
            ; Continuation lines start with exactly one whitespace char

        Args:
            ldif_content: Raw LDIF content with potentially folded lines

        Returns:
            List of unfolded logical lines

        """
        lines: list[str] = []
        current_line = ""
        continuation_space = FlextLdifConstants.Rfc.LINE_CONTINUATION_SPACE

        for raw_line in ldif_content.split(FlextLdifConstants.Rfc.LINE_SEPARATOR):
            if raw_line.startswith(continuation_space) and current_line:
                # Continuation line - append to current (skip leading space)
                current_line += raw_line[1:]
            elif raw_line.startswith("\t") and current_line:
                # RFC 2849: TAB is also valid continuation char
                current_line += raw_line[1:]
            else:
                # New logical line
                if current_line:
                    lines.append(current_line)
                current_line = raw_line

        if current_line:
            lines.append(current_line)

        return lines

    @staticmethod
    def _process_ldif_line(
        line: str,
        current_dn: str | None,
        current_attrs: EntryAttributesDict,
        entries: list[tuple[str, EntryAttributesDict]],
    ) -> tuple[str | None, EntryAttributesDict]:
        """Process single LDIF line with RFC 2849 base64 detection.

        Root Cause Fix: Correctly handle :: (base64) vs : (regular) indicators.

        RFC 2849 Section 2:
        - attr: value  → Regular value (text)
        - attr:: base64 → Base64-encoded value (UTF-8, binary, special chars)
        - attr:< URL   → URL-referenced value
        - #comment     → Comment line (MUST be ignored)

        Previous Bug: line.partition(":") split on FIRST colon only.
        For "dn:: Y249...", it produced key="dn:", value=": Y249..." (extra colon!)
        This caused base64.b64decode(": Y249...") to fail silently.

        ZERO DATA LOSS: Preserves original line string in metadata for round-trip.

        Args:
            line: Unfolded LDIF line
            current_dn: Current entry DN (or None if no entry yet)
            current_attrs: Current entry attributes
            entries: List to append completed entries

        Returns:
            Tuple of (updated_dn, updated_attrs)

        """
        # RFC 2849 § 2: Empty lines terminate current entry
        if not line:
            if current_dn is not None:
                entries.append((current_dn, current_attrs))
            return None, {}

        # RFC 2849 § 2: Lines starting with # are comments (MUST be ignored)
        if line.startswith("#"):
            return current_dn, current_attrs

        if FlextLdifConstants.LDIF_REGULAR_INDICATOR not in line:
            return current_dn, current_attrs

        # ZERO DATA LOSS: Store original line string for metadata preservation
        original_line = line

        # RFC 2849: Detect base64 (::) vs regular (:) indicator
        is_base64 = False
        if FlextLdifConstants.LDIF_BASE64_INDICATOR in line:
            # Base64-encoded value (RFC 2849 Section 2)
            # Split on :: to get key and base64 value
            key, value = line.split(FlextLdifConstants.LDIF_BASE64_INDICATOR, 1)
            key = key.strip()
            value = value.strip()
            is_base64 = True

            # Decode base64 to UTF-8 string
            with contextlib.suppress(ValueError, UnicodeDecodeError):
                value = base64.b64decode(value).decode(
                    FlextLdifConstants.LDIF_DEFAULT_ENCODING,
                )
        else:
            # Regular text value (RFC 2849 Section 2)
            key, _, value = line.partition(FlextLdifConstants.LDIF_REGULAR_INDICATOR)
            key = key.strip()
            value = value.lstrip()  # Preserve trailing spaces per RFC 2849

        # Handle DN line (starts new entry)
        if key.lower() == "dn":
            if current_dn is not None:
                entries.append((current_dn, current_attrs))

            # Track if DN was base64-encoded (for metadata preservation)
            new_attrs: EntryAttributesDict = {}
            if is_base64:
                # Store metadata flag for server layer to preserve
                new_attrs["_base64_dn"] = ["true"]

            # ZERO DATA LOSS: Store original DN line for metadata
            new_attrs["_original_dn_line"] = [original_line]

            return value, new_attrs

        # Regular attribute line (add to current entry)
        # ZERO DATA LOSS: Store original line for each attribute
        if "_original_lines" not in current_attrs:
            current_attrs["_original_lines"] = []
        current_attrs["_original_lines"].append(original_line)

        current_attrs.setdefault(key, []).append(value)
        return current_dn, current_attrs

    @staticmethod
    def parse_ldif_lines(
        ldif_content: str,
    ) -> list[tuple[str, EntryAttributesDict]]:
        """Parse LDIF content into (dn, attributes_dict) tuples - RFC 2849 compliant.

        Returns list of (dn, {attr: [values...]}) tuples where:
        - dn: Distinguished Name string
        - attributes: dict mapping attribute names to lists of values

        Handles: Multi-line folding, base64-encoded values, empty lines, multiple DNs.

        # LEGACY: Was FlextLdifUtilities.LdifParser.parse_ldif_lines
        # Used by: rfc.py Entry quirk for LDIF content parsing
        """
        if not ldif_content or not isinstance(ldif_content, str):
            return []

        entries: list[tuple[str, EntryAttributesDict]] = []
        current_dn: str | None = None
        current_attrs: EntryAttributesDict = {}
        unfolded_lines = FlextLdifUtilitiesParser.unfold_lines(ldif_content)

        for raw_line in unfolded_lines:
            line = raw_line.rstrip("\r\n").strip()
            current_dn, current_attrs = FlextLdifUtilitiesParser._process_ldif_line(
                line,
                current_dn,
                current_attrs,
                entries,
            )

        if current_dn is not None:
            entries.append((current_dn, current_attrs))
        return entries

    @staticmethod
    def parse_attribute_line(line: str) -> tuple[str, str, bool] | None:
        """Parse LDIF attribute line into name, value, and base64 flag.

        Args:
            line: LDIF attribute line (e.g., "cn: value" or "userCertificate:: base64")

        Returns:
            Tuple of (attr_name, attr_value, is_base64) or None if not an attribute line

        """
        if ":" not in line:
            return None

        attr_name, attr_value = line.split(":", 1)
        attr_name = attr_name.strip()
        attr_value = attr_value.strip()

        # Check for base64 encoding (::)
        is_base64 = False
        if attr_value.startswith(":"):
            is_base64 = True
            attr_value = attr_value[1:].strip()

        return (attr_name, attr_value, is_base64)

    @staticmethod
    def finalize_pending_attribute(
        current_attr: str | None,
        current_values: list[str],
        entry_dict: RawEntryDict,
    ) -> None:
        """Finalize and save pending attribute to entry dictionary.

        Args:
            current_attr: Current attribute name
            current_values: Accumulated attribute values
            entry_dict: Entry dictionary to update

        """
        if not current_attr or not current_values:
            return

        # Avoid overwriting _base64_attrs metadata
        if current_attr == "_base64_attrs":
            return

        if len(current_values) == 1:
            entry_dict[current_attr] = current_values[0]
        else:
            entry_dict[current_attr] = current_values

    @staticmethod
    def handle_multivalued_attribute(
        attr_name: str,
        attr_value: str,
        entry_dict: RawEntryDict,
    ) -> bool:
        """Handle multi-valued attribute accumulation.

        Args:
            attr_name: Attribute name
            attr_value: New attribute value to add
            entry_dict: Entry dictionary to update

        Returns:
            True if attribute was handled as multi-valued, False if new attribute

        """
        if attr_name not in entry_dict or attr_name == "_base64_attrs":
            return False

        # Convert to list if needed
        existing = entry_dict[attr_name]
        # Type narrowing: handle set[str] separately as it's not in GeneralValueType
        if isinstance(existing, set):
            # Convert set to list before appending
            entry_dict[attr_name] = [*existing, attr_value]
            return True
        # For str and other types, check if list-like using FlextRuntime
        # Cast to GeneralValueType for type checker (set[str] already handled above)
        if not FlextRuntime.is_list_like(
            cast("t.GeneralValueType", existing),
        ):
            # Type narrowing: existing is str, convert to list
            if isinstance(existing, str):
                entry_dict[attr_name] = [existing, attr_value]
            else:
                entry_dict[attr_name] = [str(existing), attr_value]
        else:
            # Ensure existing is a mutable list before appending
            existing_list = (
                list(existing) if not isinstance(existing, list) else existing
            )
            existing_list.append(attr_value)
            # Type narrowing: convert to list[str] for RawEntryDict
            entry_dict[attr_name] = [
                str(item) if not isinstance(item, str) else item
                for item in existing_list
            ]

        return True

    @staticmethod
    def track_base64_attribute(
        attr_name: str,
        entry_dict: RawEntryDict,
    ) -> None:
        """Track attribute that uses base64 encoding.

        Args:
            attr_name: Attribute name to track
            entry_dict: Entry dictionary to update with metadata

        """
        if "_base64_attrs" not in entry_dict:
            entry_dict["_base64_attrs"] = set()

        if isinstance(entry_dict["_base64_attrs"], set):
            entry_dict["_base64_attrs"].add(attr_name)

    @staticmethod
    def process_ldif_attribute_line(
        line: str,
        current_attr: str | None,
        current_values: list[str],
        entry_dict: RawEntryDict,
    ) -> tuple[str | None, list[str]]:
        """Process LDIF attribute line and update entry state.

        Handles:
        - Parsing attribute name/value
        - Base64 tracking
        - Multi-valued attribute accumulation
        - Finalizing previous attribute

        Args:
            line: LDIF attribute line to process
            current_attr: Current attribute name being accumulated
            current_values: Current attribute values being accumulated
            entry_dict: Entry dictionary to update

        Returns:
            Tuple of (new_current_attr, new_current_values) for state continuation

        """
        # Parse attribute line
        parsed = FlextLdifUtilitiesParser.parse_attribute_line(line)
        if not parsed:
            return (current_attr, current_values)

        attr_name, attr_value, is_base64 = parsed

        # Save previous attribute
        FlextLdifUtilitiesParser.finalize_pending_attribute(
            current_attr,
            current_values,
            entry_dict,
        )

        # Decode base64 values (RFC 2849: :: indicates base64)
        if is_base64:
            FlextLdifUtilitiesParser.track_base64_attribute(attr_name, entry_dict)
            # Decode base64 to UTF-8 string (keep original if decode fails)
            with contextlib.suppress(ValueError, UnicodeDecodeError):
                attr_value = base64.b64decode(attr_value).decode("utf-8")

        # Handle multi-valued attributes
        if FlextLdifUtilitiesParser.handle_multivalued_attribute(
            attr_name,
            attr_value,
            entry_dict,
        ):
            return (None, [])

        return (attr_name, [attr_value])

    @staticmethod
    def parse(
        ldif_lines: list[str],
    ) -> list[RawEntryDict]:
        """Parse list of LDIF lines into entries (simple version).

        # LEGACY: Original simple parser (kept for backward compat if needed)
        # Use: FlextLdifParser for full parsing with quirks
        """
        entries: list[RawEntryDict] = []
        current_entry: RawEntryDict = {}

        for line in ldif_lines:
            if not line.strip():
                if current_entry:
                    entries.append(current_entry)
                    current_entry = {}
                continue

            if ":" in line:
                key, value = line.split(":", 1)
                current_entry[key.strip()] = value.strip()

        if current_entry:
            entries.append(current_entry)

        return entries

    @staticmethod
    def extract_schema_definitions(
        ldif_content: str,
        definition_type: str = "attributeTypes",
        parse_callback: Callable[[str], t.GeneralValueType] | None = None,
    ) -> list[t.GeneralValueType]:
        """Extract and parse schema definitions from LDIF content.

        Generic line-by-line parser that:
        1. Iterates LDIF lines
        2. Identifies definition type (case-insensitive)
        3. Calls parse_callback for each definition
        4. Returns list of parsed models

        Args:
            ldif_content: Raw LDIF content containing schema definitions
            definition_type: Type to extract (attributeTypes, objectClasses, etc.)
            parse_callback: Callable to parse each definition

        Returns:
            List of successfully parsed schema objects

        """
        definitions: list[t.GeneralValueType] = []

        for raw_line in ldif_content.split("\n"):
            line = raw_line.strip()

            # Case-insensitive match for definition type
            if line.lower().startswith(f"{definition_type.lower()}:"):
                definition = line.split(":", 1)[1].strip()
                if parse_callback and callable(parse_callback):
                    result = parse_callback(definition)
                    # Handle FlextResult returns - check for both attributes
                    is_success_attr = getattr(result, "is_success", None)
                    unwrap_method = getattr(result, "unwrap", None)

                    if is_success_attr is not None and unwrap_method is not None:
                        # This is a FlextResult
                        if is_success_attr:
                            definitions.append(unwrap_method())
                    # Direct return value (not FlextResult)
                    elif result is not None:
                        definitions.append(result)
                else:
                    # No callback, just collect definitions
                    definitions.append(definition)

        return definitions

    @staticmethod
    def extract_regex_field(
        definition: str,
        pattern: str,
        default: str | None = None,
    ) -> str | None:
        """Extract field from definition using regex pattern.

        Generic helper to reduce duplication in schema parsing.
        Made public for use by RFC parsers.

        Args:
            definition: Schema definition string
            pattern: Regex pattern to match
            default: Default value if not found

        Returns:
            Extracted value or default

        """
        match = re.search(pattern, definition)
        return match.group(1) if match else default

    @staticmethod
    def extract_syntax_and_length(
        definition: str,
    ) -> tuple[str | None, int | None]:
        """Extract syntax OID and optional length from definition.

        Made public for use by RFC parsers.

        Args:
            definition: Schema definition string

        Returns:
            Tuple of (syntax_oid, length)

        """
        syntax_match = re.search(
            FlextLdifConstants.LdifPatterns.SCHEMA_SYNTAX_LENGTH,
            definition,
        )
        if not syntax_match:
            return (None, None)

        syntax = syntax_match.group(1)

        # ARCHITECTURE: Parser ONLY captures data, does NOT transform
        # Quirks are responsible for cleaning/normalizing syntax OIDs
        # - OID quirk: removes quotes during parse
        # - OUD quirk: ensures no quotes during write
        # Parser preserves raw syntax value from LDIF

        length = int(syntax_match.group(2)) if syntax_match.group(2) else None

        return (syntax, length)

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
        server_type: str | None = None,
    ) -> FlextLdifModelsDomains.QuirkMetadata | None:
        """Build metadata for attribute including extensions.

        Args:
            attr_definition: Original attribute definition
            syntax: Syntax OID
            syntax_validation_error: Validation error if any
            server_type: Server type identifier (e.g., "oid", "oud", "rfc")

        Returns:
            QuirkMetadata or None

        """
        # Use build_attribute_metadata from base.py which handles server_type correctly
        return FlextLdifServersBase.Schema.build_attribute_metadata(
            attr_definition=attr_definition,
            syntax=syntax,
            syntax_validation_error=syntax_validation_error,
            server_type=server_type,
        )

    @staticmethod
    def parse_rfc_attribute(
        attr_definition: str,
        *,
        case_insensitive: bool = False,
    ) -> FlextResult[FlextLdifModelsDomains.SchemaAttribute]:
        """Parse RFC 4512 attribute definition.

        Args:
            attr_definition: RFC 4512 attribute definition string
            case_insensitive: Whether to use case-insensitive pattern matching

        """
        try:
            oid_match = re.match(
                FlextLdifConstants.LdifPatterns.SCHEMA_OID_EXTRACTION,
                attr_definition,
            )
            if not oid_match:
                return FlextResult.fail("RFC attribute parsing failed: missing an OID")
            oid = oid_match.group(1)

            # Extract all string fields using helper
            name = FlextLdifUtilitiesParser.extract_regex_field(
                attr_definition,
                FlextLdifConstants.LdifPatterns.SCHEMA_NAME,
                default=oid,
            )
            desc = FlextLdifUtilitiesParser.extract_regex_field(
                attr_definition,
                FlextLdifConstants.LdifPatterns.SCHEMA_DESC,
            )
            equality = FlextLdifUtilitiesParser.extract_regex_field(
                attr_definition,
                FlextLdifConstants.LdifPatterns.SCHEMA_EQUALITY,
            )
            substr = FlextLdifUtilitiesParser.extract_regex_field(
                attr_definition,
                FlextLdifConstants.LdifPatterns.SCHEMA_SUBSTR,
            )
            ordering = FlextLdifUtilitiesParser.extract_regex_field(
                attr_definition,
                FlextLdifConstants.LdifPatterns.SCHEMA_ORDERING,
            )
            sup = FlextLdifUtilitiesParser.extract_regex_field(
                attr_definition,
                FlextLdifConstants.LdifPatterns.SCHEMA_SUP,
            )
            usage = FlextLdifUtilitiesParser.extract_regex_field(
                attr_definition,
                FlextLdifConstants.LdifPatterns.SCHEMA_USAGE,
            )

            # Extract syntax and length using helper
            syntax, length = FlextLdifUtilitiesParser.extract_syntax_and_length(
                attr_definition,
            )

            # Validate syntax using helper
            syntax_validation_error = FlextLdifUtilitiesParser._validate_syntax_oid(
                syntax,
            )

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
            # (server_type not available in parse_rfc_attribute)
            # Default to "rfc" for RFC parser,
            # actual server_type set by server-specific parsers
            metadata = FlextLdifUtilitiesParser._build_attribute_metadata(
                attr_definition,
                syntax,
                syntax_validation_error,
                server_type="rfc",
            )

            attribute = FlextLdifModelsDomains.SchemaAttribute(
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

            return FlextResult.ok(attribute)

        except (ValueError, TypeError, AttributeError) as e:
            logger.exception(
                "RFC attribute parsing exception",
                attr_definition=attr_definition[:100] if attr_definition else None,
                error=str(e),
                error_type=type(e).__name__,
            )
            return FlextResult.fail(f"RFC attribute parsing failed: {e}")

    @staticmethod
    def parse_rfc_objectclass(
        oc_definition: str,
    ) -> FlextResult[FlextLdifModelsDomains.SchemaObjectClass]:
        """Parse RFC 4512 objectClass definition.

        Args:
            oc_definition: ObjectClass definition string

        """
        try:
            oid_match = re.match(
                FlextLdifConstants.LdifPatterns.SCHEMA_OID_EXTRACTION,
                oc_definition,
            )
            if not oid_match:
                return FlextResult.fail(
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

            metadata_extensions = FlextLdifUtilitiesParser.extract_extensions(
                oc_definition,
            )

            metadata_extensions[FlextLdifConstants.MetadataKeys.ORIGINAL_FORMAT] = (
                oc_definition.strip()
            )

            metadata = (
                FlextLdifModelsDomains.QuirkMetadata(
                    quirk_type="rfc",
                    extensions=FlextLdifModelsMetadata.DynamicMetadata(
                        **metadata_extensions,
                    ),
                )
                if metadata_extensions
                else None
            )

            objectclass = FlextLdifModelsDomains.SchemaObjectClass(
                oid=oid,
                name=name,
                desc=desc,
                sup=sup,
                kind=kind,
                must=must,
                may=may,
                metadata=metadata,
            )

            return FlextResult.ok(objectclass)

        except (ValueError, TypeError, AttributeError) as e:
            logger.exception(
                "RFC objectClass parsing exception",
                oc_definition=oc_definition[:100] if oc_definition else None,
                error=str(e),
                error_type=type(e).__name__,
            )
            return FlextResult.fail(f"RFC objectClass parsing failed: {e}")


__all__ = [
    "FlextLdifUtilitiesParser",
]
