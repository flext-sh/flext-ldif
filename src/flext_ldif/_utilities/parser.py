"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64
import logging
import re
from typing import Any

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.syntax import FlextLdifSyntax

logger = logging.getLogger(__name__)


class FlextLdifUtilitiesParser:
    """Generic LDIF parsing utilities - simple helper functions.

    # LEGACY: Was FlextLdifUtilities.LdifParser
    # Now: Simple pure functions for schema/LDIF parsing
    # Use: parser.py (FlextLdifParser) for full LDIF parsing with quirks
    """

    @staticmethod
    def ext(metadata: dict[str, Any]) -> dict[str, Any]:
        """Extract extension information from parsed metadata."""
        result = metadata.get("extensions", {})
        return result if isinstance(result, dict) else {}

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
    def extract_extensions(definition: str) -> dict[str, Any]:
        """Extract extension information from schema definition string.

        Simple helper to extract X- extensions, DESC, ORDERING, SUBSTR from
        schema attribute/objectClass definitions.

        # LEGACY: Was part of LdifParser.extract_extensions
        """
        if not definition or not isinstance(definition, str):
            return {}

        extensions: dict[str, Any] = {}

        # Extract X- extensions (custom properties)
        x_pattern = re.compile(
            r'X-([A-Z0-9_-]+)\s+["\']?([^"\']*)["\']?(?:\s|$)', re.IGNORECASE
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
        """Unfold LDIF lines folded across multiple lines per RFC 2849.

        Continuation lines start with a single space.
        """
        lines: list[str] = []
        current_line = ""

        for raw_line in ldif_content.split("\n"):
            if raw_line.startswith(" ") and current_line:
                # Continuation line - append to current (skip leading space)
                current_line += raw_line[1:]
            else:
                # New line
                if current_line:
                    lines.append(current_line)
                current_line = raw_line

        if current_line:
            lines.append(current_line)

        return lines

    @staticmethod
    def _decode_ldif_value(key: str, value: str) -> tuple[str, str]:
        """Handle base64-encoded LDIF values (attr:: base64value)."""
        if key.endswith(":"):
            key = key[:-1]
            try:
                value = base64.b64decode(value.lstrip()).decode("utf-8")
            except Exception:
                value = value.lstrip()
        return key.strip(), value.lstrip()

    @staticmethod
    def _process_ldif_line(
        line: str,
        current_dn: str | None,
        current_attrs: dict[str, list[str]],
        entries: list[tuple[str, dict[str, list[str]]]],
    ) -> tuple[str | None, dict[str, list[str]]]:
        """Process single LDIF line, return updated (dn, attrs)."""
        if not line:
            if current_dn is not None:
                entries.append((current_dn, current_attrs))
            return None, {}

        if ":" not in line:
            return current_dn, current_attrs

        key, _, value = line.partition(":")
        key, value = FlextLdifUtilitiesParser._decode_ldif_value(key, value)

        if key.lower() == "dn":
            if current_dn is not None:
                entries.append((current_dn, current_attrs))
            return value, {}

        current_attrs.setdefault(key, []).append(value)
        return current_dn, current_attrs

    @staticmethod
    def parse_ldif_lines(
        ldif_content: str,
    ) -> list[tuple[str, dict[str, list[str]]]]:
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

        entries: list[tuple[str, dict[str, list[str]]]] = []
        current_dn: str | None = None
        current_attrs: dict[str, list[str]] = {}
        unfolded_lines = FlextLdifUtilitiesParser.unfold_lines(ldif_content)

        for raw_line in unfolded_lines:
            line = raw_line.rstrip("\r\n").strip()
            current_dn, current_attrs = FlextLdifUtilitiesParser._process_ldif_line(
                line, current_dn, current_attrs, entries
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
        entry_dict: dict[str, object],
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
        entry_dict: dict[str, object],
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
        if not isinstance(existing, list):
            entry_dict[attr_name] = [existing, attr_value]
        else:
            existing.append(attr_value)

        return True

    @staticmethod
    def track_base64_attribute(
        attr_name: str,
        entry_dict: dict[str, object],
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
        entry_dict: dict[str, object],
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
            current_attr, current_values, entry_dict
        )

        # Track base64 encoding
        if is_base64:
            FlextLdifUtilitiesParser.track_base64_attribute(attr_name, entry_dict)

        # Handle multi-valued attributes
        if FlextLdifUtilitiesParser.handle_multivalued_attribute(
            attr_name, attr_value, entry_dict
        ):
            return (None, [])

        return (attr_name, [attr_value])

    @staticmethod
    def parse(
        ldif_lines: list[str],
    ) -> list[dict[str, Any]]:
        """Parse list of LDIF lines into entries (simple version).

        # LEGACY: Original simple parser (kept for backward compat if needed)
        # Use: FlextLdifParser for full parsing with quirks
        """
        entries = []
        current_entry: dict[str, Any] = {}

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
        parse_callback: Any | None = None,
    ) -> list[Any]:
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
        definitions: list[Any] = []

        for raw_line in ldif_content.split("\n"):
            line = raw_line.strip()

            # Case-insensitive match for definition type
            if line.lower().startswith(f"{definition_type.lower()}:"):
                definition = line.split(":", 1)[1].strip()
                if parse_callback and callable(parse_callback):
                    result = parse_callback(definition)
                    # Handle FlextResult returns
                    if hasattr(result, "is_success") and hasattr(result, "unwrap"):
                        if result.is_success:
                            definitions.append(result.unwrap())
                    # Direct return value (not FlextResult)
                    elif result is not None:
                        definitions.append(result)
                else:
                    # No callback, just collect definitions
                    definitions.append(definition)

        return definitions

    @staticmethod
    def parse_rfc_attribute(
        attr_definition: str,
        *,
        case_insensitive: bool = False,
        allow_syntax_quotes: bool = False,
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Parse RFC 4512 attribute definition."""
        try:
            oid_match = re.match(
                FlextLdifConstants.LdifPatterns.SCHEMA_OID_EXTRACTION,
                attr_definition,
            )
            if not oid_match:
                return FlextResult.fail("RFC attribute parsing failed: missing an OID")
            oid = oid_match.group(1)

            name_match = re.search(
                FlextLdifConstants.LdifPatterns.SCHEMA_NAME, attr_definition
            )
            name = name_match.group(1) if name_match else oid

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

            syntax_validation_error: str | None = None
            if syntax is not None and syntax.strip():
                syntax_service = FlextLdifSyntax()
                validate_result = syntax_service.validate_oid(syntax)
                if validate_result.is_failure:
                    syntax_validation_error = (
                        f"Syntax OID validation failed: {validate_result.error}"
                    )
                elif not validate_result.unwrap():
                    syntax_validation_error = f"Invalid syntax OID format: {syntax}"

            equality_match = re.search(
                FlextLdifConstants.LdifPatterns.SCHEMA_EQUALITY,
                attr_definition,
            )
            equality = equality_match.group(1) if equality_match else None

            substr_match = re.search(
                FlextLdifConstants.LdifPatterns.SCHEMA_SUBSTR,
                attr_definition,
            )
            substr = substr_match.group(1) if substr_match else None

            ordering_match = re.search(
                FlextLdifConstants.LdifPatterns.SCHEMA_ORDERING,
                attr_definition,
            )
            ordering = ordering_match.group(1) if ordering_match else None

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

            sup_match = re.search(
                FlextLdifConstants.LdifPatterns.SCHEMA_SUP,
                attr_definition,
            )
            sup = sup_match.group(1) if sup_match else None

            usage_match = re.search(
                FlextLdifConstants.LdifPatterns.SCHEMA_USAGE,
                attr_definition,
            )
            usage = usage_match.group(1) if usage_match else None

            metadata_extensions = FlextLdifUtilitiesParser.extract_extensions(
                attr_definition
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

            metadata = (
                FlextLdifModels.QuirkMetadata(
                    quirk_type="rfc",
                    extensions=metadata_extensions,
                )
                if metadata_extensions
                else None
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
            )

            return FlextResult.ok(attribute)

        except (ValueError, TypeError, AttributeError) as e:
            logger.exception("RFC attribute parsing exception")
            return FlextResult.fail(f"RFC attribute parsing failed: {e}")

    @staticmethod
    def parse_rfc_objectclass(
        oc_definition: str,
        *,
        case_insensitive: bool = False,
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Parse RFC 4512 objectClass definition."""
        try:
            oid_match = re.match(
                FlextLdifConstants.LdifPatterns.SCHEMA_OID_EXTRACTION, oc_definition
            )
            if not oid_match:
                return FlextResult.fail(
                    "RFC objectClass parsing failed: missing an OID"
                )
            oid = oid_match.group(1)

            name_match = re.search(
                FlextLdifConstants.LdifPatterns.SCHEMA_NAME, oc_definition
            )
            name = name_match.group(1) if name_match else oid

            desc_match = re.search(
                FlextLdifConstants.LdifPatterns.SCHEMA_DESC, oc_definition
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
                oc_definition
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

            return FlextResult.ok(objectclass)

        except (ValueError, TypeError, AttributeError) as e:
            logger.exception("RFC objectClass parsing exception")
            return FlextResult.fail(f"RFC objectClass parsing failed: {e}")


__all__ = [
    "FlextLdifUtilitiesParser",
]
