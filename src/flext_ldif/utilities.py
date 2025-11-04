"""LDIF Utilities - Pure Helper Functions for LDIF Processing.

RFC 4514 DN operations, string manipulation, LDIF formatting.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import base64
import re
import string
from pathlib import Path
from typing import Any

from flext_core import FlextResult
from jinja2 import Environment

from flext_ldif.constants import FlextLdifConstants

# NOTE: Removed ldap3.utils.dn.parse_dn import (not available in current ldap3 version)
# Implemented pure RFC 4514 DN parsing below


class FlextLdifUtilities:
    """Pure LDIF Utilities - RFC 4514 DN operations, string manipulation."""

    class DN:
        """RFC 4514 DN Operations - Pure string functions for DN manipulation.

        All methods return primitives (str, list, tuple, bool, int, None).
        Pure functions: no models, no server-specific logic, no side effects.

        Methods:
        - split: Split DN string into components
        - norm_component: Normalize single DN component
        - norm_string: Normalize full DN to RFC 4514 format
        - validate: Validate DN format according to RFC 4514
        - parse: Parse DN into (attr, value) tuples
        - norm: Normalize DN per RFC 4514 (lowercase attrs, preserve values)
        - clean_dn: Clean DN string to fix spacing and escaping issues
        - esc: Escape special characters in DN value per RFC 4514
        - unesc: Unescape special characters in DN value per RFC 4514
        - compare_dns: Compare two DNs per RFC 4514 (case-insensitive)
        - parse_rdn: Parse a single RDN component per RFC 4514

        """

        @staticmethod
        def split(dn: str) -> list[str]:
            """Split DN string into individual components."""
            if not dn:
                return []
            return [comp.strip() for comp in dn.split(",") if comp.strip()]

        @staticmethod
        def norm_component(component: str) -> str:
            """Normalize single DN component (e.g., 'cn = John' → 'cn=John')."""
            if "=" not in component:
                return component
            parts = component.split("=", 1)
            return f"{parts[0].strip()}={parts[1].strip()}"

        @staticmethod
        def norm_string(dn: str) -> str:
            """Normalize full DN to RFC 4514 format."""
            if not dn or "=" not in dn:
                return dn
            components = FlextLdifUtilities.DN.split(dn)
            normalized = [
                FlextLdifUtilities.DN.norm_component(comp) for comp in components
            ]
            return ",".join(normalized)

        @staticmethod
        def validate(dn: str) -> bool:
            """Validate DN format according to RFC 4514."""
            if not dn or "=" not in dn:
                return False

            try:
                components = FlextLdifUtilities.DN.split(dn)
                if not components:
                    return False

                # Check each component has attr=value with both non-empty
                for comp in components:
                    if "=" not in comp:
                        return False
                    attr, _, value = comp.partition("=")
                    attr = attr.strip()
                    value = value.strip()
                    # Both attribute and value must be non-empty
                    if not attr or not value:
                        return False

                return True
            except Exception:
                return False

        @staticmethod
        def parse(dn: str) -> list[tuple[str, str]] | None:
            """Parse DN into RFC 4514 components (attr, value pairs).

            Pure RFC 4514 parsing without external dependencies.
            Returns [(attr1, value1), (attr2, value2), ...] or None on error.
            """
            if not dn or "=" not in dn:
                return None

            try:
                components = FlextLdifUtilities.DN.split(dn)
                result: list[tuple[str, str]] = []

                for comp in components:
                    if "=" not in comp:
                        continue
                    attr, _, value = comp.partition("=")
                    result.append((attr.strip(), value.strip()))

                return result or None
            except Exception:
                return None

        @staticmethod
        def norm(dn: str) -> str | None:
            """Normalize DN per RFC 4514 (lowercase attrs, preserve values).

            Pure implementation without external dependencies.
            """
            try:
                if not dn or "=" not in dn:
                    return None

                components = FlextLdifUtilities.DN.split(dn)
                normalized: list[str] = []

                for comp in components:
                    if "=" not in comp:
                        continue
                    attr, _, value = comp.partition("=")
                    # Lowercase attribute, preserve value per RFC 4514
                    normalized.append(f"{attr.strip().lower()}={value.strip()}")

                return ",".join(normalized) if normalized else None
            except Exception:
                return None

        @staticmethod
        def clean_dn(dn: str) -> str:
            """Clean DN string to fix spacing and escaping issues.

            Removes spaces before '=', fixes trailing backslash+space,
            normalizes whitespace around commas.
            """
            if not dn:
                return dn

            # Remove spaces ONLY BEFORE '=' in each RDN component
            cleaned = re.sub(r"\s+=", "=", dn)

            # Fix trailing backslash+space before commas
            cleaned = re.sub(
                FlextLdifConstants.DnPatterns.DN_TRAILING_BACKSLASH_SPACE,
                FlextLdifConstants.DnPatterns.DN_COMMA,
                cleaned,
            )

            # Normalize spaces around commas: ", cn=..." -> ",cn=..."
            cleaned = re.sub(
                FlextLdifConstants.DnPatterns.DN_SPACES_AROUND_COMMA,
                FlextLdifConstants.DnPatterns.DN_COMMA,
                cleaned,
            )

            # Remove unnecessary character escapes (RFC 4514 compliance)
            cleaned = re.sub(
                FlextLdifConstants.DnPatterns.DN_UNNECESSARY_ESCAPES,
                r"\1",
                cleaned,
            )

            # Normalize multiple spaces to single space
            cleaned = re.sub(
                FlextLdifConstants.DnPatterns.DN_MULTIPLE_SPACES, " ", cleaned
            )

            return cleaned.strip()

        @staticmethod
        def esc(value: str) -> str:
            """Escape special characters in DN value per RFC 4514."""
            if not value:
                return value

            escape_chars = {",", "+", '"', "\\", "<", ">", ";", "#"}
            result: list[str] = []

            for i, char in enumerate(value):
                is_special = char in escape_chars
                is_edge_space = (i == 0 or i == len(value) - 1) and char == " "
                if is_special or is_edge_space:
                    result.append(f"\\{ord(char):02x}")
                else:
                    result.append(char)

            return "".join(result)

        @staticmethod
        def unesc(value: str) -> str:
            """Unescape special characters in DN value per RFC 4514."""
            if not value or "\\" not in value:
                return value

            result: list[str] = []
            i = 0
            while i < len(value):
                if value[i] == "\\" and i + 1 < len(value):
                    # Check if next two chars are hex digits
                    if i + 2 < len(value) and all(
                        c in string.hexdigits for c in value[i + 1 : i + 3]
                    ):
                        hex_code = value[i + 1 : i + 3]
                        result.append(chr(int(hex_code, 16)))
                        i += 3
                    else:
                        result.append(value[i + 1])
                        i += 2
                else:
                    result.append(value[i])
                    i += 1

            return "".join(result)

        @staticmethod
        def compare_dns(dn1: str, dn2: str) -> int | None:
            """Compare two DNs per RFC 4514 (case-insensitive).

            Returns: -1 if dn1 < dn2, 0 if equal, 1 if dn1 > dn2, None on error
            """
            try:
                norm1 = FlextLdifUtilities.DN.norm(dn1)
                norm2 = FlextLdifUtilities.DN.norm(dn2)

                if norm1 is None or norm2 is None:
                    return None

                norm1_lower = norm1.lower()
                norm2_lower = norm2.lower()

                if norm1_lower < norm2_lower:
                    return -1
                if norm1_lower > norm2_lower:
                    return 1
                return 0
            except Exception:
                return None

        @staticmethod
        def parse_rdn(rdn: str) -> list[tuple[str, str]] | None:  # noqa: C901
            """Parse a single RDN component per RFC 4514.

            Returns None on error.
            """
            if not rdn or not isinstance(rdn, str):
                return None

            try:
                pairs: list[tuple[str, str]] = []
                current_attr = ""
                current_val = ""
                in_value = False
                i = 0

                while i < len(rdn):
                    char = rdn[i]

                    # Handle escape sequence
                    if char == "\\" and i + 1 < len(rdn):
                        next_char = rdn[i + 1]
                        if i + 2 < len(rdn) and all(
                            c in string.hexdigits for c in rdn[i + 1 : i + 3]
                        ):
                            current_val += rdn[i : i + 3]
                            i += 3
                        else:
                            current_val += next_char
                            i += 2
                        continue

                    # Handle equals (attribute-value separator)
                    if char == "=" and not in_value:
                        current_attr = current_attr.strip().lower()
                        if not current_attr:
                            return None
                        in_value = True
                        i += 1
                        continue

                    # Handle plus (multi-valued RDN separator)
                    if char == "+" and in_value:
                        current_val = current_val.strip()
                        if current_attr:
                            pairs.append((current_attr, current_val))
                        current_attr = ""
                        current_val = ""
                        in_value = False
                        i += 1
                        continue

                    # Accumulate character
                    if in_value:
                        current_val += char
                    else:
                        current_attr += char

                    i += 1

                # Handle final pair
                if not in_value or not current_attr:
                    return None

                current_val = current_val.strip()
                if not current_val:
                    return None
                pairs.append((current_attr, current_val))

                return pairs

            except Exception:
                return None

        @staticmethod
        def extract_rdn(dn: str) -> str | None:
            """Extract leftmost RDN from DN.

            For DN "cn=John,ou=Users,dc=example,dc=com", returns "cn=John".

            Args:
                dn: Distinguished Name string

            Returns:
                Leftmost RDN (attr=value) or None if DN is empty/invalid

            """
            if not dn or "=" not in dn:
                return None

            try:
                components = FlextLdifUtilities.DN.split(dn)
                return components[0] if components else None
            except Exception:
                return None

        @staticmethod
        def extract_parent_dn(dn: str) -> str | None:
            """Extract parent DN (remove leftmost RDN).

            For DN "cn=John,ou=Users,dc=example,dc=com",
            returns "ou=Users,dc=example,dc=com".

            Args:
                dn: Distinguished Name string

            Returns:
                Parent DN (without leftmost RDN) or None if DN has ≤1 component

            """
            if not dn or "=" not in dn:
                return None

            try:
                components = FlextLdifUtilities.DN.split(dn)
                if len(components) <= 1:
                    return None
                return ",".join(components[1:])
            except Exception:
                return None

        @staticmethod
        def is_config_dn(dn: str) -> bool:
            """Check if DN is in cn=config tree (OpenLDAP dynamic config).

            Used by OpenLDAP and other servers for config DN detection.

            Args:
                dn: Distinguished Name string

            Returns:
                True if DN contains cn=config component, False otherwise

            """
            if not dn:
                return False
            return "cn=config" in dn.lower()

        @staticmethod
        def contains_pattern(
            dn: str,
            pattern: str,
            case_sensitive: bool = False,
        ) -> bool:
            """Check if DN contains pattern substring.

            Useful for DN filtering by organizational unit, DC, etc.

            Args:
                dn: Distinguished Name string
                pattern: Pattern to search for (can be full component or substring)
                case_sensitive: If True, match case exactly

            Returns:
                True if pattern is found in DN, False otherwise

            Example:
                contains_pattern("cn=admin,ou=users,dc=example", "ou=users")
                # Returns: True
                contains_pattern("cn=admin,ou=users,dc=example", "OU=USERS")
                # Returns: False (case mismatch)
                contains_pattern("cn=admin,ou=users,dc=example", "OU=USERS", case_sensitive=False)
                # Returns: True

            """
            if not dn or not pattern:
                return False

            search_dn = dn if case_sensitive else dn.lower()
            search_pattern = pattern if case_sensitive else pattern.lower()

            return search_pattern in search_dn

    class Writer:
        """Pure LDIF Formatting Operations - No Models, No Side Effects.

        ╔══════════════════════════════════════════════════════════════════════╗
        ║  PURE LDIF FORMATTING OPERATIONS                                     ║
        ╠══════════════════════════════════════════════════════════════════════╣
        ║  ✅ DN formatting with line folding                                    ║
        ║  ✅ Line folding (RFC 2849)                                           ║
        ║  ✅ Whitespace normalization                                          ║
        ║  ✅ Attribute:value line formatting                                  ║
        ║  ✅ Template rendering (Jinja2)                                      ║
        ║  ✅ File writing (text operations)                                    ║
        ║  ✅ 100% Pure functions (no models, no side effects)                  ║
        ╚══════════════════════════════════════════════════════════════════════╝

        ═══════════════════════════════════════════════════════════════════════
        RESPONSIBILITY (SRP)

        This class handles LDIF FORMATTING OPERATIONS ONLY:
        - DN string formatting with line folding
        - LDIF line folding (RFC 2849)
        - Whitespace normalization
        - Attribute:value line formatting
        - Template rendering (Jinja2)
        - File writing (text I/O)

        What it does NOT do:
        - Use models (works with primitives: str, list, dict)
        - Handle server-specific quirks (quirks handle that)
        - Perform business logic (services handle that)

        ═══════════════════════════════════════════════════════════════════════
        DESIGN NOTES

        - All methods are @staticmethod (no instance state)
        - Returns primitives (str, list[str]) or FlextResult for I/O operations
        - Safe for services to use (no circular dependencies)
        - No models used (pure string/file operations)
        - No server-specific logic (quirks handle that)

        """

        @staticmethod
        def fmt_dn(
            dn_value: str, *, width: int = 78, fold: bool = True
        ) -> list[str]:
            """Format DN line with optional line folding (RFC 2849).

            Args:
                dn_value: DN string to format
                width: Maximum line width (default: 78)
                fold: Whether to fold long lines (default: True)

            Returns:
                List of formatted lines (unfolded: single line, folded: multiple lines)

            Example:
                >>> LdifWriter.fmt_dn("dn: cn=John,dc=example,dc=com", width=30)
                ['dn: cn=John,dc=example,', ' dc=com']

            """
            if not dn_value:
                return [""]

            line = f"dn: {dn_value}"
            if not fold or len(line) <= width:
                return [line]

            return FlextLdifUtilities.Writer.fold(line, width=width)

        @staticmethod
        def fold(line: str, width: int = 78) -> list[str]:
            """Fold long LDIF line according to RFC 2849.

            LDIF line folding: continuation lines start with a single space.

            Args:
                line: Line to fold
                width: Maximum line width (default: 78)

            Returns:
                List of folded lines (first line + continuation lines)

            Example:
                >>> LdifWriter.fold("cn: very long attribute value", width=10)
                ['cn: very', ' long attr', 'ibute valu', 'e']

            """
            if not line or len(line) <= width:
                return [line]

            folded = [line[:width]]
            remaining = line[width:]

            while remaining:
                # Continuation lines start with a single space (RFC 2849)
                if len(remaining) > width - 1:
                    folded.append(f" {remaining[:width - 1]}")
                    remaining = remaining[width - 1 :]
                else:
                    folded.append(f" {remaining}")
                    break

            return folded

        @staticmethod
        def norm_ws(value_str: str) -> str:
            """Normalize whitespace in LDIF value string.

            Removes leading/trailing whitespace and normalizes internal whitespace.

            Args:
                value_str: Value string to normalize

            Returns:
                Normalized value string

            Example:
                >>> LdifWriter.norm_ws("  hello   world  ")
                'hello world'

            """
            if not value_str:
                return ""
            # Normalize internal whitespace (multiple spaces to single)
            return " ".join(value_str.split())

        @staticmethod
        def fmt_attr(
            attr_name: str, value_str: str, *, use_base64: bool = False
        ) -> str:
            """Format attribute:value line for LDIF output.

            Args:
                attr_name: Attribute name
                value_str: Attribute value
                use_base64: Whether to use base64 encoding (default: False)

            Returns:
                Formatted attribute:value line

            Example:
                >>> LdifWriter.fmt_attr("cn", "John Doe")
                'cn: John Doe'

            """
            if not attr_name:
                return ""

            if use_base64:
                encoded = base64.b64encode(value_str.encode("utf-8")).decode("ascii")
                return f"{attr_name}:: {encoded}"

            return f"{attr_name}: {value_str}"

        @staticmethod
        def render_template(
            template_str: str, context: dict[str, Any]
        ) -> FlextResult[str]:
            """Render Jinja2 template with context.

            Args:
                template_str: Jinja2 template string
                context: Template context variables

            Returns:
                FlextResult with rendered string or error

            Example:
                >>> result = LdifWriter.render_template(
                ...     "Hello {{ name }}", {"name": "World"}
                ... )
                >>> result.unwrap()
                'Hello World'

            """
            try:
                env = Environment(autoescape=True)
                template = env.from_string(template_str)
                rendered = template.render(**context)
                return FlextResult[str].ok(rendered)
            except Exception as e:
                return FlextResult[str].fail(f"Template rendering failed: {e}")

        @staticmethod
        def write_file(
            content: str, file_path: Path, encoding: str = "utf-8"
        ) -> FlextResult[dict[str, Any]]:
            """Write content to file (pure I/O operation).

            Args:
                content: Content to write
                file_path: Path to output file
                encoding: File encoding (default: utf-8)

            Returns:
                FlextResult with file stats dict or error

            Example:
                >>> result = LdifWriter.write_file("content", Path("out.ldif"))
                >>> stats = result.unwrap()
                >>> stats["bytes_written"]
                7

            """
            try:
                file_path.write_text(content, encoding=encoding)
                stats = {
                    "bytes_written": len(content.encode(encoding)),
                    "path": str(file_path),
                    "encoding": encoding,
                }
                return FlextResult[dict[str, Any]].ok(stats)
            except Exception as e:
                return FlextResult[dict[str, Any]].fail(f"File write failed: {e}")

    class Schema:
        """Generic attribute definition normalization utilities."""

        @staticmethod
        def normalize_name(
            name_value: str | None,
            suffixes_to_remove: list[str] | None = None,
            char_replacements: dict[str, str] | None = None,
        ) -> str | None:
            """Normalize attribute NAME field."""
            if not name_value or not isinstance(name_value, str):
                return name_value

            result = name_value
            if suffixes_to_remove is None:
                suffixes_to_remove = [";binary"]
            if char_replacements is None:
                char_replacements = {"_": "-"}

            for suffix in suffixes_to_remove:
                if suffix in result:
                    result = result.replace(suffix, "")

            for old, new in char_replacements.items():
                if old in result:
                    result = result.replace(old, new)

            return result if result != name_value else name_value

        @staticmethod
        def normalize_matching_rules(
            matching_rules: list[str] | None,
        ) -> list[str]:
            """Normalize matching rule OIDs."""
            return matching_rules or []

    class Parser:
        """Generic LDIF parsing utilities - simple helper functions.

        # LEGACY: Was FlextLdifUtilities.LdifParser
        # Now: Simple pure functions for schema/LDIF parsing
        # Use: parser.py (FlextLdifParserService) for full LDIF parsing with quirks
        """

        @staticmethod
        def ext(metadata: dict[str, Any]) -> dict[str, Any]:
            """Extract extension information from parsed metadata."""
            result = metadata.get("extensions", {})
            return result if isinstance(result, dict) else {}

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

            # LEGACY: Was part of LdifParser._unfold_lines
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
        def parse_ldif_lines(ldif_content: str) -> list[tuple[str, dict[str, list[str]]]]:  # noqa: C901
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

            def decode_key_value(key: str, value: str) -> tuple[str, str]:
                """Handle base64-encoded LDIF values (attr:: base64value)."""
                if key.endswith(":"):
                    key = key[:-1]
                    try:
                        value = base64.b64decode(value.lstrip()).decode("utf-8")
                    except Exception:
                        value = value.lstrip()
                return key.strip(), value.lstrip()

            def save_entry(
                dn: str | None,
                attrs: dict[str, list[str]],
            ) -> tuple[str | None, dict[str, list[str]]]:
                """Save current entry if DN exists, return reset state."""
                if dn is not None:
                    entries.append((dn, attrs))
                return None, {}

            entries: list[tuple[str, dict[str, list[str]]]] = []
            current_dn: str | None = None
            current_attrs: dict[str, list[str]] = {}
            unfolded_lines = FlextLdifUtilities.Parser.unfold_lines(ldif_content)

            for raw_line in unfolded_lines:
                line = raw_line.rstrip("\r\n").strip()
                if not line:
                    current_dn, current_attrs = save_entry(current_dn, current_attrs)
                    continue
                if ":" not in line:
                    continue
                key, _, value = line.partition(":")
                key, value = decode_key_value(key, value)
                if key.lower() == "dn":
                    current_dn, current_attrs = save_entry(current_dn, current_attrs)
                    current_dn = value
                else:
                    current_attrs.setdefault(key, []).append(value)

            if current_dn is not None:
                entries.append((current_dn, current_attrs))
            return entries

        @staticmethod
        def parse(
            ldif_lines: list[str],
        ) -> list[dict[str, Any]]:
            """Parse list of LDIF lines into entries (simple version).

            # LEGACY: Original simple parser (kept for backward compat if needed)
            # Use: FlextLdifParserService for full parsing with quirks
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

    class ACL:
        """Generic ACL parsing and writing utilities."""

        @staticmethod
        def parser(acl_line: str) -> dict[str, Any] | None:
            """Parse ACL line into components."""
            if not acl_line or not acl_line.strip():
                return None

            result: dict[str, Any] = {}
            line = acl_line.strip()

            if line.startswith("("):
                result["format"] = "oid"
                result["content"] = line
            elif ":" in line:
                parts = line.split(":", 1)
                result["format"] = "oud"
                result["key"] = parts[0]
                result["value"] = parts[1] if len(parts) > 1 else ""
            else:
                result["format"] = "unknown"
                result["content"] = line

            return result or None

    class ObjectClass:
        """RFC 4512 ObjectClass Validation and Correction Utilities.

        Pure static methods for validating and fixing ObjectClass definitions
        according to RFC 4512. These methods modify SchemaObjectClass models in-place.

        Used by server quirks during normalization/denormalization to fix common
        ObjectClass issues that violate RFC 4512 compliance.

        ═══════════════════════════════════════════════════════════════════════
        RFC 4512 ObjectClass Requirements

        - AUXILIARY classes MUST have explicit SUP clause
        - ObjectClass kind must match superior class kind (STRUCTURAL vs AUXILIARY)
        - Abstract classes must have SUP (except root abstract classes like "top")

        ═══════════════════════════════════════════════════════════════════════
        Usage Pattern

        These methods are called by server quirks during schema normalization:

            from flext_ldif.utilities import FlextLdifUtilities

            FlextLdifUtilities.ObjectClass.fix_missing_sup(
                schema_oc, server_type="oid"
            )
            FlextLdifUtilities.ObjectClass.fix_kind_mismatch(
                schema_oc, server_type="oid"
            )
            FlextLdifUtilities.ObjectClass.ensure_sup_for_auxiliary(schema_oc)
            FlextLdifUtilities.ObjectClass.align_kind_with_superior(
                schema_oc, superior_kind
            )

        """

        @staticmethod
        def fix_missing_sup(
            schema_oc: Any,  # SchemaObjectClass (lazy import to avoid circular deps)
            server_type: str = "oid",
        ) -> None:
            """Fix missing SUP for AUXILIARY objectClasses (server-specific fixes).

            RFC 4512 requires AUXILIARY classes to have explicit SUP clause.
            This method fixes known AUXILIARY classes that are missing SUP,
            using server-specific knowledge.

            For general fixes, use ensure_sup_for_auxiliary() instead.

            Args:
                schema_oc: ObjectClass model to potentially fix (modified in-place)
                server_type: Server type hint for logging (e.g., "oid", "oud")

            Returns:
                None - modifies schema_oc in-place

            Note:
                Only fixes AUXILIARY classes without SUP. Known problematic
                classes from OID/OUD are fixed automatically. For general cases,
                delegates to ensure_sup_for_auxiliary().

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

            # If it's a known problematic class, fix it
            if name_lower in auxiliary_without_sup:
                schema_oc.sup = "top"
            else:
                # For unknown cases, use general fix
                FlextLdifUtilities.ObjectClass.ensure_sup_for_auxiliary(schema_oc)

        @staticmethod
        def fix_kind_mismatch(
            schema_oc: Any,  # SchemaObjectClass (lazy import to avoid circular deps)
            server_type: str = "oid",
        ) -> None:
            """Fix objectClass kind mismatches with superior classes (server-specific).

            Some ObjectClasses have kind mismatches with their superior classes
            (e.g., AUXILIARY class with STRUCTURAL superior). This method fixes
            such mismatches using server-specific knowledge.

            For general fixes when you know the superior_kind, use
            align_kind_with_superior() instead.

            Args:
                schema_oc: ObjectClass model to potentially fix (modified in-place)
                server_type: Server type hint for logging (e.g., "oid", "oud")

            Returns:
                None - modifies schema_oc in-place

            Note:
                Only fixes if both SUP and kind are present. Known problematic
                superior classes are handled automatically. For general cases,
                requires superior_kind to use align_kind_with_superior().

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
                schema_oc.kind = FlextLdifConstants.Schema.STRUCTURAL

            # If SUP is AUXILIARY but objectClass is STRUCTURAL, change to AUXILIARY
            elif (
                sup_lower in auxiliary_superiors
                and schema_oc.kind == FlextLdifConstants.Schema.STRUCTURAL
            ):
                schema_oc.kind = FlextLdifConstants.Schema.AUXILIARY

        @staticmethod
        def ensure_sup_for_auxiliary(
            schema_oc: Any,  # SchemaObjectClass (lazy import to avoid circular deps)
            default_sup: str = "top",
        ) -> None:
            """Ensure AUXILIARY objectClasses have a SUP clause.

            RFC 4512 requires AUXILIARY classes to have explicit SUP.
            If missing, adds the specified default SUP value.

            This is a general method that can be used by all quirks.
            For server-specific fixes, use fix_missing_sup() instead.

            Args:
                schema_oc: ObjectClass model to potentially fix (modified in-place)
                default_sup: Default SUP value to add if missing (default: "top")

            Returns:
                None - modifies schema_oc in-place

            """
            if (
                not schema_oc.sup
                and schema_oc.kind == FlextLdifConstants.Schema.AUXILIARY
            ):
                schema_oc.sup = default_sup

        @staticmethod
        def align_kind_with_superior(
            schema_oc: Any,  # SchemaObjectClass (lazy import to avoid circular deps)
            superior_kind: str | None,
        ) -> None:
            """Align ObjectClass kind with its superior class kind.

            General method that aligns ObjectClass kind with superior class kind
            for RFC 4512 compliance. This is called by fix_kind_mismatch() for
            known problematic cases, but can also be used directly.

            Args:
                schema_oc: ObjectClass model to potentially fix (modified in-place)
                superior_kind: Kind of the superior ObjectClass

            Returns:
                None - modifies schema_oc in-place

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


__all__ = [
    "FlextLdifUtilities",
]
