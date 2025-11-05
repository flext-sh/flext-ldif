"""LDIF Utilities - Pure Helper Functions for LDIF Processing.

RFC 4514 DN operations, string manipulation, LDIF formatting.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import base64
import copy
import logging
import re
import string
from pathlib import Path
from typing import Any

from flext_core import FlextResult
from jinja2 import Environment

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.syntax import FlextLdifSyntaxService

logger = logging.getLogger(__name__)

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
        def parse_rdn(rdn: str) -> list[tuple[str, str]] | None:
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
        def fmt_dn(dn_value: str, *, width: int = 78, fold: bool = True) -> list[str]:
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
                    folded.append(f" {remaining[: width - 1]}")
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
                # Create parent directories if they don't exist
                file_path.parent.mkdir(parents=True, exist_ok=True)
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
            equality: str | None,
            substr: str | None = None,
            *,
            replacements: dict[str, str] | None = None,
            substr_rules_in_equality: dict[str, str] | None = None,
            normalized_substr_values: dict[str, str] | None = None,
        ) -> tuple[str | None, str | None]:
            """Normalize EQUALITY and SUBSTR matching rules.

            Handles:
            1. SUBSTR rule incorrectly in EQUALITY field → move to SUBSTR
            2. Apply server-specific matching rule replacements
            3. Normalize case variants (caseIgnoreSubStringsMatch → caseIgnoreSubstringsMatch)

            Args:
                equality: Current EQUALITY rule
                substr: Current SUBSTR rule
                replacements: Dict of custom replacements {old: new}
                substr_rules_in_equality: Map of SUBSTR rules found in EQUALITY → correct EQUALITY
                normalized_substr_values: Map of SUBSTR variants → normalized SUBSTR

            Returns:
                Tuple of (normalized_equality, normalized_substr)

            """
            if not equality:
                return equality, substr

            result_equality = equality
            result_substr = substr

            # Fix SUBSTR rules incorrectly used in EQUALITY field
            # When a SUBSTR rule is found in EQUALITY, move it to SUBSTR and set EQUALITY to default
            if substr_rules_in_equality and equality in substr_rules_in_equality:
                # Move the SUBSTR rule from EQUALITY to SUBSTR
                # The original equality value (e.g., "caseIgnoreSubstringsMatch") goes to substr
                result_substr = equality  # The original equality value is a SUBSTR rule
                # Set EQUALITY to the mapped correct EQUALITY rule
                result_equality = substr_rules_in_equality[equality]  # e.g., "caseIgnoreMatch"

            # Normalize SUBSTR case variants
            if (
                result_substr
                and normalized_substr_values
                and result_substr in normalized_substr_values
            ):
                result_substr = normalized_substr_values[result_substr]

            # Apply server-specific matching rule replacements
            if replacements and result_equality in replacements:
                result_equality = replacements[result_equality]

            return result_equality, result_substr

        @staticmethod
        def normalize_syntax_oid(
            syntax: str | None,
            *,
            replacements: dict[str, str] | None = None,
        ) -> str | None:
            """Normalize SYNTAX OID field.

            Transformations:
            - Remove quotes (Oracle OID uses 'OID', RFC uses OID)
            - Apply server-specific syntax OID replacements

            Args:
                syntax: Original SYNTAX OID
                replacements: Dict of syntax OID replacements {old: new}

            Returns:
                Normalized syntax OID

            """
            if not syntax:
                return syntax

            result = syntax

            # Remove quotes if present (Oracle OID: '1.2.3', RFC: 1.2.3)
            if result.startswith("'") and result.endswith("'"):
                result = result[1:-1]

            # Apply server-specific syntax OID replacements
            if replacements and result in replacements:
                result = replacements[result]

            return result

        @staticmethod
        def apply_transformations(
            schema_obj: Any,
            *,
            field_transforms: dict[str, Any] | None = None,
        ) -> FlextResult[Any]:
            """Apply transformation pipeline to schema object.

            Generic transformation pipeline accepting optional transformer callables.

            Args:
                schema_obj: SchemaAttribute or SchemaObjectClass
                field_transforms: Dict of {field_name: transform_callable}

            Returns:
                FlextResult with transformed schema object

            """
            if not schema_obj:
                return FlextResult[Any].ok(schema_obj)

            try:
                # Create copy using model_copy if available
                if hasattr(schema_obj, "model_copy"):
                    transformed = schema_obj.model_copy()
                else:
                    transformed = copy.copy(schema_obj)

                # Apply transformations
                if field_transforms:
                    for field_name, transform_fn in field_transforms.items():
                        if hasattr(transformed, field_name):
                            old_value = getattr(transformed, field_name, None)
                            if callable(transform_fn):
                                # Apply transformation even if old_value is None
                                # Some transformations need to set values that were None
                                new_value = transform_fn(old_value)
                                setattr(transformed, field_name, new_value)

                return FlextResult[Any].ok(transformed)
            except Exception as e:
                return FlextResult[Any].fail(f"Failed to apply transformations: {e}")

        @staticmethod
        def set_server_type(
            model_instance: Any,
            server_type: str,
        ) -> FlextResult[Any]:
            """Copy schema model and set server_type in metadata.

            Common pattern used by quirks when converting from RFC format.

            Args:
                model_instance: RFC-compliant schema model
                server_type: Server type identifier (e.g., "oid", "oud")

            Returns:
                FlextResult with model copy containing server_type in metadata

            """
            if not model_instance:
                return FlextResult[Any].ok(model_instance)

            try:
                # Create copy
                if hasattr(model_instance, "model_copy"):
                    result = model_instance.model_copy(deep=True)
                else:
                    result = copy.deepcopy(model_instance)

                # Set server_type in metadata
                if (
                    hasattr(result, "metadata")
                    and result.metadata is not None
                    and hasattr(result.metadata, "server_type")
                ):
                    result.metadata.server_type = server_type

                return FlextResult[Any].ok(result)
            except Exception as e:
                return FlextResult[Any].fail(f"Failed to set server type: {e}")

        @staticmethod
        def build_metadata(
            definition: str,
            quirk_type: str,
            additional_extensions: dict[str, object] | None = None,
        ) -> dict[str, Any]:
            """Build metadata extensions dictionary for schema definitions.

            Generic method to build metadata from schema definition string.
            Extracts extensions and adds original format and additional extensions.

            Args:
                definition: Original schema definition string
                quirk_type: Server type identifier
                additional_extensions: Additional extension key-value pairs

            Returns:
                Dictionary of metadata extensions (empty if none)

            """
            # Use Parser to extract extensions
            extensions = FlextLdifUtilities.Parser.extract_extensions(definition)

            # Store original format for round-trip fidelity
            extensions[FlextLdifConstants.MetadataKeys.ORIGINAL_FORMAT] = (
                definition.strip()
            )

            # Add any additional extensions
            if additional_extensions:
                extensions.update(additional_extensions)

            return extensions

        @staticmethod
        def parse_attribute(
            attr_definition: str,
            *,
            case_insensitive: bool = False,
            allow_syntax_quotes: bool = False,
            quirk_type: str = "rfc",
            validate_syntax: bool = True,
        ) -> dict[str, Any]:
            """Parse RFC 4512 attribute definition into structured data.

            Generic parsing method that extracts all fields from attribute definition.
            Used by server quirks to get base parsing logic without duplication.

            Args:
                attr_definition: RFC 4512 attribute definition string
                case_insensitive: If True, use case-insensitive NAME matching
                allow_syntax_quotes: If True, allow optional quotes in SYNTAX
                quirk_type: Server type identifier for metadata
                validate_syntax: If True, validate syntax OID format

            Returns:
                Dictionary with parsed fields:
                - oid: str (required)
                - name: str | None
                - desc: str | None
                - syntax: str | None
                - length: int | None
                - equality: str | None
                - ordering: str | None
                - substr: str | None
                - single_value: bool
                - no_user_modification: bool
                - sup: str | None
                - usage: str | None
                - metadata_extensions: dict[str, object]
                - syntax_validation: dict[str, object] | None

            Raises:
                ValueError: If OID is missing or invalid

            """
            # Extract OID (required)
            oid = FlextLdifUtilities.Parser.extract_oid(attr_definition)
            if not oid:
                msg = "RFC attribute parsing failed: missing an OID"
                raise ValueError(msg)

            # Extract NAME (optional) - use utilities with OID as fallback
            name = FlextLdifUtilities.Parser.extract_optional_field(
                attr_definition,
                FlextLdifConstants.LdifPatterns.SCHEMA_NAME,
                default=oid,
            )

            # Extract DESC (optional)
            desc = FlextLdifUtilities.Parser.extract_optional_field(
                attr_definition,
                FlextLdifConstants.LdifPatterns.SCHEMA_DESC,
            )

            # Extract SYNTAX (optional) with optional length constraint
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

            # Validate syntax OID (if requested)
            syntax_extensions: dict[str, object] = {}
            syntax_validation: dict[str, object] | None = None
            if validate_syntax and syntax and syntax.strip():
                syntax_service = FlextLdifSyntaxService()
                validate_result = syntax_service.validate_oid(syntax)
                if validate_result.is_failure:
                    syntax_extensions[
                        FlextLdifConstants.MetadataKeys.SYNTAX_VALIDATION_ERROR
                    ] = f"Syntax OID validation failed: {validate_result.error}"
                elif not validate_result.unwrap():
                    syntax_extensions[
                        FlextLdifConstants.MetadataKeys.SYNTAX_VALIDATION_ERROR
                    ] = (
                        f"Invalid syntax OID format: {syntax} "
                        f"(must be numeric dot-separated format)"
                    )
                syntax_extensions[FlextLdifConstants.MetadataKeys.SYNTAX_OID_VALID] = (
                    FlextLdifConstants.MetadataKeys.SYNTAX_VALIDATION_ERROR
                    not in syntax_extensions
                )
                syntax_validation = syntax_extensions.copy()

            # Extract matching rules (optional)
            equality = FlextLdifUtilities.Parser.extract_optional_field(
                attr_definition,
                FlextLdifConstants.LdifPatterns.SCHEMA_EQUALITY,
            )
            substr = FlextLdifUtilities.Parser.extract_optional_field(
                attr_definition,
                FlextLdifConstants.LdifPatterns.SCHEMA_SUBSTR,
            )
            ordering = FlextLdifUtilities.Parser.extract_optional_field(
                attr_definition,
                FlextLdifConstants.LdifPatterns.SCHEMA_ORDERING,
            )

            # Extract flags (boolean)
            single_value = FlextLdifUtilities.Parser.extract_boolean_flag(
                attr_definition,
                FlextLdifConstants.LdifPatterns.SCHEMA_SINGLE_VALUE,
            )

            no_user_modification = False
            if case_insensitive:  # Lenient mode (OID)
                no_user_modification = FlextLdifUtilities.Parser.extract_boolean_flag(
                    attr_definition,
                    FlextLdifConstants.LdifPatterns.SCHEMA_NO_USER_MODIFICATION,
                )

            # Extract SUP and USAGE (optional)
            sup = FlextLdifUtilities.Parser.extract_optional_field(
                attr_definition,
                FlextLdifConstants.LdifPatterns.SCHEMA_SUP,
            )
            usage = FlextLdifUtilities.Parser.extract_optional_field(
                attr_definition,
                FlextLdifConstants.LdifPatterns.SCHEMA_USAGE,
            )

            # Build metadata using utilities
            extensions = FlextLdifUtilities.Schema.build_metadata(
                attr_definition,
                quirk_type=quirk_type,
                additional_extensions=syntax_extensions if syntax_validation else None,
            )

            return {
                "oid": oid,
                "name": name,
                "desc": desc,
                "syntax": syntax,
                "length": length,
                "equality": equality,
                "ordering": ordering,
                "substr": substr,
                "single_value": single_value,
                "no_user_modification": no_user_modification,
                "sup": sup,
                "usage": usage,
                "metadata_extensions": extensions,
                "syntax_validation": syntax_validation,
            }

        @staticmethod
        def parse_objectclass(
            oc_definition: str,
            *,
            case_insensitive: bool = False,
            quirk_type: str = "rfc",
        ) -> dict[str, Any]:
            """Parse RFC 4512 objectClass definition into structured data.

            Generic parsing method that extracts all fields from objectClass definition.
            Used by server quirks to get base parsing logic without duplication.

            Args:
                oc_definition: RFC 4512 objectClass definition string
                case_insensitive: If True, use case-insensitive NAME matching
                quirk_type: Server type identifier for metadata

            Returns:
                Dictionary with parsed fields:
                - oid: str (required)
                - name: str | None
                - desc: str | None
                - sup: str | None
                - kind: str (STRUCTURAL, AUXILIARY, or ABSTRACT)
                - must: list[str] | None
                - may: list[str] | None
                - metadata_extensions: dict[str, object]

            Raises:
                ValueError: If OID is missing or invalid

            """
            # Extract OID (required)
            oid = FlextLdifUtilities.Parser.extract_oid(oc_definition)
            if not oid:
                msg = "RFC objectClass parsing failed: missing an OID"
                raise ValueError(msg)

            # Extract NAME (optional) - use utilities with OID as fallback
            name = FlextLdifUtilities.Parser.extract_optional_field(
                oc_definition,
                FlextLdifConstants.LdifPatterns.SCHEMA_NAME,
                default=oid,
            )

            # Extract DESC (optional)
            desc = FlextLdifUtilities.Parser.extract_optional_field(
                oc_definition,
                FlextLdifConstants.LdifPatterns.SCHEMA_DESC,
            )

            # Extract SUP (optional) - superior objectClass(es)
            sup = None
            sup_match = re.search(
                FlextLdifConstants.LdifPatterns.SCHEMA_OBJECTCLASS_SUP,
                oc_definition,
            )
            if sup_match:
                sup_value = sup_match.group(1) or sup_match.group(2)
                sup_value = sup_value.strip()
                # Handle multiple superior classes - use first one
                sup = next(
                    (s.strip() for s in sup_value.split("$")),
                    sup_value,
                )

            # Determine kind (STRUCTURAL, AUXILIARY, ABSTRACT)
            # RFC 4512: Default to STRUCTURAL if KIND is not specified
            kind_match = re.search(
                FlextLdifConstants.LdifPatterns.SCHEMA_OBJECTCLASS_KIND,
                oc_definition,
                re.IGNORECASE,
            )
            kind = (
                kind_match.group(1).upper()
                if kind_match
                else FlextLdifConstants.Schema.STRUCTURAL
            )

            # Extract MUST attributes (optional) - can be single or multiple
            must = None
            must_match = re.search(
                FlextLdifConstants.LdifPatterns.SCHEMA_OBJECTCLASS_MUST,
                oc_definition,
            )
            if must_match:
                must_value = (must_match.group(1) or must_match.group(2)).strip()
                must = [m.strip() for m in must_value.split("$")]

            # Extract MAY attributes (optional) - can be single or multiple
            may = None
            may_match = re.search(
                FlextLdifConstants.LdifPatterns.SCHEMA_OBJECTCLASS_MAY,
                oc_definition,
            )
            if may_match:
                may_value = (may_match.group(1) or may_match.group(2)).strip()
                may = [m.strip() for m in may_value.split("$")]

            # Build metadata using utilities
            extensions = FlextLdifUtilities.Schema.build_metadata(
                oc_definition,
                quirk_type=quirk_type,
            )

            return {
                "oid": oid,
                "name": name,
                "desc": desc,
                "sup": sup,
                "kind": kind,
                "must": must,
                "may": may,
                "metadata_extensions": extensions,
            }

        @staticmethod
        def write_attribute(
            attr_data: Any,
        ) -> str:
            """Write RFC 4512 attribute definition string from SchemaAttribute model.

            Generic writing method that builds RFC-compliant attribute definition string.
            Used by server quirks to get base writing logic without duplication.

            Args:
                attr_data: SchemaAttribute model (oid required)

            Returns:
                RFC 4512 formatted string

            Raises:
                ValueError: If OID is missing

            """
            if not isinstance(attr_data, FlextLdifModels.SchemaAttribute):
                msg = "attr_data must be SchemaAttribute model"
                raise TypeError(msg)

            # OID is required
            if not attr_data.oid:
                msg = "RFC attribute writing failed: missing OID"
                raise ValueError(msg)

            parts: list[str] = [f"( {attr_data.oid}"]

            # Add NAME (optional)
            if attr_data.name:
                parts.append(f"NAME '{attr_data.name}'")

            # Add DESC (optional)
            if attr_data.desc:
                parts.append(f"DESC '{attr_data.desc}'")

            # Add OBSOLETE flag (optional) - check metadata extensions
            if attr_data.metadata and attr_data.metadata.extensions.get(
                FlextLdifConstants.MetadataKeys.OBSOLETE
            ):
                parts.append("OBSOLETE")

            # Add SUP (optional)
            if attr_data.sup:
                parts.append(f"SUP {attr_data.sup}")

            # Add matching rules (optional)
            if attr_data.equality:
                parts.append(f"EQUALITY {attr_data.equality}")

            if attr_data.ordering:
                parts.append(f"ORDERING {attr_data.ordering}")

            if attr_data.substr:
                parts.append(f"SUBSTR {attr_data.substr}")

            # Add SYNTAX with optional length (optional)
            if attr_data.syntax:
                syntax_str = str(attr_data.syntax)
                if attr_data.length is not None:
                    syntax_str += f"{{{attr_data.length}}}"
                parts.append(f"SYNTAX {syntax_str}")

            # Add flags (optional)
            if attr_data.single_value:
                parts.append("SINGLE-VALUE")

            # COLLECTIVE flag from metadata extensions
            if attr_data.metadata and attr_data.metadata.extensions.get(
                FlextLdifConstants.MetadataKeys.COLLECTIVE
            ):
                parts.append("COLLECTIVE")

            if attr_data.no_user_modification:
                parts.append("NO-USER-MODIFICATION")

            # Add USAGE (optional)
            if attr_data.usage:
                parts.append(f"USAGE {attr_data.usage}")

            # Add X-ORIGIN (optional) from metadata
            if attr_data.metadata and attr_data.metadata.x_origin:
                parts.append(f"X-ORIGIN '{attr_data.metadata.x_origin}'")

            # Close definition
            parts.append(")")

            return " ".join(parts)

        @staticmethod
        def write_objectclass(
            oc_data: Any,
        ) -> str:
            """Write RFC 4512 objectClass definition string from SchemaObjectClass model.

            Generic writing method that builds RFC-compliant objectClass definition string.
            Used by server quirks to get base writing logic without duplication.

            Args:
                oc_data: SchemaObjectClass model (oid required)

            Returns:
                RFC 4512 formatted string

            Raises:
                ValueError: If OID is missing

            """
            if not isinstance(oc_data, FlextLdifModels.SchemaObjectClass):
                msg = "oc_data must be SchemaObjectClass model"
                raise TypeError(msg)

            # OID is required and must not be empty
            if not oc_data.oid:
                msg = "RFC objectClass writing failed: missing OID"
                raise ValueError(msg)

            parts: list[str] = [f"( {oc_data.oid}"]

            # Add NAME (optional)
            if oc_data.name:
                parts.append(f"NAME '{oc_data.name}'")

            # Add DESC (optional)
            if oc_data.desc:
                parts.append(f"DESC '{oc_data.desc}'")

            # Add OBSOLETE flag (optional) - check metadata extensions
            if oc_data.metadata and oc_data.metadata.extensions.get(
                FlextLdifConstants.MetadataKeys.OBSOLETE
            ):
                parts.append("OBSOLETE")

            # Add SUP (optional) - can be single string or list
            if oc_data.sup:
                if isinstance(oc_data.sup, list):
                    if len(oc_data.sup) == 1:
                        parts.append(f"SUP {oc_data.sup[0]}")
                    else:
                        sup_str = " $ ".join(oc_data.sup)
                        parts.append(f"SUP ( {sup_str} )")
                else:
                    parts.append(f"SUP {oc_data.sup}")

            # Add kind (optional, defaults to STRUCTURAL per RFC)
            kind = oc_data.kind or FlextLdifConstants.Schema.STRUCTURAL
            parts.append(str(kind))

            # Add MUST (optional) - can be single or list
            if oc_data.must:
                if isinstance(oc_data.must, list):
                    if len(oc_data.must) == 1:
                        parts.append(f"MUST {oc_data.must[0]}")
                    else:
                        must_str = " $ ".join(oc_data.must)
                        parts.append(f"MUST ( {must_str} )")
                else:
                    parts.append(f"MUST {oc_data.must}")

            # Add MAY (optional) - can be single or list
            if oc_data.may:
                if isinstance(oc_data.may, list):
                    if len(oc_data.may) == 1:
                        parts.append(f"MAY {oc_data.may[0]}")
                    else:
                        may_str = " $ ".join(oc_data.may)
                        parts.append(f"MAY ( {may_str} )")
                else:
                    parts.append(f"MAY {oc_data.may}")

            # Add X-ORIGIN (optional) from metadata
            if oc_data.metadata and oc_data.metadata.x_origin:
                parts.append(f"X-ORIGIN '{oc_data.metadata.x_origin}'")

            # Close definition
            parts.append(")")

            return " ".join(parts)

    class OID:
        """OID extraction and validation utilities.

        Pure functions for extracting and validating OIDs from schema definitions.
        Independent of quirks and services - only string/regex operations.

        Methods:
        - extract_from_definition: Extract OID from raw schema definition string
        - extract_from_schema_object: Extract OID from schema model (metadata or field)
        - matches_pattern: Check if OID matches a regex pattern

        """

        @staticmethod
        def extract_from_definition(definition: str) -> str | None:
            """Extract OID from schema definition string.

            Extracts OID from raw attribute or objectClass definition string.
            Looks for OID in parentheses at start: ( 2.5.4.3 ...

            This is a pure utility function with no dependencies on quirks or services.

            Args:
                definition: Raw attribute or objectClass definition string
                           (e.g., "( 2.5.4.3 NAME 'cn' DESC 'Common Name' ...)")

            Returns:
                OID string (e.g., "2.5.4.3") or None if not found

            Example:
                oid = FlextLdifUtilities.OID.extract_from_definition(
                    "( 2.16.840.1.113894.1.1.1 NAME 'orclGuid' ...)"
                )
                # Returns: "2.16.840.1.113894.1.1.1"

            """
            try:
                # Look for OID in parentheses at start: ( 2.16.840.1.113894. ...
                match = re.search(r"\(\s*([\d.]+)", definition)
                if match:
                    return match.group(1)
            except (re.error, AttributeError) as e:
                logger.debug(
                    "Failed to extract OID from definition: %s",
                    e,
                )
            return None

        @staticmethod
        def extract_from_schema_object(
            schema_obj: FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass,
        ) -> str | None:
            """Extract OID from schema object metadata or model.

            Checks both sources:
            1. Original format in metadata (via regex extraction)
            2. OID field in model (fallback)

            This is a pure utility function with no dependencies on quirks or services.

            Args:
                schema_obj: Attribute or ObjectClass model (already parsed)

            Returns:
                OID string (e.g., "2.5.4.3") or None if not found

            """
            # First try: Extract from original_format if available
            if schema_obj.metadata and schema_obj.metadata.original_format:
                try:
                    # Look for OID in parentheses at start: ( 2.16.840.1.113894. ...
                    match = re.search(r"\(\s*([\d.]+)", schema_obj.metadata.original_format)
                    if match:
                        return match.group(1)
                except (re.error, AttributeError):
                    # Regex error or original_format type issue - continue to fallback
                    logger.debug(
                        "Failed to extract OID from original_format: %s",
                        schema_obj.metadata.original_format[:100]
                        if schema_obj.metadata.original_format
                        else "None",
                    )

            # Fallback: Use OID field from model
            return schema_obj.oid

        @staticmethod
        def matches_pattern(
            definition: str,
            oid_pattern: re.Pattern[str],
        ) -> bool:
            r"""Check if schema definition string matches server's OID pattern.

            Generic method for checking if a schema definition matches an OID pattern.
            Works with raw definition strings BEFORE parsing.

            This is a pure utility function with no dependencies on quirks or services.

            Example:
                # Check if attribute matches Oracle OID pattern
                if FlextLdifUtilities.OID.matches_pattern(
                    attr_definition,  # Raw string: "( 2.16.840.1.113894.1.1.1 ...)"
                    re.compile(r'2\.16\.840\.1\.113894\..*')  # Oracle OID pattern
                ):
                    # Handle Oracle-specific attribute

            Args:
                definition: Raw attribute or objectClass definition string
                oid_pattern: Compiled regex pattern to match OID (e.g., re.compile(r'2\\.16\\.840\\..*'))

            Returns:
                True if OID matches pattern, False otherwise

            """
            # Extract OID from definition string
            oid = FlextLdifUtilities.OID.extract_from_definition(definition)
            if not oid:
                return False

            # Check if OID matches server's pattern
            return bool(oid_pattern.match(oid))

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

    class Entry:
        """Entry transformation utilities - pure helper functions.

        Common entry transformations extracted from server quirks.
        Servers can use these for consistent attribute handling.
        """

        # Minimum length for base64 pattern matching
        _MIN_BASE64_LENGTH: int = 8

        @staticmethod
        def convert_boolean_attributes(
            attributes: dict[str, list[str]],
            boolean_attr_names: set[str],
            *,
            source_format: str = "0/1",
            target_format: str = "TRUE/FALSE",
        ) -> dict[str, list[str]]:
            """Convert boolean attribute values between formats.

            Args:
                attributes: Entry attributes {attr_name: [values]}
                boolean_attr_names: Set of attribute names (lowercase) to convert
                source_format: Input format ("0/1" or "TRUE/FALSE")
                target_format: Output format ("0/1" or "TRUE/FALSE")

            Returns:
                New attributes dict with converted boolean values

            """
            if not attributes or not boolean_attr_names:
                return attributes

            result = dict(attributes)

            for attr_name, values in result.items():
                if attr_name.lower() in boolean_attr_names:
                    converted = []

                    for value in values:
                        if source_format == "0/1" and target_format == "TRUE/FALSE":
                            converted.append("TRUE" if value == "1" else "FALSE")
                        elif source_format == "TRUE/FALSE" and target_format == "0/1":
                            converted.append("1" if value.upper() == "TRUE" else "0")
                        else:
                            converted.append(value)

                    result[attr_name] = converted

            return result

        @staticmethod
        def validate_telephone_numbers(
            telephone_values: list[str],
        ) -> list[str]:
            """Validate telephone numbers - must contain at least one digit.

            Args:
                telephone_values: List of telephone number values

            Returns:
                Filtered list containing only valid telephone numbers

            """
            if not telephone_values:
                return []

            # Telephone numbers must contain at least one digit
            return [
                value
                for value in telephone_values
                if any(char.isdigit() for char in value)
            ]

        @staticmethod
        def normalize_attribute_names(
            attributes: dict[str, list[str]],
            case_map: dict[str, str],
        ) -> dict[str, list[str]]:
            """Normalize attribute names using case mapping.

            Args:
                attributes: Entry attributes dict
                case_map: Dict mapping lowercase names → proper case

            Returns:
                New attributes dict with normalized attribute names

            """
            if not attributes or not case_map:
                return attributes

            result: dict[str, list[str]] = {}

            for attr_name, values in attributes.items():
                # Check if this attribute needs case normalization
                normalized_name = case_map.get(attr_name.lower(), attr_name)
                result[normalized_name] = values

            return result

        @staticmethod
        def detect_base64_attributes(
            attributes: dict[str, list[str]],
        ) -> set[str]:
            """Detect which attributes contain base64-encoded values.

            Args:
                attributes: Entry attributes dict

            Returns:
                Set of attribute names that contain base64 data

            """
            if not attributes:
                return set()

            base64_attrs: set[str] = set()

            for attr_name, values in attributes.items():
                for value in values:
                    if not isinstance(value, str):
                        continue

                    # Check for base64 markers or non-UTF8 patterns
                    try:
                        value.encode("utf-8").decode("utf-8")
                    except (UnicodeDecodeError, AttributeError):
                        base64_attrs.add(attr_name)
                        break

                    # Check for common base64 patterns
                    if (
                        re.match(r"^[A-Za-z0-9+/]*={0,2}$", value)
                        and len(value) > FlextLdifUtilities.Entry._MIN_BASE64_LENGTH
                    ):
                        # Looks like base64
                        try:
                            base64.b64decode(value, validate=True)
                            base64_attrs.add(attr_name)
                            break
                        except Exception as e:
                            logger.debug(
                                f"Base64 validation failed for {attr_name}: {e}"
                            )

            return base64_attrs


__all__ = [
    "FlextLdifUtilities",
]
