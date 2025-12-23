"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64
from collections.abc import Iterable, Sequence
from pathlib import Path

from flext_core import (
    FlextLogger,
    FlextResult,
    FlextRuntime,
    FlextTypes,
    u,
)
from jinja2 import Environment

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.settings import FlextLdifModelsSettings
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.typings import t

# REMOVED: Runtime aliases redundantes - use c, m, t diretamente (já importados com runtime alias)
# REMOVED: Type aliases para objetos nested - use m.* ou FlextLdifModelsDomains.* diretamente
# SchemaAttribute: TypeAlias = m.Ldif.SchemaAttribute  # Use m.Ldif.SchemaAttribute or m.Ldif.SchemaAttribute directly
# SchemaObjectClass: TypeAlias = m.Ldif.SchemaObjectClass  # Use m.Ldif.SchemaObjectClass or m.Ldif.SchemaObjectClass directly
# QuirkMetadata: TypeAlias = FlextLdifModelsDomains.QuirkMetadata  # Use m.Ldif.QuirkMetadata or FlextLdifModelsDomains.QuirkMetadata directly

# Aliases for simplified usage - after all imports
# Use flext-core utilities directly (FlextLdifUtilities extends FlextUtilities)
# u is already imported as u above
r = FlextResult  # Shared from flext-core

# Constants
_TUPLE_LENGTH_TWO = 2  # Length for tuple unpacking validation

logger = FlextLogger(__name__)


class FlextLdifUtilitiesWriter:
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

        return FlextLdifUtilitiesWriter.fold(line, width=width)

    @staticmethod
    def fold(
        line: str,
        width: int = c.Ldif.Format.LINE_FOLD_WIDTH,
    ) -> list[str]:
        """Fold long LDIF line according to RFC 2849 §3.

        RFC 2849 §3: Lines longer than 76 BYTES should be folded with
        a newline followed by a single space. The fold point should
        not split multi-byte UTF-8 sequences.

        ABNF Grammar (RFC 2849):
            ldif-content = *LDIF-attrval
            LDIF-attrval = LDIF-dn / LDIF-attr-value-record
            ; Lines may be folded by inserting:
            ; CRLF followed by exactly one space or TAB

        Args:
            line: Line to fold (UTF-8 string)
            width: Maximum line width in bytes (default: 76 per RFC 2849)

        Returns:
            List of folded lines (first line + continuation lines with space prefix)

        Example:
            >>> FlextLdifUtilitiesWriter.fold("cn: very long value", width=10)
            ['cn: very l', ' ong value']

        """
        if not line:
            return [line]

        line_bytes = line.encode("utf-8")
        if len(line_bytes) <= width:
            return [line]

        # RFC 2849: Fold by bytes, ensuring we don't split multibyte UTF-8 sequences
        folded: list[str] = []
        pos = 0

        while pos < len(line_bytes):
            if not folded:
                # First line: max_width bytes
                chunk_end = min(pos + width, len(line_bytes))
            else:
                # Continuation lines: width - 1 (space prefix takes 1 byte)
                chunk_end = min(pos + width - 1, len(line_bytes))

            # Find valid UTF-8 boundary (don't split multibyte chars)
            while chunk_end > pos:
                try:
                    chunk = line_bytes[pos:chunk_end].decode("utf-8")
                    break
                except UnicodeDecodeError:
                    # Backup to previous byte to find valid boundary
                    chunk_end -= 1
            else:
                # Should not happen with valid UTF-8, but handle gracefully
                chunk_end = pos + 1
                chunk = line_bytes[pos:chunk_end].decode("utf-8", errors="replace")

            if folded:
                # Continuation line: prefix with space (RFC 2849 §3)
                folded.append(
                    c.Ldif.Format.LINE_CONTINUATION_SPACE + chunk,
                )
            else:
                # First line: no prefix
                folded.append(chunk)

            pos = chunk_end

        return folded

    @staticmethod
    def fmt_attr(attr_name: str, value_str: str, *, use_base64: bool = False) -> str:
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
        template_str: str,
        context: dict[str, object],
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
            >>> result.value
            'Hello World'

        """
        try:
            env = Environment(autoescape=True)
            template = env.from_string(template_str)
            rendered = template.render(**context)
            return FlextResult[str].ok(rendered)
        except Exception as e:
            logger.exception(
                "Template rendering failed",
            )
            return FlextResult[str].fail(f"Template rendering failed: {e}")

    @staticmethod
    def write_file(
        content: str,
        file_path: Path,
        encoding: str = "utf-8",
    ) -> FlextResult[dict[str, str | int]]:
        """Write content to file (pure I/O operation).

        Args:
            content: Content to write
            file_path: Path to output file
            encoding: File encoding (default: utf-8)

        Returns:
            FlextResult with file stats dict or error

        Example:
            >>> result = LdifWriter.write_file("content", Path("out.ldif"))
            >>> stats = result.value
            >>> stats["bytes_written"]
            7

        """
        try:
            # Create parent directories if they don't exist
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content, encoding=encoding)
            stats: dict[str, str | int] = {
                "bytes_written": len(content.encode(encoding)),
                "path": str(file_path),
                "encoding": encoding,
            }
            return FlextResult[dict[str, str | int]].ok(stats)
        except Exception as e:
            logger.exception(
                "File write failed",
                file_path=str(file_path),
            )
            return FlextResult[dict[str, str | int]].fail(
                f"File write failed: {e}",
            )

    @staticmethod
    def add_attribute_matching_rules(
        attr_data: FlextLdifModelsDomains.SchemaAttribute,
        parts: list[str],
    ) -> None:
        """Add matching rules to attribute parts list."""
        if attr_data.equality:
            parts.append(f"EQUALITY {attr_data.equality}")
        if attr_data.ordering:
            parts.append(f"ORDERING {attr_data.ordering}")
        if attr_data.substr:
            parts.append(f"SUBSTR {attr_data.substr}")

    @staticmethod
    def add_attribute_syntax(
        attr_data: FlextLdifModelsDomains.SchemaAttribute,
        parts: list[str],
    ) -> None:
        """Add syntax and length to attribute parts list.

        ARCHITECTURE: Writer ONLY formats data, does NOT transform
        Quirks are responsible for ensuring correct syntax format:
        - RFC/OUD quirks: ensure syntax has no quotes before calling writer
        - Writer preserves syntax value from model as-is
        """
        if attr_data.syntax:
            # Format syntax as-is from model (quirks ensure correct format)
            syntax_str = str(attr_data.syntax)
            if attr_data.length is not None:
                syntax_str += f"{{{attr_data.length}}}"
            parts.append(f"SYNTAX {syntax_str}")

    @staticmethod
    def add_attribute_flags(
        attr_data: FlextLdifModelsDomains.SchemaAttribute,
        parts: list[str],
    ) -> None:
        """Add flags to attribute parts list."""
        if attr_data.single_value:
            parts.append("SINGLE-VALUE")
        if attr_data.metadata and u.mapper().get(
            attr_data.metadata.extensions,
            c.Ldif.MetadataKeys.COLLECTIVE,
        ):
            parts.append("COLLECTIVE")
        if attr_data.no_user_modification:
            parts.append("NO-USER-MODIFICATION")

    @staticmethod
    def _build_attribute_parts(
        attr_data: FlextLdifModelsDomains.SchemaAttribute,
    ) -> list[str]:
        """Build RFC attribute definition parts (extracted to reduce complexity)."""
        parts: list[str] = [f"( {attr_data.oid}"]

        if attr_data.name:
            parts.append(f"NAME '{attr_data.name}'")

        if attr_data.desc:
            parts.append(f"DESC '{attr_data.desc}'")

        if attr_data.metadata and u.mapper().get(
            attr_data.metadata.extensions,
            c.Ldif.MetadataKeys.OBSOLETE,
        ):
            parts.append("OBSOLETE")

        if attr_data.sup:
            parts.append(f"SUP {attr_data.sup}")

        FlextLdifUtilitiesWriter.add_attribute_matching_rules(attr_data, parts)
        FlextLdifUtilitiesWriter.add_attribute_syntax(attr_data, parts)
        FlextLdifUtilitiesWriter.add_attribute_flags(attr_data, parts)

        if attr_data.usage:
            parts.append(f"USAGE {attr_data.usage}")

        x_origin = (
            u.mapper().get(attr_data.metadata.extensions, "x_origin")
            if attr_data.metadata
            else None
        )
        if x_origin:
            parts.append(f"X-ORIGIN '{x_origin}'")

        parts.append(")")
        return parts

    @staticmethod
    def write_rfc_attribute(
        attr_data: FlextLdifModelsDomains.SchemaAttribute,
    ) -> FlextResult[str]:
        """Write attribute data to RFC 4512 format."""
        try:
            if not attr_data.oid:
                return FlextResult.fail("RFC attribute writing failed: missing OID")

            parts = FlextLdifUtilitiesWriter._build_attribute_parts(attr_data)
            return FlextResult.ok(" ".join(parts))

        except (ValueError, TypeError, AttributeError) as e:
            logger.exception("RFC attribute writing exception")
            return FlextResult.fail(f"RFC attribute writing failed: {e}")

    @staticmethod
    def _add_oc_must_may(
        parts: list[str],
        attr_list: str | list[str] | None,
        keyword: str,
    ) -> None:
        """Add MUST or MAY clause to objectClass definition parts.

        RFC-compliant implementation - passes attribute names as-is from Entry model.
        Server-specific normalization should happen in quirks layer during parsing.
        """
        if not attr_list:
            return

        if isinstance(attr_list, list):
            attr_list_str: list[str] = [str(item) for item in attr_list]
            if len(attr_list_str) == 1:
                parts.append(f"{keyword} {attr_list_str[0]}")
            else:
                attrs_str = " $ ".join(attr_list_str)
                parts.append(f"{keyword} ( {attrs_str} )")
        else:
            # attr_list is str
            parts.append(f"{keyword} {attr_list}")

    @staticmethod
    def _build_objectclass_parts(
        oc_data: FlextLdifModelsDomains.SchemaObjectClass,
    ) -> list[str]:
        """Build RFC objectClass definition parts (extracted to reduce complexity)."""
        parts: list[str] = [f"( {oc_data.oid}"]

        if oc_data.name:
            parts.append(f"NAME '{oc_data.name}'")

        if oc_data.desc:
            parts.append(f"DESC '{oc_data.desc}'")

        if oc_data.metadata and u.mapper().get(
            oc_data.metadata.extensions,
            c.Ldif.MetadataKeys.OBSOLETE,
        ):
            parts.append("OBSOLETE")

        if oc_data.sup:
            # Handle SUP as string or list
            if isinstance(oc_data.sup, list):
                # Multiple SUP values: format as ( value1 $ value2 $ ... )
                sup_list_str: list[str] = [str(item) for item in oc_data.sup]
                sup_str = " $ ".join(sup_list_str)
                parts.append(f"SUP ( {sup_str} )")
            else:
                # Single SUP value (str)
                parts.append(f"SUP {oc_data.sup}")

        # Use full path to avoid type resolution issues
        # Access Schema class directly from ErrorCategory namespace
        kind = oc_data.kind or c.Ldif.SchemaKind.STRUCTURAL.value
        parts.append(str(kind))

        FlextLdifUtilitiesWriter._add_oc_must_may(parts, oc_data.must, "MUST")
        FlextLdifUtilitiesWriter._add_oc_must_may(parts, oc_data.may, "MAY")

        oc_x_origin = (
            u.mapper().get(oc_data.metadata.extensions, "x_origin")
            if oc_data.metadata
            else None
        )
        if oc_x_origin:
            parts.append(f"X-ORIGIN '{oc_x_origin}'")

        parts.append(")")

        return parts

    @staticmethod
    def write_rfc_objectclass(
        objectclass: FlextLdifModelsDomains.SchemaObjectClass,
    ) -> FlextResult[str]:
        """Write objectClass data to RFC 4512 format."""
        try:
            if not objectclass.oid:
                return FlextResult.fail("RFC objectClass writing failed: missing OID")

            parts = FlextLdifUtilitiesWriter._build_objectclass_parts(objectclass)
            return FlextResult.ok(" ".join(parts))

        except (ValueError, TypeError, AttributeError) as e:
            logger.exception("RFC objectClass writing exception")
            return FlextResult.fail(f"RFC objectClass writing failed: {e}")

    @staticmethod
    def order_attribute_names(
        attr_names: list[str],
        *,
        use_rfc_order: bool = False,
        sort_alphabetical: bool = False,
        priority_attrs: list[str] | None = None,
    ) -> list[str]:
        """Order attribute names using various strategies.

        Pure ordering function - no models, no side effects.

        Args:
            attr_names: List of attribute names to order
            use_rfc_order: If True, use RFC 2849 priority ordering
            sort_alphabetical: If True, sort alphabetically
            priority_attrs: Priority attributes for RFC ordering

        Returns:
            Ordered list of attribute names

        """
        # RFC 2849 priority ordering: priority attrs first, rest alphabetical
        if use_rfc_order:
            priority = priority_attrs or ["objectClass"]
            priority_list = [a for a in priority if a in attr_names]
            remaining = sorted(n for n in attr_names if n not in priority_list)
            return priority_list + remaining

        # Simple alphabetical ordering
        if sort_alphabetical:
            return sorted(attr_names)

        # Default: preserve original order
        return attr_names

    @staticmethod
    def determine_attribute_order(
        entry_data: dict[str, FlextTypes.GeneralValueType],
    ) -> list[tuple[str, FlextTypes.GeneralValueType]] | None:
        """Determine attribute processing order from entry metadata.

        Args:
            entry_data: Entry dictionary with optional _metadata

        Returns:
            List of (attr_name, attr_value) tuples in order, or None for default order

        """
        if "_metadata" not in entry_data:
            return None

        metadata = entry_data["_metadata"]
        attr_order = None

        # Extract attribute_order from metadata
        extensions = getattr(metadata, "extensions", None)
        if extensions is not None:
            attr_order = (
                u.mapper().get(extensions, "attribute_order")
                if hasattr(extensions, "get")
                else None
            )
        elif isinstance(metadata, dict):
            extensions_raw: dict[str, t.MetadataAttributeValue] | object = (
                u.mapper().get(metadata, "extensions", default={})
            )
            if not isinstance(extensions_raw, dict):
                attr_order = None
            else:
                # Type narrowing: after isinstance check, extensions_raw is dict[str, t.MetadataAttributeValue]
                # Business Rule: extensions_raw is dict[str, t.GeneralValueType] from metadata
                # but we need dict[str, MetadataAttributeValue] for type safety.
                # t.GeneralValueType includes recursive types, but metadata extensions
                # in practice only contain ScalarValue or Sequence[ScalarValue].
                extensions_dict: dict[str, t.MetadataAttributeValue] = extensions_raw
                if FlextRuntime.is_dict_like(extensions_dict):
                    attr_order = u.mapper().get(extensions_dict, "attribute_order")
                else:
                    attr_order = None

        if attr_order is None:
            return None

        # Type narrowing: ensure attr_order is list for iteration
        if not isinstance(attr_order, list):
            return None

        # Build ordered list from attr_order
        skip_keys = {
            c.Ldif.DictKeys.DN,
            "_metadata",
            "server_type",
            "_acl_attributes",
        }

        # Type narrowing: ensure tuple elements are (str, t.GeneralValueType) for return type
        result: list[tuple[str, FlextTypes.GeneralValueType]] = []
        attr_order_list: list[object] = attr_order
        for key in attr_order_list:
            if not isinstance(key, str):
                continue  # Skip non-string keys
            if key in entry_data and key not in skip_keys:
                result.append((key, entry_data[key]))
        return result

    @staticmethod
    def extract_base64_attrs(
        entry_data: dict[str, FlextTypes.GeneralValueType],
    ) -> set[str]:
        """Extract set of attribute names that require base64 encoding.

        Args:
            entry_data: Entry dictionary with optional _base64_attrs

        Returns:
            Set of attribute names requiring base64 encoding

        """
        if "_base64_attrs" not in entry_data:
            return set()

        base64_data = entry_data["_base64_attrs"]
        # t.GeneralValueType only includes Sequence, not set
        # Convert list/tuple to set[str]
        if isinstance(base64_data, (list, tuple)):
            return {str(item) for item in base64_data}

        return set()

    @staticmethod
    def should_skip_attribute(attr_name: str) -> bool:
        """Check if attribute should be skipped during LDIF writing.

        Args:
            attr_name: Attribute name to check

        Returns:
            True if attribute should be skipped

        """
        # Skip DN (written separately)
        if attr_name.lower() == c.Ldif.DictKeys.DN:
            return True

        # Skip internal metadata attributes
        return bool(attr_name.startswith("_"))

    @staticmethod
    def format_attribute_line(
        attr_name: str,
        attr_value: t.ScalarValue | list[str],
        *,
        is_base64: bool,
        attribute_case_map: dict[str, str] | None = None,
    ) -> list[str]:
        """Format attribute into LDIF lines.

        Args:
            attr_name: Attribute name
            attr_value: Attribute value (single or list)
            is_base64: Whether to use base64 encoding marker
            attribute_case_map: Optional case mapping dictionary

        Returns:
            List of formatted LDIF lines (empty list if value is empty)

        """
        # Skip empty-valued attributes per RFC 2849
        if FlextRuntime.is_list_like(attr_value):
            # Type narrowing: ensure attr_value is iterable (list, tuple, or sequence)
            if not isinstance(attr_value, (list, tuple)):
                return []
            # Filter out empty strings from list
            non_empty_values = [v for v in attr_value if v]
            if not non_empty_values:
                return []
        elif not attr_value:
            # Skip single empty values
            return []

        # Apply attribute name mapping
        mapped_attr_name = attr_name
        if attribute_case_map:
            mapped_attr_name = u.mapper().get(
                attribute_case_map,
                attr_name.lower(),
                default=attr_name,
            )

        # Determine prefix
        attr_prefix = f"{mapped_attr_name}::" if is_base64 else f"{mapped_attr_name}:"

        # Handle both list and single values
        if FlextRuntime.is_list_like(attr_value):
            # Type narrowing: ensure attr_value is iterable (list, tuple, or sequence)
            if not isinstance(attr_value, (list, tuple)):
                return [f"{attr_prefix} {attr_value}"]
            # At this point, we know attr_value is a non-empty list
            # with non-empty values
            non_empty_values = [v for v in attr_value if v]
            return [f"{attr_prefix} {value}" for value in non_empty_values]

        return [f"{attr_prefix} {attr_value}"]

    # ==========================================================================
    # RFC 2849 Character Class Validation (ABNF-based)
    # ==========================================================================

    @staticmethod
    def is_safe_char(char: str) -> bool:
        """Check if char is SAFE-CHAR per RFC 2849 §2.

        SAFE-CHAR = %x01-09 / %x0B-0C / %x0E-7F
        (excludes NUL, LF, CR)

        Uses c.Ldif.Format.SAFE_CHAR_* for validation.

        Args:
            char: Single character to validate

        Returns:
            True if char is SAFE-CHAR, False otherwise

        """
        if not char or len(char) != 1:
            return False
        code = ord(char)
        safe_min = c.Ldif.Format.SAFE_CHAR_MIN
        safe_max = c.Ldif.Format.SAFE_CHAR_MAX
        safe_exclude = c.Ldif.Format.SAFE_CHAR_EXCLUDE
        return safe_min <= code <= safe_max and code not in safe_exclude

    @staticmethod
    def is_safe_init_char(char: str) -> bool:
        """Check if char is SAFE-INIT-CHAR per RFC 2849 §2.

        SAFE-INIT-CHAR = %x01-09 / %x0B-0C / %x0E-1F / %x21-39 / %x3B / %x3D-7F
        (SAFE-CHAR excluding SPACE, COLON, LESS-THAN)

        Uses c.Ldif.Format.SAFE_INIT_CHAR_EXCLUDE for exclusion set.

        Args:
            char: Single character to validate

        Returns:
            True if char is SAFE-INIT-CHAR, False otherwise

        """
        if not char or len(char) != 1:
            return False
        code = ord(char)
        # First check if it's a SAFE-CHAR
        if not FlextLdifUtilitiesWriter.is_safe_char(char):
            return False
        # Then check SAFE-INIT-CHAR exclusions
        return code not in c.Ldif.Format.SAFE_INIT_CHAR_EXCLUDE

    @staticmethod
    def is_base64_char(char: str) -> bool:
        """Check if char is BASE64-CHAR per RFC 2849 §2.

        BASE64-CHAR = %x2B / %x2F / %x30-39 / %x3D / %x41-5A / %x61-7A
        (+ / 0-9 = A-Z a-z)

        Uses c.Ldif.Format.BASE64_CHARS for validation.

        Args:
            char: Single character to validate

        Returns:
            True if char is BASE64-CHAR, False otherwise

        """
        if not char or len(char) != 1:
            return False
        return char in c.Ldif.Format.BASE64_CHARS

    @staticmethod
    def is_valid_safe_string(value: str) -> bool:
        """Check if value is valid SAFE-STRING per RFC 2849 §2.

        SAFE-STRING = [SAFE-INIT-CHAR *SAFE-CHAR]

        Args:
            value: String to validate

        Returns:
            True if value is valid SAFE-STRING, False otherwise

        """
        if not value:
            return True  # Empty string is valid

        # First char must be SAFE-INIT-CHAR
        if not FlextLdifUtilitiesWriter.is_safe_init_char(value[0]):
            return False

        # Rest must be SAFE-CHAR
        for char in value[1:]:
            if not FlextLdifUtilitiesWriter.is_safe_char(char):
                return False

        # Trailing space is not allowed
        return value[-1] != " "

    # ==========================================================================
    # RFC 2849 Encoding Helpers
    # ==========================================================================

    @staticmethod
    def needs_base64_encoding(
        value: str,
        *,
        check_trailing_space: bool = True,
    ) -> bool:
        """Check if value needs base64 encoding per RFC 2849 §2.

        RFC 2849 §2 defines SAFE-CHAR and SAFE-INIT-CHAR:
            SAFE-CHAR = %x01-09 / %x0B-0C / %x0E-7F
            SAFE-INIT-CHAR = %x01-09 / %x0B-0C / %x0E-1F /
                             %x21-39 / %x3B / %x3D-7F
                             ; Any SAFE-CHAR except: SPACE, ':', '<'

        Base64 encoding is required when:
        - Value starts with SPACE ' ', COLON ':', or LESS-THAN '<'
        - Value ends with SPACE ' ' (controllable via check_trailing_space)
        - Value contains NUL, LF, CR, or non-ASCII chars

        Args:
            value: The attribute value to check
            check_trailing_space: If True, trailing space requires base64
                (default True per RFC, servers may override)

        Returns:
            True if value needs base64 encoding, False otherwise

        """
        if not value:
            return False

        # RFC 2849 §2 - Unsafe characters at start (SAFE-INIT-CHAR exclusions)
        if value[0] in c.Ldif.Format.BASE64_START_CHARS:
            return True

        # RFC 2849 - Value ending with space requires base64 (parameterizable)
        if check_trailing_space and value[-1] == " ":
            return True

        # Use the optimized is_valid_safe_string for full validation
        # but we need char-by-char check for performance
        safe_min = c.Ldif.Format.SAFE_CHAR_MIN
        safe_max = c.Ldif.Format.SAFE_CHAR_MAX
        safe_exclude = c.Ldif.Format.SAFE_CHAR_EXCLUDE

        # Check for control characters or non-printable ASCII
        for char in value:
            byte_val = ord(char)
            # Outside SAFE-CHAR range or in exclusion set requires base64
            if byte_val < safe_min or byte_val > safe_max or byte_val in safe_exclude:
                return True

        return False

    @staticmethod
    def write_modify_operations(
        entry_data: dict[str, FlextTypes.GeneralValueType],
    ) -> list[str]:
        """Write LDIF modify operations for schema additions.

        Args:
            entry_data: Entry dictionary with modify operations

        Returns:
            List of LDIF lines for modify operations

        """
        lines = []

        # Write modify-add operations for attributetypes
        if "_modify_add_attributetypes" in entry_data:
            attr_types = entry_data["_modify_add_attributetypes"]
            # Type narrowing: ensure attr_types is iterable before using extend
            if (
                FlextRuntime.is_list_like(attr_types)
                and attr_types
                and isinstance(attr_types, (list, tuple))
            ):
                lines.append("add: attributetypes")
                lines.extend(f"attributetypes: {attr_type}" for attr_type in attr_types)
                lines.append("-")

        # Write modify-add operations for objectclasses
        if "_modify_add_objectclasses" in entry_data:
            obj_classes = entry_data["_modify_add_objectclasses"]
            # Type narrowing: ensure obj_classes is iterable before using extend
            if (
                FlextRuntime.is_list_like(obj_classes)
                and obj_classes
                and isinstance(obj_classes, (list, tuple))
            ):
                lines.append("add: objectclasses")
                lines.extend(f"objectclasses: {obj_class}" for obj_class in obj_classes)
                lines.append("-")

        return lines

    @staticmethod
    def format_schema_modify_entry(
        entry_dn: str,
        schema_type: str,
        schema_value: str,
    ) -> str:
        r"""Format single schema element as modify-add LDIF entry.

        Args:
            entry_dn: DN for the entry
            schema_type: Schema type (attributeTypes, objectClasses, etc.)
            schema_value: Schema definition string

        Returns:
            Formatted LDIF entry string

        Example:
            >>> FlextLdifUtilitiesWriter.format_schema_modify_entry(
            ...     "cn=subschemasubentry", "attributeTypes", "( 1.2.3.4 NAME 'test' )"
            ... )
            'dn: cn=subschemasubentry\nchangetype: modify\n'
            'add: attributeTypes\n'
            'attributeTypes: ( 1.2.3.4 NAME \'test\' )\n'

        """
        return (
            f"dn: {entry_dn}\n"
            "changetype: modify\n"
            f"add: {schema_type}\n"
            f"{schema_type}: {schema_value}\n"
        )

    @staticmethod
    def _apply_output_options(
        attr_name: str,
        attr_values: list[str],
        entry_metadata: m.Ldif.QuirkMetadata,
        output_options: FlextLdifModelsSettings.WriteOutputOptions,
    ) -> tuple[str, list[str]] | None:
        """Apply output visibility options based on attribute status.

        SRP: Writer determines output format based on marker status and options.

        Args:
            attr_name: Attribute name to check
            attr_values: Attribute values to write
            entry_metadata: Entry metadata containing marker status
            output_options: Output visibility configuration

        Returns:
            - (attr_name, values): Write normally
            - ("# " + attr_name, values): Write as comment
            - None: Don't write at all (hide)

        Example:
            result = FlextLdifUtilitiesWriter._apply_output_options(
                "telephoneNumber",
                ["+1234567890"],
                entry.metadata,
                output_options
            )
            if result is None:
                # Don't write this attribute
                pass
            else:
                attr_name, values = result
                # Write attribute (possibly as comment)

        """
        # Get marked_attributes from metadata (type narrowing)
        marked_attrs_raw: dict[str, dict[str, t.MetadataAttributeValue]] | object = (
            u.mapper().get(entry_metadata.extensions, "marked_attributes", default={})
        )
        if not isinstance(marked_attrs_raw, dict):
            return (attr_name, attr_values)

        # Type narrowing: after isinstance check, marked_attrs_raw is dict[str, dict[str, t.MetadataAttributeValue]]
        marked_attrs: dict[str, dict[str, t.MetadataAttributeValue]] = marked_attrs_raw
        attr_info = u.mapper().get(marked_attrs, attr_name)

        # If attribute not marked, write normally
        if not attr_info:
            return (attr_name, attr_values)

        # Check removed_attributes for already-removed attributes
        removed_attrs_raw: dict[str, t.MetadataAttributeValue] | object = (
            u.mapper().get(entry_metadata.extensions, "removed_attributes", default={})
        )
        if isinstance(removed_attrs_raw, dict) and attr_name in removed_attrs_raw:
            return FlextLdifUtilitiesWriter._handle_removed_attribute(
                attr_name,
                attr_values,
                output_options,
            )

        # Handle based on status - extracted to reduce complexity
        # Use full path to avoid type resolution issues
        # Access enum value directly as string literal to avoid mypy issues with nested enum access
        normal_status = "normal"  # c.Ldif.AttributeMarkerStatus.NORMAL.value
        status_raw = u.mapper().get(attr_info, "status", default=normal_status)
        # Validate status is AttributeMarkerStatusLiteral
        valid_statuses = {
            "normal",
            "marked_for_removal",
            "filtered",
            "operational",
            "hidden",
            "renamed",
        }
        status: c.Ldif.LiteralTypes.AttributeMarkerStatusLiteral
        if isinstance(status_raw, str) and status_raw in valid_statuses:
            # Use namespace completo para objetos nested (sem alias redundante)
            # Type narrowing: status_raw is in valid_statuses, so it's the literal type
            # Explicit assignment with known literal value
            if status_raw == "normal":
                status = "normal"
            elif status_raw == "marked_for_removal":
                status = "marked_for_removal"
            elif status_raw == "filtered":
                status = "filtered"
            elif status_raw == "operational":
                status = "operational"
            elif status_raw == "hidden":
                status = "hidden"
            elif status_raw == "renamed":
                status = "renamed"
            else:
                status = "normal"
        else:
            # Business Rule: Use literal "normal" to satisfy AttributeMarkerStatusLiteral
            status = "normal"
        return FlextLdifUtilitiesWriter._handle_attribute_status(
            attr_name,
            attr_values,
            status,
            output_options,
        )

    @staticmethod
    def _handle_removed_attribute(
        attr_name: str,
        attr_values: list[str],
        output_options: FlextLdifModelsSettings.WriteOutputOptions,
    ) -> tuple[str, list[str]] | None:
        """Handle already-removed attributes (extracted to reduce complexity)."""
        if output_options.show_removed_attributes:
            return (f"# {attr_name}", attr_values)
        return None

    @staticmethod
    def _handle_attribute_status(
        attr_name: str,
        attr_values: list[str],
        status: c.Ldif.LiteralTypes.AttributeMarkerStatusLiteral,
        output_options: FlextLdifModelsSettings.WriteOutputOptions,
    ) -> tuple[str, list[str]] | None:
        """Handle attribute based on status (extracted to reduce complexity)."""
        # Use full path to avoid type resolution issues
        # Access AttributeMarkerStatus enum values directly as string literals
        # (StrEnum values are known: "operational", "filtered", "marked_for_removal", "hidden")
        # This avoids mypy issues with nested enum access while maintaining type safety
        operational_value: str = (
            "operational"  # c.Ldif.AttributeMarkerStatus.OPERATIONAL.value
        )
        filtered_value: str = "filtered"  # c.Ldif.AttributeMarkerStatus.FILTERED.value
        marked_for_removal_value: str = "marked_for_removal"  # c.Ldif.AttributeMarkerStatus.MARKED_FOR_REMOVAL.value
        hidden_value: str = "hidden"  # c.Ldif.AttributeMarkerStatus.HIDDEN.value
        # Type annotations: ensure tuples are correctly typed
        # WriteOutputOptions attributes are str ("show", "hide", "comment"), not bool
        # Convert to bool for handler logic: "show" = True, "hide"/"comment" = False
        show_operational_str: str = output_options.show_operational_attributes
        show_filtered_str: str = output_options.show_filtered_attributes
        show_removed_str: str = output_options.show_removed_attributes
        # Convert str to bool: "show" means show, anything else means don't show normally
        show_operational: bool = show_operational_str == "show"
        show_filtered: bool = show_filtered_str == "show"
        show_removed: bool = show_removed_str == "show"
        operational_handler: tuple[bool, str | None] = (show_operational, attr_name)
        filtered_handler: tuple[bool, str | None] = (show_filtered, f"# {attr_name}")
        marked_for_removal_handler: tuple[bool, str | None] = (
            show_removed,
            f"# {attr_name}",
        )
        hidden_handler: tuple[bool, str | None] = (False, None)
        status_handlers: dict[str, tuple[bool, str | None]] = {
            operational_value: operational_handler,
            filtered_value: filtered_handler,
            marked_for_removal_value: marked_for_removal_handler,
            hidden_value: hidden_handler,
        }

        handler_config = u.mapper().get(status_handlers, status)
        # Type narrowing: handler_config is tuple[bool, str | None] when found
        if (
            handler_config
            and isinstance(handler_config, tuple)
            and len(handler_config) == _TUPLE_LENGTH_TWO
        ):
            # Type narrowing: handler_config is tuple[bool, str | None]
            show_flag, name_format = handler_config
            if not show_flag:
                return None
            if name_format is None:
                return None
            return (name_format, attr_values)

        # Default: write normally
        return (attr_name, attr_values)

    @staticmethod
    def check_minimal_differences_restore(
        ldif_lines: list[str],
        attr_name: str,
        minimal_differences_attrs: dict[str, t.MetadataAttributeValue],
    ) -> bool:
        """Check minimal differences and restore original attribute line if needed.

        DRY utility for _write_single_attribute patterns across servers.

        Args:
            ldif_lines: Output lines list (mutated in-place if restoring)
            attr_name: Attribute name to check
            minimal_differences_attrs: Dict of attribute differences

        Returns:
            True if original was restored (caller should return early)
            False if no restoration needed (caller should continue writing)

        """
        # Check for minimal differences using both possible keys
        attr_diff = u.mapper().get(
            minimal_differences_attrs,
            attr_name,
        ) or u.mapper().get(minimal_differences_attrs, f"attribute_{attr_name}")

        # Check if attr_diff is a dict-like object and has differences
        if FlextRuntime.is_dict_like(attr_diff):
            has_diff_result = u.mapper().get(
                attr_diff,
                c.Ldif.MetadataKeys.HAS_DIFFERENCES,
            )
            if has_diff_result:
                original_attr_str = u.mapper().get(attr_diff, "original")
                if original_attr_str and isinstance(original_attr_str, str):
                    ldif_lines.append(original_attr_str)
                    logger.debug(
                        "Restored original attribute line",
                        attribute_name=attr_name,
                    )
                    return True

        return False

    @staticmethod
    def extract_typed_attr_values(
        attr_values: FlextTypes.GeneralValueType,
    ) -> list[str] | str:
        """Type-safe extraction of attribute values.

        DRY utility for _write_single_attribute patterns across servers.

        Args:
            attr_values: Raw attribute values (str, list, or other)

        Returns:
            Typed attribute values as list[str] or str

        """
        if isinstance(attr_values, str):
            return attr_values
        # Type narrowing: ensure attr_values is iterable before using list comprehension
        if FlextRuntime.is_list_like(attr_values):
            if isinstance(attr_values, (list, tuple)):
                return [str(v) for v in attr_values]
            # Fallback for other sequence types - ensure it's iterable
            if isinstance(attr_values, Sequence):
                return [str(v) for v in attr_values]
            # If not a sequence, try to convert to list
            # Type narrowing: attr_values is list-like but not Sequence, try iter()
            # Check if it's iterable but not a string/bytes
            if hasattr(attr_values, "__iter__") and not isinstance(
                attr_values,
                (str, bytes),
            ):
                # Type narrowing: attr_values has __iter__, safe to iterate
                # Use cast to help mypy understand it's iterable
                try:
                    # Type narrowing: attr_values is iterable, convert to list
                    if isinstance(attr_values, Iterable):
                        attr_values_list: list[object] = list(attr_values)
                        return [str(v) for v in attr_values_list]
                    return str(attr_values) if attr_values else ""
                except (TypeError, ValueError):
                    return str(attr_values) if attr_values else ""
            return str(attr_values) if attr_values else ""
        return str(attr_values) if attr_values else ""

    @staticmethod
    def encode_attribute_value(
        attr_name: str,
        value: bytes | str,
    ) -> str:
        """Encode a single attribute value for LDIF output (RFC 2849).

        Handles:
        - bytes → base64 encoding
        - str → UTF-8 validation + base64 if needed (control chars, etc.)
        - Binary attributes → always base64

        DRY utility replacing _write_modify_attribute_value patterns.

        Args:
            attr_name: Attribute name (for binary attribute check)
            value: Value to encode (bytes or str)

        Returns:
            Formatted attribute line (e.g., "attr: value" or "attr:: base64value")

        """
        # Handle bytes - always base64
        if isinstance(value, bytes):
            encoded_value = base64.b64encode(value).decode("ascii")
            return f"{attr_name}:: {encoded_value}"

        # Ensure value is str
        str_value = str(value) if not isinstance(value, str) else value

        # UTF-8 validation (RFC 2849 requirement)
        try:
            str_value.encode("utf-8")
        except UnicodeEncodeError:
            str_value = str_value.encode("utf-8", errors="replace").decode(
                "utf-8",
                errors="replace",
            )
            logger.debug(
                "Corrected invalid UTF-8 in attribute: attribute_name=%s, value_length=%s",
                attr_name,
                len(value),
            )

        # Check if binary attribute (RFC 4522) or needs base64
        is_binary_attr = (
            attr_name.lower() in c.Ldif.RfcBinaryAttributes.BINARY_ATTRIBUTE_NAMES
        )
        needs_base64 = is_binary_attr or FlextLdifUtilitiesWriter.needs_base64_encoding(
            str_value,
        )

        if needs_base64:
            encoded_value = base64.b64encode(str_value.encode("utf-8")).decode("ascii")
            return f"{attr_name}:: {encoded_value}"
        return f"{attr_name}: {str_value}"

    @staticmethod
    def _add_line_with_folding(
        ldif_lines: list[str],
        line: str,
        *,
        fold_long_lines: bool,
        width: int,
    ) -> None:
        """Add line with optional folding."""
        if fold_long_lines:
            ldif_lines.extend(FlextLdifUtilitiesWriter.fold(line, width=width))
        else:
            ldif_lines.append(line)

    @staticmethod
    def _process_modify_attributes(
        attributes: t.Ldif.AttributesDict,
        hidden: set[str],
        modify_operation: str,
        *,
        fold_long_lines: bool,
        width: int,
    ) -> list[str]:
        """Process attributes in MODIFY format."""
        lines: list[str] = []
        first_attr = True
        for attr_name, values in attributes.items():
            if not values or attr_name in hidden:
                continue

            if not first_attr:
                lines.append("-")
            first_attr = False

            op_line = f"{modify_operation}: {attr_name}"
            FlextLdifUtilitiesWriter._add_line_with_folding(
                lines,
                op_line,
                fold_long_lines=fold_long_lines,
                width=width,
            )

            for value in values:
                attr_line = FlextLdifUtilitiesWriter.encode_attribute_value(
                    attr_name,
                    value,
                )
                FlextLdifUtilitiesWriter._add_line_with_folding(
                    lines,
                    attr_line,
                    fold_long_lines=fold_long_lines,
                    width=width,
                )

        if lines and lines[-1] != "-":
            lines.append("-")
        return lines

    @staticmethod
    def _process_add_attributes(
        attributes: t.Ldif.AttributesDict,
        hidden: set[str],
        *,
        fold_long_lines: bool,
        width: int,
    ) -> list[str]:
        """Process attributes in ADD format."""
        lines: list[str] = []
        for attr_name, values in attributes.items():
            if not values or attr_name in hidden:
                continue
            for value in values:
                attr_line = FlextLdifUtilitiesWriter.encode_attribute_value(
                    attr_name,
                    value,
                )
                FlextLdifUtilitiesWriter._add_line_with_folding(
                    lines,
                    attr_line,
                    fold_long_lines=fold_long_lines,
                    width=width,
                )
        return lines

    @staticmethod
    def _add_changetype_lines(
        ldif_lines: list[str],
        *,
        format_type: str,
        changetype_config: dict[str, object],
    ) -> None:
        """Add changetype lines based on format.

        Args:
            ldif_lines: List to append lines to
            format_type: Format type ("add" or "modify")
            changetype_config: Dict with keys: include_changetype, changetype_value, fold_long_lines, width

        """
        include_changetype = bool(
            u.mapper().get(changetype_config, "include_changetype"),
        )
        changetype_value = u.mapper().get(changetype_config, "changetype_value")
        fold_long_lines = bool(
            u.mapper().get(changetype_config, "fold_long_lines", default=True),
        )
        width_raw = u.mapper().get(changetype_config, "width", default=76)
        width = int(width_raw) if isinstance(width_raw, int | str) else 76

        if format_type == "modify":
            changetype_line = "changetype: modify"
            FlextLdifUtilitiesWriter._add_line_with_folding(
                ldif_lines,
                changetype_line,
                fold_long_lines=fold_long_lines,
                width=width,
            )
        elif include_changetype and changetype_value:
            changetype_line = f"changetype: {changetype_value}"
            FlextLdifUtilitiesWriter._add_line_with_folding(
                ldif_lines,
                changetype_line,
                fold_long_lines=fold_long_lines,
                width=width,
            )

    @staticmethod
    def build_entry_lines(
        dn_value: str,
        attributes: t.Ldif.AttributesDict,
        *,
        format_config: dict[str, object] | None = None,
        **kwargs: object,
    ) -> list[str]:
        """Build LDIF lines for an entry in ADD or MODIFY format.

        Generalized method for both ADD and MODIFY formats (DRY consolidation).

        Args:
            dn_value: DN value (required)
            attributes: Attributes dictionary {name: [values]}
            format_config: Configuration dict with keys (all optional):
                - format_type: "add" for content records, "modify" for change records (default: "add")
                - modify_operation: For modify format: "add", "replace", or "delete" (default: "add")
                - include_changetype: Whether to include changetype line (default: False)
                - changetype_value: Explicit changetype value (for ADD format) (default: None)
                - hidden_attrs: Attributes to skip (e.g., "changetype") (default: None)
                - line_width: Maximum line width in bytes (None = use default 76) (default: None)
                - fold_long_lines: Whether to fold lines exceeding line_width (default: True)
            **kwargs: Alternative way to pass config (merged with format_config)

        Returns:
            List of LDIF lines (folded if fold_long_lines=True)

        """
        config = {**(format_config or {}), **kwargs}
        format_type = str(u.mapper().get(config, "format_type", default="add"))
        modify_operation = str(
            u.mapper().get(config, "modify_operation", default="add"),
        )
        include_changetype = bool(u.mapper().get(config, "include_changetype"))
        changetype_value = u.mapper().get(config, "changetype_value")
        hidden_attrs = u.mapper().get(config, "hidden_attrs")
        line_width_raw = u.mapper().get(config, "line_width")
        fold_long_lines = bool(u.mapper().get(config, "fold_long_lines", default=True))

        ldif_lines: list[str] = []
        hidden: set[str] = hidden_attrs if isinstance(hidden_attrs, set) else set()
        width = (
            int(line_width_raw)
            if isinstance(line_width_raw, int | str)
            else c.Ldif.Format.LINE_FOLD_WIDTH
        )

        # DN line (required for both formats)
        dn_line = f"dn: {dn_value}"
        FlextLdifUtilitiesWriter._add_line_with_folding(
            ldif_lines,
            dn_line,
            fold_long_lines=fold_long_lines,
            width=width,
        )

        # Changetype handling
        # Type narrowing: dict[str, bool | int | str] is compatible with dict[str, object]
        changetype_config: dict[str, object] = {
            "include_changetype": include_changetype,
            "changetype_value": changetype_value,
            "fold_long_lines": fold_long_lines,
            "width": width,
        }
        FlextLdifUtilitiesWriter._add_changetype_lines(
            ldif_lines,
            format_type=format_type,
            changetype_config=changetype_config,
        )

        # Process attributes based on format
        if format_type == "modify":
            attr_lines = FlextLdifUtilitiesWriter._process_modify_attributes(
                attributes,
                hidden,
                modify_operation,
                fold_long_lines=fold_long_lines,
                width=width,
            )
        else:
            attr_lines = FlextLdifUtilitiesWriter._process_add_attributes(
                attributes,
                hidden,
                fold_long_lines=fold_long_lines,
                width=width,
            )
        ldif_lines.extend(attr_lines)

        return ldif_lines

    @staticmethod
    def finalize_ldif_text(ldif_lines: list[str]) -> str:
        """Join LDIF lines and ensure proper trailing newline.

        Args:
            ldif_lines: List of LDIF lines

        Returns:
            Properly formatted LDIF text

        """
        ldif_text = "\n".join(ldif_lines)
        if ldif_text and not ldif_text.endswith("\n"):
            ldif_text += "\n"
        return ldif_text


__all__ = [
    "FlextLdifUtilitiesWriter",
]
