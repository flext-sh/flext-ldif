"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import cast

from flext_core import FlextLogger, FlextResult, FlextRuntime, FlextUtilities, t
from jinja2 import Environment

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import m
from flext_ldif.typings import FlextLdifTypes

# Aliases for simplified usage - after all imports
# Use flext-core utilities directly (FlextLdifUtilities extends FlextUtilities)
u = FlextUtilities  # Use base class to avoid circular dependency
r = FlextResult  # Shared from flext-core

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
        width: int = FlextLdifConstants.Rfc.LINE_FOLD_WIDTH,
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
                    FlextLdifConstants.Rfc.LINE_CONTINUATION_SPACE + chunk,
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
        context: FlextLdifTypes.MetadataDictMutable,
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
            logger.exception(
                "Template rendering failed",
            )
            return FlextResult[str].fail(f"Template rendering failed: {e}")

    @staticmethod
    def write_file(
        content: str,
        file_path: Path,
        encoding: str = "utf-8",
    ) -> FlextResult[FlextLdifTypes.MetadataDictMutable]:
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
            stats: FlextLdifTypes.MetadataDictMutable = {
                "bytes_written": len(content.encode(encoding)),
                "path": str(file_path),
                "encoding": encoding,
            }
            return FlextResult[FlextLdifTypes.MetadataDictMutable].ok(stats)
        except Exception as e:
            logger.exception(
                "File write failed",
                file_path=str(file_path),
            )
            return FlextResult[FlextLdifTypes.MetadataDictMutable].fail(
                f"File write failed: {e}",
            )

    @staticmethod
    def add_attribute_matching_rules(
        attr_data: m.SchemaAttribute,
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
        attr_data: m.SchemaAttribute,
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
        attr_data: m.SchemaAttribute,
        parts: list[str],
    ) -> None:
        """Add flags to attribute parts list."""
        if attr_data.single_value:
            parts.append("SINGLE-VALUE")
        if attr_data.metadata and attr_data.metadata.extensions.get(
            FlextLdifConstants.MetadataKeys.COLLECTIVE,
        ):
            parts.append("COLLECTIVE")
        if attr_data.no_user_modification:
            parts.append("NO-USER-MODIFICATION")

    @staticmethod
    def _build_attribute_parts(
        attr_data: m.SchemaAttribute,
    ) -> list[str]:
        """Build RFC attribute definition parts (extracted to reduce complexity)."""
        parts: list[str] = [f"( {attr_data.oid}"]

        if attr_data.name:
            parts.append(f"NAME '{attr_data.name}'")

        if attr_data.desc:
            parts.append(f"DESC '{attr_data.desc}'")

        if attr_data.metadata and attr_data.metadata.extensions.get(
            FlextLdifConstants.MetadataKeys.OBSOLETE,
        ):
            parts.append("OBSOLETE")

        if attr_data.sup:
            parts.append(f"SUP {attr_data.sup}")

        FlextLdifUtilitiesWriter.add_attribute_matching_rules(attr_data, parts)
        FlextLdifUtilitiesWriter.add_attribute_syntax(attr_data, parts)
        FlextLdifUtilitiesWriter.add_attribute_flags(attr_data, parts)

        if attr_data.usage:
            parts.append(f"USAGE {attr_data.usage}")

        if attr_data.metadata and attr_data.metadata.extensions.get("x_origin"):
            parts.append(f"X-ORIGIN '{attr_data.metadata.extensions.get('x_origin')}'")

        parts.append(")")
        return parts

    @staticmethod
    def write_rfc_attribute(
        attr_data: m.SchemaAttribute,
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

        if FlextRuntime.is_list_like(attr_list):
            if not isinstance(attr_list, list):
                msg = f"Expected list, got {type(attr_list)}"
                raise TypeError(msg)
            attr_list_str: list[str] = [str(item) for item in attr_list]
            if len(attr_list_str) == 1:
                parts.append(f"{keyword} {attr_list_str[0]}")
            else:
                attrs_str = " $ ".join(attr_list_str)
                parts.append(f"{keyword} ( {attrs_str} )")
        else:
            parts.append(f"{keyword} {attr_list}")

    @staticmethod
    def _build_objectclass_parts(
        oc_data: m.SchemaObjectClass,
    ) -> list[str]:
        """Build RFC objectClass definition parts (extracted to reduce complexity)."""
        parts: list[str] = [f"( {oc_data.oid}"]

        if oc_data.name:
            parts.append(f"NAME '{oc_data.name}'")

        if oc_data.desc:
            parts.append(f"DESC '{oc_data.desc}'")

        if oc_data.metadata and oc_data.metadata.extensions.get(
            FlextLdifConstants.MetadataKeys.OBSOLETE,
        ):
            parts.append("OBSOLETE")

        if oc_data.sup:
            # Handle SUP as string or list
            if FlextRuntime.is_list_like(oc_data.sup):
                # Multiple SUP values: format as ( value1 $ value2 $ ... )
                if not isinstance(oc_data.sup, list):
                    msg = f"Expected list, got {type(oc_data.sup)}"
                    raise TypeError(msg)
                sup_list_str: list[str] = [str(item) for item in oc_data.sup]
                sup_str = " $ ".join(sup_list_str)
                parts.append(f"SUP ( {sup_str} )")
            else:
                # Single SUP value
                parts.append(f"SUP {oc_data.sup}")

        kind = oc_data.kind or FlextLdifConstants.Schema.STRUCTURAL
        parts.append(str(kind))

        FlextLdifUtilitiesWriter._add_oc_must_may(parts, oc_data.must, "MUST")
        FlextLdifUtilitiesWriter._add_oc_must_may(parts, oc_data.may, "MAY")

        if oc_data.metadata and oc_data.metadata.extensions.get("x_origin"):
            parts.append(f"X-ORIGIN '{oc_data.metadata.extensions.get('x_origin')}'")

        parts.append(")")

        return parts

    @staticmethod
    def write_rfc_objectclass(
        objectclass: m.SchemaObjectClass,
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
        entry_data: dict[str, t.GeneralValueType],
    ) -> list[tuple[str, t.GeneralValueType]] | None:
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
                extensions.get("attribute_order")
                if hasattr(extensions, "get")
                else None
            )
        elif FlextRuntime.is_dict_like(metadata):
            extensions_raw = metadata.get("extensions", {})
            if not isinstance(extensions_raw, dict):
                attr_order = None
            else:
                # Business Rule: extensions_raw is dict[str, GeneralValueType] from metadata
                # but we need dict[str, MetadataAttributeValue] for type safety.
                # GeneralValueType includes recursive types, but metadata extensions
                # in practice only contain ScalarValue or Sequence[ScalarValue].
                # Implication: We use cast for type conversion since runtime values
                # are compatible with MetadataAttributeValue.
                extensions_dict = cast(
                    "dict[str, t.MetadataAttributeValue]",
                    extensions_raw,
                )
                if FlextRuntime.is_dict_like(extensions_dict):
                    attr_order = extensions_dict.get("attribute_order")
                else:
                    attr_order = None

        if attr_order is None or not FlextRuntime.is_list_like(attr_order):
            return None

        # Build ordered list from attr_order
        skip_keys = {
            FlextLdifConstants.DictKeys.DN,
            "_metadata",
            "server_type",
            "_acl_attributes",
        }

        # Type narrowing: ensure tuple elements are (str, GeneralValueType) for return type
        result: list[tuple[str, t.GeneralValueType]] = []
        for key in attr_order:
            if key in entry_data and key not in skip_keys:
                if not isinstance(key, str):
                    msg = f"Expected str key, got {type(key)}"
                    raise TypeError(msg)
                result.append((key, entry_data[key]))
        return result

    @staticmethod
    def extract_base64_attrs(
        entry_data: dict[str, t.GeneralValueType],
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
        if isinstance(base64_data, set):
            return base64_data  # Type narrowing: set is already set[str] if it contains strings
        if FlextRuntime.is_list_like(base64_data):
            if not isinstance(base64_data, list):
                msg = f"Expected list, got {type(base64_data)}"
                raise TypeError(msg)
            base64_list_str: list[str] = [str(item) for item in base64_data]
            return set(base64_list_str)

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
        if attr_name.lower() == FlextLdifConstants.DictKeys.DN:
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
            mapped_attr_name = attribute_case_map.get(attr_name.lower(), attr_name)

        # Determine prefix
        attr_prefix = f"{mapped_attr_name}::" if is_base64 else f"{mapped_attr_name}:"

        # Handle both list and single values
        if FlextRuntime.is_list_like(attr_value):
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

        Uses FlextLdifConstants.Rfc.SAFE_CHAR_* for validation.

        Args:
            char: Single character to validate

        Returns:
            True if char is SAFE-CHAR, False otherwise

        """
        if not char or len(char) != 1:
            return False
        code = ord(char)
        safe_min = FlextLdifConstants.Rfc.SAFE_CHAR_MIN
        safe_max = FlextLdifConstants.Rfc.SAFE_CHAR_MAX
        safe_exclude = FlextLdifConstants.Rfc.SAFE_CHAR_EXCLUDE
        return safe_min <= code <= safe_max and code not in safe_exclude

    @staticmethod
    def is_safe_init_char(char: str) -> bool:
        """Check if char is SAFE-INIT-CHAR per RFC 2849 §2.

        SAFE-INIT-CHAR = %x01-09 / %x0B-0C / %x0E-1F / %x21-39 / %x3B / %x3D-7F
        (SAFE-CHAR excluding SPACE, COLON, LESS-THAN)

        Uses FlextLdifConstants.Rfc.SAFE_INIT_CHAR_EXCLUDE for exclusion set.

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
        return code not in FlextLdifConstants.Rfc.SAFE_INIT_CHAR_EXCLUDE

    @staticmethod
    def is_base64_char(char: str) -> bool:
        """Check if char is BASE64-CHAR per RFC 2849 §2.

        BASE64-CHAR = %x2B / %x2F / %x30-39 / %x3D / %x41-5A / %x61-7A
        (+ / 0-9 = A-Z a-z)

        Uses FlextLdifConstants.Rfc.BASE64_CHARS for validation.

        Args:
            char: Single character to validate

        Returns:
            True if char is BASE64-CHAR, False otherwise

        """
        if not char or len(char) != 1:
            return False
        return char in FlextLdifConstants.Rfc.BASE64_CHARS

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
        if value[0] in FlextLdifConstants.Rfc.BASE64_START_CHARS:
            return True

        # RFC 2849 - Value ending with space requires base64 (parameterizable)
        if check_trailing_space and value[-1] == " ":
            return True

        # Use the optimized is_valid_safe_string for full validation
        # but we need char-by-char check for performance
        safe_min = FlextLdifConstants.Rfc.SAFE_CHAR_MIN
        safe_max = FlextLdifConstants.Rfc.SAFE_CHAR_MAX
        safe_exclude = FlextLdifConstants.Rfc.SAFE_CHAR_EXCLUDE

        # Check for control characters or non-printable ASCII
        for char in value:
            byte_val = ord(char)
            # Outside SAFE-CHAR range or in exclusion set requires base64
            if byte_val < safe_min or byte_val > safe_max or byte_val in safe_exclude:
                return True

        return False

    @staticmethod
    def write_modify_operations(
        entry_data: dict[str, t.GeneralValueType],
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
            if FlextRuntime.is_list_like(attr_types) and attr_types:
                lines.append("add: attributetypes")
                lines.extend(f"attributetypes: {attr_type}" for attr_type in attr_types)
                lines.append("-")

        # Write modify-add operations for objectclasses
        if "_modify_add_objectclasses" in entry_data:
            obj_classes = entry_data["_modify_add_objectclasses"]
            if FlextRuntime.is_list_like(obj_classes) and obj_classes:
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
        entry_metadata: m.QuirkMetadata,
        output_options: m.WriteOutputOptions,
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
        marked_attrs_raw = entry_metadata.extensions.get("marked_attributes", {})
        if not isinstance(marked_attrs_raw, dict):
            return (attr_name, attr_values)

        # Type narrowing: ensure marked_attrs_raw is the correct nested dict type
        marked_attrs: dict[str, dict[str, t.MetadataAttributeValue]] = cast(
            "dict[str, dict[str, t.MetadataAttributeValue]]",
            marked_attrs_raw,
        )
        attr_info = marked_attrs.get(attr_name)

        # If attribute not marked, write normally
        if not attr_info:
            return (attr_name, attr_values)

        # Check removed_attributes for already-removed attributes
        removed_attrs_raw = entry_metadata.extensions.get("removed_attributes", {})
        if isinstance(removed_attrs_raw, dict) and attr_name in removed_attrs_raw:
            return FlextLdifUtilitiesWriter._handle_removed_attribute(
                attr_name,
                attr_values,
                output_options,
            )

        # Handle based on status - extracted to reduce complexity
        status_raw = attr_info.get(
            "status",
            FlextLdifConstants.AttributeMarkerStatus.NORMAL.value,
        )
        # Validate status is AttributeMarkerStatusLiteral
        valid_statuses = {
            "normal",
            "marked_for_removal",
            "filtered",
            "operational",
            "hidden",
            "renamed",
        }
        if isinstance(status_raw, str) and status_raw in valid_statuses:
            status: FlextLdifConstants.LiteralTypes.AttributeMarkerStatusLiteral = cast(
                "FlextLdifConstants.LiteralTypes.AttributeMarkerStatusLiteral",
                status_raw,
            )
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
        output_options: m.WriteOutputOptions,
    ) -> tuple[str, list[str]] | None:
        """Handle already-removed attributes (extracted to reduce complexity)."""
        if output_options.show_removed_attributes:
            return (f"# {attr_name}", attr_values)
        return None

    @staticmethod
    def _handle_attribute_status(
        attr_name: str,
        attr_values: list[str],
        status: FlextLdifConstants.LiteralTypes.AttributeMarkerStatusLiteral,
        output_options: m.WriteOutputOptions,
    ) -> tuple[str, list[str]] | None:
        """Handle attribute based on status (extracted to reduce complexity)."""
        status_handlers = {
            FlextLdifConstants.AttributeMarkerStatus.OPERATIONAL.value: (
                output_options.show_operational_attributes,
                attr_name,
            ),
            FlextLdifConstants.AttributeMarkerStatus.FILTERED.value: (
                output_options.show_filtered_attributes,
                f"# {attr_name}",
            ),
            FlextLdifConstants.AttributeMarkerStatus.MARKED_FOR_REMOVAL.value: (
                output_options.show_removed_attributes,
                f"# {attr_name}",
            ),
            FlextLdifConstants.AttributeMarkerStatus.HIDDEN.value: (False, None),
        }

        handler_config = status_handlers.get(status)
        if handler_config:
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
        mk = FlextLdifConstants.MetadataKeys
        # Check for minimal differences using both possible keys
        attr_diff = minimal_differences_attrs.get(
            attr_name,
        ) or minimal_differences_attrs.get(f"attribute_{attr_name}")

        if FlextRuntime.is_dict_like(attr_diff) and attr_diff.get(mk.HAS_DIFFERENCES):
            original_attr_str = attr_diff.get("original")
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
        attr_values: t.GeneralValueType,
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
        if FlextRuntime.is_list_like(attr_values):
            return [str(v) for v in attr_values]
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
            attr_name.lower()
            in FlextLdifConstants.RfcBinaryAttributes.BINARY_ATTRIBUTE_NAMES
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
        attributes: FlextLdifTypes.CommonDict.AttributeDict,
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
        attributes: FlextLdifTypes.CommonDict.AttributeDict,
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
        include_changetype = bool(changetype_config.get("include_changetype"))
        changetype_value = changetype_config.get("changetype_value")
        fold_long_lines = bool(changetype_config.get("fold_long_lines", True))
        width_raw = changetype_config.get("width", 76)
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
        attributes: FlextLdifTypes.CommonDict.AttributeDict,
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
        format_type = str(config.get("format_type", "add"))
        modify_operation = str(config.get("modify_operation", "add"))
        include_changetype = bool(config.get("include_changetype"))
        changetype_value = config.get("changetype_value")
        hidden_attrs = config.get("hidden_attrs")
        line_width_raw = config.get("line_width")
        fold_long_lines = bool(config.get("fold_long_lines", True))

        ldif_lines: list[str] = []
        hidden = hidden_attrs or set() if isinstance(hidden_attrs, set) else set()
        width = (
            int(line_width_raw)
            if isinstance(line_width_raw, int | str)
            else FlextLdifConstants.Rfc.LINE_FOLD_WIDTH
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
        changetype_config = {
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
