"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import cast

from flext_core import FlextLogger, FlextResult, FlextRuntime
from jinja2 import Environment

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels

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
    ) -> FlextResult[dict[str, object]]:
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
            stats: dict[str, object] = {
                "bytes_written": len(content.encode(encoding)),
                "path": str(file_path),
                "encoding": encoding,
            }
            return FlextResult[dict[str, object]].ok(stats)
        except Exception as e:
            logger.exception(
                "File write failed",
                file_path=str(file_path),
            )
            return FlextResult[dict[str, object]].fail(f"File write failed: {e}")

    @staticmethod
    def add_attribute_matching_rules(
        attr_data: FlextLdifModels.SchemaAttribute,
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
        attr_data: FlextLdifModels.SchemaAttribute,
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
        attr_data: FlextLdifModels.SchemaAttribute,
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
        attr_data: FlextLdifModels.SchemaAttribute,
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
        attr_data: FlextLdifModels.SchemaAttribute,
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
            attr_list_str = cast("list[str]", attr_list)
            if len(attr_list_str) == 1:
                parts.append(f"{keyword} {attr_list_str[0]}")
            else:
                attrs_str = " $ ".join(attr_list_str)
                parts.append(f"{keyword} ( {attrs_str} )")
        else:
            parts.append(f"{keyword} {attr_list}")

    @staticmethod
    def _build_objectclass_parts(
        oc_data: FlextLdifModels.SchemaObjectClass,
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
                sup_list_str = cast("list[str]", oc_data.sup)
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
        objectclass: FlextLdifModels.SchemaObjectClass,
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
    def determine_attribute_order(
        entry_data: dict[str, object],
    ) -> list[tuple[str, object]] | None:
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
            extensions_dict = cast("dict[str, object]", metadata.get("extensions", {}))
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

        # Type narrowing: ensure tuple elements are (str, object) for return type
        return cast(
            "list[tuple[str, object]]",
            [
                (key, entry_data[cast("str", key)])
                for key in attr_order
                if key in entry_data and key not in skip_keys
            ],
        )

    @staticmethod
    def extract_base64_attrs(entry_data: dict[str, object]) -> set[str]:
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
            return cast("set[str]", base64_data)
        if FlextRuntime.is_list_like(base64_data):
            base64_list_str = cast("list[str]", base64_data)
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
        attr_value: object,
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

    @staticmethod
    def needs_base64_encoding(value: str) -> bool:
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

    @staticmethod
    def write_modify_operations(
        entry_data: dict[str, object],
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


__all__ = [
    "FlextLdifUtilitiesWriter",
]
