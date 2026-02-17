"""Extracted nested class from FlextLdifUtilities."""

from __future__ import annotations

import base64
from collections.abc import Sequence
from pathlib import Path

from flext_core import FlextLogger, FlextResult, FlextRuntime, t, u
from jinja2 import Environment

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.settings import FlextLdifModelsSettings
from flext_ldif.constants import c
from flext_ldif.models import m

# t already imported from flext_core above

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
    """Pure LDIF Formatting Operations - No Models, No Side Effects."""

    @staticmethod
    def fmt_dn(dn_value: str, *, width: int = 78, fold: bool = True) -> list[str]:
        """Format DN line with optional line folding (RFC 2849)."""
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
        """Fold long LDIF line according to RFC 2849 §3."""
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
        """Format attribute:value line for LDIF output."""
        if not attr_name:
            return ""

        if use_base64:
            encoded = base64.b64encode(value_str.encode("utf-8")).decode("ascii")
            return f"{attr_name}:: {encoded}"

        return f"{attr_name}: {value_str}"

    @staticmethod
    def render_template(
        template_str: str,
        context: dict[str, t.GeneralValueType],
    ) -> FlextResult[str]:
        """Render Jinja2 template with context."""
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
        """Write content to file (pure I/O operation)."""
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
        """Add syntax and length to attribute parts list."""
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
        """Add MUST or MAY clause to objectClass definition parts."""
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
        """Order attribute names using various strategies."""
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
        """Determine attribute processing order from entry metadata."""
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
            extensions_raw: dict[str, t.GeneralValueType] | object = u.mapper().get(
                metadata, "extensions", default={}
            )
            if not isinstance(extensions_raw, dict):
                attr_order = None
            else:
                # Type narrowing: after isinstance check, extensions_raw is dict
                # u.mapper().get works with any Mapping, so we can use extensions_raw directly
                attr_order = u.mapper().get(extensions_raw, "attribute_order")

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
        result: list[tuple[str, t.GeneralValueType]] = []
        # attr_order is already narrowed to list by isinstance check above
        for key in attr_order:
            if not isinstance(key, str):
                continue  # Skip non-string keys
            if key in entry_data and key not in skip_keys:
                result.append((key, entry_data[key]))
        return result

    @staticmethod
    def extract_base64_attrs(
        entry_data: dict[str, t.GeneralValueType],
    ) -> set[str]:
        """Extract set of attribute names that require base64 encoding."""
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
        """Check if attribute should be skipped during LDIF writing."""
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
        """Format attribute into LDIF lines."""
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

    # RFC 2849 Character Class Validation (ABNF-based)

    @staticmethod
    def is_safe_char(char: str) -> bool:
        """Check if char is SAFE-CHAR per RFC 2849 §2."""
        if not char or len(char) != 1:
            return False
        code = ord(char)
        safe_min = c.Ldif.Format.SAFE_CHAR_MIN
        safe_max = c.Ldif.Format.SAFE_CHAR_MAX
        safe_exclude = c.Ldif.Format.SAFE_CHAR_EXCLUDE
        return safe_min <= code <= safe_max and code not in safe_exclude

    @staticmethod
    def is_safe_init_char(char: str) -> bool:
        """Check if char is SAFE-INIT-CHAR per RFC 2849 §2."""
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
        """Check if char is BASE64-CHAR per RFC 2849 §2."""
        if not char or len(char) != 1:
            return False
        return char in c.Ldif.Format.BASE64_CHARS

    @staticmethod
    def is_valid_safe_string(value: str) -> bool:
        """Check if value is valid SAFE-STRING per RFC 2849 §2."""
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

    # RFC 2849 Encoding Helpers

    @staticmethod
    def needs_base64_encoding(
        value: str,
        *,
        check_trailing_space: bool = True,
    ) -> bool:
        """Check if value needs base64 encoding per RFC 2849 §2."""
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
        entry_data: dict[str, t.GeneralValueType],
    ) -> list[str]:
        """Write LDIF modify operations for schema additions."""
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
        """Apply output visibility options based on attribute status."""
        # Get marked_attributes from metadata (type narrowing)
        marked_attrs_raw: dict[str, t.GeneralValueType] | object = u.mapper().get(
            entry_metadata.extensions, "marked_attributes", default={}
        )
        if not isinstance(marked_attrs_raw, dict):
            return (attr_name, attr_values)

        # Type narrowing: after isinstance check, marked_attrs_raw is dict
        # u.mapper().get works with any Mapping, so we can use it directly
        attr_info = u.mapper().get(marked_attrs_raw, attr_name)

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

        # Type narrowing: attr_info must be dict-like to get 'status' key
        if not isinstance(attr_info, dict):
            return (attr_name, attr_values)

        status_raw = u.mapper().get(
            attr_info,
            "status",
            default=normal_status,
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
            # Type narrowing: name_format is str after None check above
            if not isinstance(name_format, str):
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
        """Check minimal differences and restore original attribute line if needed."""
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
        attr_values: t.GeneralValueType,
    ) -> list[str] | str:
        """Type-safe extraction of attribute values."""
        if isinstance(attr_values, str):
            return attr_values
        # Type narrowing: ensure attr_values is iterable before using list comprehension
        if FlextRuntime.is_list_like(attr_values):
            if isinstance(attr_values, (list, tuple)):
                return [str(v) for v in attr_values]
            # Fallback for other sequence types - ensure it's iterable
            if isinstance(attr_values, Sequence):
                return [str(v) for v in attr_values]
            # If not a sequence, try to convert to list using hasattr check
            if hasattr(attr_values, "__iter__") and not isinstance(
                attr_values,
                (str, bytes),
            ):
                # hasattr confirms __iter__, safe to iterate directly
                try:
                    attr_values_list: list[object] = list(attr_values)
                    return [str(v) for v in attr_values_list]
                except (TypeError, ValueError):
                    return str(attr_values) if attr_values else ""
            return str(attr_values) if attr_values else ""
        return str(attr_values) if attr_values else ""

    @staticmethod
    def encode_attribute_value(
        attr_name: str,
        value: bytes | str,
    ) -> str:
        """Encode a single attribute value for LDIF output (RFC 2849)."""
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
        attributes: m.Ldif.EntryAttributesDict,
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
        attributes: m.Ldif.EntryAttributesDict,
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
        changetype_config: dict[str, t.GeneralValueType],
    ) -> None:
        """Add changetype lines based on format."""
        # u.mapper().get works with any Mapping[str, object], no cast needed
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
        attributes: m.Ldif.EntryAttributesDict,
        *,
        format_config: dict[str, t.GeneralValueType] | None = None,
        **kwargs: t.GeneralValueType,
    ) -> list[str]:
        """Build LDIF lines for an entry in ADD or MODIFY format."""
        config = {**(format_config or {}), **kwargs}
        # u.mapper().get works with any Mapping[str, object], no cast needed
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
        hidden: set[str] = set()
        if isinstance(hidden_attrs, set):
            for item in hidden_attrs:
                if isinstance(item, str):
                    hidden.add(item)
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
        # Type narrowing: dict[str, bool | int | str] is compatible with dict[str, t.GeneralValueType]
        changetype_config: dict[str, t.GeneralValueType] = {
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
        """Join LDIF lines and ensure proper trailing newline."""
        ldif_text = "\n".join(ldif_lines)
        if ldif_text and not ldif_text.endswith("\n"):
            ldif_text += "\n"
        return ldif_text


__all__ = [
    "FlextLdifUtilitiesWriter",
]
