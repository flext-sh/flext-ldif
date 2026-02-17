"""Extracted nested class from FlextLdifUtilities."""

from __future__ import annotations

import base64
from pathlib import Path

from flext_core import FlextLogger, FlextResult, t, u

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.settings import FlextLdifModelsSettings
from flext_ldif.constants import c
from flext_ldif.models import m

r = FlextResult  # Shared from flext-core

_TUPLE_LENGTH_TWO = 2  # Length for tuple unpacking validation

logger = FlextLogger(__name__)


class FlextLdifUtilitiesWriter:
    """Pure LDIF Formatting Operations - No Models, No Side Effects."""

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

        folded: list[str] = []
        pos = 0

        while pos < len(line_bytes):
            if not folded:
                chunk_end = min(pos + width, len(line_bytes))
            else:
                chunk_end = min(pos + width - 1, len(line_bytes))

            while chunk_end > pos:
                try:
                    chunk = line_bytes[pos:chunk_end].decode("utf-8")
                    break
                except UnicodeDecodeError:
                    chunk_end -= 1
            else:
                chunk_end = pos + 1
                chunk = line_bytes[pos:chunk_end].decode("utf-8", errors="replace")

            if folded:
                folded.append(
                    c.Ldif.Format.LINE_CONTINUATION_SPACE + chunk,
                )
            else:
                folded.append(chunk)

            pos = chunk_end

        return folded

    @staticmethod
    def write_file(
        content: str,
        file_path: Path,
        encoding: str = "utf-8",
    ) -> FlextResult[dict[str, str | int]]:
        """Write content to file (pure I/O operation)."""
        try:
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
            if isinstance(oc_data.sup, list):
                sup_list_str: list[str] = [str(item) for item in oc_data.sup]
                sup_str = " $ ".join(sup_list_str)
                parts.append(f"SUP ( {sup_str} )")
            else:
                parts.append(f"SUP {oc_data.sup}")

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
    def determine_attribute_order(
        entry_data: dict[str, t.GeneralValueType],
    ) -> list[tuple[str, t.GeneralValueType]] | None:
        """Determine attribute processing order from entry metadata."""
        if "_metadata" not in entry_data:
            return None

        metadata = entry_data["_metadata"]
        attr_order = None

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
                attr_order = u.mapper().get(extensions_raw, "attribute_order")

        if attr_order is None:
            return None

        if not isinstance(attr_order, list):
            return None

        skip_keys = {
            c.Ldif.DictKeys.DN,
            "_metadata",
            "server_type",
            "_acl_attributes",
        }

        result: list[tuple[str, t.GeneralValueType]] = []
        for key in attr_order:
            if not isinstance(key, str):
                continue  # Skip non-string keys
            if key in entry_data and key not in skip_keys:
                result.append((key, entry_data[key]))
        return result

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
        if not FlextLdifUtilitiesWriter.is_safe_char(char):
            return False
        return code not in c.Ldif.Format.SAFE_INIT_CHAR_EXCLUDE

    @staticmethod
    def is_valid_safe_string(value: str) -> bool:
        """Check if value is valid SAFE-STRING per RFC 2849 §2."""
        if not value:
            return True  # Empty string is valid

        if not FlextLdifUtilitiesWriter.is_safe_init_char(value[0]):
            return False

        for char in value[1:]:
            if not FlextLdifUtilitiesWriter.is_safe_char(char):
                return False

        return value[-1] != " "

    @staticmethod
    def needs_base64_encoding(
        value: str,
        *,
        check_trailing_space: bool = True,
    ) -> bool:
        """Check if value needs base64 encoding per RFC 2849 §2."""
        if not value:
            return False

        if value[0] in c.Ldif.Format.BASE64_START_CHARS:
            return True

        if check_trailing_space and value[-1] == " ":
            return True

        safe_min = c.Ldif.Format.SAFE_CHAR_MIN
        safe_max = c.Ldif.Format.SAFE_CHAR_MAX
        safe_exclude = c.Ldif.Format.SAFE_CHAR_EXCLUDE

        for char in value:
            byte_val = ord(char)
            if byte_val < safe_min or byte_val > safe_max or byte_val in safe_exclude:
                return True

        return False

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
        operational_value: str = (
            "operational"  # c.Ldif.AttributeMarkerStatus.OPERATIONAL.value
        )
        filtered_value: str = "filtered"  # c.Ldif.AttributeMarkerStatus.FILTERED.value
        marked_for_removal_value: str = "marked_for_removal"  # c.Ldif.AttributeMarkerStatus.MARKED_FOR_REMOVAL.value
        hidden_value: str = "hidden"  # c.Ldif.AttributeMarkerStatus.HIDDEN.value
        show_operational_str: str = output_options.show_operational_attributes
        show_filtered_str: str = output_options.show_filtered_attributes
        show_removed_str: str = output_options.show_removed_attributes
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
        if (
            handler_config
            and isinstance(handler_config, tuple)
            and len(handler_config) == _TUPLE_LENGTH_TWO
        ):
            show_flag, name_format = handler_config
            if not show_flag:
                return None
            if name_format is None:
                return None
            if not isinstance(name_format, str):
                return None
            return (name_format, attr_values)

        return (attr_name, attr_values)

    @staticmethod
    def encode_attribute_value(
        attr_name: str,
        value: bytes | str,
    ) -> str:
        """Encode a single attribute value for LDIF output (RFC 2849)."""
        if isinstance(value, bytes):
            encoded_value = base64.b64encode(value).decode("ascii")
            return f"{attr_name}:: {encoded_value}"

        str_value = str(value) if not isinstance(value, str) else value

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
        if fold_long_lines and not line.startswith("dn:: "):
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
    def finalize_ldif_text(ldif_lines: list[str]) -> str:
        """Join LDIF lines and ensure proper trailing newline."""
        ldif_text = "\n".join(ldif_lines)
        if ldif_text and not ldif_text.endswith("\n"):
            ldif_text += "\n"
        return ldif_text


__all__ = [
    "FlextLdifUtilitiesWriter",
]
