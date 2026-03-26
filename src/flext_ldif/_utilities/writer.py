"""Extracted nested class from FlextLdifUtilities."""

from __future__ import annotations

import base64
from collections.abc import Mapping, MutableMapping, MutableSequence, Sequence

from flext_core import FlextLogger, r
from pydantic import BaseModel

from flext_ldif import c, m, t

logger = FlextLogger(__name__)


class FlextLdifUtilitiesWriter:
    """Pure LDIF Formatting Operations - No Models, No Side Effects."""

    @staticmethod
    def _extract_extensions(
        metadata: t.NormalizedValue,
    ) -> MutableMapping[str, t.NormalizedValue | BaseModel] | None:
        """Extract extensions mapping from metadata (BaseModel or Mapping)."""
        ext_raw: t.NormalizedValue | None = None
        if isinstance(metadata, BaseModel):
            ext_raw = getattr(metadata, "extensions", None)
        elif isinstance(metadata, Mapping):
            ext_raw = metadata.get("extensions")
        if ext_raw is None:
            return None
        if isinstance(ext_raw, Mapping):
            return dict(ext_raw)
        return None

    @staticmethod
    def _add_line_with_folding(
        ldif_lines: MutableSequence[str],
        line: str,
        *,
        fold_long_lines: bool,
        width: int,
    ) -> None:
        """Add line with optional folding."""
        if fold_long_lines and (not line.startswith("dn:: ")):
            ldif_lines.extend(FlextLdifUtilitiesWriter.fold_line(line, width=width))
        else:
            ldif_lines.append(line)

    @staticmethod
    def _add_oc_must_may(
        parts: MutableSequence[str],
        attr_list: str | MutableSequence[str] | None,
        keyword: str,
    ) -> None:
        """Add MUST or MAY clause to objectClass definition parts."""
        if not attr_list:
            return
        if issubclass(attr_list.__class__, list):
            attr_list_str: MutableSequence[str] = [str(item) for item in attr_list]
            if len(attr_list_str) == 1:
                parts.append(f"{keyword} {attr_list_str[0]}")
            else:
                attrs_str = " $ ".join(attr_list_str)
                parts.append(f"{keyword} ( {attrs_str} )")
        else:
            parts.append(f"{keyword} {attr_list}")

    @staticmethod
    def _build_attribute_parts(
        attr_data: m.Ldif.SchemaAttribute,
    ) -> MutableSequence[str]:
        """Build RFC attribute definition parts (extracted to reduce complexity)."""
        parts: MutableSequence[str] = [f"( {attr_data.oid}"]
        if attr_data.name:
            parts.append(f"NAME '{attr_data.name}'")
        if attr_data.desc:
            parts.append(f"DESC '{attr_data.desc}'")
        if attr_data.metadata and attr_data.metadata.extensions.get(
            c.Ldif.OBSOLETE,
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
            attr_data.metadata.extensions.get("x_origin")
            if attr_data.metadata
            else None
        )
        if x_origin:
            parts.append(f"X-ORIGIN '{x_origin}'")
        parts.append(")")
        return parts

    @staticmethod
    def _build_objectclass_parts(
        oc_data: m.Ldif.SchemaObjectClass,
    ) -> MutableSequence[str]:
        """Build RFC objectClass definition parts (extracted to reduce complexity)."""
        parts: MutableSequence[str] = [f"( {oc_data.oid}"]
        if oc_data.name:
            parts.append(f"NAME '{oc_data.name}'")
        if oc_data.desc:
            parts.append(f"DESC '{oc_data.desc}'")
        if oc_data.metadata and oc_data.metadata.extensions.get(
            c.Ldif.OBSOLETE,
        ):
            parts.append("OBSOLETE")
        if oc_data.sup:
            if issubclass(oc_data.sup.__class__, list):
                sup_list_str: MutableSequence[str] = [str(item) for item in oc_data.sup]
                sup_str = " $ ".join(sup_list_str)
                parts.append(f"SUP ( {sup_str} )")
            else:
                parts.append(f"SUP {oc_data.sup}")
        kind = oc_data.kind or c.Ldif.SchemaKind.STRUCTURAL.value
        parts.append(str(kind))
        FlextLdifUtilitiesWriter._add_oc_must_may(parts, oc_data.must, "MUST")
        FlextLdifUtilitiesWriter._add_oc_must_may(parts, oc_data.may, "MAY")
        oc_x_origin = (
            oc_data.metadata.extensions.get("x_origin") if oc_data.metadata else None
        )
        if oc_x_origin:
            parts.append(f"X-ORIGIN '{oc_x_origin}'")
        parts.append(")")
        return parts

    @staticmethod
    def _handle_attribute_status(
        attr_name: str,
        attr_values: MutableSequence[str],
        status: c.Ldif.AttributeMarkerStatusLiteral,
        output_options: m.Ldif.WriteOutputOptions,
    ) -> tuple[str, MutableSequence[str]] | None:
        """Handle attribute based on status (extracted to reduce complexity)."""
        operational_value: str = "operational"
        filtered_value: str = "filtered"
        marked_for_removal_value: str = "marked_for_removal"
        hidden_value: str = "hidden"
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
        status_handlers: MutableMapping[str, tuple[bool, str | None]] = {
            operational_value: operational_handler,
            filtered_value: filtered_handler,
            marked_for_removal_value: marked_for_removal_handler,
            hidden_value: hidden_handler,
        }
        handler_config = status_handlers.get(status)
        if handler_config is None:
            return (attr_name, attr_values)
        show_flag, name_format = handler_config
        if not show_flag or name_format is None:
            return None
        return (name_format, attr_values)

    @staticmethod
    def _handle_removed_attribute(
        attr_name: str,
        attr_values: MutableSequence[str],
        output_options: m.Ldif.WriteOutputOptions,
    ) -> tuple[str, MutableSequence[str]] | None:
        """Handle already-removed attributes (extracted to reduce complexity)."""
        if output_options.show_removed_attributes:
            return (f"# {attr_name}", attr_values)
        return None

    @staticmethod
    def add_attribute_flags(
        attr_data: m.Ldif.SchemaAttribute,
        parts: MutableSequence[str],
    ) -> None:
        """Add flags to attribute parts list."""
        if attr_data.single_value:
            parts.append("SINGLE-VALUE")
        if attr_data.metadata and attr_data.metadata.extensions.get(
            c.Ldif.COLLECTIVE,
        ):
            parts.append("COLLECTIVE")
        if attr_data.no_user_modification:
            parts.append("NO-USER-MODIFICATION")

    @staticmethod
    def add_attribute_matching_rules(
        attr_data: m.Ldif.SchemaAttribute,
        parts: MutableSequence[str],
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
        attr_data: m.Ldif.SchemaAttribute,
        parts: MutableSequence[str],
    ) -> None:
        """Add syntax and length to attribute parts list."""
        if attr_data.syntax:
            syntax_str = str(attr_data.syntax)
            if attr_data.length is not None:
                syntax_str += f"{{{attr_data.length}}}"
            parts.append(f"SYNTAX {syntax_str}")

    @staticmethod
    def determine_attribute_order(
        entry_data: t.MutableContainerMapping,
    ) -> MutableSequence[tuple[str, t.NormalizedValue]] | None:
        """Determine attribute processing order from entry metadata."""
        metadata = entry_data.get("_metadata")
        if metadata is None:
            return None
        attr_order_raw: MutableSequence[str] | None = None
        extensions_mapping: (
            MutableMapping[str, t.NormalizedValue | BaseModel] | None
        ) = FlextLdifUtilitiesWriter._extract_extensions(metadata)
        if extensions_mapping is not None:
            typed_extensions = t.ConfigMap(root=extensions_mapping).root
            raw_attr_order: t.NormalizedValue | BaseModel | None = typed_extensions.get(
                "attribute_order",
            )
            if isinstance(raw_attr_order, Sequence) and not isinstance(
                raw_attr_order,
                (str, bytes),
            ):
                attr_order_raw = [str(item) for item in raw_attr_order]
        elif isinstance(metadata, Mapping):
            raw_extensions = metadata.get("extensions")
            if isinstance(raw_extensions, Mapping):
                typed_extensions = t.ConfigMap(root=dict(raw_extensions)).root
                raw_attr_order = typed_extensions.get("attribute_order")
                if isinstance(raw_attr_order, Sequence) and not isinstance(
                    raw_attr_order,
                    (str, bytes),
                ):
                    attr_order_raw = [str(item) for item in raw_attr_order]
        if attr_order_raw is None:
            return None
        attr_order = attr_order_raw
        skip_keys = {c.Ldif.DictKeys.DN, "_metadata", "server_type", "_acl_attributes"}
        result: MutableSequence[tuple[str, t.NormalizedValue]] = [
            (key, entry_data[key])
            for key in attr_order
            if key in entry_data and key not in skip_keys
        ]
        return result

    @staticmethod
    def encode_attribute_value(attr_name: str, value: bytes | str) -> str:
        """Encode a single attribute value for LDIF output (RFC 2849)."""
        if isinstance(value, bytes):
            encoded_value = base64.b64encode(value).decode("ascii")
            return f"{attr_name}:: {encoded_value}"
        str_value: str = value
        try:
            _ = str_value.encode("utf-8")
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
        is_binary_attr = attr_name.lower() in c.Ldif.BINARY_ATTRIBUTE_NAMES
        needs_base64 = is_binary_attr or FlextLdifUtilitiesWriter.needs_base64_encoding(
            str_value,
        )
        if needs_base64:
            encoded_value = base64.b64encode(str_value.encode("utf-8")).decode("ascii")
            return f"{attr_name}:: {encoded_value}"
        return f"{attr_name}: {str_value}"

    @staticmethod
    def finalize_ldif_text(ldif_lines: MutableSequence[str]) -> str:
        """Join LDIF lines and ensure proper trailing newline."""
        ldif_text = "\n".join(ldif_lines)
        if ldif_text and (not ldif_text.endswith("\n")):
            ldif_text += "\n"
        return ldif_text

    @staticmethod
    def fold_line(
        line: str,
        width: int = c.Ldif.LINE_FOLD_WIDTH,
    ) -> MutableSequence[str]:
        """Fold long LDIF line according to RFC 2849 §3."""
        if not line:
            return [line]
        line_bytes = line.encode("utf-8")
        if len(line_bytes) <= width:
            return [line]
        folded: MutableSequence[str] = []
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
                folded.append(c.Ldif.LINE_CONTINUATION_SPACE + chunk)
            else:
                folded.append(chunk)
            pos = chunk_end
        return folded

    @staticmethod
    def is_safe_char(char: str) -> bool:
        """Check if char is SAFE-CHAR per RFC 2849 §2."""
        if not char or len(char) != 1:
            return False
        code = ord(char)
        safe_min = c.Ldif.SAFE_CHAR_MIN
        safe_max = c.Ldif.SAFE_CHAR_MAX
        safe_exclude = c.Ldif.SAFE_CHAR_EXCLUDE
        return safe_min <= code <= safe_max and code not in safe_exclude

    @staticmethod
    def is_safe_init_char(char: str) -> bool:
        """Check if char is SAFE-INIT-CHAR per RFC 2849 §2."""
        if not char or len(char) != 1:
            return False
        code = ord(char)
        if not FlextLdifUtilitiesWriter.is_safe_char(char):
            return False
        return code not in c.Ldif.SAFE_INIT_CHAR_EXCLUDE

    @staticmethod
    def is_valid_safe_string(value: str) -> bool:
        """Check if value is valid SAFE-STRING per RFC 2849 §2."""
        if not value:
            return True
        if not FlextLdifUtilitiesWriter.is_safe_init_char(value[0]):
            return False
        for char in value[1:]:
            if not FlextLdifUtilitiesWriter.is_safe_char(char):
                return False
        return value[-1] != " "

    @staticmethod
    def needs_base64_encoding(value: str, *, check_trailing_space: bool = True) -> bool:
        """Check if value needs base64 encoding per RFC 2849 §2."""
        if not value:
            return False
        if value[0] in c.Ldif.BASE64_START_CHARS:
            return True
        if check_trailing_space and value[-1] == " ":
            return True
        safe_min = c.Ldif.SAFE_CHAR_MIN
        safe_max = c.Ldif.SAFE_CHAR_MAX
        safe_exclude = c.Ldif.SAFE_CHAR_EXCLUDE
        for char in value:
            byte_val = ord(char)
            if byte_val < safe_min or byte_val > safe_max or byte_val in safe_exclude:
                return True
        return False

    @staticmethod
    def write_rfc_attribute(
        attr_data: m.Ldif.SchemaAttribute,
    ) -> r[str]:
        """Write attribute data to RFC 4512 format."""
        try:
            if not attr_data.oid:
                return r[str].fail("RFC attribute writing failed: missing OID")
            parts = FlextLdifUtilitiesWriter._build_attribute_parts(attr_data)
            return r[str].ok(" ".join(parts))
        except (ValueError, TypeError, AttributeError) as e:
            logger.exception("RFC attribute writing exception")
            return r[str].fail(f"RFC attribute writing failed: {e}")

    @staticmethod
    def write_rfc_objectclass(
        objectclass: m.Ldif.SchemaObjectClass,
    ) -> r[str]:
        """Write objectClass data to RFC 4512 format."""
        try:
            if not objectclass.oid:
                return r[str].fail("RFC objectClass writing failed: missing OID")
            parts = FlextLdifUtilitiesWriter._build_objectclass_parts(objectclass)
            return r[str].ok(" ".join(parts))
        except (ValueError, TypeError, AttributeError) as e:
            logger.exception("RFC objectClass writing exception")
            return r[str].fail(f"RFC objectClass writing failed: {e}")


__all__ = ["FlextLdifUtilitiesWriter"]
