"""Schema-format restoration helpers for FLEXT-LDIF."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_cli import u
from flext_ldif import c, t

if TYPE_CHECKING:
    from flext_ldif import FlextLdifModels as m


class FlextLdifUtilitiesSchemaFormat:
    """Format restoration and low-level schema part builders."""

    @staticmethod
    def apply_trailing_spaces(
        attr_data: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        parts: t.MutableSequenceOf[str],
    ) -> None:
        """Apply trailing spaces from metadata if available."""
        if not attr_data.metadata or not attr_data.metadata.schema_format_details:
            return
        trailing = getattr(
            attr_data.metadata.schema_format_details, "trailing_spaces", ""
        )
        if trailing and parts:
            parts[-1] += str(trailing)

    @staticmethod
    def build_name_part(
        attr_data: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        *,
        restore_format: bool = False,
    ) -> str | None:
        """Build NAME part with optional format restoration."""
        if not attr_data.name:
            return None
        if not restore_format or not attr_data.metadata:
            return f"NAME '{attr_data.name}'"
        schema_details = attr_data.metadata.schema_format_details
        if not schema_details:
            return f"NAME '{attr_data.name}'"
        name_format = getattr(schema_details, "name_format", "single")
        name_values_ = getattr(schema_details, "name_values", [])
        name_values: t.MutableSequenceOf[str] = (
            [str(v) for v in name_values_] if u.list_like(name_values_) else []
        )
        if name_format == "multiple" and name_values:
            names_str = " ".join(f"'{n}'" for n in name_values)
            return f"NAME ( {names_str} )"
        return f"NAME '{attr_data.name}'"

    @staticmethod
    def build_obsolete_part(
        attr_data: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        parts: t.MutableSequenceOf[str],
        field_order: t.MutableSequenceOf[str] | None,
        *,
        restore_position: bool = False,
    ) -> None:
        """Build OBSOLETE part with optional position restoration."""
        has_obsolete = False
        if attr_data.metadata:
            schema_details = attr_data.metadata.schema_format_details
            has_obsolete = bool(
                getattr(schema_details, "obsolete_presence", False)
                if schema_details
                else False
            )
            if not has_obsolete:
                has_obsolete = bool(
                    attr_data.metadata.extensions.get(c.Ldif.ObsoleteField.OBSOLETE)
                )
        if not has_obsolete:
            return
        if restore_position and field_order and ("OBSOLETE" in field_order):
            obs_pos = field_order.index("OBSOLETE")
            parts.insert(min(obs_pos, len(parts)), "OBSOLETE")
        else:
            parts.append("OBSOLETE")

    @staticmethod
    def build_x_origin_part(
        attr_data: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        *,
        restore_format: bool = False,
    ) -> str | None:
        """Build X-ORIGIN part with optional format restoration."""
        if not attr_data.metadata:
            return None
        schema_details = attr_data.metadata.schema_format_details
        x_origin_value = None
        if (
            restore_format
            and schema_details
            and getattr(schema_details, "x_origin_presence", None)
            and getattr(schema_details, "x_origin_value", None)
        ):
            x_origin_value = getattr(schema_details, "x_origin_value", None)
        if not x_origin_value:
            x_origin_value = attr_data.metadata.extensions.get("x_origin")
        return f"X-ORIGIN '{x_origin_value}'" if x_origin_value else None

    @staticmethod
    def format_attribute_list(
        attr_list: str | t.MutableSequenceOf[str] | None, prefix: str
    ) -> str | None:
        """Format attribute list (MUST/MAY) for objectClass definition."""
        if not attr_list:
            return None
        if isinstance(attr_list, str):
            return f"{prefix} {attr_list}"
        attr_strs = list(attr_list)
        if len(attr_strs) == 1:
            return f"{prefix} {attr_strs[0]}"
        return f"{prefix} ( {' $ '.join(attr_strs)} )"

    @staticmethod
    def format_sup_list(sup_value: str | t.MutableSequenceOf[str] | None) -> str | None:
        """Format SUP (superior) list for objectClass definition."""
        if not sup_value:
            return None
        if isinstance(sup_value, str):
            return f"SUP {sup_value}"
        sup_strs = list(sup_value)
        return f"SUP ( {' $ '.join(sup_strs)} )"

    @staticmethod
    def get_field_order(
        attr_data: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> t.MutableSequenceOf[str] | None:
        """Extract field order from metadata if available."""
        if not attr_data.metadata or not attr_data.metadata.schema_format_details:
            return None
        field_order_ = getattr(
            attr_data.metadata.schema_format_details, "field_order", None
        )
        if field_order_ and u.list_like(field_order_):
            return [str(item) for item in field_order_]
        return None

    @staticmethod
    def try_restore_objectclass_original_format(
        oc_data: m.Ldif.SchemaObjectClass, *, restore_original: bool = True
    ) -> t.MutableSequenceOf[str] | None:
        """Try to restore original format from metadata for objectClass."""
        if not restore_original or not oc_data.metadata:
            return None
        schema_details = oc_data.metadata.schema_format_details
        if not schema_details:
            return None
        original = str(getattr(schema_details, "original_string_complete", ""))
        if not original:
            return None
        definition_match = c.Ldif.SCHEMA_DEFINITION_PARENS_RE.search(original)
        if definition_match:
            return [definition_match.group(0)]
        return None

    @staticmethod
    def try_restore_original_format(
        attr_data: m.Ldif.SchemaAttribute,
    ) -> t.MutableSequenceOf[str] | None:
        """Try to restore original format from metadata for perfect round-trip."""
        if not (
            attr_data.metadata
            and attr_data.metadata.schema_format_details
            and getattr(
                attr_data.metadata.schema_format_details,
                "original_string_complete",
                None,
            )
        ):
            return None
        original = str(
            getattr(
                attr_data.metadata.schema_format_details, "original_string_complete", ""
            )
        )
        if not original:
            return None
        definition_match = c.Ldif.SCHEMA_DEFINITION_PARENS_RE.search(original)
        return [definition_match.group(0)] if definition_match else None


__all__: list[str] = ["FlextLdifUtilitiesSchemaFormat"]
