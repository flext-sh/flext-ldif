"""Schema builders and writers for FLEXT-LDIF."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_ldif import c, p, t
from flext_ldif._utilities.oid import FlextLdifUtilitiesOID as uo
from flext_ldif._utilities.schema_format import FlextLdifUtilitiesSchemaFormat as sf
from flext_ldif._utilities.server import FlextLdifUtilitiesServer as us
from flext_ldif._utilities.writer import FlextLdifUtilitiesWriter as uw
from flext_ldif.models import FlextLdifModels as m

if TYPE_CHECKING:
    from collections.abc import Callable


class FlextLdifUtilitiesSchemaBuild:
    """Build and write RFC 4512 schema element strings."""

    @staticmethod
    def _build_attribute_parts_from_model(
        attr_data: m.Ldif.SchemaAttribute,
    ) -> t.MutableSequenceOf[str]:
        """Build RFC 4512 attribute definition parts (simple version)."""
        parts: t.MutableSequenceOf[str] = [f"( {attr_data.oid}"]
        if attr_data.name:
            parts.append(f"NAME '{attr_data.name}'")
        if attr_data.desc:
            parts.append(f"DESC '{attr_data.desc}'")
        if attr_data.sup:
            parts.append(f"SUP {attr_data.sup}")
        uw.add_attribute_matching_rules(attr_data, parts)
        uw.add_attribute_syntax(attr_data, parts)
        uw.add_attribute_flags(attr_data, parts)
        if attr_data.usage:
            parts.append(f"USAGE {attr_data.usage}")
        if attr_data.x_origin:
            parts.append(f"X-ORIGIN '{attr_data.x_origin}'")
        parts.append(")")
        return parts

    @staticmethod
    def _build_objectclass_parts_from_model(
        oc_data: m.Ldif.SchemaObjectClass,
    ) -> t.MutableSequenceOf[str]:
        """Build RFC 4512 objectClass definition parts (extracted to reduce complexity)."""
        parts: t.MutableSequenceOf[str] = [f"( {oc_data.oid}"]
        if oc_data.name:
            parts.append(f"NAME '{oc_data.name}'")
        if oc_data.desc:
            parts.append(f"DESC '{oc_data.desc}'")
        sf.build_obsolete_part(oc_data, parts, None)
        sup_part = sf.format_sup_list(oc_data.sup)
        if sup_part:
            parts.append(sup_part)
        kind = oc_data.kind or c.Ldif.SchemaKind.STRUCTURAL.value
        parts.append(kind)
        must_part = sf.format_attribute_list(oc_data.must, "MUST")
        if must_part:
            parts.append(must_part)
        may_part = sf.format_attribute_list(oc_data.may, "MAY")
        if may_part:
            parts.append(may_part)
        x_origin_part = sf.build_x_origin_part(oc_data)
        if x_origin_part:
            parts.append(x_origin_part)
        parts.append(")")
        return parts

    @staticmethod
    def _write_schema_element(
        data: p.Ldif.SchemaAttribute | p.Ldif.SchemaObjectClass,
        expected_type: (type[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass]),
        type_name: str,
        parts_builder: Callable[..., t.MutableSequenceOf[str]],
    ) -> str:
        """Generic helper for writing schema elements (DRY pattern)."""
        if not isinstance(data, expected_type):
            msg = f"{type_name} must implement {expected_type.__name__}"
            raise TypeError(msg)
        validated_data = data
        if not validated_data.oid:
            msg = f"RFC {type_name} writing failed: missing OID"
            raise ValueError(msg)
        parts = parts_builder(validated_data)
        return " ".join(parts)

    @staticmethod
    def build_attribute_parts_with_metadata(
        attr_data: m.Ldif.SchemaAttribute,
        *,
        restore_original: bool = True,
    ) -> t.MutableSequenceOf[str]:
        """Build RFC 4512 attribute parts with full metadata restoration."""
        if restore_original:
            original_parts = sf.try_restore_original_format(attr_data)
            if original_parts:
                return original_parts
        parts: t.MutableSequenceOf[str] = [f"( {attr_data.oid}"]
        field_order = sf.get_field_order(attr_data)
        name_part = sf.build_name_part(attr_data, restore_format=True)
        if name_part:
            parts.append(name_part)
        if attr_data.desc:
            parts.append(f"DESC '{attr_data.desc}'")
        if attr_data.sup:
            parts.append(f"SUP {attr_data.sup}")
        if attr_data.usage:
            parts.append(f"USAGE {attr_data.usage}")
        sf.build_obsolete_part(attr_data, parts, field_order, restore_position=True)
        uw.add_attribute_matching_rules(attr_data, parts)
        uw.add_attribute_syntax(attr_data, parts)
        uw.add_attribute_flags(attr_data, parts)
        x_origin_part = sf.build_x_origin_part(attr_data, restore_format=True)
        if x_origin_part:
            parts.append(x_origin_part)
        parts.append(")")
        sf.apply_trailing_spaces(attr_data, parts)
        return parts

    @staticmethod
    def build_objectclass_parts_with_metadata(
        oc_data: m.Ldif.SchemaObjectClass,
        *,
        restore_original: bool = True,
    ) -> t.MutableSequenceOf[str]:
        """Build RFC 4512 objectClass parts with full metadata restoration."""
        original_parts = sf.try_restore_objectclass_original_format(
            oc_data,
            restore_original=restore_original,
        )
        if original_parts:
            return original_parts
        parts: t.MutableSequenceOf[str] = [f"( {oc_data.oid}"]
        name_part = sf.build_name_part(oc_data, restore_format=True)
        if name_part:
            parts.append(name_part)
        if oc_data.desc:
            parts.append(f"DESC '{oc_data.desc}'")
        field_order = sf.get_field_order(oc_data)
        sf.build_obsolete_part(oc_data, parts, field_order, restore_position=True)
        sup_part = sf.format_sup_list(oc_data.sup)
        if sup_part:
            parts.append(sup_part)
        kind = oc_data.kind or c.Ldif.SchemaKind.STRUCTURAL.value
        parts.append(kind)
        must_part = sf.format_attribute_list(oc_data.must, "MUST")
        if must_part:
            parts.append(must_part)
        may_part = sf.format_attribute_list(oc_data.may, "MAY")
        if may_part:
            parts.append(may_part)
        x_origin_part = sf.build_x_origin_part(oc_data, restore_format=True)
        if x_origin_part:
            parts.append(x_origin_part)
        parts.append(")")
        sf.apply_trailing_spaces(oc_data, parts)
        return parts

    @staticmethod
    def should_restore_schema_original_format(
        metadata: m.Ldif.ServerMetadata | None,
        target_server_type: str | None,
    ) -> bool:
        """Restore original schema text only for same-server round-trips."""
        if metadata is None:
            return False
        source_server_type = metadata.original_server_type
        if source_server_type is None and metadata.extensions:
            source_server_type = metadata.extensions.schema_source_server
        if source_server_type is None:
            source_server_type = str(metadata.server_type)
        if not source_server_type or not target_server_type:
            return True
        try:
            normalized_source = us.normalize_server_type(
                str(source_server_type),
            )
            normalized_target = us.normalize_server_type(
                target_server_type,
            )
        except c.EXC_TYPE_VALIDATION:
            return str(source_server_type).lower() == target_server_type.lower()
        return normalized_source == normalized_target

    @staticmethod
    def validate_syntax_oid(syntax: str | None) -> str | None:
        """Validate syntax OID format.

        Generic validation for syntax OID fields used across server implementations.
        Checks that OID syntax conforms to standard OID format (numeric dot notation).

        Args:
            syntax: Syntax OID to validate

        Returns:
            Error message if validation fails, None otherwise

        """
        if syntax is None or not syntax.strip():
            return None
        validate_result = uo.validate_format(syntax)
        if validate_result.failure:
            return f"Syntax OID validation failed: {validate_result.error}"
        if not validate_result.value:
            return f"Invalid syntax OID format: {syntax}"
        return None

    @staticmethod
    def write_attribute(attr_data: p.Ldif.SchemaAttribute) -> str:
        """Write RFC 4512 attribute definition string from SchemaAttribute protocol."""
        return FlextLdifUtilitiesSchemaBuild._write_schema_element(
            attr_data,
            m.Ldif.SchemaAttribute,
            "attr_data",
            FlextLdifUtilitiesSchemaBuild._build_attribute_parts_from_model,
        )

    @staticmethod
    def write_objectclass(oc_data: p.Ldif.SchemaObjectClass) -> str:
        """Write RFC 4512 objectClass definition string from SchemaObjectClass protocol."""
        return FlextLdifUtilitiesSchemaBuild._write_schema_element(
            oc_data,
            m.Ldif.SchemaObjectClass,
            "oc_data",
            FlextLdifUtilitiesSchemaBuild._build_objectclass_parts_from_model,
        )


__all__: list[str] = ["FlextLdifUtilitiesSchemaBuild"]
