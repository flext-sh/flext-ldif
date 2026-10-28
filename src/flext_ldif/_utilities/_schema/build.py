"""Schema builders and writers for FLEXT-LDIF.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from collections.abc import MutableSequence
from typing import TYPE_CHECKING

from flext_ldif import FlextLdifModels, c, p
from flext_ldif._utilities import (
    FlextLdifUtilitiesOID,
    FlextLdifUtilitiesServer,
    FlextLdifUtilitiesWriter,
)
from flext_ldif._utilities._schema import FlextLdifUtilitiesSchemaFormat

if TYPE_CHECKING:
    from collections.abc import Callable


class FlextLdifUtilitiesSchemaBuild:
    """Build and write RFC 4512 schema element strings."""

    @staticmethod
    def _build_attribute_parts_from_model(
        attr_data: FlextLdifModels.Ldif.SchemaAttribute,
    ) -> MutableSequence[str]:
        """Build RFC 4512 attribute definition parts (simple version).

        Returns:
            The resulting ``MutableSequence[str]``.

        """
        parts: MutableSequence[str] = [f"( {attr_data.oid}"]
        if attr_data.name:
            parts.append(f"NAME '{attr_data.name}'")
        if attr_data.desc:
            parts.append(f"DESC '{attr_data.desc}'")
        if attr_data.sup:
            parts.append(f"SUP {attr_data.sup}")
        FlextLdifUtilitiesWriter.add_attribute_matching_rules(attr_data, parts)
        FlextLdifUtilitiesWriter.add_attribute_syntax(attr_data, parts)
        FlextLdifUtilitiesWriter.add_attribute_flags(attr_data, parts)
        if attr_data.usage:
            parts.append(f"USAGE {attr_data.usage}")
        if attr_data.x_origin:
            parts.append(f"X-ORIGIN '{attr_data.x_origin}'")
        parts.append(")")
        return parts

    @staticmethod
    def _append_objectclass_core_parts(
        oc_data: FlextLdifModels.Ldif.SchemaObjectClass,
        parts: MutableSequence[str],
    ) -> None:
        """Append SUP, kind, MUST and MAY parts of an objectClass definition."""
        sup_part = FlextLdifUtilitiesSchemaFormat.format_sup_list(oc_data.sup)
        if sup_part:
            parts.append(sup_part)
        kind = oc_data.kind or c.Ldif.SchemaKind.STRUCTURAL.value
        parts.append(kind)
        must_part = FlextLdifUtilitiesSchemaFormat.format_attribute_list(
            oc_data.must, "MUST"
        )
        if must_part:
            parts.append(must_part)
        may_part = FlextLdifUtilitiesSchemaFormat.format_attribute_list(
            oc_data.may, "MAY"
        )
        if may_part:
            parts.append(may_part)

    @staticmethod
    def _build_objectclass_parts_from_model(
        oc_data: FlextLdifModels.Ldif.SchemaObjectClass,
    ) -> MutableSequence[str]:
        """Build RFC 4512 objectClass definition parts (extracted to reduce complexity).

        Returns:
            The resulting ``MutableSequence[str]``.

        """
        parts: MutableSequence[str] = [f"( {oc_data.oid}"]
        if oc_data.name:
            parts.append(f"NAME '{oc_data.name}'")
        if oc_data.desc:
            parts.append(f"DESC '{oc_data.desc}'")
        FlextLdifUtilitiesSchemaFormat.build_obsolete_part(oc_data, parts, None)
        FlextLdifUtilitiesSchemaBuild._append_objectclass_core_parts(oc_data, parts)
        x_origin_part = FlextLdifUtilitiesSchemaFormat.build_x_origin_part(oc_data)
        if x_origin_part:
            parts.append(x_origin_part)
        parts.append(")")
        return parts

    @staticmethod
    def _write_schema_element(
        data: p.Ldif.SchemaAttribute | p.Ldif.SchemaObjectClass,
        expected_type: (
            type[
                FlextLdifModels.Ldif.SchemaAttribute
                | FlextLdifModels.Ldif.SchemaObjectClass
            ]
        ),
        type_name: str,
        parts_builder: Callable[..., MutableSequence[str]],
    ) -> str:
        """Write a schema element (DRY pattern).

        Returns:
            The resulting ``str``.

        Raises:
            TypeError: If ``not isinstance(data, expected_type)``.
            ValueError: If RFC.

        """
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
        attr_data: FlextLdifModels.Ldif.SchemaAttribute,
        *,
        restore_original: bool = True,
    ) -> MutableSequence[str]:
        """Build RFC 4512 attribute parts with full metadata restoration.

        Returns:
            The resulting ``MutableSequence[str]``.

        """
        if restore_original:
            original_parts = FlextLdifUtilitiesSchemaFormat.try_restore_original_format(
                attr_data
            )
            if original_parts:
                return original_parts
        parts: MutableSequence[str] = [f"( {attr_data.oid}"]
        field_order = FlextLdifUtilitiesSchemaFormat.resolve_field_order(attr_data)
        name_part = FlextLdifUtilitiesSchemaFormat.build_name_part(
            attr_data, restore_format=True
        )
        if name_part:
            parts.append(name_part)
        if attr_data.desc:
            parts.append(f"DESC '{attr_data.desc}'")
        if attr_data.sup:
            parts.append(f"SUP {attr_data.sup}")
        if attr_data.usage:
            parts.append(f"USAGE {attr_data.usage}")
        FlextLdifUtilitiesSchemaFormat.build_obsolete_part(
            attr_data, parts, field_order, restore_position=True
        )
        FlextLdifUtilitiesWriter.add_attribute_matching_rules(attr_data, parts)
        FlextLdifUtilitiesWriter.add_attribute_syntax(attr_data, parts)
        FlextLdifUtilitiesWriter.add_attribute_flags(attr_data, parts)
        x_origin_part = FlextLdifUtilitiesSchemaFormat.build_x_origin_part(
            attr_data, restore_format=True
        )
        if x_origin_part:
            parts.append(x_origin_part)
        parts.append(")")
        FlextLdifUtilitiesSchemaFormat.apply_trailing_spaces(attr_data, parts)
        return parts

    @staticmethod
    def build_objectclass_parts_with_metadata(
        oc_data: FlextLdifModels.Ldif.SchemaObjectClass,
        *,
        restore_original: bool = True,
    ) -> MutableSequence[str]:
        """Build RFC 4512 objectClass parts with full metadata restoration.

        Returns:
            The resulting ``MutableSequence[str]``.

        """
        original_parts = (
            FlextLdifUtilitiesSchemaFormat.try_restore_objectclass_original_format(
                oc_data,
                restore_original=restore_original,
            )
        )
        if original_parts:
            return original_parts
        parts: MutableSequence[str] = [f"( {oc_data.oid}"]
        name_part = FlextLdifUtilitiesSchemaFormat.build_name_part(
            oc_data, restore_format=True
        )
        if name_part:
            parts.append(name_part)
        if oc_data.desc:
            parts.append(f"DESC '{oc_data.desc}'")
        field_order = FlextLdifUtilitiesSchemaFormat.resolve_field_order(oc_data)
        FlextLdifUtilitiesSchemaFormat.build_obsolete_part(
            oc_data, parts, field_order, restore_position=True
        )
        FlextLdifUtilitiesSchemaBuild._append_objectclass_core_parts(oc_data, parts)
        x_origin_part = FlextLdifUtilitiesSchemaFormat.build_x_origin_part(
            oc_data, restore_format=True
        )
        if x_origin_part:
            parts.append(x_origin_part)
        parts.append(")")
        FlextLdifUtilitiesSchemaFormat.apply_trailing_spaces(oc_data, parts)
        return parts

    @staticmethod
    def should_restore_schema_original_format(
        metadata: FlextLdifModels.Ldif.ServerMetadata | None,
        target_server_type: str | None,
    ) -> bool:
        """Restore original schema text only for same-server round-trips.

        Returns:
            The resulting ``bool``.

        """
        if metadata is None:
            return False
        source_server_type = metadata.original_server_type
        if source_server_type is None and metadata.extensions:
            source_server_type = metadata.extensions.get("schema_source_server")
        if source_server_type is None:
            source_server_type = str(metadata.server_type)
        if not source_server_type or not target_server_type:
            return True
        try:
            normalized_source = FlextLdifUtilitiesServer.normalize_server_type(
                str(source_server_type)
            )
            normalized_target = FlextLdifUtilitiesServer.normalize_server_type(
                target_server_type
            )
        except c.EXC_TYPE_VALIDATION:
            return str(source_server_type).lower() == target_server_type.lower()
        normalized_source_value: str = normalized_source.value
        normalized_target_value: str = normalized_target.value
        return normalized_source_value == normalized_target_value

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
        validate_result = FlextLdifUtilitiesOID.validate_format(syntax)
        if validate_result.failure:
            return f"Syntax OID validation failed: {validate_result.error}"
        if not validate_result.value:
            return f"Invalid syntax OID format: {syntax}"
        return None

    @staticmethod
    def write_attribute(attr_data: p.Ldif.SchemaAttribute) -> str:
        """Write RFC 4512 attribute definition string from SchemaAttribute protocol.

        Returns:
            The resulting ``str``.

        """
        return FlextLdifUtilitiesSchemaBuild._write_schema_element(
            attr_data,
            FlextLdifModels.Ldif.SchemaAttribute,
            "attr_data",
            FlextLdifUtilitiesSchemaBuild._build_attribute_parts_from_model,
        )

    @staticmethod
    def write_objectclass(oc_data: p.Ldif.SchemaObjectClass) -> str:
        """Write RFC 4512 objectClass definition string from SchemaObjectClass protocol.

        Returns:
            The resulting ``str``.

        """
        return FlextLdifUtilitiesSchemaBuild._write_schema_element(
            oc_data,
            FlextLdifModels.Ldif.SchemaObjectClass,
            "oc_data",
            FlextLdifUtilitiesSchemaBuild._build_objectclass_parts_from_model,
        )


__all__: list[str] = ["FlextLdifUtilitiesSchemaBuild"]
