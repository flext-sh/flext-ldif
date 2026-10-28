"""RFC schema server — schema write serialization path.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC
from typing import ClassVar, override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers import FlextLdifServersBase
from flext_ldif.servers._rfc.server_constants import FlextLdifServersRfcConstants


class FlextLdifServersRfcSchemaWriteMixin(
    FlextLdifServersBase,
    ABC,
):
    """Write schema attributes/objectClasses to RFC-compliant strings."""

    Constants: ClassVar[type[FlextLdifServersRfcConstants]] = (
        FlextLdifServersRfcConstants
    )

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    def _build_attribute_parts(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> t.MutableSequenceOf[str]:
        """Build the RFC attribute definition parts for writing.

        Args:
            attr_data: Attribute to serialize.

        Returns:
            Definition parts joined with spaces to form the definition.

        """
        parts: t.MutableSequenceOf[str] = u.Ldif.build_attribute_parts_with_metadata(
            attr_data,
            restore_original=u.Ldif.should_restore_schema_original_format(
                attr_data.metadata,
                self._get_server_type(),
            ),
        )
        return parts

    def _build_objectclass_parts(
        self,
        oc_data: m.Ldif.SchemaObjectClass,
    ) -> t.MutableSequenceOf[str]:
        """Build the RFC objectClass definition parts for writing.

        Args:
            oc_data: ObjectClass to serialize.

        Returns:
            Definition parts joined with spaces to form the definition.

        """
        parts: t.MutableSequenceOf[str] = u.Ldif.build_objectclass_parts_with_metadata(
            oc_data,
            restore_original=u.Ldif.should_restore_schema_original_format(
                oc_data.metadata,
                self._get_server_type(),
            ),
        )
        return parts

    @staticmethod
    def _ensure_x_origin(
        output_str: str,
        metadata: m.Ldif.ServerMetadata | None,
    ) -> str:
        """Append the X-ORIGIN extension from metadata when missing.

        Args:
            output_str: Serialized schema definition text.
            metadata: Metadata that may carry the X-ORIGIN value.

        Returns:
            The definition text with the extension appended when applicable.

        """
        result = output_str
        if metadata is not None:
            extensions = metadata.extensions
            if extensions:
                x_origin_raw: t.JsonPayload | None = extensions.get(c.Ldif.X_ORIGIN)
                if (
                    isinstance(x_origin_raw, str)
                    and "X-ORIGIN" not in output_str
                    and output_str.endswith(")")
                ):
                    x_origin_str = f" X-ORIGIN '{x_origin_raw}'"
                    result = output_str.rstrip(")") + x_origin_str + ")"
        return result

    @staticmethod
    def _post_write_attribute(written_str: str) -> str:
        """Apply the final attribute string transformation.

        Args:
            written_str: Serialized attribute definition text.

        Returns:
            The transformed attribute definition text.

        """
        return written_str

    @staticmethod
    def _post_write_objectclass(written_str: str) -> str:
        """Apply the final objectClass string transformation.

        Args:
            written_str: Serialized objectClass definition text.

        Returns:
            The transformed objectClass definition text.

        """
        return written_str

    @override
    def _transform_attribute_for_write(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> m.Ldif.SchemaAttribute:
        """Transform an attribute before writing.

        Args:
            attr_data: Attribute about to be serialized.

        Returns:
            The transformed attribute.

        """
        return attr_data

    @override
    def _transform_objectclass_for_write(
        self,
        oc_data: m.Ldif.SchemaObjectClass,
    ) -> m.Ldif.SchemaObjectClass:
        """Transform an objectClass before writing.

        Args:
            oc_data: ObjectClass about to be serialized.

        Returns:
            The transformed objectClass.

        """
        return oc_data

    @override
    def _write_attribute(self, attr_data: m.Ldif.SchemaAttribute) -> p.Result[str]:
        """Write an attribute definition to RFC-compliant format.

        Args:
            attr_data: Attribute to serialize.

        Returns:
            Result carrying the definition string, or a failure.

        """
        return self._write_schema_item(attr_data)

    @override
    def _write_objectclass(self, oc_data: m.Ldif.SchemaObjectClass) -> p.Result[str]:
        """Write an objectClass definition to RFC-compliant format.

        Args:
            oc_data: ObjectClass to serialize.

        Returns:
            Result carrying the definition string, or a failure.

        """
        return self._write_schema_item(oc_data)

    def _write_schema_item(
        self,
        data: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> p.Result[str]:
        """Write a schema item to RFC-compliant format.

        Args:
            data: Attribute or objectClass to serialize.

        Returns:
            Result carrying the definition string, or a failure.

        """
        try:
            return self._write_schema_item_core(data)
        except c.EXC_BASIC_TYPE as e:
            item_type = (
                "attribute"
                if isinstance(data, m.Ldif.SchemaAttribute)
                else "objectclass"
            )
            self._module_logger.exception(
                "RFC %s writing exception",
                item_type,
            )
            return r[str].fail(f"RFC {item_type} writing failed: {e}")

    def _write_schema_item_core(
        self,
        data: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> p.Result[str]:
        """Write a schema item after server-specific transforms.

        Args:
            data: Attribute or objectClass to serialize.

        Returns:
            Result carrying the definition string, or a failure.

        """
        if isinstance(data, m.Ldif.SchemaAttribute):
            attr_transformed = self._transform_attribute_for_write(data)
            if not attr_transformed.oid:
                return r[str].fail("RFC attribute writing failed: missing OID")
            parts = self._build_attribute_parts(attr_transformed)
            written_str = " ".join(parts)
            transformed_str = self._post_write_attribute(written_str)
            if attr_transformed.metadata:
                fmt = attr_transformed.metadata.schema_format_details
                if fmt:
                    attr_case = getattr(fmt, "attribute_case", c.Ldif.ATTRIBUTE_TYPES)
                    attr_types_lower = c.Ldif.ATTRIBUTE_TYPES.lower()
                    if attr_types_lower in transformed_str.lower():
                        transformed_str = c.Ldif.compile_pattern(
                            f"{attr_types_lower}:",
                            ignorecase=True,
                        ).sub(f"{attr_case}:", transformed_str)
            return r[str].ok(
                self._ensure_x_origin(transformed_str, attr_transformed.metadata),
            )
        oc_transformed = self._transform_objectclass_for_write(data)
        if not oc_transformed.oid:
            return r[str].fail("RFC objectclass writing failed: missing OID")
        parts = self._build_objectclass_parts(oc_transformed)
        written_str = " ".join(parts)
        transformed_str = self._post_write_objectclass(written_str)
        return r[str].ok(
            self._ensure_x_origin(transformed_str, oc_transformed.metadata),
        )


__all__: list[str] = ["FlextLdifServersRfcSchemaWriteMixin"]
