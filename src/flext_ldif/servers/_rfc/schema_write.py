"""RFC schema server — schema write serialization path.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar, override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers._base.schema import FlextLdifServersBaseSchema
from flext_ldif.servers.base import FlextLdifServersBase



class FlextLdifServersRfcSchemaWriteMixin(FlextLdifServersBase.Schema):
    """Write schema attributes/objectClasses to RFC-compliant strings."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    def _build_attribute_parts(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> t.MutableSequenceOf[str]:
        """Build RFC attribute definition parts.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
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
        """Build RFC objectClass definition parts.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
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
        """Ensure X-ORIGIN extension is present if in metadata.

        Returns:
            The resulting ``str``.
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
    def _post_write_attribute(self, written_str: str) -> str:
        """Transform written attribute string (subclass hook).

        Returns:
            The resulting ``str``.
        """
        return written_str
    def _post_write_objectclass(self, written_str: str) -> str:
        """Transform written objectClass string (subclass hook).

        Returns:
            The resulting ``str``.
        """
        return written_str
    @override
    def _transform_attribute_for_write(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> m.Ldif.SchemaAttribute:
        """Transform attribute before writing (subclass hook).

        Returns:
            The resulting ``m.Ldif.SchemaAttribute``.
        """
        return attr_data
    @override
    def _transform_objectclass_for_write(
        self,
        oc_data: m.Ldif.SchemaObjectClass,
    ) -> m.Ldif.SchemaObjectClass:
        """Transform objectClass before writing (subclass hook).

        Returns:
            The resulting ``m.Ldif.SchemaObjectClass``.
        """
        return oc_data
    @override
    def _write_attribute(self, attr_data: m.Ldif.SchemaAttribute) -> p.Result[str]:
        """Write attribute to RFC-compliant string format (internal).

        Returns:
            The resulting ``p.Result[str]``.
        """
        return self._write_schema_item(attr_data)
    @override
    def _write_objectclass(self, oc_data: m.Ldif.SchemaObjectClass) -> p.Result[str]:
        """Write objectClass to RFC-compliant string format (internal).

        Returns:
            The resulting ``p.Result[str]``.
        """
        return self._write_schema_item(oc_data)
    def _write_schema_item(
        self,
        data: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> p.Result[str]:
        """Write schema item (attribute or objectClass) to RFC-compliant format.

        Returns:
            The resulting ``p.Result[str]``.
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
        """Write schema item after server-specific transforms.

        Returns:
            The resulting ``p.Result[str]``.
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
                        transformed_str = c.Ldif.sub_pattern(
                            f"{attr_types_lower}:",
                            f"{attr_case}:",
                            transformed_str,
                            ignorecase=True,
                        )
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
