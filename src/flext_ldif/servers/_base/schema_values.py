"""Base schema server — schema payload and operation coercion helpers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import struct

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers._base import FlextLdifServerMethodsMixin


class FlextLdifServersBaseSchemaValuesMixin:
    """Coerce raw schema payloads and operation tokens to canonical values."""

    @staticmethod
    def _coerce_schema_data(
        value: str
        | t.JsonValue
        | m.Ldif.SchemaAttribute
        | m.Ldif.SchemaObjectClass
        | None,
    ) -> str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | None:
        """Coerce raw execute payload to the concrete schema payload union.

        Returns:
            The resulting ``str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass |
                None``.

        Raises:
            TypeError: If Schema validation failed.
        """
        if value is None:
            return None
        if isinstance(value, str):
            return value
        try:
            attribute: m.Ldif.SchemaAttribute = m.Ldif.SchemaAttribute.model_validate(
                value,
            )
        except (
            c.ValidationError,
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as exc:
            msg = f"Schema validation failed: {exc}"
            raise TypeError(msg) from exc
        else:
            return attribute

    @staticmethod
    def _coerce_operation(value: t.Ldif.Scalar | None) -> str | None:
        """Coerce raw operation token to a supported schema operation.

        Returns:
            The resulting ``str | None``.
        """
        if isinstance(value, str) and value in {"parse", "write"}:
            return value
        return None

    @staticmethod
    def _detect_schema_type(definition: str) -> str:
        """Resolve schema type from definition using the shared schema utility.

        Returns:
            The resulting ``str``.
        """
        detect_method = getattr(u.Ldif, "detect_schema_type", None)
        if detect_method is not None and callable(detect_method):
            detected_type = detect_method(definition)
            if isinstance(detected_type, str):
                return detected_type
        default_schema_type: str = c.Ldif.SchemaItemKind.ATTRIBUTE.value
        return default_schema_type

    def _is_objectclass_schema_type(self, definition: str) -> bool:
        """Return whether the schema definition is an objectClass payload."""
        objectclass_schema_type: str = c.Ldif.SchemaItemKind.OBJECTCLASS.value
        return self._detect_schema_type(definition) == objectclass_schema_type

    @staticmethod
    def _coerce_attribute_model(
        value: t.JsonValue | t.Ldif.SchemaConversionValue,
    ) -> p.Result[m.Ldif.SchemaAttribute]:
        """Coerce raw value to a schema attribute model, propagating failures.

        Returns:
            The resulting ``p.Result[m.Ldif.SchemaAttribute]``.
        """
        try:
            attribute: m.Ldif.SchemaAttribute = m.Ldif.SchemaAttribute.model_validate(
                value,
            )
        except c.Ldif.EXC_LDIF_PARSE as exc:
            return r[m.Ldif.SchemaAttribute].fail(str(exc), exception=exc)
        return r[m.Ldif.SchemaAttribute].ok(attribute)

    @staticmethod
    def _coerce_objectclass_model(
        value: t.JsonValue | t.Ldif.SchemaConversionValue,
    ) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Coerce raw value to a schema objectClass model, propagating failures.

        Returns:
            The resulting ``p.Result[m.Ldif.SchemaObjectClass]``.
        """
        try:
            objectclass: m.Ldif.SchemaObjectClass = (
                m.Ldif.SchemaObjectClass.model_validate(value)
            )
        except c.Ldif.EXC_LDIF_PARSE as exc:
            return r[m.Ldif.SchemaObjectClass].fail(str(exc), exception=exc)
        return r[m.Ldif.SchemaObjectClass].ok(objectclass)

    def _resolve_data(
        self,
        data: str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | None,
        kwargs: t.JsonMapping,
    ) -> str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | None:
        """Resolve schema payload from parameter or kwargs.

        Returns:
            The resulting ``str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass |
                None``.
        """
        if data is not None:
            return data
        return self._coerce_schema_data(kwargs.get("data"))

    def _resolve_operation(
        self,
        operation: str | None,
        kwargs: t.JsonMapping,
    ) -> str | None:
        """Resolve schema operation from parameter or kwargs.

        Returns:
            The resulting ``str | None``.
        """
        if operation is not None:
            return self._coerce_operation(operation)
        return FlextLdifServerMethodsMixin.parse_operation_kwarg(kwargs).unwrap()


__all__: list[str] = ["FlextLdifServersBaseSchemaValuesMixin"]
