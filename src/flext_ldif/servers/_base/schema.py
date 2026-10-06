"""Base Server Classes for LDIF/LDAP Server Extensions.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import struct
from collections.abc import Mapping, MutableMapping
from typing import Annotated, ClassVar, Self, override

from flext_ldif import c, m, p, r, s, t, u
from flext_ldif.servers._base.mixins import FlextLdifServerMethodsMixin
from flext_ldif.servers._base.schema_metadata import (
    FlextLdifServersBaseSchemaMetadataMixin,
)
from flext_ldif.servers._base.schema_values import (
    FlextLdifServersBaseSchemaValuesMixin,
)


class FlextLdifServersBaseSchema(
    FlextLdifServersBaseSchemaMetadataMixin,
    FlextLdifServersBaseSchemaValuesMixin,
    s[t.Ldif.SchemaConversionValue],
    FlextLdifServerMethodsMixin,
):
    """Base class for schema servers using `s` with enhanced usability."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    _NORMALIZE_OBJECTCLASS: ClassVar[bool] = False

    server_type: Annotated[
        str,
        u.Field(
            description=(
                "Server type identifier (e.g., 'oid', 'oud', 'openldap', 'rfc')",
            ),
        ),
    ] = "rfc"
    priority: Annotated[
        int,
        u.Field(description="Server priority (lower number = higher priority)"),
    ] = 0
    parent_server: Annotated[
        Self | None,
        u.Field(
            exclude=True,
            repr=False,
            description="Reference to parent server instance for server-level access",
        ),
    ] = None
    attr_definition: Annotated[
        str | None,
        u.Field(
            exclude=True,
            repr=False,
            description="Attribute definition for auto-execute pattern",
        ),
    ] = None
    oc_definition: Annotated[
        str | None,
        u.Field(
            exclude=True,
            repr=False,
            description="ObjectClass definition for auto-execute pattern",
        ),
    ] = None
    attr_model: Annotated[
        m.Ldif.SchemaAttribute | None,
        u.Field(
            exclude=True,
            repr=False,
            description="SchemaAttribute model for auto-execute pattern",
        ),
    ] = None
    oc_model: Annotated[
        m.Ldif.SchemaObjectClass | None,
        u.Field(
            exclude=True,
            repr=False,
            description="SchemaObjectClass model for auto-execute pattern",
        ),
    ] = None
    operation: Annotated[
        str | None,
        u.Field(
            exclude=True,
            repr=False,
            description="Operation type for auto-execute pattern",
        ),
    ] = None

    def __new__(
        cls,
        _schema_service: p.Ldif.SchemaServer | None = None,
        _parent_server: p.Ldif.SchemaServer | None = None,
        **kwargs: t.Ldif.Scalar,
    ) -> Self:
        """Override __new__ to filter _parent_server before passing to s."""
        filtered_kwargs = {k: v for k, v in kwargs.items() if k != "_parent_server"}
        instance: Self = super().__new__(cls, **filtered_kwargs)
        if _parent_server is not None:
            object.__setattr__(instance, "_parent_server", _parent_server)
        return instance

    def __init__(
        self,
        _schema_service: p.Ldif.SchemaServer | None = None,
        _parent_server: p.Ldif.SchemaServer | None = None,
        **kwargs: t.Ldif.Scalar,
    ) -> None:
        """Initialize schema server service with optional DI service injection."""
        filtered_kwargs = {k: v for k, v in kwargs.items() if k != "_parent_server"}
        service_kwargs: MutableMapping[str, t.Ldif.Scalar] = {}
        for key, value in filtered_kwargs.items():
            if isinstance(value, c.SCALAR_TYPES):
                service_kwargs[key] = value
        super().__init__()
        self._schema_service = _schema_service
        if _parent_server is not None:
            object.__setattr__(self, "_parent_server", _parent_server)

    def _init_base_schema(
        self: Self,
        schema_service: p.Ldif.SchemaServer | None,
        parent_server: p.Ldif.SchemaServer | None,
        excluded_keys: frozenset[str],
        **kwargs: t.Ldif.Scalar | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> None:
        """Delegate to FlextLdifServersBaseSchema.__init__ then wire parent server."""
        filtered_kwargs: t.MutableConfigValueMapping = {
            key: val
            for key, val in kwargs.items()
            if key not in excluded_keys and isinstance(val, c.PRIMITIVES_TYPES)
        }
        # Why: pass parent_server straight into __init__ (which already
        # performs the frozen-model object.__setattr__ dance for
        # _parent_server) instead of a separate post-init patch — avoids a
        # second, non-dunder-context __setattr__ call (ruff PLC2801) while
        # keeping exactly one owner for that assignment.
        FlextLdifServersBaseSchema.__init__(
            self,
            _schema_service=schema_service,
            _parent_server=parent_server,
            **filtered_kwargs,
        )

    auto_execute: ClassVar[bool] = False

    def can_handle_attribute(
        self,
        attr_definition: str | m.Ldif.SchemaAttribute,
    ) -> bool:
        """Check if this server can handle the attribute definition."""
        msg = "Schema servers must implement can_handle_attribute"
        raise NotImplementedError(msg)

    def can_handle_objectclass(
        self,
        oc_definition: str | m.Ldif.SchemaObjectClass,
    ) -> bool:
        """Check if this server can handle the objectClass definition."""
        msg = "Schema servers must implement can_handle_objectclass"
        raise NotImplementedError(msg)

    @override
    def execute(
        self,
        *,
        data: str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | None = None,
        operation: str | None = None,
        **kwargs: t.Ldif.Scalar,
    ) -> p.Result[t.Ldif.SchemaConversionValue]:
        """Execute schema operation with auto-detection: str→parse, Model→write.

        Returns:
            The resulting ``p.Result[t.Ldif.SchemaConversionValue]``.
        """
        json_value_adapter = t.json_value_adapter()
        kwargs_dict: t.MutableJsonMapping = {
            key: json_value_adapter.validate_python(u.to_jsonable_python(value))
            for key, value in kwargs.items()
        }
        resolved_data = self._resolve_data(data, kwargs_dict)
        operation = self._resolve_operation(operation, kwargs_dict)
        if resolved_data is None:
            empty_str: str = ""
            return r[t.Ldif.SchemaConversionValue].ok(empty_str)
        operation_final = operation if operation in {"parse", "write"} else None
        detected_op = self._auto_detect_operation(resolved_data, operation_final)
        return self._route_operation(resolved_data, detected_op)

    def parse_server(
        self,
        value: str,
    ) -> p.Result[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass]:
        """Parse schema definition (attribute or objectClass).

        Returns:
            The resulting ``p.Result[m.Ldif.SchemaAttribute |
                m.Ldif.SchemaObjectClass]``.
        """
        return self.route_parse(value)

    def parse_input(
        self,
        schema_text: str,
    ) -> p.Result[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass]:
        """Compatibility parser entrypoint for direct schema server consumers.

        Returns:
            The resulting ``p.Result[m.Ldif.SchemaAttribute |
                m.Ldif.SchemaObjectClass]``.
        """
        return self.parse_server(schema_text)

    def parse_attribute(self, definition: str) -> p.Result[m.Ldif.SchemaAttribute]:
        """Parse attribute definition (public API).

        Returns:
            The resulting ``p.Result[m.Ldif.SchemaAttribute]``.
        """
        return self._parse_attribute(definition)

    def parse_objectclass(self, definition: str) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Parse objectClass definition (public API).

        Returns:
            The resulting ``p.Result[m.Ldif.SchemaObjectClass]``.
        """
        return self._parse_objectclass(definition)

    def route_parse(
        self,
        definition: str,
    ) -> p.Result[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass]:
        """Route schema definition to appropriate parse method.

        Returns:
            The resulting ``p.Result[m.Ldif.SchemaAttribute |
                m.Ldif.SchemaObjectClass]``.
        """
        if self._is_objectclass_schema_type(definition):
            oc_result = self._parse_objectclass(definition)
            if oc_result.failure:
                return r[
                    m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass
                ].from_failure(oc_result)
            parsed_objectclass = m.Ldif.SchemaObjectClass.model_validate(
                oc_result.unwrap(),
            )
            return r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass].ok(
                parsed_objectclass,
            )
        attr_result = self._parse_attribute(definition)
        if attr_result.failure:
            return r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass].from_failure(
                attr_result,
            )
        parsed_attribute = m.Ldif.SchemaAttribute.model_validate(attr_result.unwrap())
        return r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass].ok(parsed_attribute)

    def write(
        self,
        model: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> p.Result[str]:
        """Write schema model to string format.

        Returns:
            The resulting ``p.Result[str]``.
        """
        try:
            attribute_model = m.Ldif.SchemaAttribute.model_validate(model)
        except c.EXC_BASIC_TYPE:
            objectclass_model = m.Ldif.SchemaObjectClass.model_validate(model)
            return self.write_objectclass(objectclass_model)
        return self.write_attribute(attribute_model)

    def write_attribute(self, attr_data: m.Ldif.SchemaAttribute) -> p.Result[str]:
        """Write attribute to RFC-compliant string format (public API).

        Returns:
            The resulting ``p.Result[str]``.
        """
        validated_attr = m.Ldif.SchemaAttribute.model_validate(attr_data)
        return self._write_attribute(validated_attr)

    def write_objectclass(self, oc_data: m.Ldif.SchemaObjectClass) -> p.Result[str]:
        """Write objectClass to RFC-compliant string format (public API).

        Returns:
            The resulting ``p.Result[str]``.
        """
        validated_oc = m.Ldif.SchemaObjectClass.model_validate(oc_data)
        return self._write_objectclass(validated_oc)

    @staticmethod
    def _auto_detect_operation(
        data: t.Ldif.SchemaConversionValue,
        operation: str | None,
    ) -> str:
        """Auto-detect operation from data type.

        Returns:
            The resulting ``str``.
        """
        if operation is not None:
            return operation
        if isinstance(data, str):
            return "parse"
        return "write"

    def _handle_parse_operation(
        self,
        attr_definition: str | None,
        oc_definition: str | None,
    ) -> p.Result[t.Ldif.SchemaConversionValue]:
        """Handle parse operation for schema server.

        Returns:
            The resulting ``p.Result[t.Ldif.SchemaConversionValue]``.
        """
        if attr_definition:
            attr_result = self.parse_attribute(attr_definition)
            if attr_result.success:
                parsed_attr = m.Ldif.SchemaAttribute.model_validate(
                    attr_result.unwrap(),
                )
                return r[t.Ldif.SchemaConversionValue].ok(parsed_attr)
            error_msg: str = attr_result.error or "Parse attribute failed"
            return r[t.Ldif.SchemaConversionValue].fail(error_msg)
        if oc_definition:
            oc_result = self.parse_objectclass(oc_definition)
            if oc_result.success:
                parsed_oc = m.Ldif.SchemaObjectClass.model_validate(oc_result.unwrap())
                return r[t.Ldif.SchemaConversionValue].ok(parsed_oc)
            error_msg = oc_result.error or "Parse objectclass failed"
            return r[t.Ldif.SchemaConversionValue].fail(error_msg)
        return r[t.Ldif.SchemaConversionValue].fail("No parse parameter provided")

    def _handle_write_operation(
        self,
        attr_model: m.Ldif.SchemaAttribute | None,
        oc_model: m.Ldif.SchemaObjectClass | None,
    ) -> p.Result[t.Ldif.SchemaConversionValue]:
        """Handle write operation for schema server.

        Returns:
            The resulting ``p.Result[t.Ldif.SchemaConversionValue]``.
        """
        if attr_model:
            write_result = self.write_attribute(attr_model)
            if write_result.success:
                written_text = write_result.unwrap()
                return r[t.Ldif.SchemaConversionValue].ok(written_text)
            error_msg: str = write_result.error or "Write attribute failed"
            return r[t.Ldif.SchemaConversionValue].fail(error_msg)
        if oc_model:
            write_oc_result = self.write_objectclass(oc_model)
            if write_oc_result.success:
                written_text = write_oc_result.unwrap()
                return r[t.Ldif.SchemaConversionValue].ok(written_text)
            error_msg = write_oc_result.error or "Write objectclass failed"
            return r[t.Ldif.SchemaConversionValue].fail(error_msg)
        return r[t.Ldif.SchemaConversionValue].fail("No write parameter provided")

    def _hook_post_parse_attribute(
        self,
        attr: m.Ldif.SchemaAttribute,
    ) -> p.Result[m.Ldif.SchemaAttribute]:
        """Run hook after parsing an attribute definition."""
        msg = "Schema servers must implement _hook_post_parse_attribute"
        raise NotImplementedError(msg)

    def _hook_post_parse_objectclass(
        self,
        oc: m.Ldif.SchemaObjectClass,
    ) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Normalize objectClass data after parse when subclass opts in.

        Returns:
            The resulting ``p.Result[m.Ldif.SchemaObjectClass]``.
        """
        if self._NORMALIZE_OBJECTCLASS:
            u.Ldif.fix_missing_sup(oc)
            u.Ldif.fix_kind_mismatch(oc)
        return r[m.Ldif.SchemaObjectClass].ok(oc)

    @staticmethod
    def _hook_validate_attributes(
        attributes: t.MutableSequenceOf[m.Ldif.SchemaAttribute],
        available_attrs: set[str],
    ) -> p.Result[bool]:
        """Validate server-specific attributes during schema extraction.

        Returns:
            The resulting ``p.Result[bool]``.
        """
        _ = attributes
        _ = available_attrs
        return r[bool].ok(value=True)

    def _parse_attribute(
        self,
        attr_definition: str,
    ) -> p.Result[m.Ldif.SchemaAttribute]:
        """Parse server-specific attribute definition (internal)."""
        msg = "Schema servers must implement _parse_attribute"
        raise NotImplementedError(msg)

    def _parse_objectclass(
        self,
        oc_definition: str,
    ) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Parse server-specific objectClass definition (internal)."""
        msg = "Schema servers must implement _parse_objectclass"
        raise NotImplementedError(msg)

    def _route_operation(
        self,
        data: str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        operation: str,
    ) -> p.Result[t.Ldif.SchemaConversionValue]:
        """Route data to appropriate parse or write handler.

        Returns:
            The resulting ``p.Result[t.Ldif.SchemaConversionValue]``.

        Raises:
            AssertionError: If Unknown operation.
        """
        result: p.Result[t.Ldif.SchemaConversionValue]
        if operation == "parse":
            if not isinstance(data, str):
                result = r[t.Ldif.SchemaConversionValue].fail(
                    f"parse operation requires str, got {type(data).__name__}",
                )
            elif self._is_objectclass_schema_type(data):
                result = self._handle_parse_operation(
                    attr_definition=None,
                    oc_definition=data,
                )
            else:
                result = self._handle_parse_operation(
                    attr_definition=data,
                    oc_definition=None,
                )
        elif operation == "write":
            attr_model = self._coerce_attribute_model(data).unwrap()
            result = self._handle_write_operation(attr_model=attr_model, oc_model=None)
        else:
            msg = f"Unknown operation: {operation}"
            raise AssertionError(msg)
        return result

    def _write_attribute(self, attr_data: m.Ldif.SchemaAttribute) -> p.Result[str]:
        """Write attribute data to RFC-compliant string format (internal)."""
        msg = "Schema servers must implement _write_attribute"
        raise NotImplementedError(msg)

    def _write_objectclass(self, oc_data: m.Ldif.SchemaObjectClass) -> p.Result[str]:
        """Write objectClass data to RFC-compliant string format (internal)."""
        msg = "Schema servers must implement _write_objectclass"
        raise NotImplementedError(msg)

    def _transform_attribute_for_write(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> m.Ldif.SchemaAttribute:
        """Transform attribute before writing."""
        msg = "Schema servers must implement _transform_attribute_for_write"
        raise NotImplementedError(msg)

    def _transform_objectclass_for_write(
        self,
        oc_data: m.Ldif.SchemaObjectClass,
    ) -> m.Ldif.SchemaObjectClass:
        """Transform objectClass before writing."""
        msg = "Schema servers must implement _transform_objectclass_for_write"
        raise NotImplementedError(msg)
