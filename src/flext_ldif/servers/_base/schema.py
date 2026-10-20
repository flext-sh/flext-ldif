"""Base Server Classes for LDIF/LDAP Server Extensions.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import Annotated, ClassVar, Self, override

from flext_ldif import c, m, p, r, s, t, u
from flext_ldif.servers._base import (
    FlextLdifServerMethodsMixin,
    FlextLdifServersBaseSchemaMetadataMixin,
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
        m.Field(
            description=(
                "Server type identifier (e.g., 'oid', 'oud', 'openldap', 'rfc')"
            ),
        ),
    ] = "rfc"
    priority: Annotated[
        int,
        m.Field(description="Server priority (lower number = higher priority)"),
    ] = 0
    parent_server: Annotated[
        Self | None,
        m.Field(
            exclude=True,
            repr=False,
            description="Reference to parent server instance for server-level access",
        ),
    ] = None
    attr_definition: Annotated[
        str | None,
        m.Field(
            exclude=True,
            repr=False,
            description="Attribute definition for auto-execute pattern",
        ),
    ] = None
    oc_definition: Annotated[
        str | None,
        m.Field(
            exclude=True,
            repr=False,
            description="ObjectClass definition for auto-execute pattern",
        ),
    ] = None
    attr_model: Annotated[
        m.Ldif.SchemaAttribute | None,
        m.Field(
            exclude=True,
            repr=False,
            description="SchemaAttribute model for auto-execute pattern",
        ),
    ] = None
    oc_model: Annotated[
        m.Ldif.SchemaObjectClass | None,
        m.Field(
            exclude=True,
            repr=False,
            description="SchemaObjectClass model for auto-execute pattern",
        ),
    ] = None
    operation: Annotated[
        str | None,
        m.Field(
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
        """Filter ``_parent_server`` before passing remaining kwargs to the base.

        Args:
            _schema_service: Optional schema service injected by the DI container.
            _parent_server: Optional parent server bound via ``object.__setattr__``.
            **kwargs: Scalar fields forwarded to the base, minus ``_parent_server``.

        Returns:
            The constructed instance.

        """
        del _schema_service
        filtered_kwargs = {k: v for k, v in kwargs.items() if k != "_parent_server"}
        instance: Self = super().__new__(cls, **filtered_kwargs)
        if _parent_server is not None:
            object.__setattr__(instance, "parent_server", _parent_server)
        return instance

    def __init__(
        self,
        _schema_service: p.Ldif.SchemaServer | None = None,
        _parent_server: p.Ldif.SchemaServer | None = None,
        **kwargs: t.Ldif.Scalar,
    ) -> None:
        """Initialize the schema server with optional DI service injection.

        Args:
            _schema_service: Optional schema service injected by the DI container.
            _parent_server: Optional parent server bound via ``object.__setattr__``.
            **kwargs: Scalar fields forwarded to the service, minus
                ``_parent_server``.

        """
        filtered_kwargs = {k: v for k, v in kwargs.items() if k != "_parent_server"}
        service_kwargs: MutableMapping[str, t.Ldif.Scalar] = {}
        for key, value in filtered_kwargs.items():
            if isinstance(value, c.SCALAR_TYPES):
                service_kwargs[key] = value
        super().__init__()
        self._schema_service = _schema_service
        if _parent_server is not None:
            object.__setattr__(self, "parent_server", _parent_server)

    def _init_base_schema(
        self: Self,
        schema_service: p.Ldif.SchemaServer | None,
        parent_server: p.Ldif.SchemaServer | None,
        excluded_keys: frozenset[str],
        **kwargs: t.Ldif.Scalar | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> None:
        """Delegate to ``FlextLdifServersBaseSchema.__init__`` then wire the parent.

        Args:
            schema_service: Optional schema service injected by the DI container.
            parent_server: Optional parent server instance.
            excluded_keys: Kwarg names excluded from the filtered payload.
            **kwargs: Scalar and schema-model fields forwarded to the init.

        """
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

    @override
    def can_handle_attribute(
        self,
        attr_definition: str | m.Ldif.SchemaAttribute,
    ) -> bool:
        """Check whether this server can handle the attribute definition.

        Args:
            attr_definition: Raw attribute definition or parsed model.

        Raises:
            NotImplementedError: Always; concrete server flavors must override.

        """
        del attr_definition
        msg = "Schema servers must implement can_handle_attribute"
        raise NotImplementedError(msg)

    @override
    def can_handle_objectclass(
        self,
        oc_definition: str | m.Ldif.SchemaObjectClass,
    ) -> bool:
        """Check whether this server can handle the objectClass definition.

        Args:
            oc_definition: Raw objectClass definition or parsed model.

        Raises:
            NotImplementedError: Always; concrete server flavors must override.

        """
        del oc_definition
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
        """Execute the schema operation, auto-detecting parse for str, write for Model.

        Args:
            data: Raw definition string or parsed schema model to process.
            operation: Explicit operation token ("parse" or "write").
            **kwargs: Extra scalar parameters resolved for data and operation.

        Returns:
            Typed result carrying the parsed model or written string.

        """
        json_value_adapter = u.json_value_adapter()
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
    ) -> p.Result[p.Ldif.SchemaAttribute | p.Ldif.SchemaObjectClass]:
        """Parse a schema definition (attribute or objectClass).

        Args:
            value: Raw schema definition string.

        Returns:
            Typed result carrying the parsed attribute or objectClass.

        """
        return self.route_parse(value)

    def parse_input(
        self,
        schema_text: str,
    ) -> p.Result[p.Ldif.SchemaAttribute | p.Ldif.SchemaObjectClass]:
        """Compatibility parser entrypoint for direct schema server consumers.

        Args:
            schema_text: Raw schema definition string.

        Returns:
            Typed result carrying the parsed attribute or objectClass.

        """
        return self.parse_server(schema_text)

    def parse_attribute(self, definition: str) -> p.Result[p.Ldif.SchemaAttribute]:
        """Parse an attribute definition (public API).

        Args:
            definition: Raw attribute definition string.

        Returns:
            Typed result carrying the parsed attribute model.

        """
        result = self._parse_attribute(definition)
        if result.failure:
            return r[p.Ldif.SchemaAttribute].from_failure(result)
        payload: p.Ldif.SchemaAttribute = result.unwrap()
        return r[p.Ldif.SchemaAttribute].ok(payload)

    def parse_objectclass(self, definition: str) -> p.Result[p.Ldif.SchemaObjectClass]:
        """Parse an objectClass definition (public API).

        Args:
            definition: Raw objectClass definition string.

        Returns:
            Typed result carrying the parsed objectClass model.

        """
        result = self._parse_objectclass(definition)
        if result.failure:
            return r[p.Ldif.SchemaObjectClass].from_failure(result)
        payload: p.Ldif.SchemaObjectClass = result.unwrap()
        return r[p.Ldif.SchemaObjectClass].ok(payload)

    def route_parse(
        self,
        definition: str,
    ) -> p.Result[p.Ldif.SchemaAttribute | p.Ldif.SchemaObjectClass]:
        """Route a schema definition to the appropriate parse method.

        Args:
            definition: Raw schema definition string.

        Returns:
            Typed result carrying the parsed attribute or objectClass.

        """
        if self._is_objectclass_schema_type(definition):
            oc_result = self.parse_objectclass(definition)
            if oc_result.failure:
                return r[
                    p.Ldif.SchemaAttribute | p.Ldif.SchemaObjectClass
                ].from_failure(oc_result)
            parsed_objectclass: p.Ldif.SchemaAttribute | p.Ldif.SchemaObjectClass = (
                oc_result.unwrap()
            )
            return r[p.Ldif.SchemaAttribute | p.Ldif.SchemaObjectClass].ok(
                parsed_objectclass
            )
        attr_result = self.parse_attribute(definition)
        if attr_result.failure:
            return r[p.Ldif.SchemaAttribute | p.Ldif.SchemaObjectClass].from_failure(
                attr_result,
            )
        parsed_attribute: p.Ldif.SchemaAttribute | p.Ldif.SchemaObjectClass = (
            attr_result.unwrap()
        )
        return r[p.Ldif.SchemaAttribute | p.Ldif.SchemaObjectClass].ok(parsed_attribute)

    def write(
        self,
        model: p.Ldif.SchemaAttribute | p.Ldif.SchemaObjectClass,
    ) -> p.Result[str]:
        """Write a schema model to its string format.

        Args:
            model: Attribute or objectClass model to serialize.

        Returns:
            Typed result carrying the serialized schema string.

        """
        if isinstance(model, p.Ldif.SchemaObjectClass):
            objectclass_model = m.Ldif.SchemaObjectClass.model_validate(
                model, from_attributes=True
            )
            return self.write_objectclass(objectclass_model)
        attribute_model = m.Ldif.SchemaAttribute.model_validate(
            model, from_attributes=True
        )
        return self.write_attribute(attribute_model)

    def write_attribute(self, attr_data: p.Ldif.SchemaAttribute) -> p.Result[str]:
        """Write an attribute to the RFC-compliant string format (public API).

        Args:
            attr_data: Canonical attribute model to serialize.

        Returns:
            Typed result carrying the serialized attribute string.

        """
        validated_attr = m.Ldif.SchemaAttribute.model_validate(
            attr_data, from_attributes=True
        )
        return self._write_attribute(validated_attr)

    def write_objectclass(self, oc_data: p.Ldif.SchemaObjectClass) -> p.Result[str]:
        """Write an objectClass to the RFC-compliant string format (public API).

        Args:
            oc_data: Canonical objectClass model to serialize.

        Returns:
            Typed result carrying the serialized objectClass string.

        """
        validated_oc = m.Ldif.SchemaObjectClass.model_validate(
            oc_data, from_attributes=True
        )
        return self._write_objectclass(validated_oc)

    @staticmethod
    def _auto_detect_operation(
        data: t.Ldif.SchemaConversionValue,
        operation: str | None,
    ) -> str:
        """Auto-detect the operation from the data type.

        Args:
            data: Payload whose type selects the default operation.
            operation: Explicit operation token, when provided.

        Returns:
            The resolved operation token ("parse" or "write").

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
        """Handle the parse operation for the schema server.

        Args:
            attr_definition: Raw attribute definition, when parsing an attribute.
            oc_definition: Raw objectClass definition, when parsing an objectClass.

        Returns:
            Typed result carrying the parsed schema model.

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
        """Handle the write operation for the schema server.

        Args:
            attr_model: Attribute model to write, when writing an attribute.
            oc_model: objectClass model to write, when writing an objectClass.

        Returns:
            Typed result carrying the written schema string.

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

    @override
    def _hook_post_parse_attribute(
        self,
        attr: m.Ldif.SchemaAttribute,
    ) -> p.Result[m.Ldif.SchemaAttribute]:
        """Run the post-parse hook for an attribute definition.

        Args:
            attr: Parsed attribute model pending the hook.

        Raises:
            NotImplementedError: Always; concrete server flavors must override.

        """
        del attr
        msg = "Schema servers must implement _hook_post_parse_attribute"
        raise NotImplementedError(msg)

    def _hook_post_parse_objectclass(
        self,
        oc: m.Ldif.SchemaObjectClass,
    ) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Normalize objectClass data after parse when subclass opts in.

        Args:
            oc: Parsed objectClass model pending normalization.

        Returns:
            Typed result carrying the normalized objectClass.

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

        Args:
            attributes: Parsed attribute models to validate.
            available_attrs: Attribute names available on the server.

        Returns:
            Typed result carrying the validation outcome.

        """
        del attributes, available_attrs
        return r[bool].ok(value=True)

    @override
    def _parse_attribute(
        self,
        attr_definition: str,
    ) -> p.Result[m.Ldif.SchemaAttribute]:
        """Parse a server-specific attribute definition (internal).

        Args:
            attr_definition: Raw attribute definition string.

        Raises:
            NotImplementedError: Always; concrete server flavors must override.

        """
        del attr_definition
        msg = "Schema servers must implement _parse_attribute"
        raise NotImplementedError(msg)

    @override
    def _parse_objectclass(
        self,
        oc_definition: str,
    ) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Parse a server-specific objectClass definition (internal).

        Args:
            oc_definition: Raw objectClass definition string.

        Raises:
            NotImplementedError: Always; concrete server flavors must override.

        """
        del oc_definition
        msg = "Schema servers must implement _parse_objectclass"
        raise NotImplementedError(msg)

    def _route_operation(
        self,
        data: str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        operation: str,
    ) -> p.Result[t.Ldif.SchemaConversionValue]:
        """Route data to the appropriate parse or write handler.

        Args:
            data: Raw definition string or parsed schema model to dispatch.
            operation: Operation token selecting the handler.

        Returns:
            Typed result carrying the operation's schema conversion value.

        Raises:
            AssertionError: If the operation is unknown.

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

    @override
    def _write_attribute(self, attr_data: m.Ldif.SchemaAttribute) -> p.Result[str]:
        """Write attribute data to the RFC-compliant string format (internal).

        Args:
            attr_data: Canonical attribute model to serialize.

        Raises:
            NotImplementedError: Always; concrete server flavors must override.

        """
        del attr_data
        msg = "Schema servers must implement _write_attribute"
        raise NotImplementedError(msg)

    @override
    def _write_objectclass(self, oc_data: m.Ldif.SchemaObjectClass) -> p.Result[str]:
        """Write objectClass data to the RFC-compliant string format (internal).

        Args:
            oc_data: Canonical objectClass model to serialize.

        Raises:
            NotImplementedError: Always; concrete server flavors must override.

        """
        del oc_data
        msg = "Schema servers must implement _write_objectclass"
        raise NotImplementedError(msg)

    @override
    def _transform_attribute_for_write(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> m.Ldif.SchemaAttribute:
        """Transform an attribute before writing.

        Args:
            attr_data: Canonical attribute model pending write.

        Raises:
            NotImplementedError: Always; concrete server flavors must override.

        """
        del attr_data
        msg = "Schema servers must implement _transform_attribute_for_write"
        raise NotImplementedError(msg)

    @override
    def _transform_objectclass_for_write(
        self,
        oc_data: m.Ldif.SchemaObjectClass,
    ) -> m.Ldif.SchemaObjectClass:
        """Transform an objectClass before writing.

        Args:
            oc_data: Canonical objectClass model pending write.

        Raises:
            NotImplementedError: Always; concrete server flavors must override.

        """
        del oc_data
        msg = "Schema servers must implement _transform_objectclass_for_write"
        raise NotImplementedError(msg)


__all__: list[str] = ["FlextLdifServersBaseSchema"]
