"""Base Server Classes for LDIF/LDAP Server Extensions."""

from __future__ import annotations

import struct
from collections.abc import (
    Mapping,
    MutableMapping,
)
from typing import Annotated, ClassVar, Self, override

from flext_ldif import (
    c,
    m,
    p,
    r,
    s,
    t,
    u,
)
from flext_ldif.servers._base.mixins import FlextLdifServerMethodsMixin


class FlextLdifServersBaseSchema(
    s[t.Ldif.SchemaConversionValue],
    FlextLdifServerMethodsMixin,
):
    """Base class for schema servers using `s` with enhanced usability."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    server_type: Annotated[
        str,
        u.Field(
            description="Server type identifier (e.g., 'oid', 'oud', 'openldap', 'rfc')",
        ),
    ] = "rfc"
    priority: Annotated[
        int,
        u.Field(
            description="Server priority (lower number = higher priority)",
        ),
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
        _parent_server: Self | None = None,
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
        _parent_server: Self | None = None,
        **kwargs: t.Ldif.Scalar,
    ) -> None:
        """Initialize schema server service with optional DI service injection."""
        filtered_kwargs = {k: v for k, v in kwargs.items() if k != "_parent_server"}
        service_kwargs: MutableMapping[str, t.Ldif.Scalar] = {}
        for key, value in filtered_kwargs.items():
            if isinstance(value, t.SCALAR_TYPES):
                service_kwargs[key] = value
        super().__init__()
        self._schema_service = _schema_service
        if _parent_server is not None:
            object.__setattr__(self, "_parent_server", _parent_server)

    auto_execute: ClassVar[bool] = False

    @staticmethod
    def _extract_metadata_extensions(
        attr_definition: str,
    ) -> t.Ldif.SchemaExtensionsMapping:
        """Extract metadata extensions from attribute definition."""
        extract_method = getattr(u.Ldif, "extract_extensions", None)
        if extract_method is None or not callable(extract_method):
            return {}
        extensions_raw = extract_method(attr_definition)
        if not isinstance(extensions_raw, Mapping):
            return {}
        extensions_map = m.Ldif.DynamicMetadata.model_validate(extensions_raw)
        extracted: t.Ldif.SchemaExtensionsMapping = {}
        for raw_key, raw_value in extensions_map.items():
            if isinstance(raw_value, str | bool):
                extracted[raw_key] = raw_value
                continue
            if isinstance(raw_value, list):
                extracted[raw_key] = [str(item) for item in raw_value]
        return extracted

    @staticmethod
    def _preserve_formatting(
        metadata: m.Ldif.ServerMetadata,
        attr_definition: str,
    ) -> None:
        """Preserve schema formatting via FlextLdifUtilities.Metadata."""
        preserve_method = getattr(u.Ldif, "preserve_schema_formatting", None)
        if preserve_method is not None and callable(preserve_method):
            _ = preserve_method(metadata, attr_definition)

    @staticmethod
    def _resolve_server_type(server_type: str | None) -> c.Ldif.ServerTypes:
        """Resolve server type to valid StrEnum, defaulting to GENERIC."""
        if not server_type:
            return c.Ldif.ServerTypes.RFC
        try:
            normalized: c.Ldif.ServerTypes = u.Ldif.normalize_server_type(server_type)
            return normalized
        except ValueError:
            return c.Ldif.ServerTypes.RFC

    @staticmethod
    def build_attribute_metadata(
        attr_definition: str,
        syntax: str | None,
        syntax_validation_error: str | None,
        attribute_oid: str | None = None,
        equality_oid: str | None = None,
        ordering_oid: str | None = None,
        substr_oid: str | None = None,
        sup_oid: str | None = None,
        server_type: str | None = None,
    ) -> m.Ldif.ServerMetadata | None:
        """Build metadata for attribute including extensions and OID validation."""
        metadata_extensions = FlextLdifServersBaseSchema._extract_metadata_extensions(
            attr_definition,
        )
        if syntax:
            metadata_extensions["syntax_oid_valid"] = syntax_validation_error is None
            if syntax_validation_error:
                metadata_extensions["syntax_validation_error"] = syntax_validation_error
        FlextLdifServersBaseSchema.validate_and_track_oid(
            metadata_extensions,
            attribute_oid,
            "attribute",
        )
        for rule_name, rule_oid in [
            ("equality matching rule", equality_oid),
            ("ordering matching rule", ordering_oid),
            ("substring matching rule", substr_oid),
        ]:
            FlextLdifServersBaseSchema.validate_and_track_oid(
                metadata_extensions,
                rule_oid,
                rule_name,
            )
        FlextLdifServersBaseSchema.validate_and_track_oid(
            metadata_extensions,
            sup_oid,
            "SUP",
        )
        metadata_extensions["original_format"] = attr_definition.strip()
        metadata_extensions["schema_original_string_complete"] = attr_definition
        server_type = FlextLdifServersBaseSchema._resolve_server_type(server_type)
        metadata_extensions[c.Ldif.SCHEMA_SOURCE_SERVER] = server_type.value
        extensions_typed: t.Ldif.MutableMetadataMapping = {}
        for key, val in metadata_extensions.items():
            if val is not None:
                extensions_typed[key] = u.normalize_to_metadata(val)
        metadata = m.Ldif.ServerMetadata(
            server_type=server_type,
            extensions=m.Ldif.DynamicMetadata.from_dict(
                extensions_typed,
            )
            if extensions_typed
            else m.Ldif.DynamicMetadata(),
            original_server_type=server_type,
            target_server_type=server_type,
        )
        FlextLdifServersBaseSchema._preserve_formatting(metadata, attr_definition)
        preview_len = 100
        FlextLdifServersBaseSchema._module_logger.debug(
            "Preserved schema formatting details",
            attr_definition_preview=attr_definition[:preview_len]
            if len(attr_definition) > preview_len
            else attr_definition,
        )
        return (
            metadata if metadata_extensions or metadata.schema_format_details else None
        )

    @staticmethod
    def validate_and_track_oid(
        metadata_extensions: MutableMapping[
            str,
            t.MutableSequenceOf[str] | str | bool | None,
        ],
        oid_value: str | None,
        oid_name: str,
    ) -> None:
        """Validate OID and track result in metadata extensions."""
        if not oid_value:
            return
        oid_validate_result = (
            r[bool]
            .from_result(
                u.Ldif.validate_format(oid_value),
            )
            .map_error(
                lambda error: error or f"{oid_name} OID validation failed",
            )
        )
        if oid_validate_result.failure:
            metadata_extensions["syntax_validation_error"] = (
                f"{oid_name.capitalize()} OID validation failed: {oid_validate_result.error}"
            )
            metadata_extensions["syntax_oid_valid"] = False
        elif not oid_validate_result.value:
            metadata_extensions["syntax_validation_error"] = (
                f"Invalid {oid_name} OID format: {oid_value} (must be numeric dot-separated format)"
            )
            metadata_extensions["syntax_oid_valid"] = False
        else:
            metadata_extensions["syntax_oid_valid"] = True

    def can_handle_attribute(
        self,
        attr_definition: str | m.Ldif.SchemaAttribute,
    ) -> bool:
        """Check if this server can handle the attribute definition."""
        _ = attr_definition
        return False

    def can_handle_objectclass(
        self,
        oc_definition: str | m.Ldif.SchemaObjectClass,
    ) -> bool:
        """Check if this server can handle the objectClass definition."""
        _ = oc_definition
        return False

    @override
    def execute(
        self,
        *,
        data: str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | None = None,
        operation: str | None = None,
        **kwargs: t.Ldif.Scalar,
    ) -> p.Result[t.Ldif.SchemaConversionValue]:
        """Execute schema operation with auto-detection: str→parse, Model→write."""
        json_value_adapter = t.json_value_adapter()
        kwargs_dict: t.MutableJsonMapping = {
            key: json_value_adapter.validate_python(u.to_jsonable_python(value))
            for key, value in kwargs.items()
        }
        resolved_data = self._resolve_data(data, kwargs_dict)
        operation = self._resolve_operation(operation, kwargs_dict)
        if resolved_data is None:
            empty_str: str = ""
            return r[t.Ldif.SchemaConversionValue].ok(
                empty_str,
            )
        operation_final = operation if operation in {"parse", "write"} else None
        detected_op = self._auto_detect_operation(resolved_data, operation_final)
        return self._route_operation(resolved_data, detected_op)

    def _coerce_schema_data(
        self,
        value: str
        | t.JsonValue
        | m.Ldif.SchemaAttribute
        | m.Ldif.SchemaObjectClass
        | None,
    ) -> str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | None:
        """Coerce raw execute payload to the concrete schema payload union."""
        if value is None:
            return None
        if isinstance(value, str):
            return value
        try:
            attribute: m.Ldif.SchemaAttribute = m.Ldif.SchemaAttribute.model_validate(
                value,
            )
            return attribute
        except (
            c.ValidationError,
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ):
            pass
        try:
            objectclass: m.Ldif.SchemaObjectClass = (
                m.Ldif.SchemaObjectClass.model_validate(value)
            )
            return objectclass
        except (
            c.ValidationError,
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ):
            pass
        return None

    def _coerce_operation(self, value: t.Ldif.Scalar | None) -> str | None:
        """Coerce raw operation token to a supported schema operation."""
        if isinstance(value, str) and value in {"parse", "write"}:
            return value
        return None

    def _detect_schema_type(self, definition: str) -> str:
        """Resolve schema type from definition using the shared schema utility."""
        detect_method = getattr(u.Ldif, "detect_schema_type", None)
        if detect_method is not None and callable(detect_method):
            detected_type = detect_method(definition)
            if isinstance(detected_type, str):
                return detected_type
        return c.Ldif.SchemaItemKind.ATTRIBUTE.value

    def _is_objectclass_schema_type(self, definition: str) -> bool:
        """Return whether the schema definition is an objectClass payload."""
        return self._detect_schema_type(definition) == c.Ldif.SchemaItemKind.OBJECTCLASS

    def _coerce_attribute_model(
        self,
        value: t.JsonValue | t.Ldif.SchemaConversionValue,
    ) -> p.Result[m.Ldif.SchemaAttribute]:
        """Coerce raw value to a schema attribute model, propagating failures."""
        try:
            attribute: m.Ldif.SchemaAttribute = m.Ldif.SchemaAttribute.model_validate(
                value,
            )
        except c.Ldif.EXC_LDIF_PARSE as exc:
            return r[m.Ldif.SchemaAttribute].fail(str(exc), exception=exc)
        return r[m.Ldif.SchemaAttribute].ok(attribute)

    def _coerce_objectclass_model(
        self,
        value: t.JsonValue | t.Ldif.SchemaConversionValue,
    ) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Coerce raw value to a schema objectClass model, propagating failures."""
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
        """Resolve schema payload from parameter or kwargs."""
        if data is not None:
            return data
        return self._coerce_schema_data(kwargs.get("data"))

    def _resolve_operation(
        self,
        operation: str | None,
        kwargs: t.JsonMapping,
    ) -> str | None:
        """Resolve schema operation from parameter or kwargs."""
        if operation is not None:
            return self._coerce_operation(operation)
        raw_operation = self._parse_operation_kwarg(kwargs).unwrap_or(None)
        if raw_operation is None:
            return None
        return self._coerce_operation(raw_operation)

    @staticmethod
    def _parse_operation_kwarg(kwargs: t.JsonMapping) -> p.Result[str]:
        """Validate the raw 'operation' kwarg as a string, propagating failures."""
        try:
            raw_operation = t.str_adapter().validate_python(kwargs.get("operation"))
        except c.ValidationError as exc:
            return r[str].fail(str(exc), exception=exc)
        return r[str].ok(raw_operation)

    def parse_server(
        self,
        value: str,
    ) -> p.Result[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass]:
        """Parse schema definition (attribute or objectClass)."""
        return self.route_parse(value)

    def parse_input(
        self,
        schema_text: str,
    ) -> p.Result[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass]:
        """Compatibility parser entrypoint for direct schema server consumers."""
        return self.parse_server(schema_text)

    def parse_attribute(self, definition: str) -> p.Result[m.Ldif.SchemaAttribute]:
        """Parse attribute definition (public API)."""
        return self._parse_attribute(definition)

    def parse_objectclass(self, definition: str) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Parse objectClass definition (public API)."""
        return self._parse_objectclass(definition)

    def route_parse(
        self,
        definition: str,
    ) -> p.Result[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass]:
        """Route schema definition to appropriate parse method."""
        if self._is_objectclass_schema_type(definition):
            oc_result = self._parse_objectclass(definition)
            if oc_result.failure:
                return r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass].fail(
                    oc_result.error or "Parse failed",
                )
            parsed_objectclass = m.Ldif.SchemaObjectClass.model_validate(
                oc_result.unwrap(),
            )
            return r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass].ok(
                parsed_objectclass,
            )
        attr_result = self._parse_attribute(definition)
        if attr_result.failure:
            return r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass].fail(
                attr_result.error or "Parse failed",
            )
        parsed_attribute = m.Ldif.SchemaAttribute.model_validate(
            attr_result.unwrap(),
        )
        return r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass].ok(
            parsed_attribute,
        )

    def write(
        self,
        model: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> p.Result[str]:
        """Write schema model to string format."""
        try:
            attribute_model = m.Ldif.SchemaAttribute.model_validate(model)
        except c.EXC_BASIC_TYPE:
            objectclass_model = m.Ldif.SchemaObjectClass.model_validate(model)
            return self.write_objectclass(objectclass_model)
        return self.write_attribute(attribute_model)

    def write_attribute(self, attr_data: m.Ldif.SchemaAttribute) -> p.Result[str]:
        """Write attribute to RFC-compliant string format (public API)."""
        validated_attr = m.Ldif.SchemaAttribute.model_validate(attr_data)
        return self._write_attribute(validated_attr)

    def write_objectclass(self, oc_data: m.Ldif.SchemaObjectClass) -> p.Result[str]:
        """Write objectClass to RFC-compliant string format (public API)."""
        validated_oc = m.Ldif.SchemaObjectClass.model_validate(oc_data)
        return self._write_objectclass(validated_oc)

    def _auto_detect_operation(
        self,
        data: t.Ldif.SchemaConversionValue,
        operation: str | None,
    ) -> str:
        """Auto-detect operation from data type."""
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
        """Handle parse operation for schema server."""
        if attr_definition:
            attr_result = self.parse_attribute(attr_definition)
            if attr_result.success:
                parsed_attr = m.Ldif.SchemaAttribute.model_validate(
                    attr_result.unwrap(),
                )
                return r[t.Ldif.SchemaConversionValue].ok(
                    parsed_attr,
                )
            error_msg: str = attr_result.error or "Parse attribute failed"
            return r[t.Ldif.SchemaConversionValue].fail(
                error_msg,
            )
        if oc_definition:
            oc_result = self.parse_objectclass(oc_definition)
            if oc_result.success:
                parsed_oc = m.Ldif.SchemaObjectClass.model_validate(
                    oc_result.unwrap(),
                )
                return r[t.Ldif.SchemaConversionValue].ok(
                    parsed_oc,
                )
            error_msg = oc_result.error or "Parse objectclass failed"
            return r[t.Ldif.SchemaConversionValue].fail(
                error_msg,
            )
        return r[t.Ldif.SchemaConversionValue].fail(
            "No parse parameter provided",
        )

    def _handle_write_operation(
        self,
        attr_model: m.Ldif.SchemaAttribute | None,
        oc_model: m.Ldif.SchemaObjectClass | None,
    ) -> p.Result[t.Ldif.SchemaConversionValue]:
        """Handle write operation for schema server."""
        if attr_model:
            write_result = self.write_attribute(attr_model)
            if write_result.success:
                written_text = write_result.unwrap()
                return r[t.Ldif.SchemaConversionValue].ok(
                    written_text,
                )
            error_msg: str = write_result.error or "Write attribute failed"
            return r[t.Ldif.SchemaConversionValue].fail(
                error_msg,
            )
        if oc_model:
            write_oc_result = self.write_objectclass(oc_model)
            if write_oc_result.success:
                written_text = write_oc_result.unwrap()
                return r[t.Ldif.SchemaConversionValue].ok(
                    written_text,
                )
            error_msg = write_oc_result.error or "Write objectclass failed"
            return r[t.Ldif.SchemaConversionValue].fail(
                error_msg,
            )
        return r[t.Ldif.SchemaConversionValue].fail(
            "No write parameter provided",
        )

    def _hook_post_parse_attribute(
        self,
        attr: m.Ldif.SchemaAttribute,
    ) -> p.Result[m.Ldif.SchemaAttribute]:
        """Hook called after parsing an attribute definition."""
        return r[m.Ldif.SchemaAttribute].ok(attr)

    def _hook_post_parse_objectclass(
        self,
        oc: m.Ldif.SchemaObjectClass,
    ) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Hook called after parsing an objectClass definition."""
        return r[m.Ldif.SchemaObjectClass].ok(oc)

    def _hook_validate_attributes(
        self,
        attributes: t.MutableSequenceOf[m.Ldif.SchemaAttribute],
        available_attrs: set[str],
    ) -> p.Result[bool]:
        """Hook for server-specific attribute validation during schema extraction."""
        _ = attributes
        _ = available_attrs
        return r[bool].ok(value=True)

    def _parse_attribute(
        self,
        attr_definition: str,
    ) -> p.Result[m.Ldif.SchemaAttribute]:
        """Parse server-specific attribute definition (internal)."""
        del attr_definition
        return r[m.Ldif.SchemaAttribute].fail("Must be implemented by subclass")

    def _parse_objectclass(
        self,
        oc_definition: str,
    ) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Parse server-specific objectClass definition (internal)."""
        _ = oc_definition
        return r[m.Ldif.SchemaObjectClass].fail("Must be implemented by subclass")

    def _route_operation(
        self,
        data: str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        operation: str,
    ) -> p.Result[t.Ldif.SchemaConversionValue]:
        """Route data to appropriate parse or write handler."""
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
            attr_model = self._coerce_attribute_model(data).unwrap_or(None)
            if attr_model is not None:
                result = self._handle_write_operation(
                    attr_model=attr_model,
                    oc_model=None,
                )
            else:
                oc_model = self._coerce_objectclass_model(data).unwrap_or(None)
                if oc_model is not None:
                    result = self._handle_write_operation(
                        attr_model=None,
                        oc_model=oc_model,
                    )
                else:
                    result = r[t.Ldif.SchemaConversionValue].fail(
                        f"write operation requires SchemaAttribute or SchemaObjectClass, got {type(data).__name__}",
                    )
        else:
            msg = f"Unknown operation: {operation}"
            raise AssertionError(msg)
        return result

    def _write_attribute(self, attr_data: m.Ldif.SchemaAttribute) -> p.Result[str]:
        """Write attribute data to RFC-compliant string format (internal)."""
        _ = attr_data
        return r[str].fail("Must be implemented by subclass")

    def _write_objectclass(self, oc_data: m.Ldif.SchemaObjectClass) -> p.Result[str]:
        """Write objectClass data to RFC-compliant string format (internal)."""
        _ = oc_data
        return r[str].fail("Must be implemented by subclass")
