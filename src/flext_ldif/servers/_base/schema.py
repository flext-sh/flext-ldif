"""Base Quirk Classes for LDIF/LDAP Server Extensions."""

from __future__ import annotations

import struct
from collections.abc import Mapping, MutableMapping, MutableSequence
from typing import Annotated, ClassVar, Self, override

from pydantic import Field

from flext_core import FlextLogger, r, s
from flext_ldif import (
    FlextLdifQuirkMethodsMixin,
    FlextLdifUtilitiesMetadata,
    FlextLdifUtilitiesOID,
    FlextLdifUtilitiesParser,
    FlextLdifUtilitiesSchema,
    c,
    m,
    p,
    t,
)

logger = FlextLogger(__name__)


class FlextLdifServersBaseSchema(
    FlextLdifQuirkMethodsMixin,
    s[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str],
):
    """Base class for schema quirks - s V2 with enhanced usability."""

    server_type: str = Field(
        default="rfc",
        description="Server type identifier (e.g., 'oid', 'oud', 'openldap', 'rfc')",
    )
    priority: int = Field(
        default=0,
        description="Quirk priority (lower number = higher priority)",
    )
    parent_quirk: Annotated[
        Self | None,
        Field(
            exclude=True,
            repr=False,
            description="Reference to parent quirk instance for server-level access",
        ),
    ] = None
    attr_definition: Annotated[
        str | None,
        Field(
            exclude=True,
            repr=False,
            description="Attribute definition for auto-execute pattern",
        ),
    ] = None
    oc_definition: Annotated[
        str | None,
        Field(
            exclude=True,
            repr=False,
            description="ObjectClass definition for auto-execute pattern",
        ),
    ] = None
    attr_model: Annotated[
        m.Ldif.SchemaAttribute | None,
        Field(
            exclude=True,
            repr=False,
            description="SchemaAttribute model for auto-execute pattern",
        ),
    ] = None
    oc_model: Annotated[
        m.Ldif.SchemaObjectClass | None,
        Field(
            exclude=True,
            repr=False,
            description="SchemaObjectClass model for auto-execute pattern",
        ),
    ] = None
    operation: Annotated[
        str | None,
        Field(
            exclude=True,
            repr=False,
            description="Operation type for auto-execute pattern",
        ),
    ] = None

    def __new__(
        cls,
        _schema_service: p.Ldif.SchemaQuirk | None = None,
        _parent_quirk: Self | None = None,
        **kwargs: t.Scalar,
    ) -> Self:
        """Override __new__ to filter _parent_quirk before passing to s."""
        filtered_kwargs = {k: v for k, v in kwargs.items() if k != "_parent_quirk"}
        instance = super().__new__(cls, **filtered_kwargs)
        if _parent_quirk is not None:
            object.__setattr__(instance, "_parent_quirk", _parent_quirk)
        return instance

    def __init__(
        self,
        _schema_service: p.Ldif.SchemaQuirk | None = None,
        _parent_quirk: Self | None = None,
        **kwargs: t.Scalar,
    ) -> None:
        """Initialize schema quirk service with optional DI service injection."""
        filtered_kwargs = {k: v for k, v in kwargs.items() if k != "_parent_quirk"}
        service_kwargs: MutableMapping[
            str,
            t.Scalar | t.ConfigMap | MutableSequence[t.Scalar],
        ] = {}
        for key, value in filtered_kwargs.items():
            if isinstance(value, t.SCALAR_TYPES):
                service_kwargs[key] = value
                continue
            if isinstance(value, t.ConfigMap):
                service_kwargs[key] = value
        super().__init__()
        self._schema_service = _schema_service
        if _parent_quirk is not None:
            object.__setattr__(self, "_parent_quirk", _parent_quirk)

    auto_execute: ClassVar[bool] = False

    @staticmethod
    def _extract_metadata_extensions(
        attr_definition: str,
    ) -> t.Ldif.SchemaExtensionsMapping:
        """Extract metadata extensions from attribute definition."""
        parser_util = FlextLdifUtilitiesParser
        extract_method = getattr(parser_util, "extract_extensions", None)
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
        metadata: m.Ldif.QuirkMetadata,
        attr_definition: str,
    ) -> None:
        """Preserve schema formatting via FlextLdifUtilities.Metadata."""
        metadata_util = FlextLdifUtilitiesMetadata
        preserve_method = getattr(metadata_util, "preserve_schema_formatting", None)
        if preserve_method is not None and callable(preserve_method):
            _ = preserve_method(metadata, attr_definition)

    @staticmethod
    def _resolve_quirk_type(server_type: str | None) -> c.Ldif.ServerTypes:
        """Resolve server type to valid StrEnum, defaulting to GENERIC."""
        if not server_type:
            return c.Ldif.ServerTypes.RFC
        type_map: MutableMapping[str, c.Ldif.ServerTypes] = {
            "rfc": c.Ldif.ServerTypes.RFC,
            "oid": c.Ldif.ServerTypes.OID,
            "oud": c.Ldif.ServerTypes.OUD,
            "openldap": c.Ldif.ServerTypes.OPENLDAP,
            "openldap1": c.Ldif.ServerTypes.OPENLDAP1,
            "openldap2": c.Ldif.ServerTypes.OPENLDAP2,
            "ds389": c.Ldif.ServerTypes.DS389,
            "apache": c.Ldif.ServerTypes.APACHE,
            "ad": c.Ldif.ServerTypes.AD,
            "novell": c.Ldif.ServerTypes.NOVELL,
            "ibm_tivoli": c.Ldif.ServerTypes.IBM_TIVOLI,
            "relaxed": c.Ldif.ServerTypes.RELAXED,
            "generic": c.Ldif.ServerTypes.GENERIC,
        }
        return type_map.get(server_type.lower(), c.Ldif.ServerTypes.RFC)

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
    ) -> m.Ldif.QuirkMetadata | None:
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
        quirk_type = FlextLdifServersBaseSchema._resolve_quirk_type(server_type)
        metadata_extensions[c.Ldif.SCHEMA_SOURCE_SERVER] = quirk_type.value
        extensions_typed: t.MutableContainerMapping = {}
        for key, val in metadata_extensions.items():
            if isinstance(val, list):
                list_typed: t.NormalizedValue = list(val)
                extensions_typed[key] = list_typed
            elif val is not None:
                extensions_typed[key] = val
        metadata = m.Ldif.QuirkMetadata(
            quirk_type=quirk_type,
            extensions=m.Ldif.DynamicMetadata.from_dict(
                extensions_typed,
            )
            if extensions_typed
            else m.Ldif.DynamicMetadata(),
            original_server_type=quirk_type,
            target_server_type=quirk_type,
        )
        FlextLdifServersBaseSchema._preserve_formatting(metadata, attr_definition)
        preview_len = 100
        logger.debug(
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
            MutableSequence[str] | str | bool | None,
        ],
        oid_value: str | None,
        oid_name: str,
    ) -> None:
        """Validate OID and track result in metadata extensions."""
        if not oid_value:
            return
        oid_util = FlextLdifUtilitiesOID
        oid_validate_result: r[bool]
        validate_method = getattr(oid_util, "validate_format", None)
        if validate_method is not None and callable(validate_method):
            validate_result_raw = validate_method(oid_value)
            if isinstance(validate_result_raw, r):
                if validate_result_raw.failure:
                    oid_validate_result = r[bool].fail(validate_result_raw.error)
                else:
                    oid_validate_result = r[bool].ok(True)
            else:
                oid_validate_result = r[bool].ok(bool(validate_result_raw))
        else:
            oid_validate_result = r[bool].ok(True)
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
        """Check if this quirk can handle the attribute definition."""
        _ = attr_definition
        return False

    def can_handle_objectclass(
        self,
        oc_definition: str | m.Ldif.SchemaObjectClass,
    ) -> bool:
        """Check if this quirk can handle the objectClass definition."""
        _ = oc_definition
        return False

    @override
    def execute(
        self,
        *,
        data: str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | None = None,
        operation: str | None = None,
        **kwargs: t.Scalar,
    ) -> r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str]:
        """Execute schema operation with auto-detection: str→parse, Model→write."""
        if data is None:
            data_raw = kwargs.get("data")
            if data_raw is not None:
                try:
                    if isinstance(data_raw, str):
                        data = data_raw
                    else:
                        try:
                            data = m.Ldif.SchemaAttribute.model_validate(data_raw)
                        except (
                            ValueError,
                            KeyError,
                            AttributeError,
                            UnicodeDecodeError,
                            struct.error,
                        ):
                            data = m.Ldif.SchemaObjectClass.model_validate(data_raw)
                except (
                    ValueError,
                    KeyError,
                    AttributeError,
                    UnicodeDecodeError,
                    struct.error,
                ):
                    data = None
        if operation is None:
            operation_raw = kwargs.get("operation")
            operation_typed: str | None = None
            if isinstance(operation_raw, str):
                if operation_raw == "parse":
                    operation_typed = "parse"
                elif operation_raw == "write":
                    operation_typed = "write"
            operation = operation_typed
        if data is None:
            empty_str: str = ""
            return r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str].ok(
                empty_str,
            )
        operation_final: str | None = None
        if isinstance(operation, str) and operation in {"parse", "write"}:
            operation_final = "parse" if operation == "parse" else "write"
        detected_op = self._auto_detect_operation(data, operation_final)
        return self._route_operation(data, detected_op)

    def parse_quirk(
        self,
        value: str,
    ) -> r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass]:
        """Parse schema definition (attribute or objectClass)."""
        return self.route_parse(value)

    def parse_input(
        self,
        schema_text: str,
    ) -> r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass]:
        """Compatibility parser entrypoint for direct schema quirk consumers."""
        return self.parse_quirk(schema_text)

    def parse_attribute(self, definition: str) -> r[m.Ldif.SchemaAttribute]:
        """Parse attribute definition (public API)."""
        return self._parse_attribute(definition)

    def parse_objectclass(self, definition: str) -> r[m.Ldif.SchemaObjectClass]:
        """Parse objectClass definition (public API)."""
        return self._parse_objectclass(definition)

    def route_parse(
        self,
        definition: str,
    ) -> r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass]:
        """Route schema definition to appropriate parse method."""
        schema_util = FlextLdifUtilitiesSchema
        detect_method = getattr(schema_util, "detect_schema_type", None)
        if detect_method is not None and callable(detect_method):
            schema_type = detect_method(definition)
        else:
            schema_type = "attribute"
        if schema_type == "objectclass":
            oc_result = self._parse_objectclass(definition)
            if oc_result.failure:
                return r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass].fail(
                    oc_result.error or "Parse failed",
                )
            return r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass].ok(
                oc_result.value,
            )
        attr_result = self._parse_attribute(definition)
        if attr_result.failure:
            return r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass].fail(
                attr_result.error or "Parse failed",
            )
        return r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass].ok(
            attr_result.value,
        )

    def write(
        self,
        model: p.Ldif.SchemaAttribute | p.Ldif.SchemaObjectClass,
    ) -> r[str]:
        """Write schema model to string format."""
        try:
            attribute_model = m.Ldif.SchemaAttribute.model_validate(model)
        except (ValueError, TypeError, AttributeError):
            objectclass_model = m.Ldif.SchemaObjectClass.model_validate(model)
            return self.write_objectclass(objectclass_model)
        return self.write_attribute(attribute_model)

    def write_attribute(self, attr_data: p.Ldif.SchemaAttribute) -> r[str]:
        """Write attribute to RFC-compliant string format (public API)."""
        validated_attr = m.Ldif.SchemaAttribute.model_validate(attr_data)
        return self._write_attribute(validated_attr)

    def write_objectclass(self, oc_data: p.Ldif.SchemaObjectClass) -> r[str]:
        """Write objectClass to RFC-compliant string format (public API)."""
        validated_oc = m.Ldif.SchemaObjectClass.model_validate(oc_data)
        return self._write_objectclass(validated_oc)

    def _auto_detect_operation(
        self,
        data: str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
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
    ) -> r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str]:
        """Handle parse operation for schema quirk."""
        if attr_definition:
            attr_result = self.parse_attribute(attr_definition)
            if attr_result.success:
                parsed_attr: m.Ldif.SchemaAttribute = attr_result.value
                return r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str].ok(
                    parsed_attr,
                )
            error_msg: str = attr_result.error or "Parse attribute failed"
            return r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str].fail(
                error_msg,
            )
        if oc_definition:
            oc_result = self.parse_objectclass(oc_definition)
            if oc_result.success:
                parsed_oc: m.Ldif.SchemaObjectClass = oc_result.value
                return r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str].ok(
                    parsed_oc,
                )
            error_msg = oc_result.error or "Parse objectclass failed"
            return r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str].fail(
                error_msg,
            )
        return r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str].fail(
            "No parse parameter provided",
        )

    def _handle_write_operation(
        self,
        attr_model: m.Ldif.SchemaAttribute | None,
        oc_model: m.Ldif.SchemaObjectClass | None,
    ) -> r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str]:
        """Handle write operation for schema quirk."""
        if attr_model:
            write_result = self.write_attribute(attr_model)
            if write_result.success:
                written_text: str = write_result.value
                return r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str].ok(
                    written_text,
                )
            error_msg: str = write_result.error or "Write attribute failed"
            return r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str].fail(
                error_msg,
            )
        if oc_model:
            write_oc_result = self.write_objectclass(oc_model)
            if write_oc_result.success:
                written_text = write_oc_result.value
                return r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str].ok(
                    written_text,
                )
            error_msg = write_oc_result.error or "Write objectclass failed"
            return r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str].fail(
                error_msg,
            )
        return r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str].fail(
            "No write parameter provided",
        )

    def _hook_post_parse_attribute(
        self,
        attr: m.Ldif.SchemaAttribute,
    ) -> r[m.Ldif.SchemaAttribute]:
        """Hook called after parsing an attribute definition."""
        return r[m.Ldif.SchemaAttribute].ok(attr)

    def _hook_post_parse_objectclass(
        self,
        oc: m.Ldif.SchemaObjectClass,
    ) -> r[m.Ldif.SchemaObjectClass]:
        """Hook called after parsing an objectClass definition."""
        return r[m.Ldif.SchemaObjectClass].ok(oc)

    def _hook_validate_attributes(
        self,
        attributes: MutableSequence[m.Ldif.SchemaAttribute],
        available_attrs: set[str],
    ) -> r[bool]:
        """Hook for server-specific attribute validation during schema extraction."""
        _ = attributes
        _ = available_attrs
        return r[bool].ok(value=True)

    def _parse_attribute(self, attr_definition: str) -> r[m.Ldif.SchemaAttribute]:
        """Parse server-specific attribute definition (internal)."""
        del attr_definition
        return r[m.Ldif.SchemaAttribute].fail("Must be implemented by subclass")

    def _parse_objectclass(self, oc_definition: str) -> r[m.Ldif.SchemaObjectClass]:
        """Parse server-specific objectClass definition (internal)."""
        _ = oc_definition
        return r[m.Ldif.SchemaObjectClass].fail("Must be implemented by subclass")

    def _route_operation(
        self,
        data: str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        operation: str,
    ) -> r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str]:
        """Route data to appropriate parse or write handler."""
        if operation == "parse":
            if not isinstance(data, str):
                return r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str].fail(
                    f"parse operation requires str, got {type(data).__name__}",
                )
            schema_util = FlextLdifUtilitiesSchema
            detect_method = getattr(schema_util, "detect_schema_type", None)
            if detect_method is not None and callable(detect_method):
                schema_type = detect_method(data)
            else:
                schema_type = "attribute"
            if schema_type == "objectClass":
                return self._handle_parse_operation(
                    attr_definition=None,
                    oc_definition=data,
                )
            return self._handle_parse_operation(
                attr_definition=data,
                oc_definition=None,
            )
        if operation == "write":
            try:
                attr_model = m.Ldif.SchemaAttribute.model_validate(data)
            except (
                ValueError,
                KeyError,
                AttributeError,
                UnicodeDecodeError,
                struct.error,
            ):
                attr_model = None
            if attr_model is not None:
                return self._handle_write_operation(
                    attr_model=attr_model,
                    oc_model=None,
                )
            try:
                oc_model = m.Ldif.SchemaObjectClass.model_validate(data)
            except (
                ValueError,
                KeyError,
                AttributeError,
                UnicodeDecodeError,
                struct.error,
            ):
                oc_model = None
            if oc_model is not None:
                return self._handle_write_operation(attr_model=None, oc_model=oc_model)
            return r[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str].fail(
                f"write operation requires SchemaAttribute or SchemaObjectClass, got {type(data).__name__}",
            )
        msg = f"Unknown operation: {operation}"
        raise AssertionError(msg)

    def _write_attribute(self, attr_data: m.Ldif.SchemaAttribute) -> r[str]:
        """Write attribute data to RFC-compliant string format (internal)."""
        _ = attr_data
        return r[str].fail("Must be implemented by subclass")

    def _write_objectclass(self, oc_data: m.Ldif.SchemaObjectClass) -> r[str]:
        """Write objectClass data to RFC-compliant string format (internal)."""
        _ = oc_data
        return r[str].fail("Must be implemented by subclass")
