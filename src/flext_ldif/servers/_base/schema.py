"""Base Quirk Classes for LDIF/LDAP Server Extensions."""

from __future__ import annotations

from typing import ClassVar, Self

from flext_core import FlextLogger, FlextResult, FlextService, FlextTypes
from pydantic import Field

from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
from flext_ldif._utilities.oid import FlextLdifUtilitiesOID
from flext_ldif._utilities.parser import FlextLdifUtilitiesParser
from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.servers._base.constants import QuirkMethodsMixin
from flext_ldif.typings import t

logger = FlextLogger(__name__)


class FlextLdifServersBaseSchema(
    QuirkMethodsMixin,
    FlextService[(m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)],
):
    """Base class for schema quirks - FlextService V2 with enhanced usability."""

    server_type: str = "rfc"
    """Server type identifier (e.g., 'oid', 'oud', 'openldap', 'rfc')."""

    priority: int = 0
    """Quirk priority (lower number = higher priority).

        **STANDARDIZED CONSTANTS REQUIRED**: Each Schema implementation MUST define
        a Constants nested class with:
        - CANONICAL_NAME: Unique server identifier (e.g., "oid", "oud")
        - ALIASES: All valid names for this server including canonical
        - PRIORITY: Selection priority (lower = higher priority)
        - CAN_NORMALIZE_FROM: What source types this quirk can normalize
        - CAN_DENORMALIZE_TO: What target types this quirk can denormalize to

        **Protocol Compliance**: All implementations MUST satisfy
        p.Ldif.SchemaQuirkProtocol through structural typing.
        This means all public methods must match protocol signatures exactly.

        **Validation**: Use hasattr(quirk, "parse") and hasattr(quirk, "write")
        to check protocol compliance at runtime (structural typing).

        Common schema extension patterns:
        - Vendor-specific prefixes (e.g., vendor prefix + attribute name)
        - Enhanced schema features beyond RFC baseline
        - Configuration-specific attributes
        - Vendor-specific schema extensions
        - RFC 4512 compliant baseline (no extensions)
        """

    parent_quirk: object | None = Field(
        default=None,
        exclude=True,
        repr=False,
        description=("Reference to parent quirk instance for server-level access"),
    )

    attr_definition: str | None = Field(
        default=None,
        exclude=True,
        repr=False,
        description="Attribute definition for auto-execute pattern",
    )
    oc_definition: str | None = Field(
        default=None,
        exclude=True,
        repr=False,
        description="ObjectClass definition for auto-execute pattern",
    )
    attr_model: object | None = Field(
        default=None,
        exclude=True,
        repr=False,
        description="SchemaAttribute model for auto-execute pattern",
    )
    oc_model: object | None = Field(
        default=None,
        exclude=True,
        repr=False,
        description="SchemaObjectClass model for auto-execute pattern",
    )
    operation: str | None = Field(
        default=None,
        exclude=True,
        repr=False,
        description="Operation type for auto-execute pattern",
    )

    def __new__(
        cls,
        _schema_service: object | None = None,
        _parent_quirk: object | None = None,
        **kwargs: FlextTypes.GeneralValueType,
    ) -> Self:
        """Override __new__ to filter _parent_quirk before passing to FlextService."""
        filtered_kwargs = {k: v for k, v in kwargs.items() if k != "_parent_quirk"}

        instance = super().__new__(cls, **filtered_kwargs)

        if _parent_quirk is not None:
            object.__setattr__(instance, "_parent_quirk", _parent_quirk)

        return instance

    def __init__(
        self,
        _schema_service: object | None = None,
        _parent_quirk: object | None = None,
        **kwargs: FlextTypes.GeneralValueType,
    ) -> None:
        """Initialize schema quirk service with optional DI service injection."""
        filtered_kwargs = {k: v for k, v in kwargs.items() if k != "_parent_quirk"}
        super().__init__(**filtered_kwargs)
        self._schema_service = _schema_service

        if _parent_quirk is not None:
            object.__setattr__(self, "_parent_quirk", _parent_quirk)

    auto_execute: ClassVar[bool] = False

    def _parse_attribute(
        self,
        attr_definition: str,
    ) -> FlextResult[m.Ldif.SchemaAttribute]:
        """Parse server-specific attribute definition (internal)."""
        del attr_definition
        return FlextResult.fail("Must be implemented by subclass")

    def _parse_objectclass(
        self,
        oc_definition: str,
    ) -> FlextResult[m.Ldif.SchemaObjectClass]:
        """Parse server-specific objectClass definition (internal)."""
        _ = oc_definition
        return FlextResult.fail("Must be implemented by subclass")

    def _hook_post_parse_attribute(
        self,
        attr: m.Ldif.SchemaAttribute,
    ) -> FlextResult[m.Ldif.SchemaAttribute]:
        """Hook called after parsing an attribute definition."""
        return FlextResult.ok(attr)

    def _hook_post_parse_objectclass(
        self,
        oc: m.Ldif.SchemaObjectClass,
    ) -> FlextResult[m.Ldif.SchemaObjectClass]:
        """Hook called after parsing an objectClass definition."""
        return FlextResult.ok(oc)

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

    def parse_attribute(
        self,
        attr_definition: str,
    ) -> FlextResult[m.Ldif.SchemaAttribute]:
        """Parse attribute definition (public API)."""
        return self._parse_attribute(attr_definition)

    def parse_objectclass(
        self,
        oc_definition: str,
    ) -> FlextResult[m.Ldif.SchemaObjectClass]:
        """Parse objectClass definition (public API)."""
        return self._parse_objectclass(oc_definition)

    def route_parse(
        self,
        definition: str,
    ) -> FlextResult[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass]:
        """Route schema definition to appropriate parse method."""
        schema_util = FlextLdifUtilitiesSchema
        if schema_util is not None:
            detect_method = getattr(schema_util, "detect_schema_type", None)
            if detect_method is not None and callable(detect_method):
                schema_type = detect_method(definition)
            else:
                schema_type = "attribute"
        else:
            schema_type = "attribute"
        if schema_type == "objectclass":
            oc_result = self._parse_objectclass(definition)
            if oc_result.is_failure:
                return FlextResult[
                    (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass)
                ].fail(
                    oc_result.error or "Parse failed",
                )
            return FlextResult[(m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass)].ok(
                oc_result.value,
            )
        attr_result = self._parse_attribute(definition)
        if attr_result.is_failure:
            return FlextResult[
                (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass)
            ].fail(
                attr_result.error or "Parse failed",
            )
        return FlextResult[(m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass)].ok(
            attr_result.value,
        )

    def parse(
        self,
        definition: str,
    ) -> FlextResult[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass]:
        """Parse schema definition (attribute or objectClass)."""
        return self.route_parse(definition)

    def write_attribute(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> FlextResult[str]:
        """Write attribute to RFC-compliant string format (public API)."""
        return self._write_attribute(attr_data)

    def write_objectclass(
        self,
        oc_data: m.Ldif.SchemaObjectClass,
    ) -> FlextResult[str]:
        """Write objectClass to RFC-compliant string format (public API)."""
        return self._write_objectclass(oc_data)

    def _write_attribute(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> FlextResult[str]:
        """Write attribute data to RFC-compliant string format (internal)."""
        _ = attr_data
        return FlextResult.fail(
            "Must be implemented by subclass",
        )

    def _write_objectclass(
        self,
        oc_data: m.Ldif.SchemaObjectClass,
    ) -> FlextResult[str]:
        """Write objectClass data to RFC-compliant string format (internal)."""
        _ = oc_data
        return FlextResult.fail("Must be implemented by subclass")

    def _hook_validate_attributes(
        self,
        attributes: list[m.Ldif.SchemaAttribute],
        available_attrs: set[str],
    ) -> FlextResult[bool]:
        """Hook for server-specific attribute validation during schema extraction."""
        _ = attributes
        _ = available_attrs
        return FlextResult[bool].ok(True)

    @staticmethod
    def validate_and_track_oid(
        metadata_extensions: dict[str, list[str] | str | bool | None],
        oid_value: str | None,
        oid_name: str,
    ) -> None:
        """Validate OID and track result in metadata extensions."""
        if not oid_value:
            return

        oid_util = FlextLdifUtilitiesOID
        oid_validate_result: FlextResult[bool]
        if oid_util is not None:
            validate_method = getattr(oid_util, "validate_format", None)
            if validate_method is not None and callable(validate_method):
                validate_result_raw = validate_method(oid_value)

                if isinstance(validate_result_raw, FlextResult):
                    oid_validate_result = validate_result_raw
                else:
                    oid_validate_result = FlextResult.ok(bool(validate_result_raw))
            else:
                oid_validate_result = FlextResult.ok(True)
        else:
            oid_validate_result = FlextResult.ok(True)
        if oid_validate_result.is_failure:
            metadata_extensions["syntax_validation_error"] = (
                f"{oid_name.capitalize()} OID validation failed: {oid_validate_result.error}"
            )
            metadata_extensions["syntax_oid_valid"] = False
        elif not oid_validate_result.value:
            metadata_extensions["syntax_validation_error"] = (
                f"Invalid {oid_name} OID format: {oid_value} "
                f"(must be numeric dot-separated format)"
            )
            metadata_extensions["syntax_oid_valid"] = False
        else:
            metadata_extensions["syntax_oid_valid"] = True

    @staticmethod
    def _extract_metadata_extensions(
        attr_definition: str,
    ) -> dict[str, list[str] | str | bool | None]:
        """Extract metadata extensions from attribute definition."""
        parser_util = FlextLdifUtilitiesParser
        if parser_util is not None:
            return {}
        extract_method = getattr(parser_util, "extract_extensions", None)
        if extract_method is None or not callable(extract_method):
            return {}
        extensions_raw = extract_method(attr_definition)
        if isinstance(extensions_raw, dict):
            return {
                k: v
                for k, v in extensions_raw.items()
                if isinstance(k, str)
                and (isinstance(v, (str, bool, list)) or v is None)
            }
        return {}

    @staticmethod
    def _resolve_quirk_type(
        server_type: str | None,
    ) -> c.Ldif.ServerTypes:
        """Resolve server type to valid StrEnum, defaulting to GENERIC."""
        if not server_type:
            return c.Ldif.ServerTypes.RFC

        type_map: dict[str, c.Ldif.ServerTypes] = {
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
    def _preserve_formatting(
        metadata: m.Ldif.QuirkMetadata,
        attr_definition: str,
    ) -> None:
        """Preserve schema formatting via FlextLdifUtilities.Metadata."""
        metadata_util = FlextLdifUtilitiesMetadata
        if metadata_util is None:
            return
        preserve_method = getattr(metadata_util, "preserve_schema_formatting", None)
        if preserve_method is not None and callable(preserve_method):
            _ = preserve_method(metadata, attr_definition)

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

        extensions_typed: dict[str, t.MetadataAttributeValue] = {}
        for key, val in metadata_extensions.items():
            if isinstance(val, list):
                list_typed: t.MetadataAttributeValue = list(val)
                extensions_typed[key] = list_typed
            else:
                extensions_typed[key] = val
        metadata = m.Ldif.QuirkMetadata(
            quirk_type=quirk_type,
            extensions=FlextLdifModelsMetadata.DynamicMetadata.from_dict(
                extensions_typed
            )
            if extensions_typed
            else FlextLdifModelsMetadata.DynamicMetadata(),
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

    def _handle_parse_operation(
        self,
        attr_definition: str | None,
        oc_definition: str | None,
    ) -> FlextResult[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str]:
        """Handle parse operation for schema quirk."""
        if attr_definition:
            attr_result = self.parse_attribute(attr_definition)
            if attr_result.is_success:
                parsed_attr: m.Ldif.SchemaAttribute = attr_result.value
                return FlextResult[
                    (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)
                ].ok(
                    parsed_attr,
                )
            error_msg: str = attr_result.error or "Parse attribute failed"
            return FlextResult[
                (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)
            ].fail(
                error_msg,
            )
        if oc_definition:
            oc_result = self.parse_objectclass(oc_definition)
            if oc_result.is_success:
                parsed_oc: m.Ldif.SchemaObjectClass = oc_result.value
                return FlextResult[
                    (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)
                ].ok(
                    parsed_oc,
                )
            error_msg = oc_result.error or "Parse objectclass failed"
            return FlextResult[
                (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)
            ].fail(
                error_msg,
            )
        return FlextResult[
            (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)
        ].fail(
            "No parse parameter provided",
        )

    def _handle_write_operation(
        self,
        attr_model: m.Ldif.SchemaAttribute | None,
        oc_model: m.Ldif.SchemaObjectClass | None,
    ) -> FlextResult[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str]:
        """Handle write operation for schema quirk."""
        if attr_model:
            write_result = self.write_attribute(attr_model)
            if write_result.is_success:
                written_text: str = write_result.value
                return FlextResult[
                    (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)
                ].ok(
                    written_text,
                )
            error_msg: str = write_result.error or "Write attribute failed"
            return FlextResult[
                (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)
            ].fail(
                error_msg,
            )
        if oc_model:
            write_oc_result = self.write_objectclass(oc_model)
            if write_oc_result.is_success:
                written_text = write_oc_result.value
                return FlextResult[
                    (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)
                ].ok(
                    written_text,
                )
            error_msg = write_oc_result.error or "Write objectclass failed"
            return FlextResult[
                (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)
            ].fail(
                error_msg,
            )
        return FlextResult[
            (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)
        ].fail(
            "No write parameter provided",
        )

    def _auto_detect_operation(
        self,
        data: (str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass),
        operation: str | None,
    ) -> str | FlextResult[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str]:
        """Auto-detect operation from data type."""
        if operation is not None:
            return operation

        if isinstance(data, str):
            return "parse"

        return "write"

    def _route_operation(
        self,
        data: (str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass),
        operation: str,
    ) -> FlextResult[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str]:
        """Route data to appropriate parse or write handler."""
        if operation == "parse":
            if not isinstance(data, str):
                return FlextResult[
                    (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)
                ].fail(f"parse operation requires str, got {type(data).__name__}")

            schema_util = FlextLdifUtilitiesSchema
            if schema_util is not None:
                detect_method = getattr(schema_util, "detect_schema_type", None)
                if detect_method is not None and callable(detect_method):
                    schema_type = detect_method(data)
                else:
                    schema_type = "attribute"
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
            if isinstance(data, m.Ldif.SchemaAttribute):
                return self._handle_write_operation(attr_model=data, oc_model=None)
            if isinstance(data, m.Ldif.SchemaObjectClass):
                return self._handle_write_operation(attr_model=None, oc_model=data)
            return FlextResult[
                (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)
            ].fail(
                f"write operation requires SchemaAttribute or SchemaObjectClass, got {type(data).__name__}",
            )

        msg = f"Unknown operation: {operation}"
        raise AssertionError(msg)

    def execute(
        self,
        *,
        data: (str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | None) = None,
        operation: str | None = None,
        **kwargs: dict[str, t.GeneralValueType],
    ) -> FlextResult[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str]:
        """Execute schema operation with auto-detection: str→parse, Model→write."""
        if data is None:
            data_raw = kwargs.get("data")
            if isinstance(
                data_raw,
                (
                    str,
                    m.Ldif.SchemaAttribute,
                    m.Ldif.SchemaObjectClass,
                ),
            ):
                data = data_raw

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
            return FlextResult[
                (m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str)
            ].ok(
                empty_str,
            )

        operation_final: str | None = None
        if isinstance(operation, str) and operation in {"parse", "write"}:
            operation_final = "parse" if operation == "parse" else "write"
        detected_op = self._auto_detect_operation(data, operation_final)
        if isinstance(detected_op, FlextResult):
            return detected_op

        return self._route_operation(data, detected_op)

    def write(
        self,
        model: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> FlextResult[str]:
        """Write schema model to string format."""
        if isinstance(model, m.Ldif.SchemaAttribute):
            return self.write_attribute(model)

        return self.write_objectclass(model)
