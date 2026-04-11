"""Quirks conversion matrix for LDAP server translation."""

from __future__ import annotations

import struct
import time
from collections.abc import Callable, Mapping, MutableMapping, MutableSequence, Sequence
from datetime import datetime
from typing import (
    ClassVar,
    Final,
    Literal,
    Self,
    TypeIs,
    override,
)

from pydantic import BaseModel, Field

from flext_core import FlextLogger
from flext_ldif import (
    FlextLdifServer,
    FlextLdifServersBase,
    FlextLdifServersBaseSchema,
    FlextLdifServersOidConstants,
    c,
    m,
    p,
    r,
    s,
    t,
    u,
)

# c.Ldif.TUPLE_LENGTH_PAIR = c.Ldif.c.Ldif.TUPLE_LENGTH_PAIR
logger = u.fetch_logger(__name__)


class _MissingSentinel:
    pass


_MISSING_ATTR: Final[_MissingSentinel] = _MissingSentinel()


class FlextLdifConversion(
    s[m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl],
):
    """Facade for universal, model-driven quirk-to-quirk conversion."""

    MAX_ERRORS_TO_SHOW: ClassVar[int] = 5

    @staticmethod
    def _get_schema_from_attribute(
        quirk: FlextLdifServersBase,
    ) -> p.Ldif.SchemaQuirk:
        if FlextLdifConversion._has_attr(quirk, "schema_quirk"):
            schema = quirk.schema_quirk
            if FlextLdifConversion._is_schema_quirk_protocol(schema):
                return schema
            msg = f"Expected Schema quirk, got {type(schema)}"
            raise TypeError(msg)
        msg = "Quirk must be a Schema quirk or have schema_quirk attribute"
        raise TypeError(msg)

    @staticmethod
    def _get_schema_quirk(quirk: FlextLdifServersBase) -> p.Ldif.SchemaQuirk:
        return FlextLdifConversion._get_schema_from_attribute(quirk)

    @staticmethod
    def _has_attr(
        obj: t.NormalizedValue
        | FlextLdifServersBase
        | FlextLdifServersBaseSchema
        | FlextLogger
        | p.Ldif.SchemaQuirk
        | m.Ldif.SchemaAttributeConversionPipelineConfig
        | m.Ldif.SchemaObjectClassConversionPipelineConfig
        | m.Ldif.QuirkMetadata
        | m.Ldif.DynamicMetadata
        | m.Ldif.AclPermissions
        | m.Ldif.Attributes
        | m.Ldif.SchemaAttribute
        | m.Ldif.SchemaObjectClass,
        attr_name: str,
    ) -> bool:
        return getattr(obj, attr_name, _MISSING_ATTR) is not _MISSING_ATTR

    @staticmethod
    def _is_schema_quirk_protocol(
        obj: (
            t.NormalizedValue
            | FlextLdifServersBase
            | FlextLdifServersBaseSchema
            | p.Ldif.SchemaQuirk
        ),
    ) -> TypeIs[p.Ldif.SchemaQuirk]:
        return (
            FlextLdifConversion._has_attr(obj, "parse_attribute")
            and FlextLdifConversion._has_attr(obj, "parse_objectclass")
            and FlextLdifConversion._has_attr(obj, "write_attribute")
            and FlextLdifConversion._has_attr(obj, "write_objectclass")
        )

    @staticmethod
    def _is_mapping_value(
        value: t.NormalizedValue,
    ) -> TypeIs[t.ContainerMapping]:
        return isinstance(value, Mapping)

    @staticmethod
    def _is_sequence_value(
        value: t.NormalizedValue,
    ) -> bool:
        return isinstance(value, Sequence) and not isinstance(value, str | bytes)

    @staticmethod
    def _validate_schema_quirk(
        quirk: FlextLdifServersBase,
    ) -> p.Ldif.SchemaQuirk:
        if not FlextLdifConversion._has_attr(
            quirk,
            "parse_attribute",
        ) or not FlextLdifConversion._has_attr(quirk, "write_attribute"):
            msg = f"Expected Schema quirk, got {type(quirk)}"
            raise TypeError(msg)
        if not FlextLdifConversion._is_schema_quirk_protocol(quirk):
            msg = f"Quirk {type(quirk)} doesn't satisfy SchemaQuirk"
            raise TypeError(msg)
        return quirk

    _PERMISSION_KEY_MAPPING: ClassVar[t.MutableStrMapping] = {
        "read": "read",
        "write": "write",
        "add": "add",
        "delete": "delete",
        "search": "search",
        "compare": "compare",
        "self_write": "selfwrite",
        "proxy": "proxy",
        "browse": "browse",
        "auth": "auth",
        "all": "all",
    }

    @staticmethod
    def _default_dn_registry() -> m.Ldif.DnRegistry:
        """Default DN registry factory function."""
        return m.Ldif.DnRegistry()

    dn_registry: m.Ldif.DnRegistry = Field(
        default_factory=_default_dn_registry,
        description="DN registry for tracking distinguished names during conversion",
    )

    def __new__(cls) -> Self:
        """Create service instance with matching signature for type checker."""
        instance = super().__new__(cls)
        if not isinstance(instance, cls):
            msg = f"Expected {cls.__name__}, got {type(instance).__name__}"
            raise TypeError(msg)
        return instance

    @staticmethod
    def _analyze_attribute_case(
        original_attribute_case: t.NormalizedValue,
        target_server_type: str,
    ) -> MutableMapping[str, t.MutableContainerMapping]:
        """Analyze attribute case for target compatibility."""
        if bool(original_attribute_case):
            return {
                "attribute_case": {
                    "source_case": FlextLdifConversion._normalize_metadata_value(
                        original_attribute_case,
                    ),
                    "target_server": str(target_server_type),
                    "action": "apply_target_conventions",
                },
            }
        return {}

    @staticmethod
    def _analyze_boolean_conversions(
        boolean_conversions: t.NormalizedValue,
        target_server_type: str,
    ) -> MutableMapping[str, t.MutableStrMapping]:
        """Analyze boolean conversions for target compatibility."""
        if not boolean_conversions or not FlextLdifConversion._is_mapping_value(
            boolean_conversions,
        ):
            return {}
        typed_boolean_conversions: t.MutableContainerMapping = {}
        for raw_attr_name, raw_conv_info in boolean_conversions.items():
            typed_boolean_conversions[str(raw_attr_name)] = raw_conv_info
        result: MutableMapping[str, t.MutableStrMapping] = {}
        for attr_name, conv_info in typed_boolean_conversions.items():
            source_format = ""
            if FlextLdifConversion._is_mapping_value(conv_info):
                conv_info_dict: t.MutableContainerMapping = {}
                for raw_key, raw_value in conv_info.items():
                    conv_info_dict[str(raw_key)] = raw_value
                source_format = str(conv_info_dict.get("format", "") or "")
            result[f"boolean_{attr_name}"] = {
                "source_format": source_format,
                "target_server": target_server_type,
                "action": "convert_to_target_format",
            }
        return result

    @staticmethod
    def _analyze_dn_format(
        original_format_details: t.NormalizedValue,
        target_server_type: str,
    ) -> MutableMapping[str, t.MutableContainerMapping]:
        """Analyze DN spacing for target compatibility."""
        if FlextLdifConversion._is_mapping_value(original_format_details):
            format_details: t.MutableContainerMapping = {}
            for raw_key, raw_value in original_format_details.items():
                format_details[str(raw_key)] = raw_value
            spacing: t.NormalizedValue | None = format_details.get("dn_spacing")
            if spacing:
                return {
                    "dn_format": {
                        "source_dn": FlextLdifConversion._normalize_metadata_value(
                            spacing,
                        ),
                        "target_server": str(target_server_type),
                        "action": "normalize_for_target",
                    },
                }
        return {}

    @staticmethod
    def _analyze_metadata_for_conversion(
        source_metadata: m.Ldif.QuirkMetadata | m.Ldif.DynamicMetadata | None,
        target_server_type: str,
    ) -> MutableMapping[str, str | t.MutableContainerMapping]:
        """Analyze source metadata for intelligent conversion to target server."""
        conversion_analysis: MutableMapping[
            str,
            str | t.MutableContainerMapping,
        ] = {}
        if not source_metadata or not FlextLdifConversion._has_attr(
            source_metadata,
            "boolean_conversions",
        ):
            return conversion_analysis
        target_server_str = target_server_type
        get_boolean = u.prop("boolean_conversions")
        get_attr_case = u.prop("original_attribute_case")
        get_format_details = u.prop("original_format_details")
        boolean_raw = get_boolean(source_metadata)
        boolean_conversions: t.NormalizedValue = (
            boolean_raw if isinstance(boolean_raw, dict) else {}
        )
        boolean_analysis = FlextLdifConversion._analyze_boolean_conversions(
            boolean_conversions,
            target_server_str,
        )
        acc_typed: MutableMapping[
            str,
            str | t.MutableContainerMapping,
        ] = {}
        for key, value in boolean_analysis.items():
            if isinstance(value, str):
                acc_typed[key] = value
            elif isinstance(value, dict):
                acc_typed[key] = {
                    str(k): FlextLdifConversion._normalize_metadata_value(v)
                    for k, v in value.items()
                }
        attr_case_raw = get_attr_case(source_metadata)
        empty_map: t.ContainerMapping = {}
        attr_case_val: t.NormalizedValue = empty_map
        if FlextLdifConversion._is_normalized(attr_case_raw):
            attr_case_val = attr_case_raw
        attr_case_analysis = FlextLdifConversion._analyze_attribute_case(
            attr_case_val if attr_case_val is not None else empty_map,
            target_server_str,
        )
        for key, attr_case_value in attr_case_analysis.items():
            if isinstance(attr_case_value, dict):
                acc_typed[key] = {
                    str(k): FlextLdifConversion._normalize_metadata_value(v)
                    for k, v in attr_case_value.items()
                }
        format_raw = get_format_details(source_metadata)
        format_val: t.NormalizedValue = empty_map
        if FlextLdifConversion._is_normalized(format_raw):
            format_val = format_raw
        dn_format_analysis = FlextLdifConversion._analyze_dn_format(
            format_val if format_val is not None else empty_map,
            target_server_str,
        )
        for key, dn_format_value in dn_format_analysis.items():
            if isinstance(dn_format_value, dict):
                acc_typed[key] = {
                    str(k): FlextLdifConversion._normalize_metadata_value(v)
                    for k, v in dn_format_value.items()
                }
        return acc_typed

    @staticmethod
    def _apply_oid_to_oud_mapping(
        orig_perms_dict: t.MutableBoolMapping,
        converted_acl: m.Ldif.Acl,
        perms_to_model: Callable[
            [t.MutableOptionalBoolMapping],
            m.Ldif.AclPermissions,
        ],
    ) -> m.Ldif.Acl:
        """Apply OID to OUD permission mapping."""
        normalized_orig_perms: t.MutableBoolMapping = {
            FlextLdifConversion._normalize_permission_key(k): v
            for k, v in orig_perms_dict.items()
        }
        mapped_perms = u.Ldif.map_oid_to_oud_permissions(normalized_orig_perms)
        oid_to_oud_perms = FlextLdifConversion._build_permissions_dict(mapped_perms)
        perms_model = perms_to_model(oid_to_oud_perms)
        return converted_acl.model_copy(update={"permissions": perms_model}, deep=True)

    @staticmethod
    def _apply_oud_to_oid_mapping(
        orig_perms_dict: t.MutableBoolMapping,
        converted_acl: m.Ldif.Acl,
        perms_to_model: Callable[
            [t.MutableOptionalBoolMapping],
            m.Ldif.AclPermissions,
        ],
    ) -> m.Ldif.Acl:
        """Apply OUD to OID permission mapping."""
        mapped_perms = u.Ldif.map_oud_to_oid_permissions(orig_perms_dict)
        oud_to_oid_perms = FlextLdifConversion._build_permissions_dict(mapped_perms)
        perms_model = perms_to_model(oud_to_oid_perms)
        return converted_acl.model_copy(update={"permissions": perms_model}, deep=True)

    @staticmethod
    def _build_permissions_dict(
        mapped_perms: t.MutableBoolMapping,
    ) -> t.MutableOptionalBoolMapping:
        """Build permissions dict with standard keys."""
        result: t.MutableOptionalBoolMapping = {}
        for (
            source_key,
            mapped_key,
        ) in FlextLdifConversion._PERMISSION_KEY_MAPPING.items():
            value = mapped_perms.get(mapped_key)
            result[source_key] = value
        return result

    @staticmethod
    def _convert_schema_attribute(
        source_quirk: FlextLdifServersBase,
        target_quirk: FlextLdifServersBase,
        attribute: m.Ldif.SchemaAttribute,
    ) -> r[t.Ldif.ConvertedModel]:
        """Convert SchemaAttribute model via write_attribute->parse_attribute pipeline."""
        try:
            source_schema_result = FlextLdifConversion._get_schema_quirk_safe(
                source_quirk,
                "Source",
            )
            source_schema = source_schema_result.map_or(None)
            if source_schema is None:
                return r[t.Ldif.ConvertedModel].fail(
                    source_schema_result.error or "Source schema not available"
                )
            target_schema_result = FlextLdifConversion._get_schema_quirk_safe(
                target_quirk,
                "Target",
            )
            if target_schema_result.failure:
                return r[t.Ldif.ConvertedModel].fail(
                    target_schema_result.error
                    or "Target schema quirk error: Schema not available",
                )
            target_schema: p.Ldif.SchemaQuirk = target_schema_result.value

            config = m.Ldif.SchemaAttributeConversionPipelineConfig(
                item_type="attribute",
                source_schema=source_schema,
                target_schema=target_schema,
                item=attribute,
                item_name="attribute",
            )
            return FlextLdifConversion._process_schema_conversion_pipeline(config)
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            return r[t.Ldif.ConvertedModel].fail(
                f"SchemaAttribute conversion failed: {e}",
            )

    @staticmethod
    def _convert_schema_objectclass(
        source_quirk: FlextLdifServersBase,
        target_quirk: FlextLdifServersBase,
        objectclass: m.Ldif.SchemaObjectClass,
    ) -> r[t.Ldif.ConvertedModel]:
        """Convert SchemaObjectClass model via write_objectclass->parse_objectclass pipeline."""
        try:
            source_schema_result = FlextLdifConversion._get_schema_quirk_safe(
                source_quirk,
                "Source",
            )
            source_schema = source_schema_result.map_or(None)
            if source_schema is None:
                return r[t.Ldif.ConvertedModel].fail(
                    source_schema_result.error or "Source schema not available"
                )
            target_schema_result = FlextLdifConversion._get_schema_quirk_safe(
                target_quirk,
                "Target",
            )
            target_schema = target_schema_result.map_or(None)
            if target_schema is None:
                return r[t.Ldif.ConvertedModel].fail(
                    target_schema_result.error or "Target schema not available"
                )

            config = m.Ldif.SchemaObjectClassConversionPipelineConfig(
                item_type="objectclass",
                source_schema=source_schema,
                target_schema=target_schema,
                item=objectclass,
                item_name="objectclass",
            )
            return FlextLdifConversion._process_schema_conversion_pipeline(config)
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            return r[t.Ldif.ConvertedModel].fail(
                f"SchemaObjectClass conversion failed: {e}",
            )

    @staticmethod
    def _get_schema_quirk_safe(
        quirk: FlextLdifServersBase,
        quirk_type: str,
    ) -> r[p.Ldif.SchemaQuirk]:
        """Get schema quirk safely with error handling."""
        result = u.try_(
            lambda: FlextLdifConversion._get_schema_quirk(quirk),
            default=None,
        )
        if result.failure:
            return r[p.Ldif.SchemaQuirk].fail(
                result.error or f"{quirk_type} quirk error: Schema not available",
            )
        schema_quirk = result.value
        if not FlextLdifConversion._is_schema_quirk_protocol(schema_quirk):
            return r[p.Ldif.SchemaQuirk].fail(
                f"{quirk_type} quirk {type(schema_quirk)} doesn't satisfy SchemaQuirk",
            )
        # Narrowing schema_quirk to the protocol so r[p.Ldif.SchemaQuirk].ok works
        final_quirk: p.Ldif.SchemaQuirk = schema_quirk
        return r[p.Ldif.SchemaQuirk].ok(final_quirk)

    @staticmethod
    def _is_normalized(
        value: t.RuntimeAtomic | t.RecursiveContainer,
    ) -> TypeIs[t.NormalizedValue]:
        """Type guard: check if value is NormalizedValue (not a BaseModel)."""
        return not isinstance(value, BaseModel)

    @staticmethod
    def _normalize_metadata_value(value: t.NormalizedValue) -> t.NormalizedValue:
        """Normalize metadata value to proper type."""
        if value is None:
            return ""
        if u.is_primitive(value):
            return value
        if isinstance(value, Sequence) and not isinstance(value, str | bytes):
            normalized_items: MutableSequence[t.Scalar | str] = [
                item if isinstance(item, t.SCALAR_TYPES) else str(item)
                for item in value
            ]
            return normalized_items
        return str(value)

    @staticmethod
    def _normalize_permission_key(key: str) -> str:
        """Normalize permission key for mapping."""
        return {"self_write": "selfwrite"}.get(key, key)

    @staticmethod
    def _parse_attribute_with_schema(
        schema: p.Ldif.SchemaQuirk,
        value: str,
        *,
        parse_error_message: str,
    ) -> r[m.Ldif.SchemaAttribute]:
        parse_result = schema.parse_attribute(value)
        if parse_result.failure:
            return r[m.Ldif.SchemaAttribute].fail(
                parse_result.error or parse_error_message,
            )
        parsed_attribute = m.Ldif.SchemaAttribute.model_validate(parse_result.value)
        return r[m.Ldif.SchemaAttribute].ok(parsed_attribute)

    @staticmethod
    def _parse_objectclass_with_schema(
        schema: p.Ldif.SchemaQuirk,
        value: str,
        *,
        parse_error_message: str,
    ) -> r[m.Ldif.SchemaObjectClass]:
        parse_result = schema.parse_objectclass(value)
        if parse_result.failure:
            return r[m.Ldif.SchemaObjectClass].fail(
                parse_result.error or parse_error_message,
            )
        parsed_objectclass = m.Ldif.SchemaObjectClass.model_validate(
            parse_result.value,
        )
        return r[m.Ldif.SchemaObjectClass].ok(parsed_objectclass)

    @staticmethod
    def _perms_dict_to_model(
        perms_dict: t.MutableOptionalBoolMapping,
    ) -> m.Ldif.AclPermissions:
        """Convert permissions dict to AclPermissions model."""
        clean_dict: t.MutableBoolMapping = {
            k: v for k, v in perms_dict.items() if v is not None
        }
        return m.Ldif.AclPermissions.model_validate(clean_dict)

    @staticmethod
    def _process_schema_conversion_pipeline(
        config: m.Ldif.SchemaAttributeConversionPipelineConfig
        | m.Ldif.SchemaObjectClassConversionPipelineConfig,
    ) -> r[t.Ldif.ConvertedModel]:
        """Process schema conversion pipeline using direct method dispatch."""

        def parse_target_ldif(ldif_string: str) -> r[t.Ldif.ConvertedModel]:
            if isinstance(config, m.Ldif.SchemaAttributeConversionPipelineConfig):
                return (
                    r[t.Ldif.SchemaConversionValue]
                    .from_result(
                        config.target_schema.parse_attribute(ldif_string),
                    )
                    .map_error(
                        lambda error: (
                            "Failed to parse "
                            f"{config.item_name} in target format: {error or 'Unknown parse error'}"
                        ),
                    )
                    .map(
                        m.Ldif.SchemaAttribute.model_validate,
                    )
                )
            return (
                r[t.Ldif.SchemaConversionValue]
                .from_result(
                    config.target_schema.parse_objectclass(ldif_string),
                )
                .map_error(
                    lambda error: (
                        "Failed to parse "
                        f"{config.item_name} in target format: {error or 'Unknown parse error'}"
                    ),
                )
                .map(
                    m.Ldif.SchemaObjectClass.model_validate,
                )
            )

        write_result = (
            config.source_schema.write_attribute(config.item)
            if isinstance(config, m.Ldif.SchemaAttributeConversionPipelineConfig)
            else config.source_schema.write_objectclass(config.item)
        )
        return (
            r[str]
            .from_result(write_result)
            .map_error(
                lambda error: (
                    "Failed to write "
                    f"{config.item_name} in source format: {error or 'Unknown write error'}"
                ),
            )
            .flat_map(
                lambda write_value: FlextLdifConversion._validate_ldif_string(
                    write_value,
                    config.item_name,
                ),
            )
            .flat_map(
                parse_target_ldif,
            )
        )

    @staticmethod
    def _resolve_quirk(
        quirk_or_type: str | FlextLdifServersBase,
    ) -> FlextLdifServersBase:
        """Resolve server quirk instance from string type or return instance."""
        if isinstance(quirk_or_type, str):
            server = FlextLdifServer.get_global_instance()
            server_type_str: str = quirk_or_type
            resolved_result = server.quirk(server_type_str)
            if resolved_result.failure:
                error_msg = (
                    f"Unknown server type: {quirk_or_type}: {resolved_result.error}"
                )
                raise ValueError(error_msg)
            resolved: FlextLdifServersBase = resolved_result.value
            return resolved
        return quirk_or_type

    @staticmethod
    def _schema_conversion_fail(
        error: str | None,
        fallback: str,
    ) -> r[t.Ldif.SchemaConversionValue]:
        return r[t.Ldif.SchemaConversionValue].fail(error or fallback)

    @staticmethod
    def _schema_conversion_ok(
        value: t.Ldif.SchemaConversionValue,
    ) -> r[t.Ldif.SchemaConversionValue]:
        return r[t.Ldif.SchemaConversionValue].ok(value)

    @staticmethod
    def _to_schema_conversion_value(
        value: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> t.Ldif.SchemaConversionValue:
        return value

    @staticmethod
    def _schema_passthrough_ok(
        value: t.Ldif.SchemaConversionValue,
    ) -> r[t.Ldif.SchemaConversionValue] | None:
        if isinstance(value, str):
            return FlextLdifConversion._schema_conversion_ok(value)
        # SchemaAttribute and SchemaObjectClass are BaseModel subclasses
        # Convert to string representation for LDIF passthrough
        return FlextLdifConversion._schema_conversion_ok(str(value))

    @staticmethod
    def _validate_ldif_string(ldif_string: str, operation: str) -> r[str]:
        """Validate LDIF string is not empty."""
        if ldif_string:
            return r[str].ok(ldif_string)
        return r[str].fail(f"Write operation returned empty {operation} LDIF")

    def convert_model(
        self,
        source: str | FlextLdifServersBase,
        target: str | FlextLdifServersBase,
        model_instance: m.Ldif.Entry
        | m.Ldif.SchemaAttribute
        | m.Ldif.SchemaObjectClass
        | m.Ldif.Acl,
    ) -> r[t.Ldif.ConvertedModel]:
        """Convert a model from a source server format to a target server format."""
        start_time = time.perf_counter()
        if isinstance(source, str):
            source_format = source
        else:
            source_format = str(
                getattr(source, "server_type", c.IDENTIFIER_UNKNOWN),
            )
        if isinstance(target, str):
            target_format = target
        else:
            target_format = str(
                getattr(target, "server_type", c.IDENTIFIER_UNKNOWN),
            )
        model_type = type(model_instance).__name__
        conversion_operation = f"convert_{model_type}"
        self.logger.debug(
            "Converting model",
            source_format=str(source_format),
            target_format=str(target_format),
            model_type=model_type,
        )
        result = self._convert_model(source, target, model_instance)
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        items_converted = 1 if result.success else 0
        items_failed = 0 if result.success else 1
        conversion_config = m.Ldif.ConversionEventConfig(
            conversion_operation=conversion_operation,
            source_format=source_format,
            target_format=target_format,
            items_processed=1,
            items_converted=items_converted,
            items_failed=items_failed,
            conversion_duration_ms=duration_ms,
            error_details=[f"{model_type}: {result.error or 'Unknown error'}"]
            if result.failure
            else [],
        )
        _ = u.Ldif.log_and_emit_conversion_event(
            logger=logger,
            config=conversion_config,
            log_level="info" if result.success else "error",
        )
        return result

    def convert_entry(
        self,
        source: str | FlextLdifServersBase,
        target: str | FlextLdifServersBase,
        model_instance: m.Ldif.Entry
        | m.Ldif.SchemaAttribute
        | m.Ldif.SchemaObjectClass
        | m.Ldif.Acl,
    ) -> r[t.Ldif.ConvertedModel]:
        """Compatibility facade for conversion matrix callers."""
        return self.convert_model(
            source=source,
            target=target,
            model_instance=model_instance,
        )

    @override
    def execute(
        self,
    ) -> r[
        m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
    ]:
        """Execute conversion service health check."""
        try:
            empty_entry = m.Ldif.Entry(
                dn=m.Ldif.DN(value="cn=health-check", metadata=m.Ldif.EntryMetadata()),
                attributes=m.Ldif.Attributes(
                    attributes={},
                    attribute_metadata={},
                    metadata=None,
                ),
                changetype=None,
                metadata=None,
            )
            return r[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ].ok(empty_entry)
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            return r[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ].fail(f"Conversion service health check failed: {e}")

    def get_supported_conversions(
        self,
        quirk: FlextLdifServersBase,
    ) -> t.MutableBoolMapping:
        """Check which data types a quirk supports for conversion."""
        support: t.MutableIntMapping = {
            "attribute": 0,
            "objectclass": 0,
            "acl": 0,
            "entry": 0,
        }
        support = self._check_schema_support(quirk, support)
        support = self._check_acl_support(quirk, support)
        support = self._check_entry_support(quirk, support)
        return {
            "attribute": bool(support.get("attribute", 0)),
            "objectClass": bool(support.get("objectclass", 0)),
            "objectclass": bool(support.get("objectclass", 0)),
            "acl": bool(support.get("acl", 0)),
            "entry": bool(support.get("entry", 0)),
        }

    def _apply_permission_mapping(
        self,
        config: m.Ldif.PermissionMappingConfig | None = None,
        *,
        original_acl: m.Ldif.Acl | None = None,
        converted_acl: m.Ldif.Acl | None = None,
        orig_perms_dict: t.MutableBoolMapping | None = None,
        source_server_type: str | None = None,
        target_server_type: str | None = None,
        converted_has_permissions: bool = False,
    ) -> m.Ldif.Acl:
        """Apply permission mapping based on server types."""
        if config is not None:
            resolved_config = config
        else:
            if original_acl is None or converted_acl is None:
                if converted_acl is not None:
                    return converted_acl
                if original_acl is not None:
                    return original_acl
                return m.Ldif.Acl(
                    server_type=c.Ldif.ServerTypes.RFC,
                    validation_violations=[],
                    name="",
                    target=None,
                    subject=None,
                    permissions=None,
                    raw_line="",
                    raw_acl="",
                    metadata=None,
                )
            resolved_config = m.Ldif.PermissionMappingConfig(
                original_acl=original_acl,
                converted_acl=converted_acl,
                orig_perms_dict=dict(orig_perms_dict or {}),
                source_server_type=source_server_type,
                target_server_type=target_server_type,
                converted_has_permissions=converted_has_permissions,
            )
        normalized_source = (
            u.Ldif.normalize_server_type(resolved_config.source_server_type)
            if isinstance(resolved_config.source_server_type, str)
            else resolved_config.source_server_type
        )
        normalized_target = (
            u.Ldif.normalize_server_type(resolved_config.target_server_type)
            if isinstance(resolved_config.target_server_type, str)
            else resolved_config.target_server_type
        )
        mapping_type = "none"
        pair = (normalized_source, normalized_target)
        if pair == ("oid", "oud"):
            mapping_type = "oid_to_oud"
        elif pair == ("oud", "oid"):
            mapping_type = "oud_to_oid"
        elif (
            not resolved_config.converted_has_permissions
            and resolved_config.original_acl.permissions is not None
        ):
            mapping_type = "preserve_original"
        logger.debug(
            "ACL mapping decision",
            mapping_type=str(mapping_type),
            normalized_source=str(normalized_source),
            normalized_target=str(normalized_target),
        )
        converted_acl_typed: m.Ldif.Acl = resolved_config.converted_acl
        if mapping_type == "oid_to_oud":
            return FlextLdifConversion._apply_oid_to_oud_mapping(
                resolved_config.orig_perms_dict,
                converted_acl_typed,
                self._perms_dict_to_model,
            )
        if mapping_type == "oud_to_oid":
            return FlextLdifConversion._apply_oud_to_oid_mapping(
                resolved_config.orig_perms_dict,
                converted_acl_typed,
                self._perms_dict_to_model,
            )
        if mapping_type == "preserve_original":
            original_acl_typed: m.Ldif.Acl = resolved_config.original_acl
            return converted_acl_typed.model_copy(
                update={
                    "permissions": original_acl_typed.permissions.model_copy(deep=True)
                    if original_acl_typed.permissions
                    and FlextLdifConversion._has_attr(
                        original_acl_typed.permissions,
                        "model_copy",
                    )
                    else None,
                },
                deep=True,
            )
        return converted_acl_typed

    def _check_acl_support(
        self,
        quirk: FlextLdifServersBase,
        support: t.MutableIntMapping,
    ) -> t.MutableIntMapping:
        """Check ACL support."""
        acl = getattr(quirk, "acl_quirk", None)
        if acl is None:
            acl = getattr(quirk, "_acl_quirk", None)
        test_acl_def = 'targetattr="*" (version 3.0; acl "test"; allow (read) userdn="ldap:///self";)'
        if acl and callable(getattr(acl, "parse_quirk", None)):
            acl_result = acl.parse_quirk(test_acl_def)
            if acl_result.map_or(None) is not None:
                support["acl"] = 1
        return support

    def _check_attribute_support(
        self,
        quirk_schema: t.NormalizedValue | FlextLdifServersBase,
        test_attr_def: str,
        support: t.MutableIntMapping,
    ) -> t.MutableIntMapping:
        """Check attribute support for schema quirk."""
        if not FlextLdifConversion._has_attr(quirk_schema, "can_handle_attribute"):
            return support
        if not FlextLdifConversion._has_attr(quirk_schema, "parse_attribute"):
            return support
        can_handle_attr = getattr(quirk_schema, "can_handle_attribute", None)
        if can_handle_attr is None or not callable(can_handle_attr):
            return support
        if not can_handle_attr(test_attr_def):
            return support
        parse_attr = getattr(quirk_schema, "parse_attribute", None)
        if parse_attr is None or not callable(parse_attr):
            return support
        attr_result = parse_attr(test_attr_def)
        if isinstance(attr_result, r) and attr_result.success:
            support["attribute"] = 1
        return support

    def _check_converted_has_permissions(self, converted_acl: m.Ldif.Acl) -> bool:
        """Check if converted ACL has any permissions set."""
        permission_fields = (
            "read",
            "write",
            "add",
            "delete",
            "search",
            "compare",
            "self_write",
            "proxy",
            "browse",
            "auth",
            "all",
        )
        return bool(
            converted_acl.permissions
            and any(
                getattr(converted_acl.permissions, field, False)
                for field in permission_fields
            ),
        )

    def _check_entry_support(
        self,
        quirk: FlextLdifServersBase,
        support: t.MutableIntMapping,
    ) -> t.MutableIntMapping:
        """Check Entry support."""
        entry = getattr(quirk, "entry_quirk", None)
        if entry is None:
            entry = getattr(quirk, "_entry_quirk", None)
        if (
            entry is None
            and FlextLdifConversion._has_attr(quirk, "_parse_content")
            and FlextLdifConversion._has_attr(quirk, "can_handle")
        ):
            entry = quirk
        if entry is not None and (
            callable(getattr(entry, "_parse_content", None))
            or callable(getattr(entry, "can_handle", None))
        ):
            support["entry"] = 1
        return support

    def _check_objectclass_support(
        self,
        quirk_schema: t.NormalizedValue | FlextLdifServersBase,
        test_oc_def: str,
        support: t.MutableIntMapping,
    ) -> t.MutableIntMapping:
        """Check objectClass support for schema quirk."""
        if not FlextLdifConversion._has_attr(quirk_schema, "can_handle_objectclass"):
            return support
        if not FlextLdifConversion._has_attr(quirk_schema, "parse_objectclass"):
            return support
        can_handle_oc = getattr(quirk_schema, "can_handle_objectclass", None)
        if can_handle_oc is None or not callable(can_handle_oc):
            return support
        if not can_handle_oc(test_oc_def):
            return support
        parse_oc = getattr(quirk_schema, "parse_objectclass", None)
        if parse_oc is None or not callable(parse_oc):
            return support
        oc_result = parse_oc(test_oc_def)
        if isinstance(oc_result, r) and oc_result.success:
            support["objectclass"] = 1
        return support

    def _check_schema_support(
        self,
        quirk: FlextLdifServersBase,
        support: t.MutableIntMapping,
    ) -> t.MutableIntMapping:
        """Check schema (attribute and objectClass) support."""
        quirk_schema = self._get_schema_quirk_for_support_check(quirk)
        if quirk_schema is None:
            return support
        test_attr_def = "( 2.16.840.1.113894.1.1.1 NAME 'orclTest' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        test_oc_def = (
            "( 2.16.840.1.113894.1.2.1 NAME 'orclTest' SUP top STRUCTURAL MUST cn )"
        )
        support = self._check_attribute_support(quirk_schema, test_attr_def, support)
        return self._check_objectclass_support(quirk_schema, test_oc_def, support)

    def _convert_acl(
        self,
        source_quirk: FlextLdifServersBase,
        target_quirk: FlextLdifServersBase,
        acl: m.Ldif.Acl,
    ) -> r[t.Ldif.ConvertedModel]:
        """Convert Acl model via Entry RFC + Metadata pipeline."""
        try:

            def extract_converted_acl(
                converted_entry_value: t.Ldif.ConvertedModel,
            ) -> r[m.Ldif.Acl]:
                if not isinstance(converted_entry_value, m.Ldif.Entry):
                    return r[m.Ldif.Acl].fail(
                        "Entry conversion returned unexpected type: "
                        f"{type(converted_entry_value).__name__}",
                    )
                get_metadata = u.prop("metadata")
                converted_metadata_raw = get_metadata(converted_entry_value)
                if converted_metadata_raw is None:
                    return r[m.Ldif.Acl].fail(
                        "Converted entry has no ACLs in metadata.acls",
                    )
                if not isinstance(converted_metadata_raw, m.Ldif.QuirkMetadata):
                    return r[m.Ldif.Acl].fail(
                        f"Unexpected metadata type: {type(converted_metadata_raw).__name__}",
                    )
                converted_metadata = converted_metadata_raw
                acls_raw = converted_metadata.acls
                if not isinstance(acls_raw, list):
                    return r[m.Ldif.Acl].fail(
                        "Converted entry has no ACLs in metadata.acls",
                    )
                acls = [item for item in acls_raw if isinstance(item, m.Ldif.Acl)]
                if not acls:
                    return r[m.Ldif.Acl].fail(
                        "Converted entry has no ACLs in metadata.acls",
                    )
                return r[m.Ldif.Acl].ok(acls[0])

            acl = acl.model_copy(deep=True)
            entry_dn = m.Ldif.DN(
                value="cn=acl-conversion,dc=example,dc=com",
                metadata=m.Ldif.EntryMetadata(),
            )
            entry_attributes = m.Ldif.Attributes(
                attributes={},
                attribute_metadata={},
                metadata=None,
            )
            get_server_type = u.prop("server_type")
            server_type_raw = get_server_type(source_quirk)
            server_type_attr = (
                server_type_raw if isinstance(server_type_raw, str) else None
            )
            source_server_type: str | None = u.try_(
                lambda: (
                    u.Ldif.normalize_server_type(str(server_type_attr))
                    if isinstance(server_type_attr, str)
                    else None
                ),
                default=None,
            ).map_or(None)
            entry_metadata = m.Ldif.QuirkMetadata.create_for(
                source_server_type,
                extensions=None,
            )
            entry_metadata.acls = [acl.raw_acl] if acl.raw_acl else list[str]()
            rfc_entry = m.Ldif.Entry.model_validate({
                "dn": entry_dn,
                "attributes": entry_attributes,
                "metadata": entry_metadata,
            })
            get_server_type = u.prop("server_type")
            target_server_raw = get_server_type(target_quirk)
            target_server_type_raw = (
                target_server_raw
                if isinstance(target_server_raw, str)
                else c.IDENTIFIER_UNKNOWN
            )
            target_server_type: str | None = u.try_(
                lambda: (
                    u.Ldif.normalize_server_type(target_server_type_raw)
                    if target_server_type_raw != c.IDENTIFIER_UNKNOWN
                    else None
                ),
                default=None,
            ).map_or(None)
            return (
                self
                ._convert_entry(
                    source_quirk,
                    target_quirk,
                    rfc_entry,
                )
                .flat_map(
                    extract_converted_acl,
                )
                .flat_map(
                    lambda converted_acl: r[t.Ldif.ConvertedModel].ok(
                        self._preserve_acl_metadata(
                            acl,
                            converted_acl,
                            source_server_type=source_server_type,
                            target_server_type=target_server_type,
                        ).model_copy(
                            update={"server_type": target_server_type},
                            deep=True,
                        ),
                    ),
                )
            )
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            logger.exception("Failed to convert ACL model", error=str(e))
            return r[t.Ldif.ConvertedModel].fail(f"Acl conversion failed: {e}")

    def _convert_attribute(
        self,
        source: str | FlextLdifServersBase,
        target: str | FlextLdifServersBase,
        data: t.Ldif.SchemaConversionValue,
    ) -> r[t.Ldif.SchemaConversionValue]:
        """Convert attribute from source to target quirk via write->parse pipeline."""
        return self._convert_schema_via_rfc_pipeline(
            source=source,
            target=target,
            data=data,
            schema_item_kind="attribute",
            required_string_message="Attribute conversion requires string data",
            source_parse_error_message="Failed to parse attribute",
            source_parse_failure_message="Failed to parse source attribute",
            target_parse_error_message="Failed to parse target attribute",
            target_parse_failure_message="Failed to parse target attribute",
            conversion_failure_message="Attribute conversion failed",
        )

    def _parse_schema_item_with_schema(
        self,
        schema: p.Ldif.SchemaQuirk,
        value: str,
        *,
        parse_error_message: str,
        schema_item_kind: Literal["attribute", "objectclass"],
    ) -> r[t.Ldif.SchemaConversionValue]:
        if schema_item_kind == "attribute":
            return self._parse_attribute_with_schema(
                schema,
                value,
                parse_error_message=parse_error_message,
            ).map(
                FlextLdifConversion._to_schema_conversion_value,
            )

        return self._parse_objectclass_with_schema(
            schema,
            value,
            parse_error_message=parse_error_message,
        ).map(
            FlextLdifConversion._to_schema_conversion_value,
        )

    def _convert_schema_via_rfc_pipeline(
        self,
        source: str | FlextLdifServersBase,
        target: str | FlextLdifServersBase,
        data: t.Ldif.SchemaConversionValue,
        *,
        schema_item_kind: Literal["attribute", "objectclass"],
        required_string_message: str,
        source_parse_error_message: str,
        source_parse_failure_message: str,
        target_parse_error_message: str,
        target_parse_failure_message: str,
        conversion_failure_message: str,
    ) -> r[t.Ldif.SchemaConversionValue]:
        try:

            def write_rfc_schema_item(
                parsed_item: t.Ldif.SchemaConversionValue,
            ) -> r[t.Ldif.SchemaConversionValue]:
                return (
                    self._write_attribute_to_rfc(source, parsed_item)
                    if schema_item_kind == "attribute"
                    else self._write_objectclass_to_rfc(source, parsed_item)
                )

            def parse_target_schema_item(
                rfc_value: str,
            ) -> r[t.Ldif.SchemaConversionValue]:
                return (
                    self
                    ._resolve_schema_quirk(target, role="Target")
                    .map_error(
                        lambda error: error or "Target schema not available",
                    )
                    .flat_map(
                        lambda target_schema: self._parse_schema_item_with_schema(
                            target_schema,
                            rfc_value,
                            parse_error_message=target_parse_error_message,
                            schema_item_kind=schema_item_kind,
                        ).map_error(
                            lambda error: error or target_parse_failure_message,
                        ),
                    )
                )

            if not isinstance(data, str):
                return r[t.Ldif.SchemaConversionValue].fail(required_string_message)
            return (
                self
                ._resolve_schema_quirk(
                    source,
                    role="Source",
                )
                .map_error(
                    lambda error: error or "Source schema not available",
                )
                .flat_map(
                    lambda source_schema: self._parse_schema_item_with_schema(
                        source_schema,
                        data,
                        parse_error_message=source_parse_error_message,
                        schema_item_kind=schema_item_kind,
                    ).map_error(
                        lambda error: error or source_parse_failure_message,
                    ),
                )
                .flat_map(
                    write_rfc_schema_item,
                )
                .flat_map(
                    lambda rfc_value: (
                        FlextLdifConversion._schema_conversion_ok(rfc_value)
                        if not isinstance(rfc_value, str)
                        else parse_target_schema_item(rfc_value)
                    ),
                )
            )
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            return FlextLdifConversion._schema_conversion_fail(
                f"{conversion_failure_message}: {e}",
                conversion_failure_message,
            )

    def _convert_schema_entry_value(
        self,
        source_schema: p.Ldif.SchemaQuirk,
        target_schema: p.Ldif.SchemaQuirk,
        value: str,
        *,
        schema_item_kind: Literal["attribute", "objectclass"],
        field_name: str,
    ) -> r[str]:
        """Convert a schema definition string embedded inside an LDIF entry."""

        def write_schema_item(
            parsed_item: t.Ldif.SchemaConversionValue,
        ) -> r[str]:
            if schema_item_kind == "attribute":
                if not isinstance(parsed_item, m.Ldif.SchemaAttribute):
                    return r[str].fail(
                        "Expected SchemaAttribute for "
                        f"{field_name}, got {type(parsed_item).__name__}",
                    )
                return (
                    r[str]
                    .from_result(
                        target_schema.write_attribute(parsed_item),
                    )
                    .map_error(
                        lambda error: (
                            error or f"Failed to write converted {field_name}"
                        ),
                    )
                )
            if not isinstance(parsed_item, m.Ldif.SchemaObjectClass):
                return r[str].fail(
                    "Expected SchemaObjectClass for "
                    f"{field_name}, got {type(parsed_item).__name__}",
                )
            return (
                r[str]
                .from_result(
                    target_schema.write_objectclass(parsed_item),
                )
                .map_error(
                    lambda error: error or f"Failed to write converted {field_name}",
                )
            )

        return (
            self
            ._parse_schema_item_with_schema(
                source_schema,
                value,
                parse_error_message=f"Failed to parse {field_name} definition",
                schema_item_kind=schema_item_kind,
            )
            .map_error(
                lambda error: error or f"Failed to parse {field_name}",
            )
            .flat_map(
                write_schema_item,
            )
        )

    def _convert_schema_entry_attributes(
        self,
        source_quirk: FlextLdifServersBase,
        target_quirk: FlextLdifServersBase,
        entry: m.Ldif.Entry,
    ) -> r[m.Ldif.Entry]:
        """Convert schema definition attributes embedded in a schema entry."""
        if entry.attributes is None or not u.Ldif.is_schema_entry(entry):
            return r[m.Ldif.Entry].ok(entry)
        source_schema_result = self._resolve_schema_quirk(source_quirk, role="Source")
        if source_schema_result.failure:
            return r[m.Ldif.Entry].fail(
                source_schema_result.error or "Source schema not available",
            )
        target_schema_result = self._resolve_schema_quirk(target_quirk, role="Target")
        if target_schema_result.failure:
            return r[m.Ldif.Entry].fail(
                target_schema_result.error or "Target schema not available",
            )
        schema_field_kinds: dict[str, Literal["attribute", "objectclass"]] = {
            c.Ldif.ATTRIBUTE_TYPES.lower(): "attribute",
            c.Ldif.OBJECT_CLASSES.lower(): "objectclass",
        }
        updated_attributes = dict(entry.attributes.attributes)
        changed = False
        for attr_name, values in entry.attributes.attributes.items():
            schema_item_kind = schema_field_kinds.get(attr_name.lower())
            if schema_item_kind is None:
                continue
            converted_values: MutableSequence[str] = []
            for value in values:
                converted_value_result = self._convert_schema_entry_value(
                    source_schema_result.value,
                    target_schema_result.value,
                    value,
                    schema_item_kind=schema_item_kind,
                    field_name=attr_name,
                )
                if converted_value_result.failure:
                    return r[m.Ldif.Entry].fail(
                        converted_value_result.error
                        or f"Failed converting schema field {attr_name}",
                    )
                converted_values.append(converted_value_result.value)
            updated_attributes[attr_name] = converted_values
            changed = True
        if not changed:
            return r[m.Ldif.Entry].ok(entry)
        updated_entry = entry.model_copy(
            update={
                "attributes": entry.attributes.model_copy(
                    update={"attributes": updated_attributes},
                    deep=True,
                ),
            },
            deep=True,
        )
        return r[m.Ldif.Entry].ok(updated_entry)

    def _convert_entry(
        self,
        source_quirk: FlextLdifServersBase,
        target_quirk: FlextLdifServersBase,
        entry: m.Ldif.Entry,
    ) -> r[t.Ldif.ConvertedModel]:
        """Convert Entry model directly without serialization."""
        try:
            entry_dn = entry.dn.value if entry.dn else ""
            valid: bool = u.Ldif.validate_dn(entry_dn)
            if not valid:
                return r[t.Ldif.ConvertedModel].fail(
                    f"Entry DN failed RFC 4514 validation: {entry_dn}",
                )
            _ = self.dn_registry.register_dn(entry_dn)
            converted_entry = entry.model_copy(deep=True)
            get_server_type = u.prop("server_type")
            target_server_type_obj = get_server_type(target_quirk)
            target_server_type_raw = (
                target_server_type_obj
                if isinstance(target_server_type_obj, str)
                else c.IDENTIFIER_UNKNOWN
            )
            if target_server_type_raw != c.IDENTIFIER_UNKNOWN:
                target_server_type_str = u.Ldif.normalize_server_type(
                    target_server_type_raw,
                )
            else:
                target_server_type_str = c.Ldif.ServerTypes.RFC
            validated_quirk_type = u.Ldif.normalize_server_type(
                str(target_server_type_str),
            )
            metadata_for_analysis: (
                m.Ldif.QuirkMetadata | m.Ldif.DynamicMetadata | None
            ) = (
                entry.metadata
                if isinstance(
                    entry.metadata,
                    (m.Ldif.QuirkMetadata, m.Ldif.DynamicMetadata),
                )
                else None
            )
            conversion_analysis = FlextLdifConversion._analyze_metadata_for_conversion(
                metadata_for_analysis,
                validated_quirk_type,
            )
            source_server_type_obj = get_server_type(source_quirk)
            source_quirk_name = (
                source_server_type_obj
                if isinstance(source_server_type_obj, str)
                else c.IDENTIFIER_UNKNOWN
            )
            source_type_norm = str(source_quirk_name).lower()
            target_type_norm = str(target_server_type_str).lower()
            converted_entry = self._update_entry_metadata(
                converted_entry,
                validated_quirk_type,
                str(conversion_analysis) if conversion_analysis else None,
                str(source_quirk_name),
            )
            if source_type_norm != target_type_norm:
                schema_entry_result = self._convert_schema_entry_attributes(
                    source_quirk,
                    target_quirk,
                    converted_entry,
                )
                if schema_entry_result.failure:
                    return r[t.Ldif.ConvertedModel].fail(
                        schema_entry_result.error
                        or "Failed to convert schema attributes in entry",
                    )
                converted_entry = schema_entry_result.value
            if (
                source_type_norm == "oid"
                and target_type_norm == "rfc"
                and converted_entry.attributes
                and converted_entry.attributes.attributes
            ):
                current_attrs = dict(converted_entry.attributes.attributes)
                updated_attrs: t.MutableStrSequenceMapping = {}
                mapping = (
                    FlextLdifServersOidConstants.ATTRIBUTE_TRANSFORMATION_OID_TO_RFC
                )
                for k, v in current_attrs.items():
                    lower_k = k.lower()
                    normalized_values: MutableSequence[str] = [str(item) for item in v]
                    converted_values = (
                        [
                            FlextLdifServersOidConstants.OID_TO_RFC.get(value, value)
                            for value in normalized_values
                        ]
                        if lower_k in FlextLdifServersOidConstants.BOOLEAN_ATTRIBUTES
                        else normalized_values
                    )
                    if lower_k in mapping:
                        new_key = mapping[lower_k]
                        updated_attrs[new_key] = converted_values
                    else:
                        updated_attrs[lower_k] = converted_values
                new_attributes = m.Ldif.Attributes.model_validate({
                    "attributes": updated_attrs,
                    "attribute_metadata": {},
                    "metadata": None,
                })
                converted_entry = converted_entry.model_copy(
                    update={"attributes": new_attributes},
                )
            if (
                source_type_norm == "rfc"
                and target_type_norm == "oid"
                and converted_entry.attributes
                and converted_entry.attributes.attributes
            ):
                current_attrs = dict(converted_entry.attributes.attributes)
                updated_attrs_rfc_to_oid: t.MutableStrSequenceMapping = {}
                mapping = (
                    FlextLdifServersOidConstants.ATTRIBUTE_TRANSFORMATION_RFC_TO_OID
                )
                for k, v in current_attrs.items():
                    lower_k = k.lower()
                    normalized_values = [str(item) for item in v]
                    converted_values = (
                        [
                            FlextLdifServersOidConstants.RFC_TO_OID.get(value, value)
                            for value in normalized_values
                        ]
                        if lower_k in FlextLdifServersOidConstants.BOOLEAN_ATTRIBUTES
                        else normalized_values
                    )
                    if lower_k in mapping:
                        new_key = mapping[lower_k]
                        updated_attrs_rfc_to_oid[new_key] = converted_values
                    else:
                        updated_attrs_rfc_to_oid[lower_k] = converted_values
                new_attributes = m.Ldif.Attributes.model_validate({
                    "attributes": updated_attrs_rfc_to_oid,
                    "attribute_metadata": {},
                    "metadata": None,
                })
                converted_entry = converted_entry.model_copy(
                    update={"attributes": new_attributes},
                )
            entry_dn_model = converted_entry.dn
            if entry_dn_model is not None:
                dn_value = entry_dn_model.value
                dn_val = dn_value.lower()
                if source_type_norm == "oid" and target_type_norm == "rfc":
                    if "cn=subschemasubentry" in dn_val:
                        new_dn_val = dn_value.replace(
                            "cn=subschemasubentry",
                            "cn=schema",
                        )
                        converted_entry = converted_entry.model_copy(
                            update={
                                "dn": m.Ldif.DN(
                                    value=new_dn_val,
                                    metadata=m.Ldif.EntryMetadata(),
                                ),
                            },
                        )
                elif (
                    source_type_norm == "rfc"
                    and target_type_norm == "oid"
                    and ("cn=schema" in dn_val)
                ):
                    new_dn_val = dn_value.replace("cn=schema", "cn=subschemasubentry")
                    converted_entry = converted_entry.model_copy(
                        update={
                            "dn": m.Ldif.DN(
                                value=new_dn_val,
                                metadata=m.Ldif.EntryMetadata(),
                            ),
                        },
                    )
            return r[t.Ldif.ConvertedModel].ok(converted_entry)
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            logger.exception("Failed to convert Entry model", error=str(e))
            return r[t.Ldif.ConvertedModel].fail(
                f"Entry conversion failed: {e}",
            )

    def _convert_model(
        self,
        source: str | FlextLdifServersBase,
        target: str | FlextLdifServersBase,
        model_instance: m.Ldif.Entry
        | m.Ldif.SchemaAttribute
        | m.Ldif.SchemaObjectClass
        | m.Ldif.Acl,
    ) -> r[t.Ldif.ConvertedModel]:
        """Convert model between source and target server formats via write->parse pipeline."""
        try:
            source_quirk = self._resolve_quirk(source)
            target_quirk = self._resolve_quirk(target)
            if isinstance(model_instance, m.Ldif.Entry):
                return self._convert_entry(source_quirk, target_quirk, model_instance)
            if isinstance(model_instance, m.Ldif.SchemaAttribute):
                return FlextLdifConversion._convert_schema_attribute(
                    source_quirk,
                    target_quirk,
                    model_instance,
                )
            if isinstance(model_instance, m.Ldif.SchemaObjectClass):
                return FlextLdifConversion._convert_schema_objectclass(
                    source_quirk,
                    target_quirk,
                    model_instance,
                )
            return self._convert_acl(source_quirk, target_quirk, model_instance)
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            return r[t.Ldif.ConvertedModel].fail(f"Model conversion failed: {e}")

    def _convert_objectclass(
        self,
        source: str | FlextLdifServersBase,
        target: str | FlextLdifServersBase,
        data: t.Ldif.SchemaConversionValue,
    ) -> r[t.Ldif.SchemaConversionValue]:
        """Convert objectClass from source to target quirk via write->parse pipeline."""
        return self._convert_schema_via_rfc_pipeline(
            source=source,
            target=target,
            data=data,
            schema_item_kind="objectclass",
            required_string_message="ObjectClass conversion requires string data",
            source_parse_error_message="Failed to parse objectClass",
            source_parse_failure_message="Failed to parse source objectClass",
            target_parse_error_message="Failed to parse target objectClass",
            target_parse_failure_message="Failed to parse target objectClass",
            conversion_failure_message="ObjectClass conversion failed",
        )

    def _convert_to_metadata_attribute_value(
        self,
        value: t.NormalizedValue
        | t.MutableContainerMapping
        | t.MutableContainerList
        | None,
    ) -> t.NormalizedValue:
        """Convert value to MetadataAttributeValue type."""
        if value is None:
            return ""
        if u.is_primitive(value):
            return value
        if isinstance(value, Sequence) and not isinstance(value, str | bytes):
            converted_list: t.ScalarList = [
                item if isinstance(item, t.SCALAR_TYPES) else str(item)
                for item in value
            ]
            return converted_list
        if isinstance(value, Mapping):
            typed_value: t.MutableContainerMapping = {}
            for raw_key, raw_item in value.items():
                typed_value[str(raw_key)] = raw_item
            return str(typed_value)
        return str(value)

    def _get_extensions_dict(self, acl: m.Ldif.Acl) -> t.MutableContainerMapping:
        """Extract extensions dict from ACL metadata."""

        def to_general_value(value: t.NormalizedValue) -> t.NormalizedValue:
            if value is None:
                return None
            if isinstance(value, str):
                return value
            if isinstance(value, bool):
                return value
            if isinstance(value, int):
                return value
            if isinstance(value, float):
                return value
            if isinstance(value, datetime):
                return value.isoformat()
            if isinstance(value, Mapping):
                normalized_mapping: t.MutableContainerMapping = {}
                for raw_key, raw_item in value.items():
                    key = str(raw_key)
                    item: t.NormalizedValue = raw_item
                    normalized_mapping[key] = to_general_value(item)
                return normalized_mapping
            if isinstance(value, Sequence) and not isinstance(value, str | bytes):
                normalized_sequence: t.MutableContainerList = [
                    to_general_value(item) for item in value
                ]
                return normalized_sequence
            return str(value)

        get_metadata = u.prop("metadata")
        get_extensions = u.prop("extensions")
        if not get_metadata(acl) or not acl.metadata:
            return {}
        extensions_raw = get_extensions(acl.metadata)
        if isinstance(extensions_raw, m.Ldif.DynamicMetadata):
            return {
                key: to_general_value(value)
                for key, value in extensions_raw.to_dict().items()
            }
        if isinstance(extensions_raw, Mapping):
            return {
                str(key): to_general_value(value)
                for key, value in extensions_raw.items()
            }
        return {}

    def _get_schema_quirk_for_support_check(
        self,
        quirk: FlextLdifServersBase,
    ) -> t.NormalizedValue | FlextLdifServersBase | None:
        """Get schema quirk from base quirk for support checking."""
        if FlextLdifConversion._has_attr(
            quirk,
            "parse_attribute",
        ) or FlextLdifConversion._has_attr(quirk, "parse_objectclass"):
            required_methods = ("parse_attribute", "write")
            if all(
                FlextLdifConversion._has_attr(quirk, method)
                and callable(getattr(quirk, method))
                for method in required_methods
            ):
                return quirk
            return None
        schema_quirk_raw: t.NormalizedValue | None = getattr(
            quirk,
            "schema_quirk",
            None,
        )
        if schema_quirk_raw is not None:
            required_methods = ("parse_attribute", "write")
            if all(
                FlextLdifConversion._has_attr(schema_quirk_raw, method)
                and callable(getattr(schema_quirk_raw, method))
                for method in required_methods
            ):
                return schema_quirk_raw
            return None
        return None

    def _preserve_acl_metadata(
        self,
        original_acl: m.Ldif.Acl,
        converted_acl: m.Ldif.Acl,
        source_server_type: str | None = None,
        target_server_type: str | None = None,
    ) -> m.Ldif.Acl:
        """Preserve permissions and metadata from original ACL."""
        converted_has_permissions = self._check_converted_has_permissions(converted_acl)
        converted_acl = self._preserve_permissions(
            original_acl,
            converted_acl,
            source_server_type,
            target_server_type,
            converted_has_permissions=converted_has_permissions,
        )
        get_metadata = u.prop("metadata")
        get_extensions = u.prop("extensions")
        acl_step1: m.Ldif.Acl = (
            converted_acl.model_copy(
                update={
                    "metadata": original_acl.metadata.model_copy(deep=True)
                    if original_acl.metadata
                    else None,
                },
                deep=True,
            )
            if get_metadata(original_acl) and (not get_metadata(converted_acl))
            else converted_acl
        )
        original_metadata = original_acl.metadata
        if not (
            original_metadata is not None
            and get_extensions(original_metadata)
            and get_metadata(acl_step1)
        ):
            return acl_step1
        conv_ext = self._get_extensions_dict(acl_step1)
        orig_ext = self._get_extensions_dict(original_acl)
        merged_ext_raw: t.MutableContainerMapping = {
            **orig_ext,
            **conv_ext,
        }
        if (
            not merged_ext_raw
            or not get_metadata(acl_step1)
            or (not acl_step1.metadata)
        ):
            return acl_step1
        dynamic_metadata_dict: t.MutableContainerMapping = {}
        for key, value in merged_ext_raw.items():
            if value is None:
                dynamic_metadata_dict[key] = ""
                continue
            if isinstance(value, t.SCALAR_TYPES):
                dynamic_metadata_dict[key] = self._convert_to_metadata_attribute_value(
                    value,
                )
                continue
            if isinstance(value, Mapping):
                normalized_mapping: t.MutableContainerMapping = {}
                for raw_k, raw_v in value.items():
                    normalized_mapping[str(raw_k)] = (
                        FlextLdifConversion._normalize_metadata_value(raw_v)
                    )
                dynamic_metadata_dict[key] = self._convert_to_metadata_attribute_value(
                    normalized_mapping,
                )
                continue
            if isinstance(value, Sequence) and not isinstance(value, str | bytes):
                normalized_sequence: t.MutableContainerList = [
                    FlextLdifConversion._normalize_metadata_value(raw_item)
                    for raw_item in value
                ]
                dynamic_metadata_dict[key] = self._convert_to_metadata_attribute_value(
                    normalized_sequence,
                )
                continue
            dynamic_metadata_dict[key] = self._convert_to_metadata_attribute_value(
                str(value),
            )
        if acl_step1.metadata:
            metadata_kwargs: t.MutableContainerMapping = dynamic_metadata_dict
            updated_metadata = acl_step1.metadata.model_copy(
                update={
                    "extensions": m.Ldif.DynamicMetadata.from_dict(metadata_kwargs),
                },
                deep=True,
            )
            return acl_step1.model_copy(
                update={"metadata": updated_metadata},
                deep=True,
            )
        return acl_step1

    def _preserve_permissions(
        self,
        original_acl: m.Ldif.Acl,
        converted_acl: m.Ldif.Acl,
        source_server_type: str | None,
        target_server_type: str | None,
        *,
        converted_has_permissions: bool,
    ) -> m.Ldif.Acl:
        """Preserve permissions from original ACL."""
        if not original_acl.permissions:
            return converted_acl
        orig_perms_dict_raw = original_acl.permissions.model_dump(exclude_unset=True)
        orig_perms_dict: t.MutableBoolMapping = {
            k: v for k, v in orig_perms_dict_raw.items() if v is True
        }
        logger.debug(
            "ACL permission preservation",
            source_server_type=source_server_type or "",
            target_server_type=target_server_type or "",
            original_permissions=str(orig_perms_dict),
        )
        if orig_perms_dict:
            return self._apply_permission_mapping(
                original_acl=original_acl,
                converted_acl=converted_acl,
                orig_perms_dict=orig_perms_dict,
                source_server_type=source_server_type,
                target_server_type=target_server_type,
                converted_has_permissions=converted_has_permissions,
            )
        return converted_acl

    def _resolve_schema_quirk(
        self,
        quirk_or_type: str | FlextLdifServersBase,
        *,
        role: str,
    ) -> r[p.Ldif.SchemaQuirk]:
        quirk = self._resolve_quirk(quirk_or_type)
        try:
            schema = FlextLdifConversion._get_schema_quirk(quirk)
            return r[p.Ldif.SchemaQuirk].ok(schema)
        except TypeError as e:
            return r[p.Ldif.SchemaQuirk].fail(f"{role} quirk error: {e}")

    def _update_entry_metadata(
        self,
        entry: m.Ldif.Entry,
        validated_quirk_type: c.Ldif.ServerTypeLiteral,
        conversion_analysis: str | None,
        source_quirk_name: str,
    ) -> m.Ldif.Entry:
        """Update entry metadata for conversion (internal helper)."""
        get_metadata = u.prop("metadata")
        get_extensions = u.prop("extensions")
        current_entry = entry
        if not get_metadata(current_entry):
            metadata_obj = m.Ldif.QuirkMetadata.create_for(
                quirk_type=validated_quirk_type,
                extensions=None,
            )
            current_entry = current_entry.model_copy(
                update={"metadata": metadata_obj},
                deep=True,
            )
        entry_metadata = current_entry.metadata
        if (
            entry_metadata
            and get_metadata(current_entry)
            and (not get_extensions(entry_metadata))
        ):
            updated_metadata = entry_metadata.model_copy(
                update={"extensions": m.Ldif.DynamicMetadata()},
                deep=True,
            )
            current_entry = current_entry.model_copy(
                update={"metadata": updated_metadata},
                deep=True,
            )
        entry_metadata = current_entry.metadata
        if entry_metadata and get_metadata(current_entry):
            normalized_source_server: c.Ldif.ServerTypeLiteral | None = None
            if source_quirk_name != c.IDENTIFIER_UNKNOWN:
                normalized_source_server = u.try_(
                    lambda: u.Ldif.normalize_server_type(source_quirk_name),
                    default=None,
                ).map_or(None)
            extensions_update: t.MutableContainerMapping = {
                "converted_from_server": source_quirk_name,
            }
            if conversion_analysis:
                extensions_update["conversion_analysis"] = conversion_analysis
            updated_extensions = (
                entry_metadata.extensions or m.Ldif.DynamicMetadata()
            ).model_copy(update=extensions_update, deep=True)
            updated_metadata = entry_metadata.model_copy(
                update={
                    "quirk_type": validated_quirk_type,
                    "extensions": updated_extensions,
                    "original_server_type": (
                        entry_metadata.original_server_type or normalized_source_server
                    ),
                    "target_server_type": validated_quirk_type,
                },
                deep=True,
            )
            current_entry = current_entry.model_copy(
                update={"metadata": updated_metadata},
                deep=True,
            )
        return current_entry

    def _write_attribute_to_rfc(
        self,
        source: str | FlextLdifServersBase,
        source_attr: t.Ldif.SchemaConversionValue,
    ) -> r[t.Ldif.SchemaConversionValue]:
        """Write attribute to RFC string representation."""
        if isinstance(source_attr, str):
            return r[t.Ldif.SchemaConversionValue].ok(source_attr)
        if not isinstance(source_attr, m.Ldif.SchemaAttribute):
            return r[t.Ldif.SchemaConversionValue].ok(source_attr)
        source_quirk = self._resolve_quirk(source)
        try:
            schema_quirk = FlextLdifConversion._get_schema_quirk(source_quirk)
        except TypeError:
            return r[t.Ldif.SchemaConversionValue].ok(source_attr)
        if not isinstance(schema_quirk, FlextLdifServersBaseSchema):
            return r[t.Ldif.SchemaConversionValue].ok(source_attr)

        write_res = schema_quirk.write_attribute(source_attr)
        # Use return value directly if possible, else wrap
        if write_res.success:
            return r[t.Ldif.SchemaConversionValue].ok(write_res.value)
        return r[t.Ldif.SchemaConversionValue].fail(
            write_res.error or "Schema write failed",
        )

    def _write_objectclass_to_rfc(
        self,
        source: str | FlextLdifServersBase,
        source_oc: t.Ldif.SchemaConversionValue,
    ) -> r[t.Ldif.SchemaConversionValue]:
        """Write objectClass to RFC string representation."""
        passthrough = FlextLdifConversion._schema_passthrough_ok(source_oc)
        if passthrough is not None:
            return passthrough
        if not isinstance(source_oc, m.Ldif.SchemaObjectClass):
            msg = f"Expected SchemaObjectClass | str | dict, got {type(source_oc)}"
            raise TypeError(msg)
        source_quirk = self._resolve_quirk(source)
        try:
            schema_quirk = FlextLdifConversion._get_schema_quirk(source_quirk)
        except TypeError:
            return r[t.Ldif.SchemaConversionValue].ok(source_oc)
        if not isinstance(schema_quirk, FlextLdifServersBaseSchema):
            return r[t.Ldif.SchemaConversionValue].ok(source_oc)

        write_res = schema_quirk.write_objectclass(source_oc)
        if write_res.success:
            return r[t.Ldif.SchemaConversionValue].ok(write_res.value)
        return r[t.Ldif.SchemaConversionValue].fail(
            write_res.error or "Schema OC write failed",
        )

    def _write_target_attribute(
        self,
        parsed_attr: t.Ldif.SchemaConversionValue,
    ) -> r[t.Ldif.SchemaConversionValue]:
        """Write target attribute to final format."""
        passthrough = FlextLdifConversion._schema_passthrough_ok(parsed_attr)
        if passthrough is not None:
            return passthrough
        if isinstance(parsed_attr, m.Ldif.SchemaAttribute):
            return FlextLdifConversion._schema_conversion_ok(parsed_attr)
        msg = f"Expected SchemaAttribute | dict | str, got {type(parsed_attr)}"
        raise TypeError(msg)

    def _write_target_objectclass(
        self,
        target: str | FlextLdifServersBase,
        parsed_oc: t.Ldif.SchemaConversionValue,
    ) -> r[t.Ldif.SchemaConversionValue]:
        """Write target objectClass to final format."""
        passthrough = FlextLdifConversion._schema_passthrough_ok(parsed_oc)
        if passthrough is not None:
            return passthrough
        if not isinstance(parsed_oc, m.Ldif.SchemaObjectClass):
            msg = f"Expected SchemaObjectClass | str | dict, got {type(parsed_oc)}"
            raise TypeError(msg)
        target_quirk = self._resolve_quirk(target)
        try:
            schema_quirk = FlextLdifConversion._get_schema_quirk(target_quirk)
        except TypeError:
            return FlextLdifConversion._schema_conversion_ok(parsed_oc)
        if not isinstance(schema_quirk, FlextLdifServersBaseSchema):
            return FlextLdifConversion._schema_conversion_ok(parsed_oc)
        write_result = schema_quirk.write_objectclass(parsed_oc)
        if write_result.success:
            return FlextLdifConversion._schema_conversion_ok(write_result.value)
        error_msg = write_result.error or "Failed to write objectClass"
        return FlextLdifConversion._schema_conversion_fail(
            error_msg,
            "Failed to write objectClass",
        )


__all__ = ["FlextLdifConversion"]
