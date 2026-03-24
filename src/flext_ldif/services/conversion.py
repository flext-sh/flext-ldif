"""Quirks conversion matrix for LDAP server translation."""

from __future__ import annotations

import struct
import time
from collections.abc import Callable, Mapping, MutableMapping, MutableSequence, Sequence
from datetime import datetime
from typing import (
    Annotated,
    ClassVar,
    Final,
    Literal,
    Self,
    TypeIs,
    override,
)

from flext_core import FlextLogger
from pydantic import Field

from flext_ldif import (
    FlextLdifServer,
    FlextLdifServersBase,
    FlextLdifServersBaseSchema,
    FlextLdifServersOidConstants,
    FlextLdifServiceBase,
    FlextLdifUtilitiesDN,
    c,
    m,
    p,
    r,
    t,
    u,
)

TUPLE_LENGTH_PAIR = 2
logger = FlextLogger(__name__)


class _MissingSentinel:
    pass


_MISSING_ATTR: Final[_MissingSentinel] = _MissingSentinel()


class FlextLdifConversion(
    FlextLdifServiceBase[
        m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
    ],
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
        obj: t.NormalizedValue | FlextLdifServersBase | p.Ldif.SchemaQuirk,
    ) -> TypeIs[p.Ldif.SchemaQuirk]:
        return (
            FlextLdifConversion._has_attr(obj, "parse")
            and FlextLdifConversion._has_attr(obj, "write")
            and FlextLdifConversion._has_attr(obj, "write_attribute")
        )

    @staticmethod
    def _is_mapping_value(
        value: t.NormalizedValue,
    ) -> TypeIs[Mapping[str, t.NormalizedValue]]:
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
            "parse",
        ) or not FlextLdifConversion._has_attr(quirk, "write_attribute"):
            msg = f"Expected Schema quirk, got {type(quirk)}"
            raise TypeError(msg)
        if not FlextLdifConversion._is_schema_quirk_protocol(quirk):
            msg = f"Quirk {type(quirk)} doesn't satisfy SchemaQuirk"
            raise TypeError(msg)
        return quirk

    _PERMISSION_KEY_MAPPING: ClassVar[MutableMapping[str, str]] = {
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

    dn_registry: Annotated[
        m.Ldif.DnRegistry,
        Field(default_factory=_default_dn_registry),
    ]

    def __new__(cls) -> Self:
        """Create service instance with matching signature for type checker."""
        instance = super().__new__(cls)
        if not isinstance(instance, cls):
            msg = f"Expected {cls.__name__}, got {type(instance).__name__}"
            raise TypeError(msg)
        return instance

    def __init__(self) -> None:
        """Initialize the conversion facade with DN case registry."""
        super().__init__()

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
    ) -> MutableMapping[str, MutableMapping[str, str]]:
        """Analyze boolean conversions for target compatibility."""
        if not boolean_conversions or not FlextLdifConversion._is_mapping_value(
            boolean_conversions,
        ):
            return {}
        typed_boolean_conversions: t.MutableContainerMapping = {}
        for raw_attr_name, raw_conv_info in boolean_conversions.items():
            typed_boolean_conversions[str(raw_attr_name)] = raw_conv_info
        result: MutableMapping[str, MutableMapping[str, str]] = {}
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
    ) -> MutableMapping[str, str | MutableMapping[str, str | t.NormalizedValue]]:
        """Analyze source metadata for intelligent conversion to target server."""
        conversion_analysis: MutableMapping[
            str,
            str | MutableMapping[str, str | t.NormalizedValue],
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
            str | MutableMapping[str, str | t.NormalizedValue],
        ] = {}
        for key, value in boolean_analysis.items():
            if isinstance(value, str):
                acc_typed[key] = value
            elif isinstance(value, dict):
                acc_typed[key] = {
                    str(k): FlextLdifConversion._normalize_metadata_value(v)
                    for k, v in value.items()
                }
        attr_case_analysis = FlextLdifConversion._analyze_attribute_case(
            get_attr_case(source_metadata)
            if get_attr_case(source_metadata) is not None
            else {},
            target_server_str,
        )
        for key, attr_case_value in attr_case_analysis.items():
            if isinstance(attr_case_value, dict):
                acc_typed[key] = {
                    str(k): FlextLdifConversion._normalize_metadata_value(v)
                    for k, v in attr_case_value.items()
                }
        dn_format_analysis = FlextLdifConversion._analyze_dn_format(
            get_format_details(source_metadata)
            if get_format_details(source_metadata) is not None
            else {},
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
        orig_perms_dict: MutableMapping[str, bool],
        converted_acl: m.Ldif.Acl,
        perms_to_model: Callable[
            [MutableMapping[str, bool | None]],
            m.Ldif.AclPermissions,
        ],
    ) -> m.Ldif.Acl:
        """Apply OID to OUD permission mapping."""
        normalized_orig_perms: MutableMapping[str, bool] = {
            FlextLdifConversion._normalize_permission_key(k): v
            for k, v in orig_perms_dict.items()
        }
        mapped_perms = u.Ldif.map_oid_to_oud_permissions(normalized_orig_perms)
        oid_to_oud_perms = FlextLdifConversion._build_permissions_dict(mapped_perms)
        perms_model = perms_to_model(oid_to_oud_perms)
        return converted_acl.model_copy(update={"permissions": perms_model}, deep=True)

    @staticmethod
    def _apply_oud_to_oid_mapping(
        orig_perms_dict: MutableMapping[str, bool],
        converted_acl: m.Ldif.Acl,
        perms_to_model: Callable[
            [MutableMapping[str, bool | None]],
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
        mapped_perms: MutableMapping[str, bool],
    ) -> MutableMapping[str, bool | None]:
        """Build permissions dict with standard keys."""
        result: MutableMapping[str, bool | None] = {}
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
    ) -> r[
        m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
    ]:
        """Convert SchemaAttribute model via write_attribute->parse_attribute pipeline."""
        try:
            source_schema_result = FlextLdifConversion._get_schema_quirk_safe(
                source_quirk,
                "Source",
            )
            source_schema = source_schema_result.map_or(None)
            if source_schema is None:
                return r[
                    m.Ldif.Entry
                    | m.Ldif.SchemaAttribute
                    | m.Ldif.SchemaObjectClass
                    | m.Ldif.Acl
                ].fail(source_schema_result.error or "Source schema not available")
            target_schema_result = FlextLdifConversion._get_schema_quirk_safe(
                target_quirk,
                "Target",
            )
            if target_schema_result.is_failure:
                return r[
                    m.Ldif.Entry
                    | m.Ldif.SchemaAttribute
                    | m.Ldif.SchemaObjectClass
                    | m.Ldif.Acl
                ].fail(
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
            return r[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ].fail(f"SchemaAttribute conversion failed: {e}")

    @staticmethod
    def _convert_schema_objectclass(
        source_quirk: FlextLdifServersBase,
        target_quirk: FlextLdifServersBase,
        objectclass: m.Ldif.SchemaObjectClass,
    ) -> r[
        m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
    ]:
        """Convert SchemaObjectClass model via write_objectclass->parse_objectclass pipeline."""
        try:
            source_schema_result = FlextLdifConversion._get_schema_quirk_safe(
                source_quirk,
                "Source",
            )
            source_schema = source_schema_result.map_or(None)
            if source_schema is None:
                return r[
                    m.Ldif.Entry
                    | m.Ldif.SchemaAttribute
                    | m.Ldif.SchemaObjectClass
                    | m.Ldif.Acl
                ].fail(source_schema_result.error or "Source schema not available")
            target_schema_result = FlextLdifConversion._get_schema_quirk_safe(
                target_quirk,
                "Target",
            )
            target_schema = target_schema_result.map_or(None)
            if target_schema is None:
                return r[
                    m.Ldif.Entry
                    | m.Ldif.SchemaAttribute
                    | m.Ldif.SchemaObjectClass
                    | m.Ldif.Acl
                ].fail(target_schema_result.error or "Target schema not available")

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
            return r[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ].fail(f"SchemaObjectClass conversion failed: {e}")

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
        if result.is_failure:
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
        if parse_result.is_failure:
            return r[m.Ldif.SchemaAttribute].fail(
                parse_result.error or parse_error_message,
            )
        return r[m.Ldif.SchemaAttribute].ok(parse_result.value)

    @staticmethod
    def _parse_objectclass_with_schema(
        schema: p.Ldif.SchemaQuirk,
        value: str,
        *,
        parse_error_message: str,
    ) -> r[m.Ldif.SchemaObjectClass]:
        parse_result = schema.parse_objectclass(value)
        if parse_result.is_failure:
            return r[m.Ldif.SchemaObjectClass].fail(
                parse_result.error or parse_error_message,
            )
        return r[m.Ldif.SchemaObjectClass].ok(parse_result.value)

    @staticmethod
    def _perms_dict_to_model(
        perms_dict: MutableMapping[str, bool | None],
    ) -> m.Ldif.AclPermissions:
        """Convert permissions dict to AclPermissions model."""
        clean_dict: MutableMapping[str, bool] = {
            k: v for k, v in perms_dict.items() if v is not None
        }
        return m.Ldif.AclPermissions.model_validate(clean_dict)

    @staticmethod
    def _process_schema_conversion_pipeline(
        config: m.Ldif.SchemaAttributeConversionPipelineConfig
        | m.Ldif.SchemaObjectClassConversionPipelineConfig,
    ) -> r[t.Ldif.ConvertedModel]:
        """Process schema conversion pipeline using direct method dispatch."""
        write_result = (
            config.source_schema.write_attribute(config.item)
            if isinstance(config, m.Ldif.SchemaAttributeConversionPipelineConfig)
            else config.source_schema.write_objectclass(config.item)
        )
        if write_result.is_failure:
            return r[t.Ldif.ConvertedModel].fail(
                f"Failed to write {config.item_name} in source format: {write_result.error}",
            )

        write_val = write_result.value

        ldif_result = FlextLdifConversion._validate_ldif_string(
            write_val,
            config.item_name,
        )
        if ldif_result.is_failure:
            return r[t.Ldif.ConvertedModel].fail(
                ldif_result.error or "LDIF validation failed",
            )
        ldif_string: str = ldif_result.value
        parse_result = (
            config.target_schema.parse_attribute(ldif_string)
            if isinstance(config, m.Ldif.SchemaAttributeConversionPipelineConfig)
            else config.target_schema.parse_objectclass(ldif_string)
        )
        if parse_result.is_failure:
            parse_error = parse_result.error or "Unknown parse error"
            return r[t.Ldif.ConvertedModel].fail(
                f"Failed to parse {config.item_name} in target format: {parse_error}",
            )

        parsed_value = parse_result.value
        return r[t.Ldif.ConvertedModel].ok(parsed_value)

    @staticmethod
    def _resolve_quirk(
        quirk_or_type: str | FlextLdifServersBase,
    ) -> FlextLdifServersBase:
        """Resolve server quirk instance from string type or return instance."""
        if isinstance(quirk_or_type, str):
            server = FlextLdifServer.get_global_instance()
            server_type_str: str = quirk_or_type
            resolved_result = server.quirk(server_type_str)
            if resolved_result.is_failure:
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

    def batch_convert(
        self,
        source: str | FlextLdifServersBase,
        target: str | FlextLdifServersBase,
        model_list: MutableSequence[
            m.Ldif.Entry
            | m.Ldif.SchemaAttribute
            | m.Ldif.SchemaObjectClass
            | m.Ldif.Acl
        ],
    ) -> r[
        MutableSequence[
            m.Ldif.Entry
            | m.Ldif.SchemaAttribute
            | m.Ldif.SchemaObjectClass
            | m.Ldif.Acl
        ]
    ]:
        """Convert multiple models from source to target quirk via RFC."""
        start_time = time.perf_counter()
        if isinstance(source, str):
            source_format: str = source
        else:
            source_name_result = u.prop("server_name")(source)
            source_format = (
                source_name_result
                if isinstance(source_name_result, str)
                else c.IDENTIFIER_UNKNOWN
            )
        if isinstance(target, str):
            target_format: str = target
        else:
            target_name_result = u.prop("server_name")(target)
            target_format = (
                target_name_result
                if isinstance(target_name_result, str)
                else c.IDENTIFIER_UNKNOWN
            )
        if not model_list:
            return r[
                MutableSequence[
                    m.Ldif.Entry
                    | m.Ldif.SchemaAttribute
                    | m.Ldif.SchemaObjectClass
                    | m.Ldif.Acl
                ]
            ].ok([])
        model_type = type(model_list[0]).__name__
        conversion_operation = f"batch_convert_{model_type}"
        try:
            converted: MutableSequence[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ] = []
            errors: MutableSequence[str] = []
            error_details: MutableSequence[str] = []
            for idx, model_item in enumerate(model_list):
                result = self.convert_model(source, target, model_item)
                unwrapped = result.map_or(None)
                if unwrapped is not None:
                    converted.append(unwrapped)
                else:
                    error_msg = result.error or "Unknown error"
                    errors.append(f"Item {idx}: {error_msg}")
                    error_details.append(f"batch_item_{idx}: {error_msg}")
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            model_list_typed: MutableSequence[
                m.Ldif.Acl
                | m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
            ] = [*model_list]
            converted_typed: MutableSequence[
                m.Ldif.Acl
                | m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
            ] = [*converted]
            errors_typed: MutableSequence[str] = errors
            items_processed = u.count(model_list_typed)
            items_converted = u.count(converted_typed)
            items_failed = u.count(errors_typed)
            conversion_config = m.Ldif.ConversionEventConfig(
                conversion_operation=conversion_operation,
                source_format=source_format,
                target_format=target_format,
                items_processed=items_processed,
                items_converted=items_converted,
                items_failed=items_failed,
                conversion_duration_ms=duration_ms,
                error_details=error_details or None,
            )
            if FlextLdifConversion._has_attr(logger, "bind") and callable(
                getattr(logger, "bind", None),
            ):
                _ = u.Ldif.log_and_emit_conversion_event(
                    logger=logger,
                    config=conversion_config,
                    log_level="warning" if errors else "info",
                )
            if errors:
                error_count = u.count(errors)
                error_msg = (
                    f"Batch conversion completed with {error_count} errors:\n"
                    + "\n".join(errors[: self.MAX_ERRORS_TO_SHOW])
                )
                if error_count > self.MAX_ERRORS_TO_SHOW:
                    error_msg += (
                        f"\n... and {error_count - self.MAX_ERRORS_TO_SHOW} more errors"
                    )
                return r[
                    MutableSequence[
                        m.Ldif.Entry
                        | m.Ldif.SchemaAttribute
                        | m.Ldif.SchemaObjectClass
                        | m.Ldif.Acl
                    ]
                ].fail(error_msg)
            return r[
                MutableSequence[
                    m.Ldif.Entry
                    | m.Ldif.SchemaAttribute
                    | m.Ldif.SchemaObjectClass
                    | m.Ldif.Acl
                ]
            ].ok(converted)
        except (ValueError, TypeError, AttributeError, RuntimeError, Exception) as e:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            model_list_as_list: MutableSequence[
                m.Ldif.Acl
                | m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
            ] = [*model_list] if model_list else []
            items_count = u.count(model_list_as_list)
            conversion_config = m.Ldif.ConversionEventConfig(
                conversion_operation=conversion_operation,
                source_format=source_format,
                target_format=target_format,
                items_processed=items_count,
                items_converted=0,
                items_failed=items_count,
                conversion_duration_ms=duration_ms,
                error_details=[f"batch_conversion: Batch conversion failed: {e}"],
            )
            if FlextLdifConversion._has_attr(logger, "bind") and callable(
                getattr(logger, "bind", None),
            ):
                _ = u.Ldif.log_and_emit_conversion_event(
                    logger=logger,
                    config=conversion_config,
                    log_level="error",
                )
            return r[
                MutableSequence[
                    m.Ldif.Entry
                    | m.Ldif.SchemaAttribute
                    | m.Ldif.SchemaObjectClass
                    | m.Ldif.Acl
                ]
            ].fail(f"Batch conversion failed: {e}")

    def convert_model(
        self,
        source: str | FlextLdifServersBase,
        target: str | FlextLdifServersBase,
        model_instance: m.Ldif.Entry
        | m.Ldif.SchemaAttribute
        | m.Ldif.SchemaObjectClass
        | m.Ldif.Acl,
    ) -> r[
        m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
    ]:
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
        items_converted = 1 if result.is_success else 0
        items_failed = 0 if result.is_success else 1
        conversion_config = m.Ldif.ConversionEventConfig(
            conversion_operation=conversion_operation,
            source_format=source_format,
            target_format=target_format,
            items_processed=1,
            items_converted=items_converted,
            items_failed=items_failed,
            conversion_duration_ms=duration_ms,
            error_details=[f"{model_type}: {result.error or 'Unknown error'}"]
            if result.is_failure
            else [],
        )
        _ = u.Ldif.log_and_emit_conversion_event(
            logger=logger,
            config=conversion_config,
            log_level="info" if result.is_success else "error",
        )
        return result

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
    ) -> MutableMapping[str, bool]:
        """Check which data types a quirk supports for conversion."""
        support: t.Ldif.DistributionDict = {
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

    def reset_dn_registry(self) -> None:
        """Clear DN registry for new conversion session."""
        self.dn_registry.clear()

    def validate_oud_conversion(self) -> r[bool]:
        """Validate DN case consistency for OUD target conversion."""
        return self.dn_registry.validate_oud_consistency()

    def _apply_permission_mapping(
        self,
        config: m.Ldif.PermissionMappingConfig | None = None,
        *,
        original_acl: m.Ldif.Acl | None = None,
        converted_acl: m.Ldif.Acl | None = None,
        orig_perms_dict: MutableMapping[str, bool] | None = None,
        source_server_type: str | None = None,
        target_server_type: str | None = None,
        converted_has_permissions: bool = False,
    ) -> m.Ldif.Acl:
        """Apply permission mapping based on server types."""
        if config is None:
            if original_acl is None or converted_acl is None:
                if converted_acl is not None:
                    return converted_acl
                if original_acl is not None:
                    return original_acl
                return m.Ldif.Acl(
                    server_type="rfc",
                    validation_violations=[],
                    name="",
                    target=None,
                    subject=None,
                    permissions=None,
                    raw_line="",
                    raw_acl="",
                    metadata=None,
                )
            config = m.Ldif.PermissionMappingConfig(
                original_acl=original_acl,
                converted_acl=converted_acl,
                orig_perms_dict=dict(orig_perms_dict or {}),
                source_server_type=source_server_type,
                target_server_type=target_server_type,
                converted_has_permissions=converted_has_permissions,
            )
        normalized_source = (
            u.Ldif.normalize_server_type(config.source_server_type)
            if isinstance(config.source_server_type, str)
            else config.source_server_type
        )
        normalized_target = (
            u.Ldif.normalize_server_type(config.target_server_type)
            if isinstance(config.target_server_type, str)
            else config.target_server_type
        )
        mapping_type = "none"
        pair = (normalized_source, normalized_target)
        if pair == ("oid", "oud"):
            mapping_type = "oid_to_oud"
        elif pair == ("oud", "oid"):
            mapping_type = "oud_to_oid"
        elif (
            not config.converted_has_permissions
            and config.original_acl.permissions is not None
        ):
            mapping_type = "preserve_original"
        logger.debug(
            "ACL mapping decision",
            mapping_type=str(mapping_type),
            normalized_source=str(normalized_source),
            normalized_target=str(normalized_target),
        )
        converted_acl_typed: m.Ldif.Acl = config.converted_acl
        if mapping_type == "oid_to_oud":
            return FlextLdifConversion._apply_oid_to_oud_mapping(
                config.orig_perms_dict,
                converted_acl_typed,
                self._perms_dict_to_model,
            )
        if mapping_type == "oud_to_oid":
            return FlextLdifConversion._apply_oud_to_oid_mapping(
                config.orig_perms_dict,
                converted_acl_typed,
                self._perms_dict_to_model,
            )
        if mapping_type == "preserve_original":
            original_acl_typed: m.Ldif.Acl = config.original_acl
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
        support: t.Ldif.DistributionDict,
    ) -> t.Ldif.DistributionDict:
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
        support: t.Ldif.DistributionDict,
    ) -> t.Ldif.DistributionDict:
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
        if isinstance(attr_result, r) and attr_result.is_success:
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
        support: t.Ldif.DistributionDict,
    ) -> t.Ldif.DistributionDict:
        """Check Entry support."""
        entry = getattr(quirk, "entry_quirk", None)
        if entry is None:
            entry = getattr(quirk, "_entry_quirk", None)
        if (
            entry is None
            and FlextLdifConversion._has_attr(quirk, "parse")
            and FlextLdifConversion._has_attr(quirk, "can_handle_entry")
        ):
            entry = quirk
        if entry is not None and callable(getattr(entry, "parse", None)):
            support["entry"] = 1
        return support

    def _check_objectclass_support(
        self,
        quirk_schema: t.NormalizedValue | FlextLdifServersBase,
        test_oc_def: str,
        support: t.Ldif.DistributionDict,
    ) -> t.Ldif.DistributionDict:
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
        if isinstance(oc_result, r) and oc_result.is_success:
            support["objectclass"] = 1
        return support

    def _check_schema_support(
        self,
        quirk: FlextLdifServersBase,
        support: t.Ldif.DistributionDict,
    ) -> t.Ldif.DistributionDict:
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
    ) -> r[
        m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
    ]:
        """Convert Acl model via Entry RFC + Metadata pipeline."""
        try:
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
            entry_metadata.acls = [acl.raw_acl] if acl.raw_acl else []
            rfc_entry = m.Ldif.Entry.model_validate({
                "dn": entry_dn,
                "attributes": entry_attributes,
                "metadata": entry_metadata,
            })
            entry_result = self._convert_entry(source_quirk, target_quirk, rfc_entry)
            if entry_result.is_failure:
                return entry_result
            converted_entry_value = entry_result.value
            if not isinstance(converted_entry_value, m.Ldif.Entry):
                return r[
                    m.Ldif.Entry
                    | m.Ldif.SchemaAttribute
                    | m.Ldif.SchemaObjectClass
                    | m.Ldif.Acl
                ].fail(
                    f"Entry conversion returned unexpected type: {type(converted_entry_value).__name__}",
                )
            converted_entry: m.Ldif.Entry = converted_entry_value
            get_metadata = u.prop("metadata")
            get_acls = u.prop("acls")
            converted_metadata_raw = get_metadata(converted_entry)
            if not isinstance(
                converted_metadata_raw,
                (m.Ldif.QuirkMetadata, type(None)),
            ):
                return r[
                    m.Ldif.Entry
                    | m.Ldif.SchemaAttribute
                    | m.Ldif.SchemaObjectClass
                    | m.Ldif.Acl
                ].fail(
                    f"Unexpected metadata type: {type(converted_metadata_raw).__name__}",
                )
            converted_metadata: m.Ldif.QuirkMetadata | None = converted_metadata_raw
            acls_raw = get_acls(converted_metadata) if converted_metadata else None
            acls: MutableSequence[m.Ldif.Acl] | None = None
            if acls_raw is not None and isinstance(acls_raw, list):
                acls = [item for item in acls_raw if isinstance(item, m.Ldif.Acl)]
            if not acls:
                return r[
                    m.Ldif.Entry
                    | m.Ldif.SchemaAttribute
                    | m.Ldif.SchemaObjectClass
                    | m.Ldif.Acl
                ].fail("Converted entry has no ACLs in metadata.acls")
            if not acls or not acls:
                return r[
                    m.Ldif.Entry
                    | m.Ldif.SchemaAttribute
                    | m.Ldif.SchemaObjectClass
                    | m.Ldif.Acl
                ].fail("No ACL found in converted entry metadata")
            domain_acl = acls[0]
            converted_acl: m.Ldif.Acl = domain_acl
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
            converted_acl = self._preserve_acl_metadata(
                acl,
                converted_acl,
                source_server_type=source_server_type,
                target_server_type=target_server_type,
            )
            converted_acl = converted_acl.model_copy(
                update={"server_type": target_server_type},
                deep=True,
            )
            return r[t.Ldif.ConvertedModel].ok(converted_acl)
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            logger.exception("Failed to convert ACL model", error=str(e))
            return r[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ].fail(f"Acl conversion failed: {e}")

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
            parse_result = self._parse_attribute_with_schema(
                schema,
                value,
                parse_error_message=parse_error_message,
            )
            if parse_result.is_failure:
                return FlextLdifConversion._schema_conversion_fail(
                    parse_result.error,
                    parse_error_message,
                )
            return FlextLdifConversion._schema_conversion_ok(parse_result.value)

        parse_result = self._parse_objectclass_with_schema(
            schema,
            value,
            parse_error_message=parse_error_message,
        )
        if parse_result.is_failure:
            return FlextLdifConversion._schema_conversion_fail(
                parse_result.error,
                parse_error_message,
            )
        return FlextLdifConversion._schema_conversion_ok(parse_result.value)

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
            if not isinstance(data, str):
                return r[t.Ldif.SchemaConversionValue].fail(required_string_message)
            source_schema_result = self._resolve_schema_quirk(source, role="Source")
            if source_schema_result.is_failure:
                return FlextLdifConversion._schema_conversion_fail(
                    source_schema_result.error,
                    "Source schema not available",
                )
            parse_result = self._parse_schema_item_with_schema(
                source_schema_result.value,
                data,
                parse_error_message=source_parse_error_message,
                schema_item_kind=schema_item_kind,
            )
            if parse_result.is_failure:
                return FlextLdifConversion._schema_conversion_fail(
                    parse_result.error,
                    source_parse_failure_message,
                )
            parsed_item = parse_result.value
            rfc_result = (
                self._write_attribute_to_rfc(source, parsed_item)
                if schema_item_kind == "attribute"
                else self._write_objectclass_to_rfc(source, parsed_item)
            )
            if rfc_result.is_failure:
                return rfc_result
            rfc_value = rfc_result.value

            if not isinstance(rfc_value, str):
                return FlextLdifConversion._schema_conversion_ok(rfc_value)

            target_schema_result = self._resolve_schema_quirk(target, role="Target")
            if target_schema_result.is_failure:
                return FlextLdifConversion._schema_conversion_fail(
                    target_schema_result.error,
                    "Target schema not available",
                )
            target_parse_result = self._parse_schema_item_with_schema(
                target_schema_result.value,
                rfc_value,
                parse_error_message=target_parse_error_message,
                schema_item_kind=schema_item_kind,
            )
            if target_parse_result.is_failure:
                return FlextLdifConversion._schema_conversion_fail(
                    target_parse_result.error,
                    target_parse_failure_message,
                )

            final_val: t.Ldif.SchemaConversionValue = target_parse_result.value
            return FlextLdifConversion._schema_conversion_ok(final_val)
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

    def _convert_entry(
        self,
        source_quirk: FlextLdifServersBase,
        target_quirk: FlextLdifServersBase,
        entry: m.Ldif.Entry,
    ) -> r[
        m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
    ]:
        """Convert Entry model directly without serialization."""
        try:
            entry_dn = entry.dn.value if entry.dn else ""
            is_valid: bool = FlextLdifUtilitiesDN.validate_dn(entry_dn)
            if not is_valid:
                return r[
                    m.Ldif.Entry
                    | m.Ldif.SchemaAttribute
                    | m.Ldif.SchemaObjectClass
                    | m.Ldif.Acl
                ].fail(f"Entry DN failed RFC 4514 validation: {entry_dn}")
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
                target_server_type_str = "rfc"
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
            source_type_norm = str(source_quirk_name).lower()
            target_type_norm = str(target_server_type_str).lower()
            converted_entry = self._update_entry_metadata(
                converted_entry,
                validated_quirk_type,
                str(conversion_analysis) if conversion_analysis else None,
                str(source_quirk_name),
            )
            if (
                source_type_norm == "oid"
                and target_type_norm == "rfc"
                and converted_entry.attributes
                and converted_entry.attributes.attributes
            ):
                current_attrs = dict(converted_entry.attributes.attributes)
                updated_attrs: MutableMapping[str, MutableSequence[str]] = {}
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
                updated_attrs_rfc_to_oid: MutableMapping[str, MutableSequence[str]] = {}
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
            return r[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ].ok(converted_entry)
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            logger.exception("Failed to convert Entry model", error=str(e))
            return r[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ].fail(f"Entry conversion failed: {e}")

    def _convert_model(
        self,
        source: str | FlextLdifServersBase,
        target: str | FlextLdifServersBase,
        model_instance: m.Ldif.Entry
        | m.Ldif.SchemaAttribute
        | m.Ldif.SchemaObjectClass
        | m.Ldif.Acl,
    ) -> r[
        m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
    ]:
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
            return r[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ].fail(f"Model conversion failed: {e}")

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
            converted_list: MutableSequence[t.Scalar] = []
            for item in value:
                if isinstance(item, t.SCALAR_TYPES):
                    converted_list.append(item)
                else:
                    converted_list.append(str(item))
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
            required_methods = ("parse", "write")
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
            required_methods = ("parse", "write")
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
        orig_perms_dict: MutableMapping[str, bool] = {
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
            extensions_update: t.MutableContainerMapping = {
                "converted_from_server": source_quirk_name,
            }
            if conversion_analysis:
                extensions_update["conversion_analysis"] = conversion_analysis
            updated_extensions = (
                entry_metadata.extensions or m.Ldif.DynamicMetadata()
            ).model_copy(update=extensions_update, deep=True)
            updated_metadata = entry_metadata.model_copy(
                update={"extensions": updated_extensions},
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
        if write_res.is_success:
            return r[t.Ldif.SchemaConversionValue].ok(write_res.value)
        return r[t.Ldif.SchemaConversionValue].fail(
            write_res.error or "Schema write failed"
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
        if write_res.is_success:
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
        written_str = write_result.map_or(None)
        if written_str is not None:
            return FlextLdifConversion._schema_conversion_ok(written_str)
        error_msg = write_result.error or "Failed to write objectClass"
        return FlextLdifConversion._schema_conversion_fail(
            error_msg,
            "Failed to write objectClass",
        )


__all__ = ["FlextLdifConversion"]
