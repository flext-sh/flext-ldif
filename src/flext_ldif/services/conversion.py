"""Quirks conversion matrix for LDAP server translation."""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import ClassVar, Self, TypeGuard, TypeVar, cast, override

from flext_core import FlextLogger, FlextResult, FlextTypes, r
from pydantic import Field

from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.protocols import p
from flext_ldif.servers._oid.constants import FlextLdifServersOidConstants
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.typings import t
from flext_ldif.utilities import u

TUPLE_LENGTH_PAIR = 2
_TSchemaItem = TypeVar("_TSchemaItem", m.Ldif.SchemaAttribute, m.Ldif.SchemaObjectClass)
type _TConvertedModel = (
    m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
)
type _TSchemaConversionValue = (
    m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str | t.MetadataAttributeValue
)

logger = FlextLogger(__name__)


def _is_schema_quirk_protocol(
    obj: FlextTypes.GeneralValueType,
) -> TypeGuard[p.Ldif.SchemaQuirkProtocol]:
    """TypeGuard to check if object satisfies SchemaQuirkProtocol."""
    return (
        hasattr(obj, "parse")
        and hasattr(obj, "write")
        and hasattr(obj, "write_attribute")
    )


def _get_schema_quirk(
    quirk: FlextLdifServersBase,
) -> p.Ldif.SchemaQuirkProtocol:
    """Get schema quirk from base quirk with proper type narrowing."""
    return _get_schema_from_attribute(quirk)


def _validate_schema_quirk(
    quirk: FlextLdifServersBase,
) -> p.Ldif.SchemaQuirkProtocol:
    """Validate and return quirk as Schema protocol."""
    if not hasattr(quirk, "parse") or not hasattr(quirk, "write_attribute"):
        msg = f"Expected Schema quirk, got {type(quirk)}"
        raise TypeError(msg)

    if not _is_schema_quirk_protocol(quirk):
        msg = f"Quirk {type(quirk)} doesn't satisfy SchemaQuirkProtocol"
        raise TypeError(msg)
    return quirk


def _get_schema_from_attribute(
    quirk: FlextLdifServersBase,
) -> p.Ldif.SchemaQuirkProtocol:
    """Get schema quirk from schema_quirk attribute."""
    if hasattr(quirk, "schema_quirk"):
        schema = quirk.schema_quirk

        if _is_schema_quirk_protocol(schema):
            return schema
        msg = f"Expected Schema quirk, got {type(schema)}"
        raise TypeError(msg)
    msg = "Quirk must be a Schema quirk or have schema_quirk attribute"
    raise TypeError(msg)


class FlextLdifConversion(
    FlextLdifServiceBase[
        m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
    ],
):
    """Facade for universal, model-driven quirk-to-quirk conversion."""

    MAX_ERRORS_TO_SHOW: ClassVar[int] = 5
    _PERMISSION_KEY_MAPPING: ClassVar[dict[str, t.GeneralValueType]] = {
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
    )

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
    def _resolve_quirk(
        quirk_or_type: str | FlextLdifServersBase,
    ) -> FlextLdifServersBase:
        """Resolve server quirk instance from string type or return instance."""
        if isinstance(quirk_or_type, str):
            server = FlextLdifServer()

            server_type_str: str = quirk_or_type
            resolved_result = server.quirk(server_type_str)

            resolved = resolved_result.map_or(None)
            if resolved is None:
                error_msg = f"Unknown server type: {quirk_or_type}"
                raise ValueError(error_msg)

            return resolved

        return quirk_or_type

    @override
    def execute(
        self,
    ) -> r[
        m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
    ]:
        """Execute conversion service health check."""
        try:
            empty_entry = m.Ldif.Entry(
                dn=m.Ldif.DN(value="cn=health-check"),
                attributes=m.Ldif.Attributes(attributes={}),
            )
            return r[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ].ok(empty_entry)
        except Exception as e:
            return r[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ].fail(
                f"Conversion service health check failed: {e}",
            )

    def convert(
        self,
        source: str | FlextLdifServersBase,
        target: str | FlextLdifServersBase,
        model_instance: (
            m.Ldif.Entry
            | m.Ldif.SchemaAttribute
            | m.Ldif.SchemaObjectClass
            | m.Ldif.Acl
        ),
    ) -> r[
        m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
    ]:
        """Convert a model from a source server format to a target server format."""
        start_time = time.perf_counter()

        if isinstance(source, str):
            source_format = source
        else:
            source_format = str(getattr(source, "server_type", "unknown"))
        if isinstance(target, str):
            target_format = target
        else:
            target_format = str(getattr(target, "server_type", "unknown"))

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

        conversion_config = m.Ldif.Events.ConversionEventConfig(
            conversion_operation=conversion_operation,
            source_format=source_format,
            target_format=target_format,
            items_processed=1,
            items_converted=items_converted,
            items_failed=items_failed,
            conversion_duration_ms=duration_ms,
            error_details=[
                m.Ldif.ErrorDetail(
                    item=model_type,
                    error=result.error or "Unknown error",
                ),
            ]
            if result.is_failure
            else [],
        )

        _ = u.Ldif.Events.log_and_emit_conversion_event(
            logger=logger,
            config=conversion_config,
            log_level="info" if result.is_success else "error",
        )

        return result

    def _convert_model(
        self,
        source: str | FlextLdifServersBase,
        target: str | FlextLdifServersBase,
        model_instance: (
            m.Ldif.Entry
            | m.Ldif.SchemaAttribute
            | m.Ldif.SchemaObjectClass
            | m.Ldif.Acl
        ),
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
            if isinstance(model_instance, m.Ldif.Acl):
                return self._convert_acl(source_quirk, target_quirk, model_instance)

            return r[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ].fail(
                f"Unsupported model type for conversion: {type(model_instance).__name__}",
            )

        except Exception as e:
            return FlextResult.fail(f"Model conversion failed: {e}")

    @staticmethod
    def _normalize_metadata_value(value: object) -> t.MetadataAttributeValue:
        """Normalize metadata value to proper type."""
        if isinstance(value, (str, int, float, bool, type(None))):
            return value if value is not None else ""
        if isinstance(value, (list, tuple)):
            return list(value)
        # Removed dict support - strict typing
        return str(value) if value is not None else ""

    @staticmethod
    def _analyze_boolean_conversions(
        boolean_conversions: object,
        target_server_type: str,
    ) -> dict[str, dict[str, str]]:
        """Analyze boolean conversions for target compatibility."""
        if not boolean_conversions or not isinstance(boolean_conversions, dict):
            return {}

        boolean_conv_typed: dict[str, FlextTypes.GeneralValueType] = dict(
            boolean_conversions
        )

        def process_conversion(
            item: tuple[str, FlextTypes.GeneralValueType],
        ) -> tuple[str, dict[str, str]]:
            """Process single conversion info."""
            attr_name, conv_info = item

            if not isinstance(conv_info, dict):
                conv_info_typed: dict[str, FlextTypes.GeneralValueType] = {}
            else:
                conv_info_typed = dict(conv_info)

            if not conv_info_typed:
                return (
                    f"boolean_{attr_name}",
                    {
                        "source_format": "",
                        "target_server": str(target_server_type),
                        "action": "convert_to_target_format",
                    },
                )
            original_format = (
                u.take(conv_info_typed, "format", default="")
                if isinstance(conv_info_typed, dict)
                else ""
            )
            return (
                f"boolean_{attr_name}",
                {
                    "source_format": str(original_format),
                    "target_server": str(target_server_type),
                    "action": "convert_to_target_format",
                },
            )

        if isinstance(boolean_conv_typed, dict):
            pairs_list: list[tuple[str, FlextTypes.GeneralValueType]] = u.Ldif.pairs(
                boolean_conv_typed
            )
        else:
            pairs_list = []

        batch_result = u.Collection.batch(
            pairs_list,
            process_conversion,
            on_error="skip",
        )

        if not batch_result.is_success:
            return {}

        batch_data = batch_result.map_or(None)

        results_list_raw: list[t.GeneralValueType] = []
        if batch_data is not None:
            results_raw = batch_data.results
            if isinstance(results_raw, list):
                results_list_raw = results_raw

        results_list: list[tuple[str, dict[str, str]]] = []
        for item in results_list_raw:
            if not isinstance(item, tuple) or len(item) != TUPLE_LENGTH_PAIR:
                continue
            key_raw, value_raw = item
            if not isinstance(key_raw, str) or not isinstance(value_raw, dict):
                continue
            value_typed = {str(k): str(v) for k, v in value_raw.items()}
            results_list.append((key_raw, value_typed))

        reduced_raw = u.Ldif.reduce_dict(results_list)

        result: dict[str, dict[str, str]] = {}
        if isinstance(reduced_raw, dict):
            for k, v in reduced_raw.items():
                if isinstance(k, str) and isinstance(v, dict):
                    result[k] = {str(kk): str(vv) for kk, vv in v.items()}
        return result

    @staticmethod
    def _analyze_attribute_case(
        original_attribute_case: object,
        target_server_type: str,
    ) -> dict[str, dict[str, t.MetadataAttributeValue]]:
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
    def _analyze_dn_format(
        original_format_details: object,
        target_server_type: str,
    ) -> dict[str, dict[str, t.MetadataAttributeValue]]:
        """Analyze DN spacing for target compatibility."""
        pipe_result = u.Reliability.pipe(
            original_format_details,
            lambda d: u.take(d, "dn_spacing") if isinstance(d, dict) else None,
            lambda spacing: (
                {
                    "dn_format": {
                        "source_dn": FlextLdifConversion._normalize_metadata_value(
                            spacing,
                        ),
                        "target_server": str(target_server_type),
                        "action": "normalize_for_target",
                    },
                }
                if spacing
                else {}
            ),
        )

        if isinstance(pipe_result, dict):
            return pipe_result
        return {}

    @staticmethod
    def _analyze_metadata_for_conversion(
        source_metadata: (m.Ldif.QuirkMetadata | m.Ldif.DynamicMetadata | None),
        target_server_type: str,
    ) -> dict[str, str | dict[str, str | t.MetadataAttributeValue]]:
        """Analyze source metadata for intelligent conversion to target server."""
        conversion_analysis: dict[
            str,
            str | dict[str, str | t.MetadataAttributeValue],
        ] = {}

        if not source_metadata or not hasattr(source_metadata, "boolean_conversions"):
            return conversion_analysis

        target_server_str = str(target_server_type)
        get_boolean = u.mapper().prop("boolean_conversions")
        get_attr_case = u.mapper().prop("original_attribute_case")
        get_format_details = u.mapper().prop("original_format_details")

        boolean_conversions = u.Ldif.maybe(
            get_boolean(source_metadata),
            default={},
        )
        boolean_analysis = FlextLdifConversion._analyze_boolean_conversions(
            boolean_conversions,
            target_server_str,
        )

        acc_typed: dict[str, t.GeneralValueType] = dict(conversion_analysis)

        boolean_analysis_typed: dict[str, t.GeneralValueType] = (
            dict(boolean_analysis) if isinstance(boolean_analysis, dict) else {}
        )

        acc_typed = u.Ldif.evolve(
            acc_typed,
            u.Ldif.map_dict(
                boolean_analysis_typed,
                mapper=lambda k, v: (
                    k,
                    v if isinstance(v, (str, dict)) else str(v),
                ),
            ),
        )

        attr_case_analysis = FlextLdifConversion._analyze_attribute_case(
            u.Ldif.maybe(get_attr_case(source_metadata), default={}),
            target_server_str,
        )

        attr_case_typed: dict[str, t.GeneralValueType] = (
            dict(attr_case_analysis) if isinstance(attr_case_analysis, dict) else {}
        )
        acc_typed = u.Ldif.evolve(acc_typed, attr_case_typed)

        dn_format_analysis = FlextLdifConversion._analyze_dn_format(
            u.Ldif.maybe(get_format_details(source_metadata), default={}),
            target_server_str,
        )

        dn_format_typed: dict[str, t.GeneralValueType] = (
            dict(dn_format_analysis) if isinstance(dn_format_analysis, dict) else {}
        )
        acc_typed = u.Ldif.evolve(acc_typed, dn_format_typed)

        if isinstance(acc_typed, dict):
            normalized: dict[str, str | dict[str, str | t.MetadataAttributeValue]] = {}
            for key, value in acc_typed.items():
                if not isinstance(key, str):
                    continue
                if isinstance(value, str):
                    normalized[key] = value
                    continue
                if isinstance(value, dict):
                    nested: dict[str, str | t.MetadataAttributeValue] = {}
                    for nested_key, nested_value in value.items():
                        nested[str(nested_key)] = (
                            FlextLdifConversion._normalize_metadata_value(
                                nested_value,
                            )
                        )
                    normalized[key] = nested
            return normalized
        return {}

    def _update_entry_metadata(
        self,
        entry: m.Ldif.Entry,
        validated_quirk_type: c.Ldif.LiteralTypes.ServerTypeLiteral,
        conversion_analysis: str | None,
        source_quirk_name: str,
    ) -> m.Ldif.Entry:
        """Update entry metadata for conversion (internal helper)."""
        get_metadata = u.mapper().prop("metadata")
        get_extensions = u.mapper().prop("extensions")

        current_entry = entry
        if not get_metadata(current_entry):
            metadata_obj = m.Ldif.QuirkMetadata(quirk_type=validated_quirk_type)

            current_entry = current_entry.model_copy(
                update={"metadata": metadata_obj},
                deep=True,
            )

        entry_metadata = current_entry.metadata
        if (
            entry_metadata
            and get_metadata(current_entry)
            and not get_extensions(entry_metadata)
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
            extensions_update: dict[str, t.GeneralValueType] = {
                "converted_from_server": source_quirk_name,
            }
            if conversion_analysis:
                extensions_update["conversion_analysis"] = conversion_analysis

            updated_extensions = (
                entry_metadata.extensions or m.Ldif.DynamicMetadata()
            ).model_copy(
                update=extensions_update,
                deep=True,
            )

            updated_metadata = entry_metadata.model_copy(
                update={"extensions": updated_extensions},
                deep=True,
            )

            current_entry = current_entry.model_copy(
                update={"metadata": updated_metadata},
                deep=True,
            )

        return current_entry

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
            entry_dn = str(u.Ldif.DN.get_dn_value(entry.dn)) if entry.dn else ""
            if not u.Ldif.DN.validate(entry_dn):
                return r[
                    m.Ldif.Entry
                    | m.Ldif.SchemaAttribute
                    | m.Ldif.SchemaObjectClass
                    | m.Ldif.Acl
                ].fail(
                    f"Entry DN failed RFC 4514 validation: {entry_dn}",
                )

            _ = self.dn_registry.register_dn(entry_dn)

            converted_entry = entry.model_copy(deep=True)

            get_server_type = u.mapper().prop("server_type")
            target_server_type_raw = u.Ldif.maybe(
                get_server_type(target_quirk),
                default="unknown",
            )

            if (
                isinstance(target_server_type_raw, str)
                and target_server_type_raw != "unknown"
            ):
                normalized = u.Ldif.Server.normalize_server_type(target_server_type_raw)

                target_server_type_str: str = normalized
            else:
                target_server_type_str = "rfc"

            validated_quirk_type = u.Ldif.Server.normalize_server_type(
                str(target_server_type_str),
            )

            metadata_for_analysis: (
                m.Ldif.QuirkMetadata | m.Ldif.DynamicMetadata | None
            ) = (
                entry.metadata
                if isinstance(
                    entry.metadata,
                    (
                        m.Ldif.QuirkMetadata,
                        m.Ldif.DynamicMetadata,
                    ),
                )
                else None
            )
            conversion_analysis = FlextLdifConversion._analyze_metadata_for_conversion(
                metadata_for_analysis,
                validated_quirk_type,
            )

            source_quirk_name = u.Ldif.maybe(
                get_server_type(source_quirk),
                default="unknown",
            )

            # Normalize server types for comparison
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
            ):
                current_attrs = dict(converted_entry.attributes.attributes)
                updated_attrs = {}

                if hasattr(source_quirk, "entry_quirk") and hasattr(
                    source_quirk.entry_quirk, "_convert_boolean_attributes_to_rfc"
                ):
                    # dynamic dispatch to known method on OID quirk
                    entry_quirk = getattr(source_quirk, "entry_quirk")
                    method = getattr(entry_quirk, "_convert_boolean_attributes_to_rfc")
                    (
                        converted_bools,
                        _,
                        _,
                    ) = method(current_attrs)
                    current_attrs = converted_bools

                mapping = (
                    FlextLdifServersOidConstants.ATTRIBUTE_TRANSFORMATION_OID_TO_RFC
                )
                for k, v in current_attrs.items():
                    lower_k = k.lower()
                    if lower_k in mapping:
                        new_key = mapping[lower_k]
                        updated_attrs[new_key] = v
                    else:
                        updated_attrs[k] = v

                new_attributes = m.Ldif.Attributes(attributes=updated_attrs)
                converted_entry = converted_entry.model_copy(
                    update={"attributes": new_attributes}
                )

            if source_type_norm == "rfc" and target_type_norm == "oid":
                if hasattr(target_quirk, "entry_quirk") and hasattr(
                    target_quirk.entry_quirk, "_restore_boolean_values_to_oid"
                ):
                    # dynamic dispatch to known method on OID quirk
                    entry_quirk = getattr(target_quirk, "entry_quirk")
                    method = getattr(entry_quirk, "_restore_boolean_values_to_oid")
                    converted_entry = method(converted_entry)

                if converted_entry.attributes:
                    current_attrs = dict(converted_entry.attributes.attributes)
                    updated_attrs = {}
                    mapping = (
                        FlextLdifServersOidConstants.ATTRIBUTE_TRANSFORMATION_RFC_TO_OID
                    )

                    for k, v in current_attrs.items():
                        lower_k = k.lower()
                        if lower_k in mapping:
                            new_key = mapping[lower_k]
                            updated_attrs[new_key] = v
                        else:
                            updated_attrs[k] = v

                    new_attributes = m.Ldif.Attributes(attributes=updated_attrs)
                    converted_entry = converted_entry.model_copy(
                        update={"attributes": new_attributes}
                    )

            source_type_norm = str(source_quirk_name).lower()
            target_type_norm = str(target_server_type_str).lower()

            converted_entry = self._update_entry_metadata(
                converted_entry,
                validated_quirk_type,
                str(conversion_analysis) if conversion_analysis else None,
                str(source_quirk_name),
            )

            if not isinstance(converted_entry, m.Ldif.Entry):
                return r[
                    m.Ldif.Entry
                    | m.Ldif.SchemaAttribute
                    | m.Ldif.SchemaObjectClass
                    | m.Ldif.Acl
                ].fail(f"Expected Entry model, got {type(converted_entry)}")

            if (
                source_type_norm == "oid"
                and target_type_norm == "rfc"
                and converted_entry.attributes
                and converted_entry.attributes.attributes
            ):
                current_attrs = dict(converted_entry.attributes.attributes)
                updated_attrs = {}

                if hasattr(source_quirk, "entry_quirk") and hasattr(
                    source_quirk.entry_quirk, "_convert_boolean_attributes_to_rfc"
                ):
                    try:
                        # dynamic dispatch to known method on OID quirk
                        entry_quirk = getattr(source_quirk, "entry_quirk")
                        method = getattr(
                            entry_quirk, "_convert_boolean_attributes_to_rfc"
                        )
                        (
                            converted_bools,
                            _,
                            _,
                        ) = method(current_attrs)
                        current_attrs = converted_bools
                    except Exception as e:
                        logger.warning(f"Boolean conversion failed: {e}")

                mapping = (
                    FlextLdifServersOidConstants.ATTRIBUTE_TRANSFORMATION_OID_TO_RFC
                )
                for k, v in current_attrs.items():
                    lower_k = k.lower()
                    if lower_k in mapping:
                        new_key = mapping[lower_k]
                        updated_attrs[new_key] = v
                    else:
                        updated_attrs[k] = v

                new_attributes = m.Ldif.Attributes(attributes=updated_attrs)
                converted_entry = converted_entry.model_copy(
                    update={"attributes": new_attributes}
                )

            if source_type_norm == "rfc" and target_type_norm == "oid":
                if hasattr(target_quirk, "entry_quirk") and hasattr(
                    target_quirk.entry_quirk, "_restore_boolean_values_to_oid"
                ):
                    try:
                        # dynamic dispatch to known method on OID quirk
                        entry_quirk = getattr(target_quirk, "entry_quirk")
                        method = getattr(entry_quirk, "_restore_boolean_values_to_oid")
                        converted_entry = method(converted_entry)
                    except Exception as e:
                        logger.warning(f"Boolean restoration failed: {e}")

                if converted_entry.attributes and converted_entry.attributes.attributes:
                    current_attrs = dict(converted_entry.attributes.attributes)
                    updated_attrs = {}
                    mapping = (
                        FlextLdifServersOidConstants.ATTRIBUTE_TRANSFORMATION_RFC_TO_OID
                    )

                    for k, v in current_attrs.items():
                        lower_k = k.lower()
                        if lower_k in mapping:
                            new_key = mapping[lower_k]
                            updated_attrs[new_key] = v
                        else:
                            updated_attrs[k] = v

                    new_attributes = m.Ldif.Attributes(attributes=updated_attrs)
                    converted_entry = converted_entry.model_copy(
                        update={"attributes": new_attributes}
                    )

            entry_dn_model = converted_entry.dn
            if entry_dn_model is not None:
                dn_value = entry_dn_model.value
                dn_val = dn_value.lower()
                if source_type_norm == "oid" and target_type_norm == "rfc":
                    if "cn=subschemasubentry" in dn_val:
                        new_dn_val = dn_value.replace(
                            "cn=subschemasubentry", "cn=schema"
                        )
                        converted_entry = converted_entry.model_copy(
                            update={"dn": m.Ldif.DN(value=new_dn_val)}
                        )
                elif (
                    source_type_norm == "rfc"
                    and target_type_norm == "oid"
                    and "cn=schema" in dn_val
                ):
                    new_dn_val = dn_value.replace("cn=schema", "cn=subschemasubentry")
                    converted_entry = converted_entry.model_copy(
                        update={"dn": m.Ldif.DN(value=new_dn_val)}
                    )

            return r[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ].ok(converted_entry)

        except Exception as e:
            logger.exception(
                "Failed to convert Entry model",
                error=str(e),
            )
            return r[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ].fail(
                f"Entry conversion failed: {e}",
            )

    @staticmethod
    def _get_schema_quirk_safe(
        quirk: FlextLdifServersBase,
        quirk_type: str,
    ) -> r[p.Ldif.SchemaQuirkProtocol]:
        """Get schema quirk safely with error handling."""
        result = u.try_(
            lambda: _get_schema_quirk(quirk),
            default=None,
        )
        if result is None:
            return r[p.Ldif.SchemaQuirkProtocol].fail(
                f"{quirk_type} quirk error: Schema not available",
            )

        return r[p.Ldif.SchemaQuirkProtocol].ok(result)

    @staticmethod
    def _validate_ldif_string(ldif_string: str, operation: str) -> r[str]:
        """Validate LDIF string is not empty."""
        if u.Guards.is_string_non_empty(ldif_string):
            return FlextResult.ok(ldif_string)
        return FlextResult.fail(f"Write operation returned empty {operation} LDIF")

    @staticmethod
    def _process_schema_conversion_pipeline(
        config: p.Ldif.SchemaConversionPipelineConfigProtocol,
    ) -> r[
        m.Ldif.Entry | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
    ]:
        """Process schema conversion pipeline (write->parse)."""
        if not (hasattr(config, "write_method") and hasattr(config, "source_schema")):
            return r[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ].fail("Invalid config: missing write_method or source_schema")
        write_result = config.write_method(config.source_schema)
        write_value = write_result.map_or(None)
        item_name = getattr(config, "item_name", "item")
        if write_value is None:
            return FlextResult.fail(
                f"Failed to write {item_name} in source format: {write_result.error}",
            )

        ldif_result = FlextLdifConversion._validate_ldif_string(
            write_value,
            item_name,
        )
        ldif_string = ldif_result.map_or(None)
        if ldif_string is None:
            return FlextResult.fail(ldif_result.error or "LDIF validation failed")

        parse_method = getattr(config, "parse_method", None)
        target_schema = getattr(config, "target_schema", None)
        if parse_method is None or target_schema is None:
            return r[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ].fail("Invalid config: missing parse_method or target_schema")
        parse_result = parse_method(target_schema, ldif_string)
        parsed_value = parse_result.map_or(None)
        if parsed_value is None:
            item_name = getattr(config, "item_name", "unknown")
            return FlextResult.fail(
                f"Failed to parse {item_name} in target format: {u.err(parse_result)}",
            )

        return r[
            m.Ldif.Entry
            | m.Ldif.SchemaAttribute
            | m.Ldif.SchemaObjectClass
            | m.Ldif.Acl
        ].ok(parsed_value)

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
                return FlextResult.fail(
                    source_schema_result.error or "Source schema not available",
                )

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
                ].fail(
                    target_schema_result.error
                    or "Target schema quirk error: Schema not available",
                )

            if not (
                hasattr(source_schema, "write_attribute")
                and hasattr(target_schema, "parse_attribute")
            ):
                return r[
                    m.Ldif.Entry
                    | m.Ldif.SchemaAttribute
                    | m.Ldif.SchemaObjectClass
                    | m.Ldif.Acl
                ].fail("Schema quirks missing attribute conversion methods")

            write_attr = source_schema.write_attribute
            parse_attr = target_schema.parse_attribute

            def _parse_attribute_pipeline(
                _target_schema: p.Ldif.SchemaAttributeProtocol
                | p.Ldif.SchemaObjectClassProtocol
                | p.Ldif.SchemaQuirkProtocol,
                ldif: str,
            ) -> r[p.Ldif.SchemaAttributeProtocol | p.Ldif.SchemaObjectClassProtocol]:
                parse_result = parse_attr(ldif)
                if parse_result.is_failure:
                    return r[
                        p.Ldif.SchemaAttributeProtocol
                        | p.Ldif.SchemaObjectClassProtocol
                    ].fail(parse_result.error or "Failed to parse attribute")
                return r[
                    p.Ldif.SchemaAttributeProtocol | p.Ldif.SchemaObjectClassProtocol
                ].ok(parse_result.value)

            config = m.Ldif.Configuration.SchemaConversionPipelineConfig(
                source_schema=source_schema,
                target_schema=target_schema,
                write_method=lambda _s: write_attr(attribute),
                parse_method=_parse_attribute_pipeline,
                item_name="attribute",
            )
            return FlextLdifConversion._process_schema_conversion_pipeline(config)

        except Exception as e:
            return r[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ].fail(
                f"SchemaAttribute conversion failed: {e}",
            )

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
                return FlextResult.fail(
                    source_schema_result.error or "Source schema not available",
                )

            target_schema_result = FlextLdifConversion._get_schema_quirk_safe(
                target_quirk,
                "Target",
            )
            target_schema = target_schema_result.map_or(None)
            if target_schema is None:
                return FlextResult.fail(
                    target_schema_result.error or "Target schema not available",
                )

            if not (
                hasattr(source_schema, "write_objectclass")
                and hasattr(target_schema, "parse_objectclass")
            ):
                return r[
                    m.Ldif.Entry
                    | m.Ldif.SchemaAttribute
                    | m.Ldif.SchemaObjectClass
                    | m.Ldif.Acl
                ].fail("Schema quirks missing objectclass conversion methods")

            write_oc = source_schema.write_objectclass
            parse_oc = target_schema.parse_objectclass

            def _parse_objectclass_pipeline(
                _target_schema: p.Ldif.SchemaAttributeProtocol
                | p.Ldif.SchemaObjectClassProtocol
                | p.Ldif.SchemaQuirkProtocol,
                ldif: str,
            ) -> r[p.Ldif.SchemaAttributeProtocol | p.Ldif.SchemaObjectClassProtocol]:
                parse_result = parse_oc(ldif)
                if parse_result.is_failure:
                    return r[
                        p.Ldif.SchemaAttributeProtocol
                        | p.Ldif.SchemaObjectClassProtocol
                    ].fail(parse_result.error or "Failed to parse objectclass")
                return r[
                    p.Ldif.SchemaAttributeProtocol | p.Ldif.SchemaObjectClassProtocol
                ].ok(parse_result.value)

            config = m.Ldif.Configuration.SchemaConversionPipelineConfig(
                source_schema=source_schema,
                target_schema=target_schema,
                write_method=lambda _s: write_oc(objectclass),
                parse_method=_parse_objectclass_pipeline,
                item_name="objectclass",
            )
            return FlextLdifConversion._process_schema_conversion_pipeline(config)

        except Exception as e:
            return r[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ].fail(
                f"SchemaObjectClass conversion failed: {e}",
            )

    @staticmethod
    def _perms_dict_to_model(
        perms_dict: dict[str, bool | None],
    ) -> m.Ldif.AclPermissions:
        """Convert permissions dict to AclPermissions model."""
        clean_dict: dict[str, bool] = {
            k: v for k, v in perms_dict.items() if v is not None
        }

        return m.Ldif.AclPermissions.model_validate(clean_dict)

    @staticmethod
    def _normalize_permission_key(key: str) -> str:
        """Normalize permission key for mapping."""
        normalized = {"self_write": "selfwrite"}.get(key, key)
        return normalized if isinstance(normalized, str) else key

    @staticmethod
    def _build_permissions_dict(
        mapped_perms: dict[str, bool],
    ) -> dict[str, bool | None]:
        """Build permissions dict with standard keys."""
        map_result = u.Ldif.map_dict(
            FlextLdifConversion._PERMISSION_KEY_MAPPING,
            mapper=lambda _key, mapped_key: u.take(
                mapped_perms,
                str(mapped_key) if mapped_key is not None else "",
            ),
        )

        if isinstance(map_result, dict):
            return {
                k: v for k, v in map_result.items() if isinstance(v, bool) or v is None
            }
        return {}

    @staticmethod
    def _apply_oid_to_oud_mapping(
        orig_perms_dict: dict[str, bool],
        converted_acl: m.Ldif.Acl,
        perms_to_model: Callable[[dict[str, bool | None]], object],
    ) -> m.Ldif.Acl:
        """Apply OID to OUD permission mapping."""
        orig_perms_dict_typed: dict[str, t.GeneralValueType] = dict(orig_perms_dict)

        normalized_orig_perms_raw = u.Ldif.map_dict(
            orig_perms_dict_typed,
            key_mapper=FlextLdifConversion._normalize_permission_key,
        )

        if isinstance(normalized_orig_perms_raw, dict):
            normalized_orig_perms: dict[str, bool] = {
                k: bool(v) if isinstance(v, bool) else False
                for k, v in normalized_orig_perms_raw.items()
            }
        else:
            normalized_orig_perms = {}
        mapped_perms = u.Ldif.ACL.map_oid_to_oud_permissions(
            normalized_orig_perms,
        )
        oid_to_oud_perms = FlextLdifConversion._build_permissions_dict(mapped_perms)
        perms_model = perms_to_model(oid_to_oud_perms)

        return converted_acl.model_copy(
            update={"permissions": perms_model},
            deep=True,
        )

    @staticmethod
    def _apply_oud_to_oid_mapping(
        orig_perms_dict: dict[str, bool],
        converted_acl: m.Ldif.Acl,
        perms_to_model: Callable[[dict[str, bool | None]], object],
    ) -> m.Ldif.Acl:
        """Apply OUD to OID permission mapping."""
        mapped_perms = u.Ldif.ACL.map_oud_to_oid_permissions(
            orig_perms_dict,
        )
        oud_to_oid_perms = FlextLdifConversion._build_permissions_dict(mapped_perms)
        perms_model = perms_to_model(oud_to_oid_perms)

        return converted_acl.model_copy(
            update={"permissions": perms_model},
            deep=True,
        )

    def _apply_permission_mapping(
        self,
        config: m.Ldif.PermissionMappingConfig | None = None,
        *,
        original_acl: m.Ldif.Acl | None = None,
        converted_acl: m.Ldif.Acl | None = None,
        orig_perms_dict: dict[str, bool] | None = None,
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

                return m.Ldif.Acl(name="")
            config = m.Ldif.PermissionMappingConfig(
                original_acl=original_acl,
                converted_acl=converted_acl,
                orig_perms_dict=orig_perms_dict or {},
                source_server_type=source_server_type,
                target_server_type=target_server_type,
                converted_has_permissions=converted_has_permissions,
            )

        def normalize_server_type_wrapper(
            value: t.GeneralValueType,
        ) -> t.GeneralValueType:
            if isinstance(value, str):
                return u.Ldif.Server.normalize_server_type(value)
            return value

        normalized_source = u.Ldif.maybe(
            config.source_server_type,
            mapper=normalize_server_type_wrapper,
        )
        normalized_target = u.Ldif.maybe(
            config.target_server_type,
            mapper=normalize_server_type_wrapper,
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

        if not isinstance(config.converted_acl, m.Ldif.Acl):
            return m.Ldif.Acl()
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
            if not isinstance(config.original_acl, m.Ldif.Acl):
                return converted_acl_typed
            original_acl_typed: m.Ldif.Acl = config.original_acl
            return converted_acl_typed.model_copy(
                update={
                    "permissions": (
                        original_acl_typed.permissions.model_copy(deep=True)
                        if original_acl_typed.permissions
                        and hasattr(
                            original_acl_typed.permissions,
                            "model_copy",
                        )
                        else None
                    ),
                },
                deep=True,
            )
        return converted_acl_typed

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
        orig_perms_dict: dict[str, bool] = {
            k: v for k, v in orig_perms_dict_raw.items() if v is True
        }

        logger.debug(
            "ACL permission preservation",
            source_server_type=source_server_type,
            target_server_type=target_server_type,
            original_permissions=orig_perms_dict,
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

    def _get_extensions_dict(
        self,
        acl: m.Ldif.Acl,
    ) -> dict[str, FlextTypes.GeneralValueType]:
        """Extract extensions dict from ACL metadata."""
        get_metadata = u.mapper().prop("metadata")
        get_extensions = u.mapper().prop("extensions")

        if not get_metadata(acl) or not acl.metadata:
            return {}

        extensions_raw = get_extensions(acl.metadata)
        if isinstance(extensions_raw, m.Ldif.DynamicMetadata):
            dumped = extensions_raw.model_dump()
            if isinstance(dumped, dict):
                return dict(dumped)
            return {}

        return {}

    def _convert_to_metadata_attribute_value(
        self,
        value: FlextTypes.GeneralValueType,
    ) -> t.MetadataAttributeValue:
        """Convert value to MetadataAttributeValue type."""
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        if isinstance(value, (list, tuple)):
            converted_list: list[str | int | float | bool | datetime | None] = []
            for item in value:
                if isinstance(item, (str, int, float, bool, datetime)) or item is None:
                    converted_list.append(item)
                else:
                    converted_list.append(str(item))
            return converted_list
        if isinstance(value, dict):
            # Dict not supported in strict MetadataAttributeValue, convert to string
            return str(value)
        return str(value)

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

        get_metadata = u.mapper().prop("metadata")
        get_extensions = u.mapper().prop("extensions")

        acl_step1: m.Ldif.Acl = (
            converted_acl.model_copy(
                update={
                    "metadata": (
                        original_acl.metadata.model_copy(deep=True)
                        if original_acl.metadata
                        else None
                    ),
                },
                deep=True,
            )
            if get_metadata(original_acl) and not get_metadata(converted_acl)
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

        merged_ext_raw: dict[str, t.GeneralValueType] = {**orig_ext, **conv_ext}

        if not merged_ext_raw or not get_metadata(acl_step1) or not acl_step1.metadata:
            return acl_step1

        dynamic_metadata_dict: dict[str, t.MetadataAttributeValue] = {}
        for key, value in merged_ext_raw.items():
            dynamic_metadata_dict[key] = self._convert_to_metadata_attribute_value(
                value,
            )

        if acl_step1.metadata:
            metadata_kwargs: dict[str, t.MetadataAttributeValue] = dynamic_metadata_dict
            updated_metadata = acl_step1.metadata.model_copy(
                update={
                    "extensions": m.Ldif.DynamicMetadata.from_dict(metadata_kwargs)
                },
                deep=True,
            )
            return acl_step1.model_copy(
                update={
                    "metadata": updated_metadata,
                },
                deep=True,
            )
        return acl_step1

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
            )
            entry_attributes = m.Ldif.Attributes(attributes={})

            get_server_type = u.mapper().prop("server_type")
            server_type_attr = u.Ldif.maybe(get_server_type(source_quirk))

            source_server_type: str | None = u.try_(
                lambda: (
                    u.Ldif.Server.normalize_server_type(str(server_type_attr))
                    if isinstance(server_type_attr, str)
                    else None
                ),
                default=None,
            )

            entry_metadata = m.Ldif.QuirkMetadata.create_for(
                source_server_type,
                extensions=None,
            )
            entry_metadata.acls = [acl]

            rfc_entry = m.Ldif.Entry.model_validate({
                "dn": entry_dn,
                "attributes": entry_attributes,
                "metadata": entry_metadata,
            })

            entry_result = self._convert_entry(source_quirk, target_quirk, rfc_entry)
            converted_entry = entry_result.map_or(None)
            if converted_entry is None:
                return entry_result
            if not isinstance(converted_entry, m.Ldif.Entry):
                return FlextResult.fail(
                    f"Entry conversion returned unexpected type: {type(converted_entry).__name__}",
                )

            get_metadata = u.mapper().prop("metadata")
            get_acls = u.mapper().prop("acls")
            converted_metadata_raw = get_metadata(converted_entry)

            if not isinstance(
                converted_metadata_raw,
                (m.Ldif.QuirkMetadata, type(None)),
            ):
                return FlextResult.fail(
                    f"Unexpected metadata type: {type(converted_metadata_raw).__name__}",
                )

            converted_metadata: m.Ldif.QuirkMetadata | None = converted_metadata_raw

            acls_raw = get_acls(converted_metadata) if converted_metadata else None
            acls: list[m.Ldif.Acl] | None = None
            if acls_raw is not None and isinstance(acls_raw, list):
                acls = [item for item in acls_raw if isinstance(item, m.Ldif.Acl)]

            if not acls:
                return FlextResult.fail(
                    "Converted entry has no ACLs in metadata.acls",
                )

            if not u.Guards.is_list_non_empty(acls):
                return FlextResult.fail("No ACL found in converted entry metadata")
            domain_acl = acls[0]

            if isinstance(domain_acl, m.Ldif.Acl):
                converted_acl: m.Ldif.Acl = domain_acl
            else:
                validation_result: r[m.Ldif.Acl] = r[m.Ldif.Acl].ok(
                    m.Ldif.Acl.model_validate(domain_acl.model_dump())
                )
                if not validation_result.is_success:
                    return FlextResult.fail("Failed to convert ACL model")
                converted_acl = validation_result.value

            get_server_type = u.mapper().prop("server_type")
            target_server_type_raw = u.Ldif.maybe(
                get_server_type(target_quirk),
                default="unknown",
            )

            target_server_type: str | None = u.try_(
                lambda: (
                    u.Ldif.Server.normalize_server_type(target_server_type_raw)
                    if isinstance(target_server_type_raw, str)
                    and target_server_type_raw != "unknown"
                    else None
                ),
                default=None,
            )

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

            return r[_TConvertedModel].ok(converted_acl)

        except Exception as e:
            logger.exception(
                "Failed to convert ACL model",
                error=str(e),
            )
            return r[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ].fail(
                f"Acl conversion failed: {e}",
            )

    def _write_attribute_to_rfc(
        self,
        source: str | FlextLdifServersBase,
        source_attr: m.Ldif.SchemaAttribute | t.MetadataAttributeValue | str,
    ) -> r[
        str
        | m.Ldif.SchemaAttribute
        | m.Ldif.SchemaObjectClass
        | t.MetadataAttributeValue
    ]:
        """Write attribute to RFC string representation."""
        if isinstance(source_attr, str):
            return r[str].ok(source_attr)
        if not isinstance(source_attr, m.Ldif.SchemaAttribute):
            return r[str].ok(source_attr)

        source_quirk = self._resolve_quirk(source)
        try:
            schema_quirk = _get_schema_quirk(source_quirk)
        except TypeError:
            return r[str].ok(source_attr)

        return r.ok(schema_quirk.write_attribute(source_attr).map_or(source_attr))

    @staticmethod
    def _schema_conversion_fail(
        error: str | None,
        fallback: str,
    ) -> r[_TSchemaConversionValue]:
        return r[_TSchemaConversionValue].fail(error or fallback)

    @staticmethod
    def _schema_conversion_ok(
        value: _TSchemaConversionValue,
    ) -> r[_TSchemaConversionValue]:
        return r[_TSchemaConversionValue].ok(value)

    @staticmethod
    def _schema_passthrough_ok(value: object) -> r[_TSchemaConversionValue] | None:
        if isinstance(value, str):
            return FlextLdifConversion._schema_conversion_ok(value)
        if isinstance(value, dict):
            # Dict not supported in strict _TSchemaConversionValue, convert to string
            return FlextLdifConversion._schema_conversion_ok(str(value))
        return None

    def _convert_attribute(
        self,
        source: str | FlextLdifServersBase,
        target: str | FlextLdifServersBase,
        data: str | t.MetadataAttributeValue,
    ) -> r[_TSchemaConversionValue]:
        """Convert attribute from source to target quirk via write->parse pipeline."""
        try:
            if not isinstance(data, str):
                return FlextResult.fail("Attribute conversion requires string data")

            source_schema_result = self._resolve_schema_quirk(source, role="Source")
            if source_schema_result.is_failure:
                return FlextLdifConversion._schema_conversion_fail(
                    source_schema_result.error,
                    "Source schema not available",
                )

            parse_result = self._parse_attribute_with_schema(
                source_schema_result.value,
                data,
                parse_error_message="Failed to parse attribute",
            )
            parsed_attr = parse_result.map_or(None)
            if parsed_attr is None:
                return FlextLdifConversion._schema_conversion_fail(
                    parse_result.error,
                    "Failed to parse source attribute",
                )

            rfc_result = self._write_attribute_to_rfc(source, parsed_attr)
            rfc_value = rfc_result.map_or(None)
            if rfc_value is None:
                return rfc_result

            if not isinstance(rfc_value, str):
                return FlextLdifConversion._schema_conversion_ok(rfc_value)

            target_schema_result = self._resolve_schema_quirk(target, role="Target")
            if target_schema_result.is_failure:
                return FlextLdifConversion._schema_conversion_fail(
                    target_schema_result.error,
                    "Target schema not available",
                )

            target_parse_result = self._parse_attribute_with_schema(
                target_schema_result.value,
                rfc_value,
                parse_error_message="Failed to parse target attribute",
            )

            if target_parse_result.is_failure:
                return FlextLdifConversion._schema_conversion_fail(
                    target_parse_result.error,
                    "Failed to parse target attribute",
                )

            parsed_value: m.Ldif.SchemaAttribute = target_parse_result.value

            return self._write_target_attribute(parsed_value)

        except Exception as e:
            return FlextLdifConversion._schema_conversion_fail(
                f"Attribute conversion failed: {e}",
                "Attribute conversion failed",
            )

    def _write_target_attribute(
        self,
        parsed_attr: m.Ldif.SchemaAttribute | str | t.MetadataAttributeValue,
    ) -> r[_TSchemaConversionValue]:
        """Write target attribute to final format."""
        passthrough = FlextLdifConversion._schema_passthrough_ok(parsed_attr)
        if passthrough is not None:
            return passthrough
        if isinstance(parsed_attr, m.Ldif.SchemaAttribute):
            return FlextLdifConversion._schema_conversion_ok(parsed_attr)

        msg = f"Expected SchemaAttribute | dict | str, got {type(parsed_attr)}"
        raise TypeError(msg)

    def _write_objectclass_to_rfc(
        self,
        source: str | FlextLdifServersBase,
        source_oc: m.Ldif.SchemaObjectClass | t.MetadataAttributeValue | str,
    ) -> r[_TSchemaConversionValue]:
        """Write objectClass to RFC string representation."""
        passthrough = FlextLdifConversion._schema_passthrough_ok(source_oc)
        if passthrough is not None:
            return passthrough

        if not isinstance(source_oc, m.Ldif.SchemaObjectClass):
            msg = f"Expected SchemaObjectClass | str | dict, got {type(source_oc)}"
            raise TypeError(msg)

        source_quirk = self._resolve_quirk(source)
        try:
            schema_quirk = _get_schema_quirk(source_quirk)
        except TypeError:
            return r[_TSchemaConversionValue].ok(source_oc)

        write_result: r[_TSchemaConversionValue] = r[_TSchemaConversionValue].ok(
            schema_quirk.write_objectclass(source_oc).map_or(source_oc)
        )
        write_value = write_result.map_or(None)
        if write_value is not None and isinstance(write_value, str):
            return FlextLdifConversion._schema_conversion_ok(write_value)

        return write_result

    def _convert_objectclass(
        self,
        source: str | FlextLdifServersBase,
        target: str | FlextLdifServersBase,
        data: str | t.MetadataAttributeValue,
    ) -> r[_TSchemaConversionValue]:
        """Convert objectClass from source to target quirk via write->parse pipeline."""
        try:
            if not isinstance(data, str):
                return FlextResult.fail("ObjectClass conversion requires string data")

            source_schema_result = self._resolve_schema_quirk(source, role="Source")
            if source_schema_result.is_failure:
                return FlextLdifConversion._schema_conversion_fail(
                    source_schema_result.error,
                    "Source schema not available",
                )

            parse_result = self._parse_objectclass_with_schema(
                source_schema_result.value,
                data,
                parse_error_message="Failed to parse objectClass",
            )
            parsed_oc = parse_result.map_or(None)
            if parsed_oc is None:
                return FlextLdifConversion._schema_conversion_fail(
                    parse_result.error,
                    "Failed to parse source objectClass",
                )

            write_result = self._write_objectclass_to_rfc(source, parsed_oc)
            rfc_value = write_result.map_or(None)
            if rfc_value is None:
                return write_result
            if not isinstance(rfc_value, str):
                return FlextLdifConversion._schema_conversion_ok(rfc_value)

            target_schema_result = self._resolve_schema_quirk(target, role="Target")
            if target_schema_result.is_failure:
                return FlextLdifConversion._schema_conversion_fail(
                    target_schema_result.error,
                    "Target schema not available",
                )

            target_result = self._parse_objectclass_with_schema(
                target_schema_result.value,
                rfc_value,
                parse_error_message="Failed to parse target objectClass",
            )

            if target_result.is_failure:
                return FlextLdifConversion._schema_conversion_fail(
                    target_result.error,
                    "Failed to parse target objectClass",
                )
            parsed_value = target_result.value

            return self._write_target_objectclass(target, parsed_value)

        except Exception as e:
            return FlextLdifConversion._schema_conversion_fail(
                f"ObjectClass conversion failed: {e}",
                "ObjectClass conversion failed",
            )

    def _resolve_schema_quirk(
        self,
        quirk_or_type: str | FlextLdifServersBase,
        *,
        role: str,
    ) -> r[p.Ldif.SchemaQuirkProtocol]:
        quirk = self._resolve_quirk(quirk_or_type)
        try:
            schema = _get_schema_quirk(quirk)
            return r[p.Ldif.SchemaQuirkProtocol].ok(schema)
        except TypeError as e:
            return r[p.Ldif.SchemaQuirkProtocol].fail(f"{role} quirk error: {e}")

    @staticmethod
    def _parse_schema_item_with_schema(
        parse_fn: Callable[..., r[_TSchemaItem]],
        value: str,
        *,
        expected_type: type[_TSchemaItem],
        expected_label: str,
        parse_error_message: str,
    ) -> r[_TSchemaItem]:
        parse_result = parse_fn(value)
        if parse_result.is_failure:
            return r[_TSchemaItem].fail(parse_result.error or parse_error_message)

        parsed_value = parse_result.value
        if not isinstance(parsed_value, expected_type):
            return r[_TSchemaItem].fail(
                f"Expected {expected_label}, got {type(parsed_value).__name__}",
            )

        return r[_TSchemaItem].ok(parsed_value)

    @staticmethod
    def _parse_attribute_with_schema(
        schema: p.Ldif.SchemaQuirkProtocol,
        value: str,
        *,
        parse_error_message: str,
    ) -> r[m.Ldif.SchemaAttribute]:
        return FlextLdifConversion._parse_schema_item_with_schema(
            cast("Callable[..., r[m.Ldif.SchemaAttribute]]", schema.parse_attribute),
            value,
            expected_type=m.Ldif.SchemaAttribute,
            expected_label="SchemaAttribute",
            parse_error_message=parse_error_message,
        )

    @staticmethod
    def _parse_objectclass_with_schema(
        schema: p.Ldif.SchemaQuirkProtocol,
        value: str,
        *,
        parse_error_message: str,
    ) -> r[m.Ldif.SchemaObjectClass]:
        return FlextLdifConversion._parse_schema_item_with_schema(
            cast(
                "Callable[..., r[m.Ldif.SchemaObjectClass]]", schema.parse_objectclass
            ),
            value,
            expected_type=m.Ldif.SchemaObjectClass,
            expected_label="SchemaObjectClass",
            parse_error_message=parse_error_message,
        )

    def _write_target_objectclass(
        self,
        target: str | FlextLdifServersBase,
        parsed_oc: m.Ldif.SchemaObjectClass | str | t.MetadataAttributeValue,
    ) -> r[_TSchemaConversionValue]:
        """Write target objectClass to final format."""
        passthrough = FlextLdifConversion._schema_passthrough_ok(parsed_oc)
        if passthrough is not None:
            return passthrough
        if not isinstance(parsed_oc, m.Ldif.SchemaObjectClass):
            msg = f"Expected SchemaObjectClass | str | dict, got {type(parsed_oc)}"
            raise TypeError(msg)

        target_quirk = self._resolve_quirk(target)

        try:
            schema_quirk = _get_schema_quirk(target_quirk)
        except TypeError:
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

    def batch_convert(
        self,
        source: str | FlextLdifServersBase,
        target: str | FlextLdifServersBase,
        model_list: Sequence[
            m.Ldif.Entry
            | m.Ldif.SchemaAttribute
            | m.Ldif.SchemaObjectClass
            | m.Ldif.Acl
        ],
    ) -> r[
        list[
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
            source_name_result = u.mapper().prop("server_name")(source)
            source_format = (
                source_name_result if isinstance(source_name_result, str) else "unknown"
            )

        if isinstance(target, str):
            target_format: str = target
        else:
            target_name_result = u.mapper().prop("server_name")(target)
            target_format = (
                target_name_result if isinstance(target_name_result, str) else "unknown"
            )

        if not model_list:
            return r[
                list[
                    m.Ldif.Entry
                    | m.Ldif.SchemaAttribute
                    | m.Ldif.SchemaObjectClass
                    | m.Ldif.Acl
                ]
            ].ok([])

        model_type = type(model_list[0]).__name__
        conversion_operation = f"batch_convert_{model_type}"

        try:
            converted: list[
                m.Ldif.Entry
                | m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | m.Ldif.Acl
            ] = []
            errors: list[str] = []
            error_details: list[m.Ldif.ErrorDetail] = []

            for idx, model_item in enumerate(model_list):
                if not isinstance(
                    model_item,
                    (
                        m.Ldif.Entry,
                        m.Ldif.SchemaAttribute,
                        m.Ldif.SchemaObjectClass,
                        m.Ldif.Acl,
                    ),
                ):
                    error_msg = f"Item {idx}: Expected convertible model, got {type(model_item).__name__}"
                    errors.append(error_msg)
                    error_details.append(
                        m.Ldif.ErrorDetail.model_validate({
                            "item": f"batch_item_{idx}",
                            "error": error_msg,
                        }),
                    )
                    continue
                result = self.convert(source, target, model_item)
                unwrapped = result.map_or(None)
                if unwrapped is not None:
                    converted.append(unwrapped)
                else:
                    error_msg = result.error or "Unknown error"
                    errors.append(f"Item {idx}: {error_msg}")
                    error_details.append(
                        m.Ldif.ErrorDetail.model_validate({
                            "item": f"batch_item_{idx}",
                            "error": error_msg,
                        }),
                    )

            duration_ms = (time.perf_counter() - start_time) * 1000.0

            model_list_typed: list[object] = list(model_list)
            converted_typed: list[object] = list(converted)

            errors_typed: list[str] = errors if isinstance(errors, list) else []
            items_processed = u.count(model_list_typed)
            items_converted = u.count(converted_typed)
            items_failed = u.count(errors_typed)

            conversion_config = m.Ldif.LdifResults.Events.ConversionEventConfig(
                conversion_operation=conversion_operation,
                source_format=source_format,
                target_format=target_format,
                items_processed=items_processed,
                items_converted=items_converted,
                items_failed=items_failed,
                conversion_duration_ms=duration_ms,
                error_details=error_details or None,
            )

            if hasattr(logger, "bind") and callable(getattr(logger, "bind", None)):
                _ = u.Ldif.Events.log_and_emit_conversion_event(
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
                    list[
                        m.Ldif.Entry
                        | m.Ldif.SchemaAttribute
                        | m.Ldif.SchemaObjectClass
                        | m.Ldif.Acl
                    ]
                ].fail(
                    error_msg,
                )

            return r[
                list[
                    m.Ldif.Entry
                    | m.Ldif.SchemaAttribute
                    | m.Ldif.SchemaObjectClass
                    | m.Ldif.Acl
                ]
            ].ok(converted)

        except (ValueError, TypeError, AttributeError, RuntimeError, Exception) as e:
            duration_ms = (time.perf_counter() - start_time) * 1000.0

            model_list_as_list: list[object] = list(model_list) if model_list else []
            items_count = u.count(model_list_as_list)
            conversion_config = m.Ldif.LdifResults.Events.ConversionEventConfig(
                conversion_operation=conversion_operation,
                source_format=source_format,
                target_format=target_format,
                items_processed=items_count,
                items_converted=0,
                items_failed=items_count,
                conversion_duration_ms=duration_ms,
                error_details=[
                    m.Ldif.ErrorDetail.model_validate({
                        "item": "batch_conversion",
                        "error": f"Batch conversion failed: {e}",
                    }),
                ],
            )

            if hasattr(logger, "bind") and callable(getattr(logger, "bind", None)):
                _ = u.Ldif.Events.log_and_emit_conversion_event(
                    logger=logger,
                    config=conversion_config,
                    log_level="error",
                )

            return r[
                list[
                    m.Ldif.Entry
                    | m.Ldif.SchemaAttribute
                    | m.Ldif.SchemaObjectClass
                    | m.Ldif.Acl
                ]
            ].fail(
                f"Batch conversion failed: {e}",
            )

    def validate_oud_conversion(self) -> r[bool]:
        """Validate DN case consistency for OUD target conversion."""
        return self.dn_registry.validate_oud_consistency()

    def reset_dn_registry(self) -> None:
        """Clear DN registry for new conversion session."""
        self.dn_registry.clear()

    def get_supported_conversions(self, quirk: FlextLdifServersBase) -> dict[str, bool]:
        """Check which data types a quirk supports for conversion."""
        support: t.Ldif.CommonDict.DistributionDict = {
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
            "objectClass": bool(
                support.get("objectclass", 0),
            ),
            "objectclass": bool(
                support.get("objectclass", 0),
            ),
            "acl": bool(support.get("acl", 0)),
            "entry": bool(support.get("entry", 0)),
        }

    def _get_schema_quirk_for_support_check(
        self,
        quirk: FlextLdifServersBase,
    ) -> object | None:
        """Get schema quirk from base quirk for support checking."""
        if hasattr(quirk, "parse_attribute") or hasattr(quirk, "parse_objectclass"):
            required_methods = ("parse", "write")
            if all(
                hasattr(quirk, method) and callable(getattr(quirk, method))
                for method in required_methods
            ):
                return quirk
            return None

        schema_quirk_raw: object | None = getattr(quirk, "schema_quirk", None)
        if schema_quirk_raw is not None:
            required_methods = ("parse", "write")
            if all(
                hasattr(schema_quirk_raw, method)
                and callable(getattr(schema_quirk_raw, method))
                for method in required_methods
            ):
                return schema_quirk_raw
            return None
        return None

    def _check_attribute_support(
        self,
        quirk_schema: object,
        test_attr_def: str,
        support: t.Ldif.CommonDict.DistributionDict,
    ) -> t.Ldif.CommonDict.DistributionDict:
        """Check attribute support for schema quirk."""
        if not hasattr(quirk_schema, "can_handle_attribute"):
            return support
        if not hasattr(quirk_schema, "parse_attribute"):
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

        if isinstance(attr_result, FlextResult) and attr_result.is_success:
            support["attribute"] = 1

        return support

    def _check_objectclass_support(
        self,
        quirk_schema: object,
        test_oc_def: str,
        support: t.Ldif.CommonDict.DistributionDict,
    ) -> t.Ldif.CommonDict.DistributionDict:
        """Check objectClass support for schema quirk."""
        if not hasattr(quirk_schema, "can_handle_objectclass"):
            return support
        if not hasattr(quirk_schema, "parse_objectclass"):
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
        if isinstance(oc_result, FlextResult) and oc_result.map_or(None) is not None:
            support["objectclass"] = 1

        return support

    def _check_schema_support(
        self,
        quirk: FlextLdifServersBase,
        support: t.Ldif.CommonDict.DistributionDict,
    ) -> t.Ldif.CommonDict.DistributionDict:
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

    def _check_acl_support(
        self,
        quirk: FlextLdifServersBase,
        support: t.Ldif.CommonDict.DistributionDict,
    ) -> t.Ldif.CommonDict.DistributionDict:
        """Check ACL support."""
        acl = getattr(quirk, "acl_quirk", None)
        if acl is None:
            acl = getattr(quirk, "_acl_quirk", None)
        test_acl_def = 'targetattr="*" (version 3.0; acl "test"; allow (read) userdn="ldap:///self";)'
        if acl and callable(getattr(acl, "parse", None)):
            acl_result = acl.parse(test_acl_def)
            if acl_result.map_or(None) is not None:
                support["acl"] = 1
        return support

    def _check_entry_support(
        self,
        quirk: FlextLdifServersBase,
        support: t.Ldif.CommonDict.DistributionDict,
    ) -> t.Ldif.CommonDict.DistributionDict:
        """Check Entry support."""
        entry = getattr(quirk, "entry_quirk", None)
        if entry is None:
            entry = getattr(quirk, "_entry_quirk", None)
        if (
            entry is None
            and hasattr(quirk, "parse")
            and hasattr(quirk, "can_handle_entry")
        ):
            entry = quirk
        if entry is not None and callable(getattr(entry, "parse", None)):
            support["entry"] = 1
        return support


__all__ = ["FlextLdifConversion"]
