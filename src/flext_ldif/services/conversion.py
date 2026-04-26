"""Quirks conversion matrix for LDAP server translation."""

from __future__ import annotations

import struct
import time
from collections.abc import (
    Callable,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)
from typing import (
    Self,
    TypeIs,
)

from flext_ldif import (
    FlextLdifServer,
    FlextLdifServersBase,
    c,
    m,
    p,
    r,
    s,
    t,
    u,
)

logger = u.fetch_logger(__name__)


class FlextLdifConversion(
    s,
):
    """Facade for universal, model-driven quirk-to-quirk conversion."""

    @staticmethod
    def _get_schema_from_attribute(
        quirk: FlextLdifServersBase,
    ) -> p.Ldif.SchemaQuirk:
        if FlextLdifConversion._has_attr(quirk, "schema_quirk"):
            schema = quirk.schema_quirk
            if FlextLdifConversion._is_schema_quirk_protocol(schema):
                return schema
        msg = "Quirk must be a Schema quirk or have schema_quirk attribute"
        raise TypeError(msg)

    @staticmethod
    def _has_attr(
        obj: t.JsonPayload | m.BaseModel | p.Ldif.SchemaQuirk | type,
        attr_name: str,
    ) -> bool:
        return hasattr(obj, attr_name)

    @staticmethod
    def _is_schema_quirk_protocol(
        obj: t.JsonPayload | m.BaseModel | p.Ldif.SchemaQuirk | type,
    ) -> TypeIs[p.Ldif.SchemaQuirk]:
        return (
            FlextLdifConversion._has_attr(obj, "parse_attribute")
            and FlextLdifConversion._has_attr(obj, "parse_objectclass")
            and FlextLdifConversion._has_attr(obj, "write_attribute")
            and FlextLdifConversion._has_attr(obj, "write_objectclass")
        )

    dn_registry: m.Ldif.DnRegistry = u.Field(
        default_factory=m.Ldif.DnRegistry,
        description="DN registry for tracking distinguished names during conversion",
    )

    def __new__(cls, *args: object, **kwargs: object) -> Self:
        """Create service instance with matching signature for type checker."""
        _ = args, kwargs
        instance = super().__new__(cls)
        if not isinstance(instance, cls):
            msg = f"Expected {cls.__name__}, got {type(instance).__name__}"
            raise TypeError(msg)
        return instance

    @staticmethod
    def _analyze_attribute_case(
        original_attribute_case: t.JsonMapping,
        target_server_type: str,
    ) -> MutableMapping[str, t.Ldif.MutableMetadataInputMapping]:
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
        boolean_conversions: t.JsonMapping,
        target_server_type: str,
    ) -> MutableMapping[str, t.Ldif.MutableMetadataInputMapping]:
        """Analyze boolean conversions for target compatibility."""
        if not boolean_conversions:
            return {}
        result: MutableMapping[str, t.Ldif.MutableMetadataInputMapping] = {}
        for attr_name, conv_info in boolean_conversions.items():
            source_format = ""
            if isinstance(conv_info, Mapping):
                conv_info_dict = u.Cli.json_as_mapping(
                    u.normalize_to_metadata(conv_info),
                )
                source_format = str(conv_info_dict.get("format", "") or "")
            result[f"boolean_{attr_name}"] = {
                "source_format": source_format,
                "target_server": target_server_type,
                "action": "convert_to_target_format",
            }
        return result

    @staticmethod
    def _analyze_dn_format(
        original_format_details: t.JsonMapping,
        target_server_type: str,
    ) -> MutableMapping[str, t.Ldif.MutableMetadataInputMapping]:
        """Analyze DN spacing for target compatibility."""
        spacing = original_format_details.get("dn_spacing")
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
    ) -> MutableMapping[str, t.Ldif.MutableMetadataInputMapping]:
        """Analyze source metadata for intelligent conversion to target server."""
        conversion_analysis: MutableMapping[
            str, t.Ldif.MutableMetadataInputMapping
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
        boolean_conversions = u.Cli.json_as_mapping(boolean_raw)
        boolean_analysis = FlextLdifConversion._analyze_boolean_conversions(
            boolean_conversions,
            target_server_str,
        )
        acc_typed: MutableMapping[str, t.Ldif.MutableMetadataInputMapping] = {}
        for key, value in boolean_analysis.items():
            if isinstance(value, dict):
                acc_typed[key] = {
                    str(k): FlextLdifConversion._normalize_metadata_value(v)
                    for k, v in value.items()
                }
        attr_case_raw = get_attr_case(source_metadata)
        attr_case_val = u.Cli.json_as_mapping(attr_case_raw)
        attr_case_analysis = FlextLdifConversion._analyze_attribute_case(
            attr_case_val,
            target_server_str,
        )
        for key, attr_case_value in attr_case_analysis.items():
            if isinstance(attr_case_value, dict):
                acc_typed[key] = {
                    str(k): FlextLdifConversion._normalize_metadata_value(v)
                    for k, v in attr_case_value.items()
                }
        format_raw = get_format_details(source_metadata)
        format_val = u.Cli.json_as_mapping(format_raw)
        dn_format_analysis = FlextLdifConversion._analyze_dn_format(
            format_val,
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
        mapped_perms = u.Ldif.map_oid_to_oud_permissions(orig_perms_dict)
        oid_to_oud_perms = u.Ldif.build_mapped_permissions_dict(
            mapped_perms,
            {
                key: u.Ldif.normalize_permission_key(key)
                for key in c.Ldif.ACL_PERMISSION_KEYS
            },
        )
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
        oud_to_oid_perms = u.Ldif.build_mapped_permissions_dict(
            mapped_perms,
            {
                key: u.Ldif.normalize_permission_key(key)
                for key in c.Ldif.ACL_PERMISSION_KEYS
            },
        )
        perms_model = perms_to_model(oud_to_oid_perms)
        return converted_acl.model_copy(update={"permissions": perms_model}, deep=True)

    def _convert_schema_attribute(
        self,
        source_quirk: FlextLdifServersBase,
        target_quirk: FlextLdifServersBase,
        attribute: m.Ldif.SchemaAttribute,
    ) -> r[t.Ldif.ConvertedModel]:
        """Convert SchemaAttribute model through Entry bridge orchestration."""
        return self._convert_schema_model_via_entry(
            source_quirk,
            target_quirk,
            item=attribute,
            schema_item_kind=c.Ldif.SchemaItemKind.ATTRIBUTE,
            item_name="attribute",
        )

    def _convert_schema_objectclass(
        self,
        source_quirk: FlextLdifServersBase,
        target_quirk: FlextLdifServersBase,
        objectclass: m.Ldif.SchemaObjectClass,
    ) -> r[t.Ldif.ConvertedModel]:
        """Convert SchemaObjectClass model through Entry bridge orchestration."""
        return self._convert_schema_model_via_entry(
            source_quirk,
            target_quirk,
            item=objectclass,
            schema_item_kind=c.Ldif.SchemaItemKind.OBJECTCLASS,
            item_name="objectclass",
        )

    @staticmethod
    def _extract_schema_values_from_entry(
        entry: m.Ldif.Entry,
        field_name: str,
    ) -> t.StrSequence:
        attributes_model = entry.attributes
        if attributes_model is None:
            return tuple[str, ...]()
        for attr_name, values in attributes_model.attributes.items():
            if attr_name.lower() == field_name.lower():
                return [str(value) for value in values]
        return tuple[str, ...]()

    def _build_schema_bridge_entry(
        self,
        source_quirk: FlextLdifServersBase,
        schema_item_kind: c.Ldif.SchemaItemKind,
        schema_value: str,
    ) -> m.Ldif.Entry:
        source_server_type = u.try_(
            lambda: u.Ldif.normalize_server_type(
                str(getattr(source_quirk, "server_type", "")),
            ),
        ).map_or(None)
        metadata = m.Ldif.QuirkMetadata.create_for(source_server_type, extensions=None)
        field_name = (
            c.Ldif.ATTRIBUTE_TYPES
            if schema_item_kind == c.Ldif.SchemaItemKind.ATTRIBUTE
            else c.Ldif.OBJECT_CLASSES
        )
        attributes = m.Ldif.Attributes.model_validate(
            {
                "attributes": {field_name: [schema_value]},
                "attribute_metadata": {},
                "metadata": None,
            },
        )
        entry_result: m.Ldif.Entry = m.Ldif.Entry.model_validate(
            {
                "dn": m.Ldif.DN(
                    value="cn=schema,dc=example,dc=com",
                    metadata=m.Ldif.EntryMetadata(),
                ),
                "attributes": attributes,
                "metadata": metadata,
            },
        )
        return entry_result

    def _convert_schema_model_via_entry(
        self,
        source_quirk: FlextLdifServersBase,
        target_quirk: FlextLdifServersBase,
        item: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        *,
        schema_item_kind: c.Ldif.SchemaItemKind,
        item_name: str,
    ) -> r[t.Ldif.ConvertedModel]:
        """Orchestrate schema conversion through m.Ldif.Entry intermediary."""
        source_schema_result = self._resolve_schema_quirk(source_quirk, role="Source")
        if source_schema_result.failure:
            return r[t.Ldif.ConvertedModel].fail(
                source_schema_result.error or "Source schema not available",
            )
        target_schema_result = self._resolve_schema_quirk(target_quirk, role="Target")
        if target_schema_result.failure:
            return r[t.Ldif.ConvertedModel].fail(
                target_schema_result.error or "Target schema not available",
            )
        if schema_item_kind == c.Ldif.SchemaItemKind.ATTRIBUTE:
            if not isinstance(item, m.Ldif.SchemaAttribute):
                return r[t.Ldif.ConvertedModel].fail(
                    "Expected SchemaAttribute in attribute conversion path",
                )
            write_result = source_schema_result.value.write_attribute(item)
        else:
            if not isinstance(item, m.Ldif.SchemaObjectClass):
                return r[t.Ldif.ConvertedModel].fail(
                    "Expected SchemaObjectClass in objectclass conversion path",
                )
            write_result = source_schema_result.value.write_objectclass(item)
        source_value_result = (
            r[str]
            .from_result(write_result)
            .map_error(
                lambda error: (
                    f"Failed to write {item_name} in source format: "
                    f"{error or 'Unknown write error'}"
                ),
            )
        )
        if source_value_result.failure:
            return r[t.Ldif.ConvertedModel].fail(source_value_result.error)
        bridge_entry = self._build_schema_bridge_entry(
            source_quirk,
            schema_item_kind,
            source_value_result.value,
        )
        converted_entry_result = self._convert_entry(
            source_quirk,
            target_quirk,
            bridge_entry,
        )
        if converted_entry_result.failure:
            return r[t.Ldif.ConvertedModel].fail(
                converted_entry_result.error
                or f"Failed to convert {item_name} via Entry intermediary",
            )
        converted_entry_value = converted_entry_result.value
        if not isinstance(converted_entry_value, m.Ldif.Entry):
            return r[t.Ldif.ConvertedModel].fail(
                "Entry intermediary returned unexpected type: "
                f"{type(converted_entry_value).__name__}",
            )
        field_name = (
            c.Ldif.ATTRIBUTE_TYPES
            if schema_item_kind == "attribute"
            else c.Ldif.OBJECT_CLASSES
        )
        converted_values = self._extract_schema_values_from_entry(
            converted_entry_value,
            field_name,
        )
        if not converted_values:
            return r[t.Ldif.ConvertedModel].fail(
                f"Converted Entry does not contain {field_name}",
            )
        first_value = converted_values[0]
        if schema_item_kind == "attribute":
            parsed_result = self._parse_attribute_with_schema(
                target_schema_result.value,
                first_value,
                parse_error_message="Failed to parse converted attribute",
            )
            return parsed_result.map(lambda parsed: parsed)
        parsed_oc_result = self._parse_objectclass_with_schema(
            target_schema_result.value,
            first_value,
            parse_error_message="Failed to parse converted objectclass",
        )
        return parsed_oc_result.map(lambda parsed: parsed)

    @staticmethod
    def _normalize_metadata_value(
        value: t.JsonPayload | Mapping[str, t.JsonPayload] | None,
    ) -> t.JsonValue:
        """Normalize metadata value to proper type."""
        if value is None:
            empty_val: t.JsonValue = u.Cli.normalize_json_value("")
            return empty_val
        if isinstance(value, Mapping):
            normalized_mapping: dict[str, t.JsonValue] = {
                str(key): u.Cli.normalize_json_value(item)
                for key, item in value.items()
            }
            return normalized_mapping
        normalized: t.JsonValue = u.Cli.normalize_json_value(value)
        return normalized

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
        validated: m.Ldif.AclPermissions = m.Ldif.AclPermissions.model_validate(
            clean_dict,
        )
        return validated

    @staticmethod
    def _resolve_quirk(
        quirk_or_type: str | FlextLdifServersBase,
    ) -> FlextLdifServersBase:
        """Resolve server quirk instance from string type or return instance."""
        if isinstance(quirk_or_type, str):
            server = FlextLdifServer.fetch_global_instance()
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

    def dsl_convert_between_quirks(
        self,
        source_quirk: FlextLdifServersBase,
        target_quirk: FlextLdifServersBase,
        model_instance: m.Ldif.Entry
        | m.Ldif.SchemaAttribute
        | m.Ldif.SchemaObjectClass
        | m.Ldif.Acl,
    ) -> r[t.Ldif.ConvertedModel]:
        """DSL: orchestrate model conversion between quirks."""
        if isinstance(model_instance, m.Ldif.Entry):
            return self._convert_entry(source_quirk, target_quirk, model_instance)
        if isinstance(model_instance, m.Ldif.SchemaAttribute):
            return self._convert_schema_attribute(
                source_quirk,
                target_quirk,
                model_instance,
            )
        if isinstance(model_instance, m.Ldif.SchemaObjectClass):
            return self._convert_schema_objectclass(
                source_quirk,
                target_quirk,
                model_instance,
            )
        return self._convert_acl(
            source_quirk,
            target_quirk,
            model_instance,
        )

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
        try:
            source_quirk = self._resolve_quirk(source)
            target_quirk = self._resolve_quirk(target)
            result = self.dsl_convert_between_quirks(
                source_quirk,
                target_quirk,
                model_instance,
            )
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            result = r[t.Ldif.ConvertedModel].fail(f"Model conversion failed: {e}")
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
            settings=conversion_config,
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

    def resolve_supported_conversions(
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
        settings: m.Ldif.PermissionMappingConfig | None = None,
        *,
        original_acl: m.Ldif.Acl | None = None,
        converted_acl: m.Ldif.Acl | None = None,
        orig_perms_dict: t.MutableBoolMapping | None = None,
        source_server_type: str | None = None,
        target_server_type: str | None = None,
        converted_has_permissions: bool = False,
    ) -> m.Ldif.Acl:
        """Apply permission mapping based on server types."""
        if settings is not None:
            resolved_config = settings
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
                orig_perms_dict=dict((orig_perms_dict or {}).items()),
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
        quirk_schema: m.BaseModel | FlextLdifServersBase,
        test_attr_def: str,
        support: t.MutableIntMapping,
    ) -> t.MutableIntMapping:
        """Check attribute support for schema quirk."""
        return self._check_schema_component_support(
            quirk_schema,
            can_handle_attr="can_handle_attribute",
            parse_attr="parse_attribute",
            test_definition=test_attr_def,
            support_key="attribute",
            support=support,
        )

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

    def _check_schema_component_support(
        self,
        quirk_schema: m.BaseModel | FlextLdifServersBase,
        *,
        can_handle_attr: str,
        parse_attr: str,
        test_definition: str,
        support_key: str,
        support: t.MutableIntMapping,
    ) -> t.MutableIntMapping:
        """Check schema support for one component type (attribute/objectclass)."""
        if not FlextLdifConversion._has_attr(quirk_schema, can_handle_attr):
            return support
        if not FlextLdifConversion._has_attr(quirk_schema, parse_attr):
            return support
        can_handle = getattr(quirk_schema, can_handle_attr, None)
        if can_handle is None or not callable(can_handle):
            return support
        if not can_handle(test_definition):
            return support
        parse_component = getattr(quirk_schema, parse_attr, None)
        if parse_component is None or not callable(parse_component):
            return support
        component_result = parse_component(test_definition)
        if isinstance(component_result, r) and component_result.success:
            support[support_key] = 1
        return support

    def _check_objectclass_support(
        self,
        quirk_schema: m.BaseModel | FlextLdifServersBase,
        test_oc_def: str,
        support: t.MutableIntMapping,
    ) -> t.MutableIntMapping:
        """Check objectClass support for schema quirk."""
        return self._check_schema_component_support(
            quirk_schema,
            can_handle_attr="can_handle_objectclass",
            parse_attr="parse_objectclass",
            test_definition=test_oc_def,
            support_key="objectclass",
            support=support,
        )

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
            ).map_or(None)
            entry_metadata = m.Ldif.QuirkMetadata.create_for(
                source_server_type,
                extensions=None,
            )
            entry_metadata.acls = [acl.raw_acl] if acl.raw_acl else list[str]()
            rfc_entry = m.Ldif.Entry.create(
                dn=entry_dn,
                attributes=entry_attributes,
                metadata=entry_metadata,
            ).unwrap()
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

    def _convert_schema_entry_value(
        self,
        source_schema: p.Ldif.SchemaQuirk,
        target_schema: p.Ldif.SchemaQuirk,
        value: str,
        *,
        schema_item_kind: c.Ldif.SchemaItemKind,
        field_name: str,
    ) -> r[str]:
        """Convert a schema definition string embedded inside an LDIF entry."""

        def write_schema_item(
            parsed_item: t.Ldif.SchemaConversionValue,
        ) -> r[str]:
            if schema_item_kind == c.Ldif.SchemaItemKind.ATTRIBUTE:
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

        parse_result: r[t.Ldif.SchemaConversionValue]
        if schema_item_kind == c.Ldif.SchemaItemKind.ATTRIBUTE:
            parse_result = self._parse_attribute_with_schema(
                source_schema,
                value,
                parse_error_message=f"Failed to parse {field_name} definition",
            ).map(lambda parsed: parsed)
        else:
            parse_result = self._parse_objectclass_with_schema(
                source_schema,
                value,
                parse_error_message=f"Failed to parse {field_name} definition",
            ).map(lambda parsed: parsed)

        return parse_result.map_error(
            lambda error: error or f"Failed to parse {field_name}",
        ).flat_map(write_schema_item)

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
        schema_field_kinds: dict[str, c.Ldif.SchemaItemKind] = {
            c.Ldif.ATTRIBUTE_TYPES.lower(): c.Ldif.SchemaItemKind.ATTRIBUTE,
            c.Ldif.OBJECT_CLASSES.lower(): c.Ldif.SchemaItemKind.OBJECTCLASS,
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
            transformed_attributes = u.Ldif.transform_entry_attributes_between_oid_rfc(
                converted_entry,
                source_type_norm,
                target_type_norm,
            )
            if transformed_attributes is not None:
                converted_entry = converted_entry.model_copy(
                    update={
                        "attributes": m.Ldif.Attributes.model_validate(
                            {
                                "attributes": transformed_attributes,
                                "attribute_metadata": {},
                                "metadata": None,
                            },
                        ),
                    },
                )
            transformed_dn = u.Ldif.transform_schema_dn_between_oid_rfc(
                converted_entry,
                source_type_norm,
                target_type_norm,
            )
            if transformed_dn is not None:
                converted_entry = converted_entry.model_copy(
                    update={
                        "dn": m.Ldif.DN(
                            value=transformed_dn,
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

    def _convert_to_metadata_attribute_value(
        self,
        value: t.JsonPayload | None,
    ) -> t.JsonValue:
        """Convert value to JsonValue type."""
        normalized: t.JsonValue = u.Cli.normalize_json_value(
            "" if value is None else value,
        )
        return normalized

    def _get_extensions_dict(
        self,
        acl: m.Ldif.Acl,
    ) -> t.Ldif.MutableMetadataInputMapping:
        """Extract extensions dict from ACL metadata."""

        def to_general_value(
            value: t.JsonPayload | None,
        ) -> t.JsonValue:
            normalized_local: t.JsonValue = u.Cli.normalize_json_value(
                value if value is not None else "",
            )
            return normalized_local

        metadata = acl.metadata
        if metadata is None or not metadata:
            return {}
        extensions_raw = metadata.extensions
        return {
            key: to_general_value(value)
            for key, value in extensions_raw.to_dict().items()
        }

    def _get_schema_quirk_for_support_check(
        self,
        quirk: FlextLdifServersBase,
    ) -> m.BaseModel | FlextLdifServersBase | None:
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
        schema_quirk_raw: m.BaseModel | None = getattr(
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
        merged_ext_raw: t.Ldif.MutableMetadataInputMapping = {
            **orig_ext,
            **conv_ext,
        }
        if (
            not merged_ext_raw
            or not get_metadata(acl_step1)
            or (not acl_step1.metadata)
        ):
            return acl_step1
        dynamic_metadata_dict: t.Ldif.MutableMetadataInputMapping = {}
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
                normalized_mapping: t.Ldif.MutableMetadataInputMapping = {}
                for raw_k, raw_v in value.items():
                    normalized_mapping[str(raw_k)] = (
                        FlextLdifConversion._normalize_metadata_value(raw_v)
                    )
                dynamic_metadata_dict[key] = self._convert_to_metadata_attribute_value(
                    t.Cli.JSON_VALUE_ADAPTER.validate_python(normalized_mapping),
                )
                continue
            if isinstance(value, Sequence) and not isinstance(value, str | bytes):
                normalized_sequence: MutableSequence[t.JsonPayload] = [
                    FlextLdifConversion._normalize_metadata_value(raw_item)
                    for raw_item in value
                ]
                dynamic_metadata_dict[key] = self._convert_to_metadata_attribute_value(
                    t.Cli.JSON_VALUE_ADAPTER.validate_python(normalized_sequence),
                )
                continue
            dynamic_metadata_dict[key] = self._convert_to_metadata_attribute_value(
                str(value),
            )
        if acl_step1.metadata:
            metadata_kwargs: t.Ldif.MutableMetadataInputMapping = dynamic_metadata_dict
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
            schema = FlextLdifConversion._get_schema_from_attribute(quirk)
            return r[p.Ldif.SchemaQuirk].ok(schema)
        except TypeError as e:
            return r[p.Ldif.SchemaQuirk].fail(f"{role} quirk error: {e}")

    def _update_entry_metadata(
        self,
        entry: m.Ldif.Entry,
        validated_quirk_type: c.Ldif.ServerTypes,
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
            normalized_source_server: c.Ldif.ServerTypes | None = None
            if source_quirk_name != c.IDENTIFIER_UNKNOWN:
                normalized_source_server = u.try_(
                    lambda: u.Ldif.normalize_server_type(source_quirk_name),
                ).map_or(None)
            extensions_update: t.Ldif.MutableMetadataInputMapping = {
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


__all__: list[str] = ["FlextLdifConversion"]
