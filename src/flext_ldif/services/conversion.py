"""Servers conversion matrix for LDAP server translation."""

from __future__ import annotations

import struct
import time
from collections.abc import (
    Mapping,
    Sequence,
)

from flext_ldif import (
    FlextLdifServer,
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
    """Facade for universal, model-driven server-to-server conversion."""

    dn_registry: m.Ldif.DnRegistry = u.Field(
        default_factory=m.Ldif.DnRegistry,
        description="DN registry for tracking distinguished names during conversion",
    )

    @staticmethod
    def _get_schema_from_attribute(
        server: p.Ldif.ServerServer,
    ) -> p.Ldif.SchemaServer:
        return server.schema_server

    @staticmethod
    def _analyze_attribute_case(
        original_attribute_case: t.JsonMapping,
        target_server_type: str,
    ) -> t.MutableMappingKV[str, t.Ldif.MutableMetadataInputMapping]:
        """Analyze attribute case for target compatibility."""
        if bool(original_attribute_case):
            return {
                "attribute_case": {
                    "source_case": FlextLdifConversion._normalize_metadata_value(
                        original_attribute_case,
                    ),
                    "target_server": target_server_type,
                    "action": "apply_target_conventions",
                },
            }
        return {}

    @staticmethod
    def _analyze_boolean_conversions(
        boolean_conversions: t.JsonMapping,
        target_server_type: str,
    ) -> t.MutableMappingKV[str, t.Ldif.MutableMetadataInputMapping]:
        """Analyze boolean conversions for target compatibility."""
        if not boolean_conversions:
            return {}
        result: t.MutableMappingKV[str, t.Ldif.MutableMetadataInputMapping] = {}
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
    ) -> t.MutableMappingKV[str, t.Ldif.MutableMetadataInputMapping]:
        """Analyze DN spacing for target compatibility."""
        spacing = original_format_details.get("dn_spacing")
        if spacing:
            return {
                "dn_format": {
                    "source_dn": FlextLdifConversion._normalize_metadata_value(
                        spacing,
                    ),
                    "target_server": target_server_type,
                    "action": "normalize_for_target",
                },
            }
        return {}

    @staticmethod
    def _analyze_metadata_for_conversion(
        source_metadata: m.Ldif.ServerMetadata | m.Ldif.DynamicMetadata | None,
        target_server_type: str,
    ) -> t.MutableMappingKV[str, t.Ldif.MutableMetadataInputMapping]:
        """Analyze source metadata for intelligent conversion to target server."""
        conversion_analysis: t.MutableMappingKV[
            str,
            t.Ldif.MutableMetadataInputMapping,
        ] = {}
        if not source_metadata:
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
        acc_typed: t.MutableMappingKV[str, t.Ldif.MutableMetadataInputMapping] = {}
        for key, value in boolean_analysis.items():
            if isinstance(value, dict):
                acc_typed[key] = {
                    k: FlextLdifConversion._normalize_metadata_value(v)
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
                    k: FlextLdifConversion._normalize_metadata_value(v)
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
                    k: FlextLdifConversion._normalize_metadata_value(v)
                    for k, v in dn_format_value.items()
                }
        return acc_typed

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
                return list(values)
        return tuple[str, ...]()

    def _build_schema_bridge_entry(
        self,
        source_server: p.Ldif.ServerServer,
        schema_item_kind: c.Ldif.SchemaItemKind,
        schema_value: str,
    ) -> m.Ldif.Entry:
        source_server_type = u.try_(
            lambda: u.Ldif.normalize_server_type(
                source_server.server_type,
            ),
        ).map_or(None)
        metadata = m.Ldif.ServerMetadata.create_for(source_server_type, extensions=None)
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
        source_server: p.Ldif.ServerServer,
        target_server: p.Ldif.ServerServer,
        item: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        source_schema: p.Ldif.SchemaServer,
        target_schema: p.Ldif.SchemaServer,
    ) -> r[t.Ldif.ConvertedModel]:
        """Orchestrate schema conversion through m.Ldif.Entry intermediary."""
        is_attribute = isinstance(item, m.Ldif.SchemaAttribute)
        item_name = "attribute" if is_attribute else "objectclass"
        item_type = (
            c.Ldif.SchemaItemKind.ATTRIBUTE
            if is_attribute
            else c.Ldif.SchemaItemKind.OBJECTCLASS
        )
        write_result = (
            source_schema.write_attribute(item)
            if is_attribute
            else source_schema.write_objectclass(item)
        )
        field_name = c.Ldif.ATTRIBUTE_TYPES if is_attribute else c.Ldif.OBJECT_CLASSES
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
            return r[t.Ldif.ConvertedModel].fail(
                source_value_result.error
                or "Failed to write schema item in source format",
            )
        bridge_entry = self._build_schema_bridge_entry(
            source_server,
            item_type,
            source_value_result.value,
        )
        converted_entry_result = self._convert_entry(
            source_server,
            target_server,
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
        converted_values = self._extract_schema_values_from_entry(
            converted_entry_value,
            field_name,
        )
        if not converted_values:
            return r[t.Ldif.ConvertedModel].fail(
                f"Converted Entry does not contain {field_name}",
            )
        first_value = converted_values[0]
        parsed_result = (
            self._parse_attribute_with_schema(
                target_schema,
                first_value,
                parse_error_message="Failed to parse converted attribute",
            )
            if is_attribute
            else self._parse_objectclass_with_schema(
                target_schema,
                first_value,
                parse_error_message="Failed to parse converted objectclass",
            )
        )
        return parsed_result.flat_map(
            lambda parsed: r[t.Ldif.ConvertedModel].ok(parsed),
        )

    @staticmethod
    def _normalize_metadata_value(
        value: t.JsonPayload | t.MappingKV[str, t.JsonPayload] | None,
    ) -> t.JsonValue:
        """Normalize metadata value to proper type."""
        if value is None:
            empty_val: t.JsonValue = u.normalize_to_json_value("")
            return empty_val
        if isinstance(value, Mapping):
            normalized_mapping: dict[str, t.JsonValue] = {
                key: u.normalize_to_json_value(item) for key, item in value.items()
            }
            return normalized_mapping
        if isinstance(value, Sequence) and not isinstance(value, str | bytes):
            normalized_sequence: list[t.JsonValue] = [
                u.normalize_to_json_value(item) for item in value
            ]
            return normalized_sequence
        normalized: t.JsonValue = t.Cli.JSON_VALUE_ADAPTER.validate_python(value)
        return normalized

    @staticmethod
    def _parse_attribute_with_schema(
        schema: p.Ldif.SchemaServer,
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
        schema: p.Ldif.SchemaServer,
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
    def _resolve_server(
        server_or_type: str | p.Ldif.ServerReference | p.Ldif.ServerServer,
    ) -> p.Ldif.ServerServer:
        """Resolve server server instance from string type or return instance."""
        if isinstance(server_or_type, str):
            server = FlextLdifServer.fetch_global_instance()
            server_type_str: str = server_or_type
            resolved_result = server.server(server_type_str)
            if resolved_result.failure:
                error_msg = (
                    f"Unknown server type: {server_or_type}: {resolved_result.error}"
                )
                raise ValueError(error_msg)
            resolved: p.Ldif.ServerServer = resolved_result.value
            return resolved
        if isinstance(server_or_type, p.Ldif.ServerServer):
            return server_or_type
        resolved_from_ref = FlextLdifServer.fetch_global_instance().server(
            server_or_type.server_type,
        )
        if resolved_from_ref.failure:
            error_msg = (
                f"Unknown server type: {server_or_type.server_type}: "
                f"{resolved_from_ref.error}"
            )
            raise ValueError(error_msg)
        return resolved_from_ref.value

    def dsl_convert_between_servers(
        self,
        source_server: p.Ldif.ServerServer,
        target_server: p.Ldif.ServerServer,
        model_instance: m.Ldif.Entry
        | m.Ldif.SchemaAttribute
        | m.Ldif.SchemaObjectClass
        | m.Ldif.Acl,
    ) -> r[t.Ldif.ConvertedModel]:
        """DSL: orchestrate model conversion between servers."""
        if isinstance(model_instance, m.Ldif.Entry):
            return self._convert_entry(source_server, target_server, model_instance)
        if isinstance(
            model_instance,
            m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        ):
            source_schema_result = self._resolve_schema_server(
                source_server,
                role="Source",
            )
            if source_schema_result.failure:
                return r[t.Ldif.ConvertedModel].fail(
                    source_schema_result.error or "Source schema not available",
                )
            target_schema_result = self._resolve_schema_server(
                target_server,
                role="Target",
            )
            if target_schema_result.failure:
                return r[t.Ldif.ConvertedModel].fail(
                    target_schema_result.error or "Target schema not available",
                )
            return self._convert_schema_model_via_entry(
                source_server,
                target_server,
                model_instance,
                source_schema_result.value,
                target_schema_result.value,
            )
        return self._convert_acl(
            source_server,
            target_server,
            model_instance,
        )

    def convert_model(
        self,
        source: str | p.Ldif.ServerReference | p.Ldif.ServerServer,
        target: str | p.Ldif.ServerReference | p.Ldif.ServerServer,
        model_instance: m.Ldif.Entry
        | m.Ldif.SchemaAttribute
        | m.Ldif.SchemaObjectClass
        | m.Ldif.Acl,
    ) -> r[t.Ldif.ConvertedModel]:
        """Convert a model from a source server format to a target server format."""
        start_time = time.perf_counter()
        source_format = source if isinstance(source, str) else source.server_type
        target_format = target if isinstance(target, str) else target.server_type
        model_type = type(model_instance).__name__
        conversion_operation = f"convert_{model_type}"
        self.logger.debug(
            "Converting model",
            source_format=source_format,
            target_format=target_format,
            model_type=model_type,
        )
        try:
            source_server = self._resolve_server(source)
            target_server = self._resolve_server(target)
            result = self.dsl_convert_between_servers(
                source_server,
                target_server,
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
        source: str | p.Ldif.ServerReference,
        target: str | p.Ldif.ServerReference,
        entry: p.Ldif.Entry,
    ) -> p.Result[p.Ldif.Entry]:
        """Compatibility facade for conversion matrix callers."""
        source_str = source if isinstance(source, str) else source.server_type
        target_str = target if isinstance(target, str) else target.server_type
        concrete_entry = (
            entry
            if isinstance(entry, m.Ldif.Entry)
            else m.Ldif.Entry.model_validate(entry)
        )
        result = self.convert_model(
            source=source_str,
            target=target_str,
            model_instance=concrete_entry,
        )
        if result.success:
            value = result.map_or(None)
            if isinstance(value, m.Ldif.Entry):
                return r[p.Ldif.Entry].ok(value)
        return r[p.Ldif.Entry].fail(result.error or "Entry conversion failed")

    def resolve_supported_conversions(
        self,
        server: p.Ldif.ServerReference | str,
    ) -> t.MutableBoolMapping:
        """Check which data types a server supports for conversion."""
        support: t.MutableIntMapping = {
            "attribute": 0,
            "objectclass": 0,
            "acl": 0,
            "entry": 0,
        }
        concrete_server = self._server.resolve_base_server(
            server if isinstance(server, str) else server.server_type,
        ).map_or(None)
        if concrete_server is None:
            return {
                "attribute": False,
                "objectClass": False,
                "objectclass": False,
                "acl": False,
                "entry": False,
            }
        support = self._check_schema_support(concrete_server, support)
        support = self._check_acl_support(concrete_server, support)
        support = self._check_entry_support(concrete_server, support)
        return {
            "attribute": bool(support.get("attribute", 0)),
            "objectClass": bool(support.get("objectclass", 0)),
            "objectclass": bool(support.get("objectclass", 0)),
            "acl": bool(support.get("acl", 0)),
            "entry": bool(support.get("entry", 0)),
        }

    def _check_acl_support(
        self,
        server: p.Ldif.ServerServer,
        support: t.MutableIntMapping,
    ) -> t.MutableIntMapping:
        """Check ACL support."""
        acl = server.acl_server
        test_acl_def = 'targetattr="*" (version 3.0; acl "test"; allow (read) userdn="ldap:///self";)'
        acl_result = acl.parse_server(test_acl_def)
        if acl_result.map_or(None) is not None:
            support["acl"] = 1
        return support

    def _check_attribute_support(
        self,
        server_schema: p.Ldif.SchemaServer,
        test_attr_def: str,
        support: t.MutableIntMapping,
    ) -> t.MutableIntMapping:
        """Check attribute support for schema server."""
        attribute_result = server_schema.parse_attribute(test_attr_def)
        if attribute_result.success:
            support["attribute"] = 1
        return support

    def _check_converted_has_permissions(self, converted_acl: m.Ldif.Acl) -> bool:
        """Check if converted ACL has any permissions set."""
        permissions = converted_acl.permissions
        if permissions is None:
            return False
        return (
            permissions.read
            or permissions.write
            or permissions.add
            or permissions.delete
            or permissions.search
            or permissions.compare
            or permissions.self_write
            or permissions.proxy
            or permissions.browse
            or permissions.auth
            or permissions.all
        )

    def _check_entry_support(
        self,
        server: p.Ldif.ServerServer,
        support: t.MutableIntMapping,
    ) -> t.MutableIntMapping:
        """Check Entry support via the canonical entry server public surface."""
        if server.entry_server.parse_entry("cn=test,dc=example,dc=com", {}).success:
            support["entry"] = 1
        return support

    def _check_objectclass_support(
        self,
        server_schema: p.Ldif.SchemaServer,
        test_oc_def: str,
        support: t.MutableIntMapping,
    ) -> t.MutableIntMapping:
        """Check objectClass support for schema server."""
        objectclass_result = server_schema.parse_objectclass(test_oc_def)
        if objectclass_result.success:
            support["objectclass"] = 1
        return support

    def _check_schema_support(
        self,
        server: p.Ldif.ServerServer,
        support: t.MutableIntMapping,
    ) -> t.MutableIntMapping:
        """Check schema (attribute and objectClass) support."""
        server_schema = self._get_schema_server_for_support_check(server)
        test_attr_def = "( 2.16.840.1.113894.1.1.1 NAME 'orclTest' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        test_oc_def = (
            "( 2.16.840.1.113894.1.2.1 NAME 'orclTest' SUP top STRUCTURAL MUST cn )"
        )
        support = self._check_attribute_support(server_schema, test_attr_def, support)
        return self._check_objectclass_support(server_schema, test_oc_def, support)

    def _convert_acl(
        self,
        source_server: p.Ldif.ServerServer,
        target_server: p.Ldif.ServerServer,
        acl: m.Ldif.Acl,
    ) -> r[t.Ldif.ConvertedModel]:
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
            source_server_type: str | None = u.try_(
                lambda: (
                    u.Ldif.normalize_server_type(source_server.server_type)
                    if source_server.server_type
                    else None
                ),
            ).map_or(None)
            entry_metadata = m.Ldif.ServerMetadata.create_for(
                source_server_type,
                extensions=None,
            )
            entry_metadata.acls = [acl.raw_acl] if acl.raw_acl else list[str]()
            rfc_entry = m.Ldif.Entry.create(
                dn=entry_dn,
                attributes=entry_attributes,
                metadata=entry_metadata,
            ).unwrap()
            target_server_type: str | None = u.try_(
                lambda: (
                    u.Ldif.normalize_server_type(target_server.server_type)
                    if target_server.server_type != c.IDENTIFIER_UNKNOWN
                    else None
                ),
            ).map_or(None)
            converted_entry_result = self._convert_entry(
                source_server,
                target_server,
                rfc_entry,
            )
            converted_acl_result: r[m.Ldif.Acl]
            if converted_entry_result.failure:
                converted_acl_result = r[m.Ldif.Acl].fail(
                    converted_entry_result.error or "Acl conversion returned no entry",
                )
            elif not isinstance(converted_entry_result.value, m.Ldif.Entry):
                converted_acl_result = r[m.Ldif.Acl].fail(
                    "Entry conversion returned unexpected type: "
                    f"{type(converted_entry_result.value).__name__}",
                )
            else:
                get_metadata = u.prop("metadata")
                converted_metadata_raw = get_metadata(converted_entry_result.value)
                if converted_metadata_raw is None:
                    converted_acl_result = r[m.Ldif.Acl].fail(
                        "Converted entry has no ACLs in metadata.acls",
                    )
                elif not isinstance(converted_metadata_raw, m.Ldif.ServerMetadata):
                    converted_acl_result = r[m.Ldif.Acl].fail(
                        f"Unexpected metadata type: {type(converted_metadata_raw).__name__}",
                    )
                elif not isinstance(converted_metadata_raw.acls, list):
                    converted_acl_result = r[m.Ldif.Acl].fail(
                        "Converted entry has no ACLs in metadata.acls",
                    )
                else:
                    acls = [
                        item
                        for item in converted_metadata_raw.acls
                        if isinstance(item, m.Ldif.Acl)
                    ]
                    converted_acl_result = (
                        r[m.Ldif.Acl].ok(acls[0])
                        if acls
                        else r[m.Ldif.Acl].fail(
                            "Converted entry has no ACLs in metadata.acls",
                        )
                    )
            return converted_acl_result.flat_map(
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
        source_schema: p.Ldif.SchemaServer,
        target_schema: p.Ldif.SchemaServer,
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
        source_server: p.Ldif.ServerServer,
        target_server: p.Ldif.ServerServer,
        entry: m.Ldif.Entry,
    ) -> r[m.Ldif.Entry]:
        """Convert schema definition attributes embedded in a schema entry."""
        result = r[m.Ldif.Entry].ok(entry)
        if entry.attributes is not None and u.Ldif.is_schema_entry(entry):
            source_schema_result = self._resolve_schema_server(
                source_server,
                role="Source",
            )
            target_schema_result = self._resolve_schema_server(
                target_server,
                role="Target",
            )
            if source_schema_result.failure:
                result = r[m.Ldif.Entry].fail(
                    source_schema_result.error or "Source schema not available",
                )
            elif target_schema_result.failure:
                result = r[m.Ldif.Entry].fail(
                    target_schema_result.error or "Target schema not available",
                )
            else:
                schema_field_kinds: dict[str, c.Ldif.SchemaItemKind] = {
                    c.Ldif.ATTRIBUTE_TYPES.lower(): c.Ldif.SchemaItemKind.ATTRIBUTE,
                    c.Ldif.OBJECT_CLASSES.lower(): c.Ldif.SchemaItemKind.OBJECTCLASS,
                }
                updated_attributes = dict(entry.attributes.attributes)
                changed = False
                conversion_error: str | None = None
                for attr_name, values in entry.attributes.attributes.items():
                    schema_item_kind = schema_field_kinds.get(attr_name.lower())
                    if schema_item_kind is None:
                        continue
                    converted_values: t.MutableSequenceOf[str] = []
                    for value in values:
                        converted_value_result = self._convert_schema_entry_value(
                            source_schema_result.value,
                            target_schema_result.value,
                            value,
                            schema_item_kind=schema_item_kind,
                            field_name=attr_name,
                        )
                        if converted_value_result.failure:
                            conversion_error = (
                                converted_value_result.error
                                or f"Failed converting schema field {attr_name}"
                            )
                            break
                        converted_values.append(converted_value_result.value)
                    if conversion_error is not None:
                        break
                    updated_attributes[attr_name] = converted_values
                    changed = True
                if conversion_error is not None:
                    result = r[m.Ldif.Entry].fail(conversion_error)
                elif changed:
                    updated_entry = entry.model_copy(
                        update={
                            "attributes": entry.attributes.model_copy(
                                update={"attributes": updated_attributes},
                                deep=True,
                            ),
                        },
                        deep=True,
                    )
                    result = r[m.Ldif.Entry].ok(updated_entry)
        return result

    def _convert_entry(
        self,
        source_server: p.Ldif.ServerServer,
        target_server: p.Ldif.ServerServer,
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
            target_server_type_raw = target_server.server_type
            if target_server_type_raw != c.IDENTIFIER_UNKNOWN:
                target_server_type_str = u.Ldif.normalize_server_type(
                    target_server_type_raw,
                )
            else:
                target_server_type_str = c.Ldif.ServerTypes.RFC
            validated_server_type = u.Ldif.normalize_server_type(
                str(target_server_type_str),
            )
            metadata_for_analysis: (
                m.Ldif.ServerMetadata | m.Ldif.DynamicMetadata | None
            ) = (
                entry.metadata
                if isinstance(
                    entry.metadata,
                    (m.Ldif.ServerMetadata, m.Ldif.DynamicMetadata),
                )
                else None
            )
            conversion_analysis = FlextLdifConversion._analyze_metadata_for_conversion(
                metadata_for_analysis,
                validated_server_type,
            )
            source_server_name = source_server.server_type
            source_type_norm = source_server_name.lower()
            target_type_norm = str(target_server_type_str).lower()
            converted_entry = self._update_entry_metadata(
                converted_entry,
                validated_server_type,
                str(conversion_analysis) if conversion_analysis else None,
                source_server_name,
            )
            if source_type_norm != target_type_norm:
                schema_entry_result = self._convert_schema_entry_attributes(
                    source_server,
                    target_server,
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
        normalized: t.JsonValue = u.normalize_to_json_value(
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
            normalized_local: t.JsonValue = u.normalize_to_json_value(
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

    def _get_schema_server_for_support_check(
        self,
        server: p.Ldif.ServerServer,
    ) -> p.Ldif.SchemaServer:
        """Get schema server from base server for support checking."""
        return server.schema_server

    def _preserve_acl_metadata(
        self,
        original_acl: m.Ldif.Acl,
        converted_acl: m.Ldif.Acl,
        source_server_type: str | None = None,
        target_server_type: str | None = None,
    ) -> m.Ldif.Acl:
        """Preserve permissions and metadata from original ACL."""
        converted_has_permissions = self._check_converted_has_permissions(converted_acl)
        if original_acl.permissions:
            orig_perms_dict_raw = original_acl.permissions.model_dump(
                exclude_unset=True,
            )
            orig_perms_dict: t.MutableBoolMapping = {
                key: value
                for key, value in orig_perms_dict_raw.items()
                if value is True
            }
            logger.debug(
                "ACL permission preservation",
                source_server_type=source_server_type or "",
                target_server_type=target_server_type or "",
                original_permissions=str(orig_perms_dict),
            )
            if orig_perms_dict:
                permission_settings = m.Ldif.PermissionMappingConfig.model_validate({
                    "original_acl": original_acl,
                    "converted_acl": converted_acl,
                    "orig_perms_dict": orig_perms_dict,
                    "source_server_type": source_server_type,
                    "target_server_type": target_server_type,
                    "converted_has_permissions": converted_has_permissions,
                })
                normalized_source = (
                    u.Ldif.normalize_server_type(
                        permission_settings.source_server_type,
                    )
                    if isinstance(permission_settings.source_server_type, str)
                    else permission_settings.source_server_type
                )
                normalized_target = (
                    u.Ldif.normalize_server_type(
                        permission_settings.target_server_type,
                    )
                    if isinstance(permission_settings.target_server_type, str)
                    else permission_settings.target_server_type
                )
                permission_mapper = None
                mapping_type = "none"
                match (normalized_source, normalized_target):
                    case ("oid", "oud"):
                        mapping_type = "oid_to_oud"
                        permission_mapper = u.Ldif.map_oid_to_oud_permissions
                    case ("oud", "oid"):
                        mapping_type = "oud_to_oid"
                        permission_mapper = u.Ldif.map_oud_to_oid_permissions
                    case _ if (
                        not permission_settings.converted_has_permissions
                        and permission_settings.original_acl.permissions is not None
                    ):
                        mapping_type = "preserve_original"
                        converted_acl = permission_settings.converted_acl.model_copy(
                            update={
                                "permissions": permission_settings.original_acl.permissions.model_copy(
                                    deep=True,
                                )
                                if permission_settings.original_acl.permissions
                                else None,
                            },
                            deep=True,
                        )
                    case _:
                        pass
                if permission_mapper is not None:
                    mapped_perms = permission_mapper(
                        permission_settings.orig_perms_dict,
                    )
                    normalized_perms = u.Ldif.build_mapped_permissions_dict(
                        mapped_perms,
                        {
                            key: u.Ldif.normalize_permission_key(key)
                            for key in c.Ldif.ACL_PERMISSION_KEYS
                        },
                    )
                    perms_model = self._perms_dict_to_model(normalized_perms)
                    converted_acl = permission_settings.converted_acl.model_copy(
                        update={"permissions": perms_model},
                        deep=True,
                    )
                logger.debug(
                    "ACL t.MappingKV decision",
                    mapping_type=mapping_type,
                    normalized_source=str(normalized_source),
                    normalized_target=str(normalized_target),
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
                    normalized_mapping[raw_k] = (
                        FlextLdifConversion._normalize_metadata_value(raw_v)
                    )
                dynamic_metadata_dict[key] = self._convert_to_metadata_attribute_value(
                    t.Cli.JSON_VALUE_ADAPTER.validate_python(normalized_mapping),
                )
                continue
            if isinstance(value, Sequence) and not isinstance(value, str | bytes):
                normalized_sequence: t.MutableSequenceOf[t.JsonPayload] = [
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

    def _resolve_schema_server(
        self,
        server_or_type: str | p.Ldif.ServerReference | p.Ldif.ServerServer,
        *,
        role: str,
    ) -> r[p.Ldif.SchemaServer]:
        server = self._resolve_server(server_or_type)
        try:
            schema = FlextLdifConversion._get_schema_from_attribute(server)
            return r[p.Ldif.SchemaServer].ok(schema)
        except TypeError as e:
            return r[p.Ldif.SchemaServer].fail(f"{role} server error: {e}")

    def _update_entry_metadata(
        self,
        entry: m.Ldif.Entry,
        validated_server_type: c.Ldif.ServerTypes,
        conversion_analysis: str | None,
        source_server_name: str,
    ) -> m.Ldif.Entry:
        """Update entry metadata for conversion (internal helper)."""
        get_metadata = u.prop("metadata")
        get_extensions = u.prop("extensions")
        current_entry = entry
        if not get_metadata(current_entry):
            metadata_obj = m.Ldif.ServerMetadata.create_for(
                server_type=validated_server_type,
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
            if source_server_name != c.IDENTIFIER_UNKNOWN:
                normalized_source_server = u.try_(
                    lambda: u.Ldif.normalize_server_type(source_server_name),
                ).map_or(None)
            extensions_update: t.Ldif.MutableMetadataInputMapping = {
                "converted_from_server": source_server_name,
            }
            if conversion_analysis:
                extensions_update["conversion_analysis"] = conversion_analysis
            updated_extensions = (
                entry_metadata.extensions or m.Ldif.DynamicMetadata()
            ).model_copy(update=extensions_update, deep=True)
            updated_metadata = entry_metadata.model_copy(
                update={
                    "server_type": validated_server_type,
                    "extensions": updated_extensions,
                    "original_server_type": (
                        entry_metadata.original_server_type or normalized_source_server
                    ),
                    "target_server_type": validated_server_type,
                },
                deep=True,
            )
            current_entry = current_entry.model_copy(
                update={"metadata": updated_metadata},
                deep=True,
            )
        return current_entry


__all__: list[str] = ["FlextLdifConversion"]
