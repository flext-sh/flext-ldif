"""Servers conversion matrix for LDAP server translation."""

from __future__ import annotations

import time
from typing import override

from flext_ldif import (
    FlextLdifConversionAclMixin,
    FlextLdifConversionMetadataMixin,
    FlextLdifConversionSchemaMixin,
    FlextLdifConversionSupportMixin,
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
    FlextLdifConversionMetadataMixin,
    FlextLdifConversionAclMixin,
    FlextLdifConversionSupportMixin,
    FlextLdifConversionSchemaMixin,
    s,
):
    """Facade for universal, model-driven server-to-server conversion."""

    dn_registry: m.Ldif.DnRegistry = u.Field(
        default_factory=m.Ldif.DnRegistry,
        description="DN registry for tracking distinguished names during conversion",
    )

    def dsl_convert_between_servers(
        self,
        source_server: p.Ldif.ServerServer,
        target_server: p.Ldif.ServerServer,
        model_instance: m.Ldif.Entry
        | m.Ldif.SchemaAttribute
        | m.Ldif.SchemaObjectClass
        | m.Ldif.Acl,
    ) -> p.Result[t.Ldif.ConvertedModel]:
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
    ) -> p.Result[t.Ldif.ConvertedModel]:
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
        except c.Ldif.EXC_LDIF_PARSE as e:
            result = r[t.Ldif.ConvertedModel].fail_op("Model conversion", e)
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

    @override
    def _convert_entry(
        self,
        source_server: p.Ldif.ServerServer,
        target_server: p.Ldif.ServerServer,
        entry: m.Ldif.Entry,
    ) -> p.Result[t.Ldif.ConvertedModel]:
        """Convert Entry model directly without serialization."""
        try:
            entry_dn = str(entry.dn) if entry.dn else ""
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
        except c.Ldif.EXC_LDIF_PARSE as e:
            logger.exception("Failed to convert Entry model", error=str(e))
            return r[t.Ldif.ConvertedModel].fail_op("Entry conversion", e)

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
