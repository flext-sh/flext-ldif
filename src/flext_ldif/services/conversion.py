"""Servers conversion matrix for LDAP server translation."""

from __future__ import annotations

import time

from flext_ldif import c, m, p, r, t, u
from flext_ldif.services.conversion_acl import FlextLdifConversionAclMixin
from flext_ldif.services.conversion_entry import FlextLdifConversionEntryMixin


class FlextLdifConversion(FlextLdifConversionEntryMixin, FlextLdifConversionAclMixin):
    """Facade for universal, model-driven server-to-server conversion.

    Composes the entry-conversion concern (which brings metadata / support /
    schema) and the ACL-model concern. State (``dn_registry``, ``base_dn``)
    lives on the entry mixin.
    """

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
            model_instance, m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass
        ):
            source_schema_result = self._resolve_schema_server(
                source_server, role="Source"
            )
            if source_schema_result.failure:
                return r[t.Ldif.ConvertedModel].fail(
                    source_schema_result.error or "Source schema not available"
                )
            target_schema_result = self._resolve_schema_server(
                target_server, role="Target"
            )
            if target_schema_result.failure:
                return r[t.Ldif.ConvertedModel].fail(
                    target_schema_result.error or "Target schema not available"
                )
            return self._convert_schema_model_via_entry(
                source_server,
                target_server,
                model_instance,
                source_schema_result.value,
                target_schema_result.value,
            )
        return self._convert_acl(source_server, target_server, model_instance)

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
                source_server, target_server, model_instance
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
            logger=self.logger,
            settings=conversion_config,
            log_level="info" if result.success else "error",
        )
        return result


__all__: list[str] = ["FlextLdifConversion"]
