"""FLEXT-LDIF API - Unified Facade for LDIF Operations via MRO.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Self, cast, override

from flext_ldif import (
    FlextLdifAcl,
    FlextLdifAnalysis,
    FlextLdifCategorization,
    FlextLdifConversion,
    FlextLdifDetector,
    FlextLdifEntries,
    FlextLdifFilters,
    FlextLdifMigrationPipeline,
    FlextLdifParser,
    FlextLdifProcessing,
    FlextLdifStatistics,
    FlextLdifValidation,
    FlextLdifWriter,
    c,
    e,
    m,
    p,
    r,
    t,
    u,
)
from flext_ldif.services.pipeline import FlextLdifProcessingPipeline

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


class FlextLdif(
    FlextLdifAcl,
    FlextLdifCategorization,
    FlextLdifConversion,
    FlextLdifDetector,
    FlextLdifParser,
    FlextLdifWriter,
    FlextLdifAnalysis,
    FlextLdifEntries,
    FlextLdifProcessing,
    FlextLdifValidation,
    FlextLdifStatistics,
):
    """MRO facade over LDIF services.

    All operations come from mixin bases via MRO. Only infrastructure
    helpers are defined locally.
    """

    def __init__(
        self,
        *,
        server: p.Ldif.ServerRegistry | None = None,
        registry: p.Ldif.ServerRegistry | None = None,
        settings: p.Ldif.Settings | None = None,
        runtime_settings: p.Ldif.Settings | None = None,
    ) -> None:
        """Initialize the LDIF facade with the canonical shared registry.

        ``registry`` is the service-base field name (the base DSL payload
        feeds it); ``server`` remains the public facade alias.
        """
        super().__init__()
        resolved_registry = server if server is not None else registry
        if resolved_registry is not None:
            self.registry = resolved_registry
        resolved_settings = (
            runtime_settings if runtime_settings is not None else settings
        )
        self.bind_runtime_settings(resolved_settings)

    def __call__(
        self,
        *,
        server: p.Ldif.ServerRegistry | None = None,
        settings: p.Ldif.Settings | None = None,
        **fields: t.JsonValue,
    ) -> Self:
        """Return a configured facade instance while keeping the DSL alias callable."""
        configured = super().__call__(server=server, settings=settings, **fields)
        return cast("Self", configured)

    def categorization(
        self,
        *,
        options: m.Ldif.MigrateOptions | None = None,
        base_dn: str | None = None,
        server_type: str = c.Ldif.ServerTypes.RFC.value,
    ) -> p.Ldif.CategorizationService:
        """Create a categorization service bound to the facade registry.

        Returns:
            The resulting ``p.Ldif.CategorizationService``.
        """
        resolved_base_dn = (
            base_dn
            if base_dn is not None
            else options.base_dn
            if options is not None
            else None
        )
        categorization = FlextLdifCategorization(
            categorization_rules=options.categorization_rules
            if options is not None
            else None,
            schema_whitelist_rules=options.schema_whitelist_rules
            if options is not None
            else None,
            forbidden_attributes=options.forbidden_attributes
            if options is not None
            else None,
            forbidden_objectclasses=options.forbidden_objectclasses
            if options is not None
            else None,
            base_dn=resolved_base_dn,
            server_type=server_type,
            registry=self._server,
            server_registry=self._server,
        )
        bound_categorization: FlextLdifCategorization = (
            categorization.bind_runtime_settings(self.settings)
        )
        return bound_categorization

    @staticmethod
    def filter_entry_attributes(
        entry: p.Ldif.Entry,
        forbidden_attrs: t.StrSequence,
        forbidden_ocs: t.StrSequence,
    ) -> p.Ldif.Entry:
        """Expose the stateless filter helper through the facade DSL.

        Returns:
            The resulting ``p.Ldif.Entry``.
        """
        concrete = u.Ldif.as_entry(entry)
        return FlextLdifFilters.filter_entry_attributes(
            entry=concrete,
            forbidden_attrs=forbidden_attrs,
            forbidden_ocs=forbidden_ocs,
        )

    @staticmethod
    def filter_schema_attribute_values(
        entry: p.Ldif.Entry,
        allowed_oids: m.Ldif.WhitelistRules | t.FrozensetMapping,
    ) -> p.Ldif.Entry:
        """Expose schema-attribute OID filtering through the facade DSL.

        Returns:
            The resulting ``p.Ldif.Entry``.
        """
        concrete = u.Ldif.as_entry(entry)
        return FlextLdifFilters.filter_schema_attribute_values(
            entry=concrete,
            allowed_oids=allowed_oids,
        )

    def _resolve_registry_server[T](
        self,
        server_type: str,
        *,
        resource_type: str,
        lookup: Callable[[p.Ldif.ServerRegistry, str], T | None],
    ) -> p.Result[T]:
        """Resolve one registry server with the canonical not-found failure.

        Returns:
            The resulting ``p.Result[T]``.
        """
        server_registry: p.Ldif.ServerRegistry = self._server
        resolved = lookup(server_registry, server_type)
        if resolved is None:
            return e.fail_not_found(
                resource_type,
                server_type,
                result_type=r[T],
            )
        return r[T].ok(resolved)

    def acl(self, server_type: str) -> p.Result[p.Ldif.AclServer]:
        """Expose ACL server lookup through the public facade (ENFORCE-056).

        Returns:
            The resulting ``p.Result[p.Ldif.AclServer]``.
        """
        return self._resolve_registry_server(
            server_type,
            resource_type="acl_server",
            lookup=lambda registry, requested: registry.acl(requested),
        )

    def entry(self, server_type: str) -> p.Result[p.Ldif.EntryServer]:
        """Expose entry server lookup through the public facade (ENFORCE-056).

        Returns:
            The resulting ``p.Result[p.Ldif.EntryServer]``.
        """
        return self._resolve_registry_server(
            server_type,
            resource_type="entry_server",
            lookup=lambda registry, requested: registry.entry(requested),
        )

    def resolve_base_server(self, server_type: str) -> p.Result[p.Ldif.ServerServer]:
        """Expose base server resolution through the public facade.

        Returns:
            The resulting ``p.Result[p.Ldif.ServerServer]``.
        """
        return r[p.Ldif.ServerServer].from_result(
            self._server.resolve_base_server(server_type),
        )

    def schema_server(self, server_type: str) -> p.Result[p.Ldif.SchemaServer]:
        """Expose schema server lookup through the public facade (ENFORCE-056).

        Returns:
            The resulting ``p.Result[p.Ldif.SchemaServer]``.
        """
        return self._resolve_registry_server(
            server_type,
            resource_type="schema_server",
            lookup=lambda registry, requested: registry.schema_server(requested),
        )

    def resolve_schema_server(self, server_type: str) -> p.Result[p.Ldif.SchemaServer]:
        """Expose canonical schema server resolution (ENFORCE-056).

        Returns:
            The resulting ``p.Result[p.Ldif.SchemaServer]``.
        """
        return self._resolve_registry_server(
            server_type,
            resource_type="schema_server",
            lookup=lambda registry, requested: registry.resolve_schema_server(
                requested,
            ),
        )

    def resolve_server_bundle(
        self,
        server_type: str,
    ) -> p.Result[
        t.MappingKV[str, p.Ldif.SchemaServer | p.Ldif.AclServer | p.Ldif.EntryServer]
    ]:
        """Expose full server bundle resolution through the public facade.

        Returns:
            The resulting ``p.Result[t.MappingKV[str, p.Ldif.SchemaServer |
                p.Ldif.AclServer | p.Ldif.EntryServer]]``.
        """
        return r[
            t.MappingKV[
                str,
                p.Ldif.SchemaServer | p.Ldif.AclServer | p.Ldif.EntryServer,
            ]
        ].from_result(self._server.resolve_server_bundle(server_type))

    def resolve_server_constants(
        self,
        server_type: str,
    ) -> p.Result[type[p.Ldif.ServerConstants]]:
        """Expose server constants lookup through the public facade.

        Returns:
            The resulting ``p.Result[type[p.Ldif.ServerConstants]]``.
        """
        return r[type[p.Ldif.ServerConstants]].from_result(
            self._server.resolve_server_constants(server_type),
        )

    def list_registered_servers(self) -> p.Result[t.MutableSequenceOf[str]]:
        """Expose the normalized registered server list (ENFORCE-056).

        Returns:
            The resulting ``p.Result[t.MutableSequenceOf[str]]``.
        """
        server_registry: p.Ldif.ServerRegistry = self._server
        return r[t.MutableSequenceOf[str]].ok(server_registry.list_registered_servers())

    def summarize_registry(self) -> p.Result[t.Ldif.MutableMetadataInputMapping]:
        """Expose registry statistics through the public facade (ENFORCE-056).

        Returns:
            The resulting ``p.Result[t.Ldif.MutableMetadataInputMapping]``.
        """
        server_registry: p.Ldif.ServerRegistry = self._server
        return r[t.Ldif.MutableMetadataInputMapping].ok(
            server_registry.summarize_registry(),
        )

    @staticmethod
    def processing_pipeline(
        *,
        settings: m.Ldif.TransformConfig | None = None,
        source_server: str | c.Ldif.ServerTypes | None = None,
        target_server: str | c.Ldif.ServerTypes | None = None,
    ) -> p.Ldif.ProcessingPipeline:
        """Create a processing pipeline from explicit config or server pair.

        Returns:
            The resulting ``p.Ldif.ProcessingPipeline``.
        """
        if settings is not None:
            return FlextLdifProcessingPipeline(transform_config=settings)
        if source_server is not None and target_server is not None:
            return FlextLdifProcessingPipeline.for_servers(
                source_server=source_server,
                target_server=target_server,
            )
        return FlextLdifProcessingPipeline()

    def migration_pipeline(
        self,
        *,
        input_dir: Path | None = None,
        output_dir: Path | None = None,
        settings: m.Ldif.TransformConfig | None = None,
        options: m.Ldif.MigrateOptions | None = None,
    ) -> p.Ldif.MigrationPipeline:
        """Create a configured migration pipeline bound to the facade runtime.

        Returns:
            The resulting ``p.Ldif.MigrationPipeline``.
        """
        process_config = settings.process_config if settings is not None else None
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type=(
                process_config.source_server if process_config is not None else None
            ),
            target_server_type=(
                process_config.target_server if process_config is not None else None
            ),
            output_filename=(options.output_filename if options is not None else None),
            registry=self._server,
        )
        bound_pipeline: FlextLdifMigrationPipeline = pipeline.bind_runtime_settings(
            self.settings,
        )
        return bound_pipeline

    def migrate(
        self,
        input_dir: Path | None = None,
        output_dir: Path | None = None,
        source_server: str = c.Ldif.ServerTypes.RFC.value,
        target_server: str = c.Ldif.ServerTypes.RFC.value,
        options: m.Ldif.MigrateOptions | None = None,
    ) -> p.Result[m.Ldif.MigrationPipelineResult]:
        """Migrate LDIF data between servers.

        Returns:
            The resulting ``p.Result[m.Ldif.MigrationPipelineResult]``.
        """
        transform_config = m.Ldif.TransformConfig.servers(
            source_server=source_server,
            target_server=target_server,
        )
        pipeline = self.migration_pipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            settings=transform_config,
            options=options,
        )
        return pipeline.execute()

    @override
    def validate_entries(
        self,
        entries: t.MutableSequenceOf[m.Ldif.Entry] | m.Ldif.ParseResponse,
        validation_service: p.Ldif.ValidationService | None = None,
    ) -> p.Result[m.Ldif.ValidationResult]:
        """Validate list of entries.

        Returns:
            The resulting ``p.Result[m.Ldif.ValidationResult]``.
        """
        resolved_validation_service = validation_service or self
        return super().validate_entries(entries, resolved_validation_service)


ldif: FlextLdif = FlextLdif.fetch_global()
"""Process-wide FlextLdif facade singleton resolved from the global container."""

__all__: list[str] = ["FlextLdif", "ldif"]
