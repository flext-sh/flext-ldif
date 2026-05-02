"""FLEXT-LDIF API - Unified Facade for LDIF Operations via MRO."""

from __future__ import annotations

from pathlib import Path
from typing import Self, override

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
    FlextLdifProcessingPipeline,
    FlextLdifSettings,
    FlextLdifStatistics,
    FlextLdifValidation,
    FlextLdifWriter,
    c,
    m,
    p,
    r,
    t,
)


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
        settings: FlextLdifSettings | None = None,
    ) -> None:
        """Initialize the LDIF facade with the canonical shared registry."""
        super().__init__(server=server, runtime_settings=settings)

    def __call__(
        self,
        *,
        server: p.Ldif.ServerRegistry | None = None,
        settings: FlextLdifSettings | None = None,
    ) -> Self:
        """Return a configured facade instance while keeping the DSL alias callable."""
        return type(self)(
            server=self._server if server is None else server,
            settings=settings,
        )

    def categorization(
        self,
        *,
        options: m.Ldif.MigrateOptions | None = None,
        base_dn: str | None = None,
        server_type: str = c.Ldif.ServerTypes.RFC.value,
    ) -> p.Ldif.CategorizationService:
        """Create a categorization service bound to the facade registry."""
        resolved_base_dn = (
            base_dn
            if base_dn is not None
            else (options.base_dn if options is not None else None)
        )
        return FlextLdifCategorization(
            categorization_rules=(
                options.categorization_rules if options is not None else None
            ),
            schema_whitelist_rules=(
                options.schema_whitelist_rules if options is not None else None
            ),
            forbidden_attributes=(
                options.forbidden_attributes if options is not None else None
            ),
            forbidden_objectclasses=(
                options.forbidden_objectclasses if options is not None else None
            ),
            base_dn=resolved_base_dn,
            server_type=server_type,
            server=self._server,
            runtime_settings=self.runtime_settings,
            server_registry=self._server,
        )

    def filter_entry_attributes(
        self,
        entry: p.Ldif.Entry,
        forbidden_attrs: t.StrSequence,
        forbidden_ocs: t.StrSequence,
    ) -> p.Ldif.Entry:
        """Expose the stateless filter helper through the facade DSL."""
        concrete = (
            entry
            if isinstance(entry, m.Ldif.Entry)
            else m.Ldif.Entry.model_validate(entry)
        )
        return FlextLdifFilters.filter_entry_attributes(
            entry=concrete,
            forbidden_attrs=forbidden_attrs,
            forbidden_ocs=forbidden_ocs,
        )

    def filter_schema_attribute_values(
        self,
        entry: p.Ldif.Entry,
        allowed_oids: t.MappingKV[str, frozenset[str]],
    ) -> p.Ldif.Entry:
        """Expose schema-attribute OID filtering through the facade DSL."""
        concrete = (
            entry
            if isinstance(entry, m.Ldif.Entry)
            else m.Ldif.Entry.model_validate(entry)
        )
        return FlextLdifFilters.filter_schema_attribute_values(
            entry=concrete,
            allowed_oids=allowed_oids,
        )

    def acl(self, server_type: str) -> p.Ldif.AclServer | None:
        """Expose ACL server lookup through the public facade."""
        return self._server.acl(server_type)

    def entry(self, server_type: str) -> p.Ldif.EntryServer | None:
        """Expose entry server lookup through the public facade."""
        return self._server.entry(server_type)

    def resolve_base_server(self, server_type: str) -> r[p.Ldif.ServerServer]:
        """Expose base server resolution through the public facade."""
        return r[p.Ldif.ServerServer].from_result(
            self._server.resolve_base_server(server_type),
        )

    def schema_server(self, server_type: str) -> p.Ldif.SchemaServer | None:
        """Expose schema server lookup through the public facade."""
        return self._server.schema_server(server_type)

    def resolve_schema_server(
        self,
        server_type: str,
    ) -> p.Ldif.SchemaServer | None:
        """Expose canonical schema server resolution through the public facade."""
        return self._server.resolve_schema_server(server_type)

    def resolve_server_bundle(
        self,
        server_type: str,
    ) -> r[
        t.MappingKV[
            str,
            p.Ldif.SchemaServer | p.Ldif.AclServer | p.Ldif.EntryServer,
        ]
    ]:
        """Expose full server bundle resolution through the public facade."""
        return r[
            t.MappingKV[
                str,
                p.Ldif.SchemaServer | p.Ldif.AclServer | p.Ldif.EntryServer,
            ]
        ].from_result(self._server.resolve_server_bundle(server_type))

    def resolve_server_constants(self, server_type: str) -> r[type]:
        """Expose server constants lookup through the public facade."""
        return r[type].from_result(self._server.resolve_server_constants(server_type))

    def list_registered_servers(self) -> t.MutableSequenceOf[str]:
        """Expose the normalized registered server list through the facade."""
        return self._server.list_registered_servers()

    def summarize_registry(self) -> t.Ldif.MutableMetadataInputMapping:
        """Expose registry statistics through the public facade."""
        return self._server.summarize_registry()

    def processing_pipeline(
        self,
        *,
        settings: m.Ldif.TransformConfig | None = None,
        source_server: str | c.Ldif.ServerTypes | None = None,
        target_server: str | c.Ldif.ServerTypes | None = None,
    ) -> p.Ldif.ProcessingPipeline:
        """Create a processing pipeline from explicit config or server pair."""
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
        """Create a configured migration pipeline bound to the facade runtime."""
        process_config = settings.process_config if settings is not None else None
        return FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type=(
                process_config.source_server if process_config is not None else None
            ),
            target_server_type=(
                process_config.target_server if process_config is not None else None
            ),
            output_filename=(options.output_filename if options is not None else None),
            server=self._server,
            runtime_settings=self.runtime_settings,
        )

    def migrate(
        self,
        input_dir: Path | None = None,
        output_dir: Path | None = None,
        source_server: str = c.Ldif.ServerTypes.RFC.value,
        target_server: str = c.Ldif.ServerTypes.RFC.value,
        options: m.Ldif.MigrateOptions | None = None,
    ) -> p.Result[m.Ldif.MigrationPipelineResult]:
        """Migrate LDIF data between servers."""
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
    ) -> r[m.Ldif.ValidationResult]:
        """Validate list of entries."""
        resolved_validation_service = validation_service or self
        return FlextLdifAnalysis().validate_entries(
            entries,
            resolved_validation_service,
        )


ldif = FlextLdif()

__all__: list[str] = ["FlextLdif", "ldif"]
