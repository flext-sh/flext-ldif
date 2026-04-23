"""FLEXT-LDIF API - Unified Facade for LDIF Operations via MRO."""

from __future__ import annotations

from collections.abc import (
    MutableMapping,
    MutableSequence,
)
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
    FlextLdifServer,
    FlextLdifServersBase,
    FlextLdifServersBaseEntry,
    FlextLdifServersBaseSchema,
    FlextLdifServersBaseSchemaAcl,
    FlextLdifSettings,
    FlextLdifStatistics,
    FlextLdifValidation,
    FlextLdifWriter,
    c,
    m,
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
        server: FlextLdifServer | None = None,
        settings: FlextLdifSettings | None = None,
    ) -> None:
        """Initialize the LDIF facade with the canonical shared registry."""
        super().__init__(server=server, runtime_settings=settings)

    def __call__(
        self,
        *,
        server: FlextLdifServer | None = None,
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
        categorization_rules: m.Ldif.CategoryRules | None = None,
        schema_whitelist_rules: m.Ldif.WhitelistRules | None = None,
        forbidden_attributes: MutableSequence[str] | None = None,
        forbidden_objectclasses: MutableSequence[str] | None = None,
        base_dn: str | None = None,
        server_type: str = c.Ldif.ServerTypes.RFC.value,
    ) -> FlextLdifCategorization:
        """Create a categorization service bound to the facade registry."""
        return FlextLdifCategorization(
            categorization_rules=categorization_rules,
            schema_whitelist_rules=schema_whitelist_rules,
            forbidden_attributes=forbidden_attributes,
            forbidden_objectclasses=forbidden_objectclasses,
            base_dn=base_dn,
            server_type=server_type,
            server=self._server,
            runtime_settings=self.runtime_settings,
            server_registry=self._server,
        )

    def filter_entry_attributes(
        self,
        entry: m.Ldif.Entry,
        forbidden_attrs: t.StrSequence,
        forbidden_ocs: t.StrSequence,
    ) -> m.Ldif.Entry:
        """Expose the stateless filter helper through the facade DSL."""
        return FlextLdifFilters.filter_entry_attributes(
            entry=entry,
            forbidden_attrs=forbidden_attrs,
            forbidden_ocs=forbidden_ocs,
        )

    def filter_schema_attribute_values(
        self,
        entry: m.Ldif.Entry,
        allowed_oids: dict[str, frozenset[str]],
    ) -> m.Ldif.Entry:
        """Expose schema-attribute OID filtering through the facade DSL."""
        return FlextLdifFilters.filter_schema_attribute_values(
            entry=entry,
            allowed_oids=allowed_oids,
        )

    def acl(self, server_type: str) -> FlextLdifServersBaseSchemaAcl | None:
        """Expose ACL quirk lookup through the public facade."""
        return self._server.acl(server_type)

    def entry(self, server_type: str) -> FlextLdifServersBaseEntry | None:
        """Expose entry quirk lookup through the public facade."""
        return self._server.entry(server_type)

    def quirk(self, server_type: str) -> r[FlextLdifServersBase]:
        """Expose base quirk lookup through the public facade."""
        return self._server.quirk(server_type)

    def get_base_quirk(self, server_type: str) -> r[FlextLdifServersBase]:
        """Expose base quirk resolution through the public facade."""
        return self._server.get_base_quirk(server_type)

    def schema_quirk(self, server_type: str) -> FlextLdifServersBaseSchema | None:
        """Expose schema quirk lookup through the public facade."""
        return self._server.schema_quirk(server_type)

    def get_schema_quirk(
        self,
        server_type: str,
    ) -> FlextLdifServersBaseSchema | None:
        """Expose canonical schema quirk resolution through the public facade."""
        return self._server.get_schema_quirk(server_type)

    def get_all_quirks(
        self,
        server_type: str,
    ) -> r[
        MutableMapping[
            str,
            FlextLdifServersBaseSchema
            | FlextLdifServersBaseSchemaAcl
            | FlextLdifServersBaseEntry,
        ]
    ]:
        """Expose full quirk bundle resolution through the public facade."""
        return self._server.get_all_quirks(server_type)

    def get_constants(self, server_type: str) -> r[type]:
        """Expose server constants lookup through the public facade."""
        return self._server.get_constants(server_type)

    def list_registered_servers(self) -> MutableSequence[str]:
        """Expose the normalized registered server list through the facade."""
        return self._server.list_registered_servers()

    def get_registry_stats(self) -> t.Ldif.MutableMetadataInputMapping:
        """Expose registry statistics through the public facade."""
        return self._server.get_registry_stats()

    def processing_pipeline(
        self,
        *,
        settings: m.Ldif.TransformConfig | None = None,
        source_server: str | c.Ldif.ServerTypes | None = None,
        target_server: str | c.Ldif.ServerTypes | None = None,
    ) -> FlextLdifProcessingPipeline:
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
        source_server: str | c.Ldif.ServerTypes = c.Ldif.ServerTypes.RFC.value,
        target_server: str | c.Ldif.ServerTypes = c.Ldif.ServerTypes.RFC.value,
        output_filename: str | None = None,
    ) -> FlextLdifMigrationPipeline:
        """Create a configured migration pipeline bound to the facade runtime."""
        return FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server=source_server,
            target_server=target_server,
            output_filename=output_filename,
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
    ) -> r[m.Ldif.MigrationPipelineResult]:
        """Migrate LDIF data between servers."""
        output_filename = options.output_filename if options else None
        pipeline = self.migration_pipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server=source_server,
            target_server=target_server,
            output_filename=output_filename,
        )
        return pipeline.execute()

    @staticmethod
    @override
    def validate_entries(
        entries: MutableSequence[m.Ldif.Entry] | m.Ldif.ParseResponse,
        validation_service: FlextLdifValidation | None = None,
    ) -> r[m.Ldif.ValidationResult]:
        """Validate list of entries."""
        resolved_validation_service = validation_service or FlextLdifValidation()
        return FlextLdifAnalysis.validate_entries(
            entries,
            resolved_validation_service,
        )


ldif = FlextLdif()

__all__: list[str] = ["FlextLdif", "ldif"]
