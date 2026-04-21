"""FLEXT-LDIF API - Unified Facade for LDIF Operations via MRO."""

from __future__ import annotations

from collections.abc import (
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
    FlextLdifMigrationPipeline,
    FlextLdifParser,
    FlextLdifProcessing,
    FlextLdifProcessingPipeline,
    FlextLdifServer,
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

    All operations come from mixin bases via MRO. Only ``execute()``
    and infrastructure classmethods are defined locally.
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

    @override
    def validate_entries(
        self,
        entries: MutableSequence[m.Ldif.Entry] | m.Ldif.ParseResponse,
    ) -> r[m.Ldif.ValidationResult]:
        """Validate list of entries."""
        validation_service = FlextLdifValidation()
        return FlextLdifAnalysis.validate_entries(entries, validation_service)

    @override
    def execute(
        self,
        params: t.Container | None = None,
    ) -> r[m.Ldif.Response]:
        """Execute FlextServiceBase pattern compliance."""
        _ = params
        return r[m.Ldif.Response].fail_op(
            "execute ldif facade",
            "FlextLdif is a facade. Use parse_ldif(), write(), or migrate() instead.",
        )


ldif = FlextLdif()

__all__: list[str] = ["FlextLdif", "ldif"]
