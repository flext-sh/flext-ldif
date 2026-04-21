"""FLEXT-LDIF API - Unified Facade for LDIF Operations via MRO."""

from __future__ import annotations

from collections.abc import (
    MutableSequence,
)
from pathlib import Path
from typing import override

from flext_ldif import (
    FlextLdifAnalysis,
    FlextLdifCategorization,
    FlextLdifDetectorMixin,
    FlextLdifMigrationPipeline,
    FlextLdifParser,
    FlextLdifServer,
    FlextLdifServersBaseSchema,
    FlextLdifSettings,
    FlextLdifValidation,
    FlextLdifWriter,
    c,
    m,
    r,
    t,
)


class FlextLdif(
    FlextLdifServer,
    FlextLdifServersBaseSchema,
    FlextLdifDetectorMixin,
    FlextLdifAnalysis,
    FlextLdifCategorization,
    FlextLdifMigrationPipeline,
    FlextLdifParser,
    FlextLdifSettings,
    FlextLdifValidation,
    FlextLdifWriter,
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
        """Initialize LDIF facade with server registry."""
        super().__init__(server=server, settings=settings)

    @classmethod
    def categorization(
        cls,
        *,
        categorization_rules: m.Ldif.CategoryRules | None = None,
        schema_whitelist_rules: m.Ldif.WhitelistRules | None = None,
        forbidden_attributes: MutableSequence[str] | None = None,
        forbidden_objectclasses: MutableSequence[str] | None = None,
        base_dn: str | None = None,
        server_type: str = c.Ldif.ServerTypes.RFC.value,
    ) -> FlextLdifCategorization:
        """Create a categorization service with the global server registry."""
        return FlextLdifCategorization(
            categorization_rules=categorization_rules,
            schema_whitelist_rules=schema_whitelist_rules,
            forbidden_attributes=forbidden_attributes,
            forbidden_objectclasses=forbidden_objectclasses,
            base_dn=base_dn,
            server_type=server_type,
            server_registry=FlextLdifServer.get_global_instance(),
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
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type=source_server,
            target_server_type=target_server,
            output_filename=output_filename,
        )
        return pipeline.execute()

    def get_schema_quirk(
        self,
        server_type: str,
    ) -> FlextLdifServersBaseSchema | None:
        """Expose schema quirk lookup through the public LDIF facade."""
        return self._server.get_schema_quirk(server_type)

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
        params: t.ValueOrModel | None = None,
    ) -> r[m.Ldif.Response]:
        """Execute FlextServiceBase pattern compliance."""
        _ = params
        return r[m.Ldif.Response].fail_op(
            "execute ldif facade",
            "FlextLdif is a facade. Use parse_ldif(), write(), or migrate() instead.",
        )


ldif = FlextLdif

__all__: list[str] = ["FlextLdif", "ldif"]
