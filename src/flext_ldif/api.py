"""FLEXT-LDIF API - Unified Facade for LDIF Operations via MRO."""

from __future__ import annotations

from collections.abc import MutableSequence
from pathlib import Path
from typing import ClassVar, override

from flext_ldif import (
    FlextLdifAnalysis,
    FlextLdifCategorization,
    FlextLdifDetectorMixin,
    FlextLdifMigrationPipeline,
    FlextLdifParserMixin,
    FlextLdifServer,
    FlextLdifServersBaseSchema,
    FlextLdifSettings,
    FlextLdifValidation,
    FlextLdifWriterMixin,
    m,
    r,
    s,
    t,
    u,
)


class FlextLdif(
    FlextLdifDetectorMixin,
    FlextLdifParserMixin,
    FlextLdifWriterMixin,
    s[m.Ldif.Entry],
):
    """MRO facade over LDIF services.

    All operations come from mixin bases via MRO. Only ``execute()``
    and infrastructure classmethods are defined locally.
    """

    _instance: ClassVar[FlextLdif | None] = None
    _init_config_overrides: ClassVar[t.MutableContainerMapping | None] = None

    def __init__(
        self,
        *,
        settings: FlextLdifSettings | None = None,
        **kwargs: str | float | bool | None,
    ) -> None:
        """Initialize LDIF facade with server registry."""
        del kwargs
        try:
            if settings is not None:
                self._set_init_config_overrides(settings)
        finally:
            self._clear_init_config_overrides()
        super().__init__()
        object.__setattr__(
            self,
            "_server",
            FlextLdifServer.get_global_instance(),
        )
        _ = u.fetch_logger(__name__).info("FlextLdif facade initialized")

    @classmethod
    def _clear_init_config_overrides(cls) -> None:
        """Clear temporary init settings overrides after initialization."""
        cls._init_config_overrides = None

    @classmethod
    @override
    def _runtime_bootstrap_options(cls) -> m.RuntimeBootstrapOptions:
        """Allow per-instance settings overrides on initialization."""
        base_options = m.RuntimeBootstrapOptions(settings_type=FlextLdifSettings)
        overrides = cls._init_config_overrides
        if not overrides:
            return base_options
        return base_options.model_copy(update={"config_overrides": dict(overrides)})

    @classmethod
    def _set_init_config_overrides(cls, settings: FlextLdifSettings) -> None:
        """Set temporary init settings overrides for runtime bootstrap."""
        cls._init_config_overrides = settings.model_dump(exclude_none=True)

    @classmethod
    def categorization(
        cls,
        *,
        categorization_rules: m.Ldif.CategoryRules | None = None,
        schema_whitelist_rules: m.Ldif.WhitelistRules | None = None,
        forbidden_attributes: MutableSequence[str] | None = None,
        forbidden_objectclasses: MutableSequence[str] | None = None,
        base_dn: str | None = None,
        server_type: str = "rfc",
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
        source_server: str = "rfc",
        target_server: str = "rfc",
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
    def execute(self) -> r[m.Ldif.Entry]:
        """Execute FlextServiceBase pattern compliance."""
        return r[m.Ldif.Entry].fail(
            "FlextLdif is a facade. Use parse_ldif(), write(), or migrate() instead.",
        )

    @classmethod
    def get_instance(cls) -> FlextLdif:
        """Get singleton instance of FlextLdif."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance


ldif = FlextLdif

__all__ = ["FlextLdif", "ldif"]
