"""FLEXT-LDIF API - Unified Facade for LDIF Operations via MRO.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from collections.abc import Sequence
from typing import TYPE_CHECKING, Self

from flext_ldif import c, m, p, t, u
from flext_ldif.servers import (
    FlextLdifServersAd,
    FlextLdifServersApache,
    FlextLdifServersDs389,
    FlextLdifServersNovell,
    FlextLdifServersOid,
    FlextLdifServersOpenldap,
    FlextLdifServersOpenldap1,
    FlextLdifServersOud,
    FlextLdifServersRelaxed,
    FlextLdifServersRfc,
    FlextLdifServersTivoli,
)
from flext_ldif.services import (
    FlextLdifAcl,
    FlextLdifAnalysis,
    FlextLdifCategorization,
    FlextLdifDetector,
    FlextLdifEntries,
    FlextLdifFilters,
    FlextLdifMigrationPipeline,
    FlextLdifParser,
    FlextLdifProcessing,
    FlextLdifProcessingPipeline,
    FlextLdifStatistics,
    FlextLdifTransformer,
    FlextLdifValidation,
    FlextLdifWriter,
)

if TYPE_CHECKING:
    from pathlib import Path


class FlextLdifFacade(
    FlextLdifAcl,
    FlextLdifCategorization,
    FlextLdifTransformer,
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

    registry: t.Port[p.Registry] = m.Field(
        default_factory=u.build_registry,
        exclude=True,
        description="Instance-scoped dialect registry composed by the facade",
    )

    def __init__(
        self,
        *,
        registry: p.Registry | None = None,
        runtime_settings: p.Ldif.Settings | None = None,
        settings_type: p.SettingsType | None = None,
        settings_overrides: t.JsonMapping | None = None,
        initial_context: p.Context | None = None,
        **fields: t.ModelInput[p.Model] | Sequence[p.Model],
    ) -> None:
        """Compose isolated registry/runtime dependencies and builtin dialects.

        An injected registry intentionally shares its exact state and lifecycle;
        it is never repopulated after a caller removes one of its dialects.
        """
        self.__pydantic_validator__.validate_python(
            {
                **fields,
                **({"registry": registry} if registry is not None else {}),
                "runtime_settings": runtime_settings,
                "settings_type": settings_type,
                "settings_overrides": settings_overrides,
                "initial_context": initial_context,
            },
            self_instance=self,
        )
        if registry is not None:
            return
        registered = self.list_registered_servers().unwrap()
        for factory in (
            FlextLdifServersAd,
            FlextLdifServersApache,
            FlextLdifServersDs389,
            FlextLdifServersNovell,
            FlextLdifServersOid,
            FlextLdifServersOpenldap,
            FlextLdifServersOpenldap1,
            FlextLdifServersOud,
            FlextLdifServersRelaxed,
            FlextLdifServersRfc,
            FlextLdifServersTivoli,
        ):
            if factory.server_type in registered:
                self.server(factory.server_type).unwrap()
            elif issubclass(factory, FlextLdifServersOud):
                self.register_server(
                    factory(registry=self.registry, runtime_settings=self.settings)
                ).unwrap()
            else:
                self.register_server(factory(runtime_settings=self.settings)).unwrap()

    def __call__(
        self,
        *,
        server: p.Ldif.ServerRegistry | None = None,
        settings: p.Ldif.Settings | None = None,
        registry: p.Registry | None = None,
        **fields: t.ModelInput[p.Model] | Sequence[p.Model],
    ) -> Self:
        """Return a configured facade instance while keeping the DSL alias callable.

        Args:
            server: Optional server registry to bind on the new instance.
            settings: Optional runtime settings to bind on the new instance.
            registry: Optional core registry replacing the server-derived one.
            **fields: Additional DSL field values forwarded to the base.

        Returns:
            A configured copy of this facade.

        Raises:
            ValueError: If both a server registry and an explicit registry are given.

        """
        if server is not None and registry is not None:
            message = "Provide one explicit registry dependency"
            raise ValueError(message)
        return type(self).model_validate({
            **fields,
            "registry": server.registry if server is not None else registry,
            "runtime_settings": self.settings if settings is None else settings,
        })

    def categorization(
        self,
        *,
        options: m.Ldif.MigrateOptions | None = None,
        base_dn: str | None = None,
        server_type: str = c.Ldif.ServerTypes.RFC.value,
    ) -> p.Ldif.CategorizationService:
        """Create a categorization service bound to the facade registry.

        Args:
            options: Optional migration options supplying rules and base DN.
            base_dn: Explicit base DN overriding the options-derived value.
            server_type: Server flavor used for categorization context.

        Returns:
            The bound categorization service.

        """
        resolved_base_dn = (
            base_dn
            if base_dn is not None
            else options.base_dn
            if options is not None
            else None
        )
        return FlextLdifCategorization(
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
            registry=self.registry,
            runtime_settings=self.settings,
        )

    @staticmethod
    def filter_entry_attributes(
        entry: p.Ldif.Entry,
        forbidden_attrs: Sequence[str],
        forbidden_ocs: Sequence[str],
    ) -> p.Ldif.Entry:
        """Expose the stateless filter helper through the facade DSL.

        Args:
            entry: Entry whose attributes are filtered.
            forbidden_attrs: Attribute names to remove from the entry.
            forbidden_ocs: objectClass names to remove from the entry.

        Returns:
            The filtered entry.

        """
        concrete = u.Ldif.as_entry(entry)
        return FlextLdifFilters.filter_entry_attributes(
            entry=concrete,
            forbidden_attrs=forbidden_attrs,
            forbidden_ocs=forbidden_ocs,
        )

    @staticmethod
    def filter_schema_attribute_values(
        entry: m.Ldif.Entry,
        allowed_oids: m.Ldif.WhitelistRules | t.FrozensetMapping,
    ) -> m.Ldif.Entry:
        """Expose schema-attribute OID filtering through the facade DSL.

        Args:
            entry: Entry whose schema attribute values are filtered.
            allowed_oids: Whitelist rules or OID mapping selecting values to keep.

        Returns:
            The filtered entry.

        """
        return FlextLdifFilters.filter_schema_attribute_values(
            entry=entry,
            allowed_oids=allowed_oids,
        )

    def processing_pipeline(
        self,
        *,
        settings: p.Ldif.TransformConfig | None = None,
        source_server: str | c.Ldif.ServerTypes | None = None,
        target_server: str | c.Ldif.ServerTypes | None = None,
        base_dn: str = "",
        runtime_settings: p.Ldif.Settings | None = None,
        **fields: t.ModelInput[p.Model] | Sequence[p.Model],
    ) -> p.Ldif.ProcessingPipeline:
        """Create a processing pipeline from explicit config or server pair.

        Args:
            settings: Optional transform config selecting the pipeline shape.
            source_server: Source server type when no transform config is given.
            target_server: Target server type when no transform config is given.
            base_dn: Base DN used when building the server-pair transform config.
            runtime_settings: Optional runtime settings overriding the facade
                bounds.
            **fields: Additional pipeline fields forwarded to the constructor.

        Returns:
            The constructed processing pipeline.

        """
        if settings is not None:
            fields["transform_config"] = settings
        if source_server is not None and target_server is not None:
            fields["transform_config"] = m.Ldif.TransformConfig.servers(
                source_server=source_server,
                target_server=target_server,
                base_dn=base_dn,
            )
        return FlextLdifProcessingPipeline.model_validate({
            **fields,
            "registry": self.registry,
            "runtime_settings": (
                self.settings if runtime_settings is None else runtime_settings
            ),
        })

    def migration_pipeline(
        self,
        *,
        input_dir: Path | None = None,
        output_dir: Path | None = None,
        settings: p.Ldif.TransformConfig | None = None,
        options: p.Ldif.MigrationOutputOptions | None = None,
        runtime_settings: p.Ldif.Settings | None = None,
    ) -> p.Ldif.MigrationPipeline:
        """Create a configured migration pipeline bound to the facade runtime.

        Args:
            input_dir: Optional directory holding the source LDIF files.
            output_dir: Optional directory receiving the migrated LDIF files.
            settings: Optional transform config supplying server types.
            options: Optional migration options supplying the output filename,
                hierarchical entry ordering and output formatting.
            runtime_settings: Optional runtime settings overriding the facade
                bounds.

        Returns:
            The runtime-bound migration pipeline.

        """
        defaults = m.Ldif.MigrationPipelineOptions()
        process_config = settings.process_config if settings is not None else None
        return FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            registry=self.registry,
            runtime_settings=(
                self.settings if runtime_settings is None else runtime_settings
            ),
            output_filename=None if options is None else options.output_filename,
            sort_entries_hierarchically=(
                defaults.sort_entries_hierarchically
                if options is None
                else options.sort_entries_hierarchically
            ),
            format_options=None if options is None else options.format_options,
            source_server_type=(
                defaults.source_server_type
                if process_config is None or process_config.source_server is None
                else process_config.source_server
            ),
            target_server_type=(
                defaults.target_server_type
                if process_config is None or process_config.target_server is None
                else process_config.target_server
            ),
            base_dn=(
                defaults.base_dn if process_config is None else process_config.base_dn
            ),
        )

    def migrate(
        self,
        input_dir: Path | None = None,
        output_dir: Path | None = None,
        source_server: str = c.Ldif.ServerTypes.RFC.value,
        target_server: str = c.Ldif.ServerTypes.RFC.value,
        options: p.Ldif.MigrationOutputOptions | None = None,
    ) -> p.Result[p.Ldif.MigrationPipelineResult]:
        """Migrate LDIF data between servers.

        Args:
            input_dir: Optional directory holding the source LDIF files.
            output_dir: Optional directory receiving the migrated LDIF files.
            source_server: Source server flavor identifier.
            target_server: Target server flavor identifier.
            options: Optional migration options forwarded to the pipeline.

        Returns:
            Typed result carrying the migration pipeline result.

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


__all__: list[str] = ["FlextLdifFacade"]
