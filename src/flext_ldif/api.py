"""FLEXT-LDIF API - Unified Facade for LDIF Operations via MRO.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Self, override

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


class FlextLdif(
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

    def __init__(
        self,
        *,
        registry: p.Registry | None = None,
        runtime_settings: p.Ldif.Settings | None = None,
        **fields: t.ModelInput | t.SequenceOf[p.Model],
    ) -> None:
        """Compose isolated registry/runtime dependencies and builtin dialects.

        An injected registry intentionally shares its exact state and lifecycle;
        it is never repopulated after a caller removes one of its dialects.
        """
        super().__init__(
            registry=u.build_registry() if registry is None else registry,
            runtime_settings=runtime_settings,
            **fields,
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
            elif factory is FlextLdifServersOud:
                self.register_server(
                    factory(
                        registry=self.registry,
                        runtime_settings=self.settings,
                    )
                ).unwrap()
            else:
                self.register_server(factory(runtime_settings=self.settings)).unwrap()

    def __call__(
        self,
        *,
        server: p.Ldif.ServerRegistry | None = None,
        settings: p.Ldif.Settings | None = None,
        registry: p.Registry | None = None,
        **fields: t.ModelInput | t.SequenceOf[p.Model],
    ) -> Self:
        """Return a configured facade instance while keeping the DSL alias callable.

        Args:
            server: Optional server registry to bind on the new instance.
            settings: Optional runtime settings to bind on the new instance.
            **fields: Additional DSL field values forwarded to the base.

        Returns:
            A configured copy of this facade.

        """
        if server is not None and registry is not None:
            message = "Provide one explicit registry dependency"
            raise ValueError(message)
        return type(self)(
            registry=server.registry if server is not None else registry,
            runtime_settings=self.settings if settings is None else settings,
            **fields,
        )

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
        forbidden_attrs: t.StrSequence,
        forbidden_ocs: t.StrSequence,
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
        entry: p.Ldif.Entry,
        allowed_oids: m.Ldif.WhitelistRules | t.FrozensetMapping,
    ) -> p.Ldif.Entry:
        """Expose schema-attribute OID filtering through the facade DSL.

        Args:
            entry: Entry whose schema attribute values are filtered.
            allowed_oids: Whitelist rules or OID mapping selecting values to keep.

        Returns:
            The filtered entry.

        """
        concrete = u.Ldif.as_entry(entry)
        return FlextLdifFilters.filter_schema_attribute_values(
            entry=concrete,
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
        **fields: t.ModelInput | t.SequenceOf[p.Model],
    ) -> p.Ldif.ProcessingPipeline:
        """Create a processing pipeline from explicit config or server pair.

        Args:
            settings: Optional transform config selecting the pipeline shape.
            source_server: Source server type when no transform config is given.
            target_server: Target server type when no transform config is given.

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
        return FlextLdifProcessingPipeline(
            registry=self.registry,
            runtime_settings=(
                self.settings if runtime_settings is None else runtime_settings
            ),
            **fields,
        )

    def migration_pipeline(
        self,
        *,
        input_dir: Path | None = None,
        output_dir: Path | None = None,
        settings: p.Ldif.TransformConfig | None = None,
        options: m.Ldif.MigrateOptions | None = None,
        runtime_settings: p.Ldif.Settings | None = None,
        **fields: t.ModelInput | Path,
    ) -> p.Ldif.MigrationPipeline:
        """Create a configured migration pipeline bound to the facade runtime.

        Args:
            input_dir: Optional directory holding the source LDIF files.
            output_dir: Optional directory receiving the migrated LDIF files.
            settings: Optional transform config supplying server types.
            options: Optional migration options supplying the output filename.

        Returns:
            The runtime-bound migration pipeline.

        """
        process_config = settings.process_config if settings is not None else None
        if process_config is not None:
            fields["source_server_type"] = process_config.source_server
            fields["target_server_type"] = process_config.target_server
        if options is not None:
            fields["output_filename"] = options.output_filename
        return FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            registry=self.registry,
            runtime_settings=(
                self.settings if runtime_settings is None else runtime_settings
            ),
            **fields,
        )

    def migrate(
        self,
        input_dir: Path | None = None,
        output_dir: Path | None = None,
        source_server: str = c.Ldif.ServerTypes.RFC.value,
        target_server: str = c.Ldif.ServerTypes.RFC.value,
        options: m.Ldif.MigrateOptions | None = None,
    ) -> p.Result[m.Ldif.MigrationPipelineResult]:
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

    @override
    def validate_entries(
        self,
        entries: t.MutableSequenceOf[m.Ldif.Entry] | m.Ldif.ParseResponse,
        validation_service: p.Ldif.ValidationService | None = None,
    ) -> p.Result[m.Ldif.ValidationResult]:
        """Validate a sequence of entries or a parse response.

        Args:
            entries: Entry sequence or parse response to validate.
            validation_service: Optional validation service overriding self.

        Returns:
            Typed result carrying the validation result.

        """
        resolved_validation_service = validation_service or self
        return super().validate_entries(entries, resolved_validation_service)


ldif = FlextLdif()
"""Public facade composed explicitly with its own instance-scoped registry."""

__all__: list[str] = ["FlextLdif", "ldif"]
