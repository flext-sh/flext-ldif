"""LDIF client implementation.

This module implements the core business logic for LDIF operations including
parsing, writing, validation, and migration. The FlextLdifClient class is
used by the FlextLdif facade to perform actual operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import TypeVar, cast

from flext_core import (
    FlextBus,
    FlextContainer,
    FlextContext,
    FlextResult,
    FlextService,
)
from pydantic import PrivateAttr

from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.filters import FlextLdifFilters
from flext_ldif.models import FlextLdifModels
from flext_ldif.pipelines.migration_pipeline import FlextLdifMigrationPipeline
from flext_ldif.quirks.base import (
    FlextLdifQuirksBase,
    FlextLdifQuirksBaseAclQuirk,
    FlextLdifQuirksBaseEntryQuirk,
    FlextLdifQuirksBaseSchemaQuirk,
)
from flext_ldif.quirks.registry import FlextLdifQuirksRegistry
from flext_ldif.quirks.servers import (
    FlextLdifQuirksServersAd,
    FlextLdifQuirksServersApache,
    FlextLdifQuirksServersDs389,
    FlextLdifQuirksServersNovell,
    FlextLdifQuirksServersOid,
    FlextLdifQuirksServersOpenldap,
    FlextLdifQuirksServersOpenldap1,
    FlextLdifQuirksServersOud,
    FlextLdifQuirksServersTivoli,
)
from flext_ldif.quirks.servers.relaxed_quirks import (
    FlextLdifQuirksServersRelaxedSchema,
)
from flext_ldif.rfc.rfc_ldif_parser import FlextLdifRfcLdifParser
from flext_ldif.rfc.rfc_ldif_writer import FlextLdifRfcLdifWriter
from flext_ldif.rfc.rfc_schema_parser import FlextLdifRfcSchemaParser
from flext_ldif.schema.validator import FlextLdifSchemaValidator
from flext_ldif.services.server_detector import FlextLdifServerDetector
from flext_ldif.typings import FlextLdifTypes

# TypeVar for generic service retrieval with type narrowing
ServiceT = TypeVar("ServiceT")


class FlextLdifClient(FlextService[FlextLdifTypes.Models.CustomDataDict]):
    """Main client implementation for LDIF processing operations.

    This class contains all the actual business logic for LDIF operations,
    providing a clean separation between the thin API facade and the
    implementation details.

    The client manages:
    - Service initialization and dependency injection via FlextContainer
    - CQRS handler setup and orchestration via FlextDispatcher
    - Event publishing via FlextBus for domain events
    - Default quirk registration for all supported LDAP servers
    - Business logic delegation to appropriate services
    - Context management with correlation tracking
    - Processor orchestration for batch and parallel operations

    """

    # Pydantic v2 private attributes (CRITICAL for Pydantic model initialization)
    # These MUST be declared at class level for Pydantic to handle them correctly
    # Note: _bus is inherited from FlextService, no need to redeclare
    _container: FlextContainer | None = PrivateAttr(
        default_factory=FlextContainer.get_global
    )
    _context: dict[str, object] = PrivateAttr(default_factory=dict)
    _handlers: FlextLdifTypes.Models.CustomDataDict = PrivateAttr(default_factory=dict)
    _config: FlextLdifConfig | None = PrivateAttr(default=None)

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize LDIF client with optional configuration.

        Args:
        config: Optional LDIF configuration. If not provided,
        uses global singleton instance.

        """
        # Store config for lazy initialization in properties
        object.__setattr__(self, "_init_config_value", config)

        # Call Pydantic/FlextService initialization
        super().__init__()

    def model_post_init(
        self, __context: FlextLdifTypes.Models.CustomDataDict | None, /
    ) -> None:
        """Initialize private attributes after Pydantic initialization.

        This hook is called by Pydantic after __init__ completes.

        Args:
        __context: Pydantic's validation context dictionary or None.

        """
        # Initialize private attributes that parent's __init__ may access
        self._config = getattr(self, "_init_config_value", None) or FlextLdifConfig()
        # Initialize context as empty dict (not bound to global)
        self._context = {}
        self._bus = FlextBus()
        self._handlers = {}

        # Ensure components are initialized

        # Register services in container for DI
        self._setup_services()

        # Register default quirks for all servers
        self._register_default_quirks()

        # Log config ONCE without binding to global context
        if self.logger and self._config:
            config_info: FlextLdifTypes.Models.CustomDataDict = {
                "ldif_encoding": self._config.ldif_encoding,
                "strict_rfc_compliance": self._config.strict_rfc_compliance,
                "ldif_chunk_size": self._config.ldif_chunk_size,
                "max_workers": self._config.max_workers,
            }
            self._log_config_once(config_info, message="FlextLdif client initialized")
            self.logger.debug("CQRS handlers and default quirks registered")

    def execute(self) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
        """Execute client self-check and return status.

        Returns:
        FlextResult containing client status and configuration

        """
        try:
            config = self.config
            return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok({
                "status": "initialized",
                "services": ["parser", "writer", "validator", "migration"],
                "config": {"default_encoding": config.ldif_encoding},
            })
        except Exception as e:
            return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                f"Client status check failed: {e}"
            )

    # =========================================================================
    # PRIVATE: Service Setup and Handler Initialization
    # =========================================================================

    def _setup_services(self) -> None:
        """Register all services in the dependency injection container."""
        container = self.container

        # Register quirk registry FIRST (required by RFC parsers/writers)
        quirk_registry = FlextLdifQuirksRegistry()
        container.register("quirk_registry", quirk_registry)

        # Register RFC-first parser instance (quirks handle server-specific behavior)
        rfc_parser = FlextLdifRfcLdifParser(params={}, quirk_registry=quirk_registry)
        container.register("rfc_parser", rfc_parser)

        # Register RFC writer instance
        rfc_writer = FlextLdifRfcLdifWriter(params={}, quirk_registry=quirk_registry)
        container.register("rfc_writer", rfc_writer)

        # Register schema services
        rfc_schema_parser = FlextLdifRfcSchemaParser(
            params={}, quirk_registry=quirk_registry
        )
        container.register("rfc_schema_parser", rfc_schema_parser)
        container.register("schema_validator", FlextLdifSchemaValidator())

        # Register migration pipeline (params provided at call time by handlers)
        def migration_pipeline_factory(
            params: FlextLdifTypes.Models.CustomDataDict | None,
        ) -> FlextLdifMigrationPipeline:
            if params is None:
                params = {}
            return FlextLdifMigrationPipeline(
                params=params,
                source_server_type=str(params.get("source_server_type", "oid")),
                target_server_type=str(params.get("target_server_type", "oud")),
            )

        container.register("migration_pipeline", migration_pipeline_factory)

    def _register_default_quirks(self) -> None:
        """Auto-register all default server quirks."""
        container = self.container
        logger = self.logger

        # Get quirk registry from container using helper
        registry = self._get_service_typed(
            container, "quirk_registry", FlextLdifQuirksRegistry
        )
        if registry is None:
            logger.warning(
                "Quirk registry not available, skipping default quirk registration"
            )
            return

        # Register complete implementations
        complete_quirks: list[FlextLdifQuirksBase.BaseSchemaQuirk] = [
            FlextLdifQuirksServersOid(server_type="oid", priority=10),
            FlextLdifQuirksServersOud(server_type="oud", priority=10),
            FlextLdifQuirksServersOpenldap(server_type="openldap2", priority=10),
            FlextLdifQuirksServersOpenldap1(server_type="openldap1", priority=20),
            FlextLdifQuirksServersAd(
                server_type=FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY,
                priority=15,
            ),
            FlextLdifQuirksServersApache(
                server_type=FlextLdifConstants.LdapServers.APACHE_DIRECTORY,
                priority=15,
            ),
            FlextLdifQuirksServersDs389(
                server_type=FlextLdifConstants.LdapServers.DS_389,
                priority=15,
            ),
            FlextLdifQuirksServersNovell(
                server_type=FlextLdifConstants.LdapServers.NOVELL_EDIRECTORY,
                priority=15,
            ),
            FlextLdifQuirksServersTivoli(
                server_type=FlextLdifConstants.LdapServers.IBM_TIVOLI,
                priority=15,
            ),
        ]

        # Register relaxed mode quirks
        relaxed_quirks = [
            FlextLdifQuirksServersRelaxedSchema(
                server_type=FlextLdifConstants.ServerTypes.RELAXED, priority=200
            ),
        ]
        complete_quirks.extend(relaxed_quirks)

        # Register stub implementations (for future completion)
        stub_quirks: list[FlextLdifQuirksBase.BaseSchemaQuirk] = []

        all_quirks = complete_quirks + stub_quirks

        # Register schema quirks and their nested ACL/Entry quirks
        for schema_quirk in all_quirks:
            # Register schema quirk
            schema_result = registry.register_schema_quirk(schema_quirk)
            if schema_result.is_failure:
                logger.error(f"Failed to register schema quirk: {schema_result.error}")
                continue

            # Note: Schema quirks don't have nested ACL/Entry quirks

    def _get_service_typed(
        self,
        container: FlextContainer,
        service_name: str,
        expected_type: type[ServiceT],
    ) -> ServiceT | None:
        """Helper to retrieve and type-narrow services from container.

        Consolidates service retrieval pattern: get → unwrap → type check.

        Args:
        container: The dependency injection container
        service_name: Name of the service to retrieve
        expected_type: Expected type for type narrowing

        Returns:
        Service instance if found and correct type, None otherwise

        """
        service_result = container.get(service_name)
        if service_result.is_failure:
            return None

        service_obj = service_result.unwrap()
        # Type narrowing via isinstance - MyPy recognizes this pattern
        if isinstance(service_obj, expected_type):
            return service_obj

        return None

    # Handler initialization removed - using direct service calls

    # =========================================================================
    # BUSINESS LOGIC METHODS
    # =========================================================================

    def parse_ldif(
        self, source: str | Path, server_type: str = "rfc"
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        r"""Parse LDIF from file or content string.

        Args:
            source: Either a file path (Path object) or LDIF content string
            server_type: Server type for quirk selection ("rfc", "oid", "oud", etc.)

        Returns:
            FlextResult with list of parsed Entry models

        """
        container = self.container

        # Get the RFC parser from container using helper
        parser = self._get_service_typed(
            container, "rfc_parser", FlextLdifRfcLdifParser
        )
        if not isinstance(parser, FlextLdifRfcLdifParser):
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                "Failed to retrieve RFC parser"
            )

        # Call parser directly
        # Note: server_type parameter is reserved for future quirk-based parsing
        _ = server_type  # Suppress unused argument warning
        if isinstance(source, Path):
            return parser.parse_ldif_file(source)

        # If source is a string that looks like a file path, convert to Path
        if isinstance(source, str) and (
            "\n" not in source
            and len(source) < FlextLdifConstants.MAX_PATH_LENGTH_CHECK
        ):
            # Check if it's a valid file path
            potential_path = Path(source)
            if potential_path.exists() and potential_path.is_file():
                return parser.parse_ldif_file(potential_path)

        return parser.parse_content(source)

    def write_ldif(
        self,
        entries: list[FlextLdifModels.Entry],
        output_path: Path | None = None,
    ) -> FlextResult[str]:
        """Write entries to LDIF format string or file.

        Args:
        entries: List of LDIF entries to write
        output_path: Optional path to write LDIF file. If None, returns LDIF string.

        Returns:
        FlextResult containing LDIF content as string (if output_path is None)
        or success message (if output_path provided)

        """
        container = self.container

        # Get the RFC writer from container using helper
        writer = self._get_service_typed(
            container, "rfc_writer", FlextLdifRfcLdifWriter
        )
        if not isinstance(writer, FlextLdifRfcLdifWriter):
            return FlextResult[str].fail("Failed to retrieve RFC writer")

        # Write to string first
        content_result = writer.write_entries_to_string(entries)
        if content_result.is_failure:
            return FlextResult[str].fail(
                f"Failed to write entries: {content_result.error}"
            )

        content = content_result.unwrap()

        # Write to file if path provided
        if output_path:
            try:
                output_path.write_text(content, encoding="utf-8")
                return FlextResult[str].ok(
                    f"Successfully wrote {len(entries)} entries to {output_path}"
                )
            except Exception as e:
                return FlextResult[str].fail(
                    f"Failed to write to file {output_path}: {e}"
                )

        return FlextResult[str].ok(content)

    def validate_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
        """Validate LDIF entries against RFC and business rules.

        Args:
        entries: List of entries to validate

        Returns:
        FlextResult containing validation report with details

        """
        container = self.container

        # Get the schema validator from container using helper
        validator = self._get_service_typed(
            container, "schema_validator", FlextLdifSchemaValidator
        )
        if not isinstance(validator, FlextLdifSchemaValidator):
            return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                "Failed to retrieve schema validator"
            )

        # Call validator directly
        result = validator.validate_entries(entries)

        # Return validation result as dictionary for consistent API
        if result.is_success:
            validation_result = result.unwrap()
            return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok({
                "is_valid": validation_result.is_valid,
                "total_entries": len(entries),
                "valid_entries": len(entries) - len(validation_result.errors),
                "invalid_entries": len(validation_result.errors),
                "errors": validation_result.errors,
            })
        return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
            result.error or "Validation failed"
        )

    def migrate_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        from_server: str,
        to_server: str,
    ) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
        """Migrate LDIF entries between different server types.

        Args:
            entries: List of entries to migrate
            from_server: Source server type ("oid", "oud", "openldap", etc.)
            to_server: Target server type

        Returns:
            FlextResult containing migration statistics

        """
        container = self.container

        # Get migration pipeline from container using helper
        pipeline_factory_obj = self._get_service_typed(
            container, "migration_pipeline", object
        )
        if not callable(pipeline_factory_obj):
            return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                "Migration pipeline factory is not callable"
            )
        # Use cast after runtime callable check to satisfy type checker
        pipeline_factory: Callable[..., FlextLdifMigrationPipeline] = cast(
            "Callable[..., FlextLdifMigrationPipeline]", pipeline_factory_obj
        )

        pipeline = pipeline_factory({
            "source_server_type": from_server,
            "target_server_type": to_server,
        })

        # Convert Entry objects to dict for pipeline compatibility
        entries_as_dicts: list[object] = cast(
            "list[object]", [entry.model_dump() for entry in entries]
        )

        # Call migrate_entries directly
        migration_result = pipeline.migrate_entries(
            entries=entries_as_dicts, source_format=from_server, target_format=to_server
        )

        if migration_result.is_failure:
            return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                migration_result.error or "Migration failed"
            )

        migrated_entries = migration_result.unwrap()
        stats: FlextLdifTypes.Models.CustomDataDict = {
            "total_entries": len(entries),
            "migrated_entries": len(migrated_entries),
            "from_server": from_server,
            "to_server": to_server,
            "success": True,
        }
        return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok(stats)

    def migrate_files(
        self,
        input_dir: Path,
        output_dir: Path,
        from_server: str,
        to_server: str,
        *,
        process_schema: bool = True,
        process_entries: bool = True,
    ) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
        """Migrate LDIF data between different LDAP server types from files.

        Args:
            input_dir: Directory containing source LDIF files
            output_dir: Directory for migrated LDIF files
            from_server: Source server type ("oid", "oud", "openldap", etc.)
            to_server: Target server type
            process_schema: Whether to process schema files
            process_entries: Whether to process entry files

        Returns:
            FlextResult containing migration statistics and output files

        """
        try:
            params: FlextLdifTypes.Models.CustomDataDict = {
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": process_schema,
                "process_entries": process_entries,
            }

            pipeline = FlextLdifMigrationPipeline(
                params=params,
                source_server_type=from_server,
                target_server_type=to_server,
            )

            migration_result = pipeline.execute()

            if migration_result.is_failure:
                return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                    migration_result.error or "Migration failed"
                )

            return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok(
                migration_result.unwrap()
            )

        except Exception as e:
            logger = self.logger
            logger.exception("Migration failed")
            return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                f"Migration failed: {e}"
            )

    def analyze_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
        """Analyze LDIF entries and generate statistics.

        Args:
        entries: List of entries to analyze

        Returns:
        FlextResult containing analysis statistics

        """
        # Simple analysis - count object classes
        object_class_distribution: dict[str, int] = {}
        total_entries = len(entries)

        for entry in entries:
            object_classes = entry.get_attribute_values(
                FlextLdifConstants.DictKeys.OBJECTCLASS
            )
            if object_classes:
                for obj_class in object_classes:
                    obj_class_str = str(obj_class)
                    object_class_distribution[obj_class_str] = (
                        object_class_distribution.get(obj_class_str, 0) + 1
                    )

        # Return analytics result as dictionary for consistent API
        return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok({
            "total_entries": total_entries,
            "objectclass_distribution": object_class_distribution,
            "patterns_detected": [],
        })

    def filter(
        self,
        entries: list[FlextLdifModels.Entry],
        *,
        filter_type: str = "objectclass",
        objectclass: str | tuple[str, ...] | None = None,
        dn_pattern: str | None = None,
        attributes: list[str] | None = None,
        schema_items: list[
            FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass
        ]
        | None = None,
        oid_whitelist: list[str] | None = None,
        required_attributes: list[str] | None = None,
        mode: str = "include",
        match_all: bool = False,
        mark_excluded: bool = True,
    ) -> FlextResult[
        list[FlextLdifModels.Entry]
        | list[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass]
    ]:
        """Unified filter method consolidating all filter types via parameters.

        Replaces: filter_by_objectclass, filter_persons, filter_by_dn_pattern,
        filter_by_attributes, and filter_schema_by_oid.

        Args:
            entries: List of entries to filter
            filter_type: Type of filter ("objectclass", "dn_pattern", "attributes", "schema_oid")
            objectclass: ObjectClass to filter by (for filter_type="objectclass")
            dn_pattern: DN pattern to match (for filter_type="dn_pattern")
            attributes: Attribute names to filter by (for filter_type="attributes")
            schema_items: Schema items to filter (for filter_type="schema_oid")
            oid_whitelist: OID patterns to whitelist (for filter_type="schema_oid")
            required_attributes: Required attributes (for filter_type="objectclass")
            mode: "include" or "exclude"
            match_all: All attributes must match (for filter_type="attributes")
            mark_excluded: Mark excluded items with metadata

        Returns:
            FlextResult with filtered entries or schema items

        """
        filter_type_lower = filter_type.lower()

        if filter_type_lower == "objectclass":
            if objectclass is None:
                return FlextResult.fail(
                    "objectclass filter requires objectclass parameter"
                )
            entries_result = FlextLdifFilters.filter_entries_by_objectclass(
                entries=entries,
                objectclass=objectclass,
                required_attributes=required_attributes,
                mode=mode,
                mark_excluded=mark_excluded,
            )
            return cast(
                "FlextResult[list[FlextLdifModels.Entry] | list[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass]]",
                entries_result,
            )

        if filter_type_lower == "dn_pattern":
            if dn_pattern is None:
                return FlextResult.fail(
                    "dn_pattern filter requires dn_pattern parameter"
                )
            dn_result = FlextLdifFilters.filter_entries_by_dn(
                entries=entries,
                pattern=dn_pattern,
                mode=mode,
                mark_excluded=mark_excluded,
            )
            return cast(
                "FlextResult[list[FlextLdifModels.Entry] | list[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass]]",
                dn_result,
            )

        if filter_type_lower == "attributes":
            if attributes is None:
                return FlextResult.fail(
                    "attributes filter requires attributes parameter"
                )
            attr_result = FlextLdifFilters.filter_entries_by_attributes(
                entries=entries,
                attributes=attributes,
                mode=mode,
                match_all=match_all,
                mark_excluded=mark_excluded,
            )
            return cast(
                "FlextResult[list[FlextLdifModels.Entry] | list[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass]]",
                attr_result,
            )

        if filter_type_lower == "schema_oid":
            if schema_items is None or oid_whitelist is None:
                return FlextResult.fail(
                    "schema_oid filter requires schema_items and oid_whitelist parameters"
                )
            # Return schema filter result (cast type properly)
            schema_result = self._filter_schema_by_oid_impl(
                schema_items=schema_items,
                oid_whitelist=oid_whitelist,
                mark_excluded=mark_excluded,
            )
            return cast(
                "FlextResult[list[FlextLdifModels.Entry] | list[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass]]",
                schema_result,
            )

        supported = "'objectclass', 'dn_pattern', 'attributes', 'schema_oid'"
        return FlextResult.fail(
            f"Unknown filter_type: '{filter_type}'. Supported: {supported}"
        )

    def _filter_schema_by_oid_impl(
        self,
        schema_items: list[
            FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass
        ],
        oid_whitelist: list[str],
        *,
        mark_excluded: bool = True,
    ) -> FlextResult[
        list[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass]
    ]:
        """Implementation of schema OID filtering."""
        try:
            filtered: list[
                FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass
            ] = []

            for item in schema_items:
                oid = item.oid if hasattr(item, "oid") else ""

                # Check if OID matches any whitelist pattern
                matches = FlextLdifFilters.matches_oid_pattern(oid, oid_whitelist)

                if matches:
                    filtered.append(item)
                elif mark_excluded:
                    # Mark as excluded and include in results
                    criteria = FlextLdifModels.FilterCriteria(
                        filter_type="oid_pattern",
                        whitelist=oid_whitelist,
                        mode="include",
                    )

                    # Create or update metadata
                    exclusion_info = FlextLdifModels.ExclusionInfo(
                        excluded=True,
                        exclusion_reason=f"OID not in whitelist: {oid}",
                        filter_criteria=criteria,
                        timestamp=datetime.now(UTC).isoformat(),
                    )

                    # Create new item with updated metadata (models are frozen)
                    if item.metadata is None:
                        new_metadata = FlextLdifModels.QuirkMetadata(
                            extensions={"exclusion_info": exclusion_info.model_dump()}
                        )
                    else:
                        # Preserve existing extensions and add exclusion_info
                        new_extensions = {**item.metadata.extensions}
                        new_extensions["exclusion_info"] = exclusion_info.model_dump()
                        new_metadata = FlextLdifModels.QuirkMetadata(
                            original_format=item.metadata.original_format,
                            quirk_type=item.metadata.quirk_type,
                            parsed_timestamp=item.metadata.parsed_timestamp,
                            extensions=new_extensions,
                            custom_data=item.metadata.custom_data,
                        )

                    # Create new item with updated metadata
                    updated_item = item.model_copy(update={"metadata": new_metadata})
                    filtered.append(updated_item)

            return FlextResult[
                list[
                    FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass
                ]
            ].ok(filtered)

        except Exception as e:
            return FlextResult[
                list[
                    FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass
                ]
            ].fail(f"Failed to filter schema by OID: {e}")

    def categorize_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        user_objectclasses: tuple[str, ...] = (
            "inetOrgPerson",
            "person",
            "organizationalPerson",
        ),
        group_objectclasses: tuple[str, ...] = (
            "groupOfNames",
            "groupOfUniqueNames",
            "posixGroup",
        ),
        container_objectclasses: tuple[str, ...] = (
            "organizationalUnit",
            "organization",
            "domain",
        ),
    ) -> FlextResult[FlextLdifModels.CategorizedEntries]:
        """Categorize entries into users, groups, containers, and uncategorized.

        Categorizes entries based on their objectClass attributes. Checks categories
        in priority order: users first, then groups, then containers. object entry not
        matching these categories is marked as uncategorized.

        Args:
        entries: List of LDIF entries to categorize
        user_objectclasses: Tuple of user objectClass names
        group_objectclasses: Tuple of group objectClass names
        container_objectclasses: Tuple of container objectClass names

        Returns:
        FlextResult containing CategorizedEntries with entries organized by category

        Example:
        >>> from client-a_oud_mig.constants import client-aOudMigConstants
        >>> result = client.categorize_entries(
        ...     entries,
        ...     user_objectclasses=client-aOudMigConstants.USER_CLASSES,
        ...     group_objectclasses=client-aOudMigConstants.GROUP_CLASSES,
        ...     container_objectclasses=client-aOudMigConstants.ORG_UNIT_CLASSES,
        ... )

        """
        try:
            categorized = FlextLdifModels.CategorizedEntries.create_empty()

            # Build categorization rules dict for the new API
            categorization_rules: dict[str, list[str]] = {
                "user_objectclasses": list(user_objectclasses),
                "group_objectclasses": list(group_objectclasses),
                "hierarchy_objectclasses": list(container_objectclasses),
            }

            for entry in entries:
                # Convert entry model to dict if needed
                if hasattr(entry, "model_dump") and callable(entry.model_dump):
                    entry_dict: dict[str, object] = entry.model_dump()
                else:
                    entry_dict = cast("dict[str, object]", entry)

                # categorize_entry returns tuple[str, str | None]
                category, _rejection_reason = FlextLdifFilters.categorize_entry(
                    entry_dict,
                    categorization_rules=cast(
                        "dict[str, object]", categorization_rules
                    ),
                )

                # Map new category names to old container structure
                if category == "users":
                    categorized.users.append(entry)
                elif category == "groups":
                    categorized.groups.append(entry)
                elif category == "hierarchy":
                    categorized.containers.append(entry)
                else:
                    categorized.uncategorized.append(entry)

            return FlextResult[FlextLdifModels.CategorizedEntries].ok(categorized)

        except Exception as e:
            return FlextResult[FlextLdifModels.CategorizedEntries].fail(
                f"Failed to categorize entries: {e}"
            )

    def detect_encoding(self, content: bytes) -> FlextResult[str]:
        """Detect encoding of LDIF content bytes per RFC 2849.

        RFC 2849 mandates UTF-8 encoding for LDIF files.
        Returns error if UTF-8 decode fails (file is not RFC-compliant).

        Args:
            content: Raw bytes to detect encoding from

        Returns:
            FlextResult containing "utf-8" on success
            Failure if content is not valid UTF-8 (non-RFC compliant)

        Example:
            >>> with open("data.ldif", "rb") as f:
            ...     raw_bytes = f.read()
            >>> result = client.detect_encoding(raw_bytes)
            >>> if result.is_success:
            ...     encoding = result.unwrap()  # "utf-8"
            ... else:
            ...     print(f"Not RFC 2849 compliant: {result.error}")

        """
        try:
            # RFC 2849 requires UTF-8 encoding
            content.decode("utf-8")
            return FlextResult[str].ok("utf-8")
        except UnicodeDecodeError as e:
            # File is not RFC 2849 compliant - report error don't hide it
            return FlextResult[str].fail(
                f"LDIF content is not valid UTF-8 (RFC 2849 violation): "
                f"Invalid byte at position {e.start}: {e.reason}"
            )
        except Exception as e:
            return FlextResult[str].fail(f"Failed to detect encoding: {e}")

    def normalize_encoding(
        self, content: str, target_encoding: str = "utf-8"
    ) -> FlextResult[str]:
        """Normalize text content to target encoding.

        Encodes content to target encoding and decodes back to ensure
        all characters are representable in target encoding.

        Args:
            content: Text content to normalize
            target_encoding: Target encoding (default: "utf-8")

        Returns:
            FlextResult containing normalized content string

        Example:
            >>> result = client.normalize_encoding(content, "utf-8")
            >>> normalized = result.unwrap()

        """
        try:
            # Encode to target encoding and decode back (ensures valid representation)
            normalized = content.encode(target_encoding).decode(target_encoding)
            return FlextResult[str].ok(normalized)
        except UnicodeEncodeError as e:
            msg = f"Content has characters not representable in {target_encoding}: {e}"
            return FlextResult[str].fail(msg)
        except Exception as e:
            return FlextResult[str].fail(
                f"Failed to normalize encoding to {target_encoding}: {e}"
            )

    def validate_ldif_syntax(self, content: str) -> FlextResult[bool]:
        r"""Validate basic LDIF syntax structure.

        Performs basic validation checking for:
        - Presence of at least one "dn:" line (RFC 2849 requirement)
        - Non-empty content

        Note: This is a basic syntax check. For full RFC 2849 validation,
        use parse_ldif() which performs complete parsing.

        Args:
            content: LDIF content string to validate

        Returns:
            FlextResult containing True if valid basic syntax, False otherwise

        Example:
            >>> ldif_content = "dn: cn=test,dc=example,dc=com\\ncn: test\\n"
            >>> result = client.validate_ldif_syntax(ldif_content)
            >>> is_valid = result.unwrap()  # True

        """
        try:
            # Check non-empty
            if not content or not content.strip():
                return FlextResult[bool].ok(False)

            # Check for at least one "dn:" line (RFC 2849 requirement)
            # LDIF entries MUST start with "dn:"
            if "dn:" not in content.lower():
                return FlextResult[bool].ok(False)

            return FlextResult[bool].ok(True)

        except Exception as e:
            return FlextResult[bool].fail(f"Failed to validate LDIF syntax: {e}")

    def count_ldif_entries(self, content: str) -> FlextResult[int]:
        r"""Count number of LDIF entries in content.

        Counts entries by counting empty lines between entries.
        RFC 2849 specifies that entries are separated by blank lines.

        Args:
            content: LDIF content string

        Returns:
            FlextResult containing entry count

        Example:
            >>> ldif_content = (
            ...     "dn: cn=test1,dc=example,dc=com\\n"
            ...     "cn: test1\\n\\n"
            ...     "dn: cn=test2,dc=example,dc=com\\n"
            ...     "cn: test2\\n"
            ... )
            >>> result = client.count_ldif_entries(ldif_content)
            >>> count = result.unwrap()  # 2

        """
        try:
            if not content or not content.strip():
                return FlextResult[int].ok(0)

            # Count entries by counting "dn:" lines (RFC 2849: each starts with dn:)
            dn_count = content.lower().count("dn:")

            # Ensure at least 1 entry if content exists
            count = max(1, dn_count) if content.strip() else 0

            return FlextResult[int].ok(count)

        except Exception as e:
            return FlextResult[int].fail(f"Failed to count LDIF entries: {e}")

    # =========================================================================
    # QUIRKS MANAGEMENT
    # =========================================================================

    def register_quirk(
        self,
        quirk: (
            FlextLdifQuirksBaseSchemaQuirk
            | FlextLdifQuirksBaseAclQuirk
            | FlextLdifQuirksBaseEntryQuirk
        ),
        quirk_type: str = "schema",
    ) -> FlextResult[None]:
        """Register a custom quirk for server-specific processing.

        Args:
            quirk: Quirk instance to register
            quirk_type: Type of quirk ("schema", "acl", "entry")

        Returns:
            FlextResult indicating success or failure

        """
        # Validate quirk_type
        if quirk_type not in {"schema", "acl", "entry"}:
            return FlextResult[None].fail(f"Invalid quirk type: {quirk_type}")

        container = self.container

        # Get quirk registry from container using helper
        registry = self._get_service_typed(
            container, "quirk_registry", FlextLdifQuirksRegistry
        )
        if not isinstance(registry, FlextLdifQuirksRegistry):
            return FlextResult[None].fail("Failed to retrieve quirk registry")

        # Use dispatch dict pattern instead of if/elif chain
        dispatch: dict[
            str,
            tuple[type, Callable[[FlextLdifQuirksRegistry, object], FlextResult[None]]],
        ] = {
            "schema": (
                FlextLdifQuirksBaseSchemaQuirk,
                lambda reg, q: reg.register_schema_quirk(
                    cast("FlextLdifQuirksBaseSchemaQuirk", q)
                ),
            ),
            "acl": (
                FlextLdifQuirksBaseAclQuirk,
                lambda reg, q: reg.register_acl_quirk(
                    cast("FlextLdifQuirksBaseAclQuirk", q)
                ),
            ),
            "entry": (
                FlextLdifQuirksBaseEntryQuirk,
                lambda reg, q: reg.register_entry_quirk(
                    cast("FlextLdifQuirksBaseEntryQuirk", q)
                ),
            ),
        }

        expected_type, register_fn = dispatch[quirk_type]
        if not isinstance(quirk, expected_type):
            qname = type(quirk).__name__
            expected_name = expected_type.__name__
            return FlextResult[None].fail(f"Quirk must be {expected_name}, got {qname}")

        return register_fn(registry, quirk)

    # =========================================================================
    # INFRASTRUCTURE ACCESS
    # =========================================================================

    @property
    def config(self) -> FlextLdifConfig:
        """Access to LDIF configuration instance with lazy initialization."""
        if self._config is None:
            self._config = (
                getattr(self, "_init_config_value", None) or FlextLdifConfig()
            )
        # Type narrowing: _config cannot be None after initialization above
        if self._config is None:
            msg = "Configuration initialization failed"
            raise RuntimeError(msg)
        return self._config

    @property
    def handlers(self) -> FlextLdifTypes.Models.CustomDataDict:
        """Access to initialized CQRS handlers."""
        return self._handlers

    @property
    def container(self) -> FlextContainer:
        """Access to dependency injection container."""
        if self._container is None:
            msg = "FlextContainer must be initialized"
            raise RuntimeError(msg)
        # Type narrowed by None check above
        return self._container

    @property
    def context(self) -> FlextContext:
        """Access to execution context with lazy initialization."""
        if not self._context:
            # Initialize with empty dict
            self._context = {}
        # Return as FlextContext type (which is a dict-like context object)
        return cast("FlextContext", self._context)

    @property
    def bus(self) -> FlextBus:
        """Access to event bus with lazy initialization."""
        if self._bus is None:
            self._bus = FlextBus()
        # Type narrowed by None check - cast to help type checker with inherited _bus
        return cast("FlextBus", self._bus)

    def get_effective_server_type(
        self, ldif_path: Path | None = None
    ) -> FlextResult[str]:
        """Get the effective server type based on configuration.

        Applies the following logic:
        1. If enable_relaxed_parsing: return "relaxed"
        2. If quirks_detection_mode == "manual": return quirks_server_type
        3. If quirks_detection_mode == "auto": detect from LDIF content
        4. Default: return server_type from config

        Args:
            ldif_path: Optional path for auto-detection

        Returns:
            FlextResult with effective server type

        """
        try:
            config = self.config

            # Relaxed mode takes precedence
            if config.enable_relaxed_parsing:
                return FlextResult[str].ok(FlextLdifConstants.ServerTypes.RELAXED)

            # Manual mode uses specified server type
            if config.quirks_detection_mode == "manual":
                if config.quirks_server_type:
                    return FlextResult[str].ok(config.quirks_server_type)
                return FlextResult[str].fail(
                    "Manual mode requires quirks_server_type to be set"
                )

            # Auto-detection mode
            if config.quirks_detection_mode == "auto" and ldif_path:
                detector = FlextLdifServerDetector()
                detection_result = detector.detect_server_type(ldif_path=ldif_path)
                if detection_result.is_success:
                    detected_data = detection_result.unwrap()
                    server_type_obj = detected_data.get(
                        "detected_server_type", config.server_type
                    )
                    server_type = (
                        str(server_type_obj) if server_type_obj else config.server_type
                    )
                    return FlextResult[str].ok(server_type)

            # Default to configured server type
            return FlextResult[str].ok(config.server_type)

        except Exception as e:
            return FlextResult[str].fail(f"Error determining server type: {e}")

    def detect_server_type(
        self,
        ldif_path: Path | None = None,
        ldif_content: str | None = None,
    ) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
        """Detect LDAP server type from LDIF file or content.

        Args:
            ldif_path: Path to LDIF file
            ldif_content: Raw LDIF content as string

        Returns:
            FlextResult with detection results including:
            - detected_server_type: The detected server type
            - confidence: Confidence score (0.0-1.0)
            - is_confident: Whether detection confidence is high

        """
        try:
            detector = FlextLdifServerDetector()
            return detector.detect_server_type(
                ldif_path=ldif_path,
                ldif_content=ldif_content,
            )
        except Exception as e:
            return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                f"Server detection failed: {e}"
            )


__all__ = ["FlextLdifClient"]
