"""FLEXT-LDIF Client - Main Implementation for LDIF Operations.

This module contains the core implementation logic for LDIF processing,
extracted from the thin facade API. It provides the actual business logic
for parsing, writing, validation, migration, and analysis operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

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
from flext_ldif.migration_pipeline import FlextLdifMigrationPipeline
from flext_ldif.models import FlextLdifModels
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
from flext_ldif.rfc.rfc_ldif_parser import FlextLdifRfcLdifParser
from flext_ldif.rfc.rfc_ldif_writer import FlextLdifRfcLdifWriter
from flext_ldif.rfc.rfc_schema_parser import FlextLdifRfcSchemaParser
from flext_ldif.schema.validator import FlextLdifSchemaValidator
from flext_ldif.typings import FlextLdifTypes


class FlextLdifClient(FlextService[dict[str, object]]):
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
    _context: FlextContext | None = PrivateAttr(default=None)
    _handlers: dict[str, object] = PrivateAttr(default_factory=dict)
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

    def model_post_init(self, __context: dict[str, object] | None, /) -> None:
        """Initialize private attributes after Pydantic initialization.

        This hook is called by Pydantic after __init__ completes.

        Args:
            __context: Pydantic's validation context dictionary or None.

        """
        # Initialize private attributes that parent's __init__ may access
        self._config = getattr(self, "_init_config_value", None) or FlextLdifConfig()
        # ✅ FIXED: Don't bind config to context - use _log_config_once() instead
        self._context = FlextContext()  # Empty context, not bound to global
        self._bus = FlextBus()
        self._handlers = {}

        # Ensure components are initialized

        # Register services in container for DI
        self._setup_services()

        # Register default quirks for all servers
        self._register_default_quirks()

        # ✅ Log config ONCE without binding to global context
        if self.logger and self._config:
            config_info: dict[str, object] = {
                "ldif_encoding": self._config.ldif_encoding,
                "strict_rfc_compliance": self._config.strict_rfc_compliance,
                "ldif_chunk_size": self._config.ldif_chunk_size,
                "max_workers": self._config.max_workers,
            }
            self._log_config_once(config_info, message="FlextLdif client initialized")
            self.logger.debug("CQRS handlers and default quirks registered")

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute client self-check and return status.

        Returns:
            FlextResult containing client status and configuration

        """
        try:
            config = self.config
            return FlextResult[dict[str, object]].ok({
                "status": "initialized",
                "services": ["parser", "writer", "validator", "migration"],
                "config": {"default_encoding": config.ldif_encoding},
            })
        except Exception as e:  # pragma: no cover
            return FlextResult[dict[str, object]].fail(
                f"Client status check failed: {e}"
            )

    # =========================================================================
    # PRIVATE: Service Setup and Handler Initialization
    # =========================================================================

    def _setup_services(self) -> None:
        """Register all services in the dependency injection container with instances."""
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
            params: dict[str, object] | None,
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

        # Get quirk registry from container
        registry_result = container.get("quirk_registry")
        if registry_result.is_failure:
            logger.warning(
                "Quirk registry not available, skipping default quirk registration"
            )
            return

        registry = registry_result.unwrap()
        if not isinstance(registry, FlextLdifQuirksRegistry):
            logger.warning(
                "Quirk registry not available, skipping default quirk registration"
            )
            return

        # Register complete implementations
        complete_quirks = [
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

            # Note: Schema quirks don't have nested ACL/Entry quirks in base implementation

        logger.info(
            f"Registered {len(complete_quirks)} complete quirks and {len(stub_quirks)} stub quirks"
        )

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

        # Get the RFC parser from container
        parser_result = container.get("rfc_parser")
        if parser_result.is_failure:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Failed to get RFC parser: {parser_result.error}"
            )

        # Type narrow parser from unwrap()
        parser_obj = parser_result.unwrap()
        if not isinstance(parser_obj, FlextLdifRfcLdifParser):
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                "RFC parser has unexpected type"
            )
        parser = parser_obj  # Type narrowed by isinstance check

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

        # Get the RFC writer from container
        writer_result = container.get("rfc_writer")
        if writer_result.is_failure:
            return FlextResult[str].fail(
                f"Failed to get RFC writer: {writer_result.error}"
            )

        # Type narrow writer from unwrap()
        writer_obj = writer_result.unwrap()
        if not isinstance(writer_obj, FlextLdifRfcLdifWriter):
            return FlextResult[str].fail("RFC writer has unexpected type")
        writer = writer_obj  # Type narrowed by isinstance check

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
            except Exception as e:  # pragma: no cover
                return FlextResult[str].fail(
                    f"Failed to write to file {output_path}: {e}"
                )

        return FlextResult[str].ok(content)

    def validate_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, object]]:
        """Validate LDIF entries against RFC and business rules.

        Args:
            entries: List of entries to validate

        Returns:
            FlextResult containing validation report with details

        """
        container = self.container

        # Get the schema validator from container
        validator_result = container.get("schema_validator")
        if validator_result.is_failure:
            return FlextResult[dict[str, object]].fail(
                f"Failed to get schema validator: {validator_result.error}"
            )

        # Type narrow validator from unwrap()
        validator_obj = validator_result.unwrap()
        if not isinstance(validator_obj, FlextLdifSchemaValidator):
            return FlextResult[dict[str, object]].fail(
                "Schema validator has unexpected type"
            )
        validator = validator_obj  # Type narrowed by isinstance check

        # Call validator directly
        result = validator.validate_entries(entries)

        # Return validation result as dictionary for consistent API
        if result.is_success:
            validation_result = result.unwrap()
            return FlextResult[dict[str, object]].ok({
                "is_valid": validation_result.is_valid,
                "total_entries": len(entries),
                "valid_entries": len(entries) - len(validation_result.errors),
                "invalid_entries": len(validation_result.errors),
                "errors": validation_result.errors,
            })
        return FlextResult[dict[str, object]].fail(
            result.error or "Validation failed"
        )

    def migrate_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        from_server: str,
        to_server: str,
    ) -> FlextResult[dict[str, object]]:
        """Migrate LDIF entries between different server types.

        Args:
            entries: List of entries to migrate
            from_server: Source server type ("oid", "oud", "openldap", etc.)
            to_server: Target server type

        Returns:
            FlextResult containing migration statistics

        """
        container = self.container

        # Get migration pipeline from container
        pipeline_result = container.get("migration_pipeline")
        if pipeline_result.is_failure:
            return FlextResult[dict[str, object]].fail(
                f"Failed to get migration pipeline: {pipeline_result.error}"
            )

        # Type narrow pipeline factory from unwrap()
        # The container.get returns a lambda callable
        pipeline_factory_obj = pipeline_result.unwrap()
        if not callable(pipeline_factory_obj):
            return FlextResult[dict[str, object]].fail(
                "Migration pipeline factory is not callable"
            )
        # Use cast after runtime callable check to satisfy type checker
        pipeline_factory: Callable[
            [dict[str, object] | None], FlextLdifMigrationPipeline
        ] = cast(
            "Callable[[dict[str, object] | None], FlextLdifMigrationPipeline]",
            pipeline_factory_obj,
        )

        pipeline = pipeline_factory({
            "source_server_type": from_server,
            "target_server_type": to_server,
        })

        # Convert Entry objects to dict format for pipeline compatibility
        # Use list[object] for type compatibility with migrate_entries
        entries_as_dicts: list[object] = cast(
            "list[object]", [entry.model_dump() for entry in entries]
        )

        # Call migrate_entries directly
        migration_result = pipeline.migrate_entries(
            entries=entries_as_dicts, source_format=from_server, target_format=to_server
        )

        if migration_result.is_failure:
            return FlextResult[dict[str, object]].fail(
                migration_result.error or "Migration failed"
            )

        migrated_entries = migration_result.unwrap()
        stats: dict[str, object] = {
            "total_entries": len(entries),
            "migrated_entries": len(migrated_entries),
            "from_server": from_server,
            "to_server": to_server,
            "success": True,
        }
        return FlextResult[dict[str, object]].ok(stats)

    def migrate_files(
        self,
        input_dir: Path,
        output_dir: Path,
        from_server: str,
        to_server: str,
        *,
        process_schema: bool = True,
        process_entries: bool = True,
    ) -> FlextResult[dict[str, object]]:
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
            params: dict[str, object] = {
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
                return FlextResult[dict[str, object]].fail(
                    migration_result.error or "Migration failed"
                )

            return FlextResult[dict[str, object]].ok(migration_result.unwrap())

        except Exception as e:  # pragma: no cover
            logger = self.logger
            logger.exception("Migration failed")
            return FlextResult[dict[str, object]].fail(f"Migration failed: {e}")

    def analyze_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, object]]:
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
        return FlextResult[dict[str, object]].ok({
            "total_entries": total_entries,
            "objectclass_distribution": object_class_distribution,
            "patterns_detected": [],
        })

    def filter_by_objectclass(
        self,
        entries: list[FlextLdifModels.Entry],
        objectclass: str | tuple[str, ...],
        required_attributes: list[str] | None = None,
        mode: str = "include",
        *,
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by object class with optional required attributes.

        Enhanced version that supports:
        - Multiple objectClasses (tuple)
        - Required attribute validation
        - Include/exclude modes
        - Exclusion metadata marking

        Args:
            entries: List of LDIF entries to filter
            objectclass: Single objectClass string or tuple of objectClasses
            required_attributes: Optional list of required attributes (all must be present)
            mode: "include" to keep matching entries, "exclude" to remove them
            mark_excluded: If True, mark excluded entries with metadata (keyword-only)

        Returns:
            FlextResult containing filtered entries

        Example:
            >>> # Simple filtering (backward compatible)
            >>> result = client.filter_by_objectclass(entries, "inetOrgPerson")
            >>>
            >>> # Advanced filtering with required attributes
            >>> result = client.filter_by_objectclass(
            ...     entries,
            ...     objectclass=("inetOrgPerson", "person"),
            ...     required_attributes=[FlextLdifConstants.DictKeys.CN, "sn", "mail"],
            ... )

        """
        return FlextLdifFilters.filter_entries_by_objectclass(
            entries=entries,
            objectclass=objectclass,
            required_attributes=required_attributes,
            mode=mode,
            mark_excluded=mark_excluded,
        )

    def filter_persons(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries to get only person entries.

        Args:
            entries: List of LDIF entries to filter

        Returns:
            FlextResult containing person entries

        """
        return self.filter_by_objectclass(entries, "person")

    def filter_by_dn_pattern(
        self,
        entries: list[FlextLdifModels.Entry],
        pattern: str,
        mode: str = "include",
        *,
        mark_excluded: bool = True,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by DN wildcard pattern.

        Uses fnmatch for pattern matching. Supports wildcards:
        - * (matches any sequence of characters)
        - ? (matches any single character)
        - [seq] (matches any character in seq)
        - [!seq] (matches any character not in seq)

        Args:
            entries: List of LDIF entries to filter
            pattern: DN wildcard pattern (e.g., "*,ou=users,dc=example,dc=com")
            mode: "include" to keep matching entries, "exclude" to remove them
            mark_excluded: If True, mark excluded entries with metadata (keyword-only)

        Returns:
            FlextResult containing filtered entries

        Example:
            >>> result = client.filter_by_dn_pattern(
            ...     entries, pattern="*,dc=ctbc,dc=com", mode="include"
            ... )

        """
        return FlextLdifFilters.filter_entries_by_dn(
            entries=entries,
            pattern=pattern,
            mode=mode,
            mark_excluded=mark_excluded,
        )

    def filter_schema_by_oid(
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
        """Filter schema attributes/objectClasses by OID pattern whitelist.

        Uses fnmatch for OID pattern matching. Only items matching whitelist patterns
        are included. Supports wildcards in OID patterns (e.g., "1.3.6.1.4.1.111.*").

        Args:
            schema_items: List of schema attributes or objectClasses
            oid_whitelist: List of OID patterns to whitelist (e.g., ["1.3.6.1.4.1.111.*"])
            mark_excluded: If True, mark excluded items with metadata (keyword-only)

        Returns:
            FlextResult containing filtered schema items

        Example:
            >>> result = client.filter_schema_by_oid(
            ...     schema_attributes,
            ...     oid_whitelist=["1.3.6.1.4.1.111.*", "2.16.840.1.113894.*"],
            ... )

        """
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

        except Exception as e:  # pragma: no cover
            return FlextResult[
                list[
                    FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass
                ]
            ].fail(f"Failed to filter schema by OID: {e}")

    def filter_by_attributes(
        self,
        entries: list[FlextLdifModels.Entry],
        attributes: list[str],
        mode: str = "include",
        *,
        match_all: bool = False,
        mark_excluded: bool = True,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by attribute presence.

        Args:
            entries: List of LDIF entries to filter
            attributes: List of attribute names to check
            mode: "include" to keep entries with attributes, "exclude" to remove them
            match_all: If True, entry must have ALL attributes; if False, ANY attribute (keyword-only)
            mark_excluded: If True, mark excluded entries with metadata (keyword-only)

        Returns:
            FlextResult containing filtered entries

        Example:
            >>> result = client.filter_by_attributes(
            ...     entries,
            ...     attributes=["orclguid", "modifytimestamp"],
            ...     mode="exclude",  # Remove entries with these attributes
            ... )

        """
        return FlextLdifFilters.filter_entries_by_attributes(
            entries=entries,
            attributes=attributes,
            mode=mode,
            match_all=match_all,
            mark_excluded=mark_excluded,
        )

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

            for entry in entries:
                category = FlextLdifFilters.categorize_entry(
                    entry,
                    user_objectclasses=user_objectclasses,
                    group_objectclasses=group_objectclasses,
                    container_objectclasses=container_objectclasses,
                )

                if category == "user":
                    categorized.users.append(entry)
                elif category == "group":
                    categorized.groups.append(entry)
                elif category == "container":
                    categorized.containers.append(entry)
                else:
                    categorized.uncategorized.append(entry)

            return FlextResult[FlextLdifModels.CategorizedEntries].ok(categorized)

        except Exception as e:  # pragma: no cover
            return FlextResult[FlextLdifModels.CategorizedEntries].fail(
                f"Failed to categorize entries: {e}"
            )

    def detect_encoding(self, content: bytes) -> FlextResult[str]:
        """Detect encoding of LDIF content bytes.

        Attempts UTF-8 first (RFC 2849 standard), falls back to latin-1
        as a universal fallback (all byte sequences are valid latin-1).

        Args:
            content: Raw bytes to detect encoding from

        Returns:
            FlextResult containing detected encoding name ("utf-8" or "latin-1")

        Example:
            >>> with open("data.ldif", "rb") as f:
            ...     raw_bytes = f.read()
            >>> result = client.detect_encoding(raw_bytes)
            >>> encoding = result.unwrap()  # "utf-8" or "latin-1"

        """
        try:
            # Try UTF-8 first (RFC 2849 standard encoding)
            try:
                content.decode("utf-8")
                return FlextResult[str].ok("utf-8")
            except UnicodeDecodeError:  # pragma: no cover
                # Fall back to latin-1 (universal fallback - all bytes valid)
                return FlextResult[str].ok("latin-1")
        except Exception as e:  # pragma: no cover
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
        except UnicodeEncodeError as e:  # pragma: no cover
            return FlextResult[str].fail(
                f"Content contains characters not representable in {target_encoding}: {e}"
            )
        except Exception as e:  # pragma: no cover
            return FlextResult[str].fail(
                f"Failed to normalize encoding to {target_encoding}: {e}"
            )

    def validate_ldif_syntax(self, content: str) -> FlextResult[bool]:
        r"""Validate basic LDIF syntax structure.

        Performs basic validation checking for:
        - Presence of at least one "dn:" line (RFC 2849 requirement)
        - Non-empty content

        Note: This is a basic syntax check. For full RFC 2849 validation,
        use parse_ldif() which performs comprehensive parsing.

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
            # LDIF entries MUST start with "dn:" per RFC 2849
            if "dn:" not in content.lower():
                return FlextResult[bool].ok(False)

            return FlextResult[bool].ok(True)

        except Exception as e:  # pragma: no cover
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

            # Count entries by counting "dn:" lines (RFC 2849: each entry starts with dn:)
            dn_count = content.lower().count("dn:")

            # Ensure at least 1 entry if content exists
            count = max(1, dn_count) if content.strip() else 0

            return FlextResult[int].ok(count)

        except Exception as e:  # pragma: no cover
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

        # Get quirk registry from container
        registry_result = container.get("quirk_registry")
        if registry_result.is_failure:
            return FlextResult[None].fail(
                f"Failed to get quirk registry: {registry_result.error}"
            )

        # Type narrow registry from unwrap()
        registry_obj = registry_result.unwrap()
        if not isinstance(registry_obj, FlextLdifQuirksRegistry):
            return FlextResult[None].fail("Quirk registry has unexpected type")
        registry = registry_obj  # Type narrowed by isinstance check

        # Type narrow quirk parameter and call appropriate registration method
        # Use actual class names (not type aliases) for isinstance checks
        if quirk_type == "schema":
            if not isinstance(quirk, FlextLdifQuirksBaseSchemaQuirk):
                return FlextResult[None].fail(
                    f"Quirk must be FlextLdifQuirksBaseSchemaQuirk, got {type(quirk).__name__}"
                )
            return registry.register_schema_quirk(quirk)

        if quirk_type == "acl":
            if not isinstance(quirk, FlextLdifQuirksBaseAclQuirk):
                return FlextResult[None].fail(
                    f"Quirk must be FlextLdifQuirksBaseAclQuirk, got {type(quirk).__name__}"
                )
            return registry.register_acl_quirk(quirk)

        if quirk_type == "entry":
            if not isinstance(quirk, FlextLdifQuirksBaseEntryQuirk):
                return FlextResult[None].fail(
                    f"Quirk must be FlextLdifQuirksBaseEntryQuirk, got {type(quirk).__name__}"
                )
            return registry.register_entry_quirk(quirk)

        return FlextResult[None].fail(f"Unsupported quirk type: {quirk_type}")

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
        # Type narrowed by None check above
        return self._config

    @property
    def handlers(self) -> dict[str, object]:
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
        if self._context is None:
            # ✅ FIXED: Don't bind config to context - prevents config repetition in logs
            self._context = FlextContext()  # Empty context
        # Context is guaranteed non-None after initialization
        return self._context

    @property
    def bus(self) -> FlextBus:
        """Access to event bus with lazy initialization."""
        if self._bus is None:
            self._bus = FlextBus()
        # Type narrowed by None check - cast to help type checker with inherited _bus
        return cast("FlextBus", self._bus)


__all__ = ["FlextLdifClient"]
