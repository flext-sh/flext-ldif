"""FLEXT-LDIF Client - Main Implementation for LDIF Operations.

This module contains the core implementation logic for LDIF processing,
extracted from the thin facade API. It provides the actual business logic
for parsing, writing, validation, migration, and analysis operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
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
from flext_ldif.migration_pipeline import FlextLdifMigrationPipeline
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.base import (
    FlextLdifQuirksBase,
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


class FlextLdifClient(FlextService[FlextLdifTypes.Dict]):
    """Main client implementation for LDIF processing operations.

    This class contains all the actual business logic for LDIF operations,
    providing a clean separation between the thin API facade and the
    implementation details.

    The client manages:
    - Service initialization and dependency injection
    - CQRS handler setup and orchestration
    - Default quirk registration
    - Business logic delegation to appropriate services

    """

    # Pydantic v2 private attributes (CRITICAL for Pydantic model initialization)
    # These MUST be declared at class level for Pydantic to handle them correctly
    _container: FlextContainer | None = PrivateAttr(default=None)
    _context: FlextContext | None = PrivateAttr(default=None)
    _bus: object | None = PrivateAttr(default=None)
    _handlers: FlextLdifTypes.Dict = PrivateAttr(default_factory=dict)
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

    def model_post_init(self, __context: object, /) -> None:
        """Initialize private attributes after Pydantic initialization.

        This hook is called by Pydantic after __init__ completes.
        """
        # Initialize private attributes that parent's __init__ may access
        self._config = getattr(self, "_init_config_value", None) or FlextLdifConfig()
        self._container = FlextContainer.get_global()
        self._context = FlextContext({"config": self._config})
        self._bus = FlextBus()
        self._handlers = {}

        # Ensure components are initialized
        if self._container is None:
            msg = "FlextContainer must be initialized"
            raise RuntimeError(msg)
        if self._context is None:
            msg = "FlextContext must be initialized"
            raise RuntimeError(msg)
        if self._bus is None:
            msg = "FlextBus must be initialized"
            raise RuntimeError(msg)

        # Register services in container for DI
        self._setup_services()

        # Register default quirks for all servers
        self._register_default_quirks()

        if self.logger:
            self.logger.info(
                "Initialized FlextLdif client with CQRS handlers and default quirks"
            )

    def execute(self) -> FlextResult[FlextLdifTypes.Dict]:
        """Execute client self-check and return status.

        Returns:
            FlextResult containing client status and configuration

        """
        try:
            config = self.config
            return FlextResult[FlextLdifTypes.Dict].ok({
                "status": "initialized",
                "services": ["parser", "writer", "validator", "migration"],
                "config": {"default_encoding": config.ldif_encoding},
            })
        except Exception as e:
            return FlextResult[FlextLdifTypes.Dict].fail(
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
        container.register(
            "migration_pipeline",
            lambda params=None, source="oid", target="oud": FlextLdifMigrationPipeline(
                params=params or {},
                source_server_type=source,
                target_server_type=target,
            ),
        )

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

            # Register nested ACL quirk if it exists
            if hasattr(schema_quirk, "AclQuirk"):
                try:
                    acl_quirk = schema_quirk.AclQuirk(
                        server_type=schema_quirk.server_type,
                        priority=schema_quirk.priority,
                    )
                    acl_result = registry.register_acl_quirk(acl_quirk)
                    if acl_result.is_failure:
                        logger.error(
                            f"Failed to register ACL quirk: {acl_result.error}"
                        )
                except Exception:
                    logger.exception("Failed to instantiate ACL quirk")

            # Register nested Entry quirk if it exists
            if hasattr(schema_quirk, "EntryQuirk"):
                try:
                    entry_quirk = schema_quirk.EntryQuirk(
                        server_type=schema_quirk.server_type,
                        priority=schema_quirk.priority,
                    )
                    entry_result = registry.register_entry_quirk(entry_quirk)
                    if entry_result.is_failure:
                        logger.error(
                            f"Failed to register entry quirk: {entry_result.error}"
                        )
                except Exception:
                    logger.exception("Failed to instantiate entry quirk")

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
        parser = cast("FlextLdifRfcLdifParser", parser_result.unwrap())

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
        writer = cast("FlextLdifRfcLdifWriter", writer_result.unwrap())

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
    ) -> FlextResult[FlextLdifTypes.Dict]:
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
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"Failed to get schema validator: {validator_result.error}"
            )
        validator = cast("FlextLdifSchemaValidator", validator_result.unwrap())

        # Call validator directly
        result = validator.validate_entries(entries)

        # Return validation result as dictionary for consistent API
        if result.is_success:
            validation_result = result.unwrap()
            return FlextResult[FlextLdifTypes.Dict].ok({
                "is_valid": validation_result.is_valid,
                "total_entries": len(entries),
                "valid_entries": len(entries) - len(validation_result.errors),
                "invalid_entries": len(validation_result.errors),
                "errors": validation_result.errors,
            })
        return FlextResult[FlextLdifTypes.Dict].fail(
            result.error or "Validation failed"
        )

    def migrate_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        from_server: str,
        to_server: str,
    ) -> FlextResult[FlextLdifTypes.Dict]:
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
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"Failed to get migration pipeline: {pipeline_result.error}"
            )

        # The container.get returns a lambda, so we need to call it with params
        pipeline_factory = cast(
            "Callable[[dict[str, str] | None], FlextLdifMigrationPipeline]",
            pipeline_result.unwrap(),
        )
        pipeline = pipeline_factory({
            "source_server_type": from_server,
            "target_server_type": to_server,
        })

        # Call migrate_entries directly
        migration_result = pipeline.migrate_entries(
            entries=list(entries), source_format=from_server, target_format=to_server
        )

        if migration_result.is_failure:
            return FlextResult[FlextLdifTypes.Dict].fail(
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
        return FlextResult[FlextLdifTypes.Dict].ok(stats)

    def migrate_files(
        self,
        input_dir: Path,
        output_dir: Path,
        from_server: str,
        to_server: str,
        *,
        process_schema: bool = True,
        process_entries: bool = True,
    ) -> FlextResult[FlextLdifTypes.Dict]:
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
                return FlextResult[FlextLdifTypes.Dict].fail(
                    migration_result.error or "Migration failed"
                )

            return FlextResult[FlextLdifTypes.Dict].ok(migration_result.unwrap())

        except Exception as e:
            logger = self.logger
            logger.exception("Migration failed")
            return FlextResult[FlextLdifTypes.Dict].fail(f"Migration failed: {e}")

    def analyze_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[FlextLdifTypes.Dict]:
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
            object_classes = entry.attributes.get(
                FlextLdifConstants.DictKeys.OBJECTCLASS, []
            )
            if object_classes:
                for obj_class in object_classes:
                    obj_class_str = str(obj_class)
                    object_class_distribution[obj_class_str] = (
                        object_class_distribution.get(obj_class_str, 0) + 1
                    )

        # Return analytics result as dictionary for consistent API
        return FlextResult[FlextLdifTypes.Dict].ok({
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
            mark_excluded: If True, mark excluded entries with metadata

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
            ...     required_attributes=["cn", "sn", "mail"]
            ... )

        """
        from flext_ldif.filters import FlextLdifFilters

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
            mark_excluded: If True, mark excluded entries with metadata

        Returns:
            FlextResult containing filtered entries

        Example:
            >>> result = client.filter_by_dn_pattern(
            ...     entries,
            ...     pattern="*,dc=ctbc,dc=com",
            ...     mode="include"
            ... )

        """
        from flext_ldif.filters import FlextLdifFilters

        return FlextLdifFilters.filter_entries_by_dn(
            entries=entries,
            pattern=pattern,
            mode=mode,
            mark_excluded=mark_excluded,
        )

    def filter_schema_by_oid(
        self,
        schema_items: list[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass],
        oid_whitelist: list[str],
        mark_excluded: bool = True,
    ) -> FlextResult[list[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass]]:
        """Filter schema attributes/objectClasses by OID pattern whitelist.

        Uses fnmatch for OID pattern matching. Only items matching whitelist patterns
        are included. Supports wildcards in OID patterns (e.g., "1.3.6.1.4.1.111.*").

        Args:
            schema_items: List of schema attributes or objectClasses
            oid_whitelist: List of OID patterns to whitelist (e.g., ["1.3.6.1.4.1.111.*"])
            mark_excluded: If True, mark excluded items with metadata

        Returns:
            FlextResult containing filtered schema items

        Example:
            >>> result = client.filter_schema_by_oid(
            ...     schema_attributes,
            ...     oid_whitelist=["1.3.6.1.4.1.111.*", "2.16.840.1.113894.*"]
            ... )

        """
        from flext_ldif.filters import FlextLdifFilters

        try:
            filtered: list[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass] = []

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
                    from datetime import UTC, datetime
                    exclusion_info = FlextLdifModels.ExclusionInfo(
                        excluded=True,
                        exclusion_reason=f"OID not in whitelist: {oid}",
                        filter_criteria=criteria,
                        timestamp=datetime.now(UTC).isoformat(),
                    )

                    if item.metadata is None:
                        item.metadata = FlextLdifModels.QuirkMetadata(
                            extensions={"exclusion_info": exclusion_info.model_dump()}
                        )
                    else:
                        item.metadata.extensions["exclusion_info"] = exclusion_info.model_dump()

                    filtered.append(item)

            return FlextResult[
                list[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass]
            ].ok(filtered)

        except Exception as e:
            return FlextResult[
                list[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass]
            ].fail(f"Failed to filter schema by OID: {e}")

    def filter_by_attributes(
        self,
        entries: list[FlextLdifModels.Entry],
        attributes: list[str],
        mode: str = "include",
        match_all: bool = False,
        mark_excluded: bool = True,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by attribute presence.

        Args:
            entries: List of LDIF entries to filter
            attributes: List of attribute names to check
            mode: "include" to keep entries with attributes, "exclude" to remove them
            match_all: If True, entry must have ALL attributes; if False, ANY attribute
            mark_excluded: If True, mark excluded entries with metadata

        Returns:
            FlextResult containing filtered entries

        Example:
            >>> result = client.filter_by_attributes(
            ...     entries,
            ...     attributes=["orclguid", "modifytimestamp"],
            ...     mode="exclude"  # Remove entries with these attributes
            ... )

        """
        from flext_ldif.filters import FlextLdifFilters

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
        user_objectclasses: tuple[str, ...] = ("inetOrgPerson", "person", "organizationalPerson"),
        group_objectclasses: tuple[str, ...] = ("groupOfNames", "groupOfUniqueNames", "posixGroup"),
        container_objectclasses: tuple[str, ...] = ("organizationalUnit", "organization", "domain"),
    ) -> FlextResult[FlextLdifModels.CategorizedEntries]:
        """Categorize entries into users, groups, containers, and uncategorized.

        Categorizes entries based on their objectClass attributes. Checks categories
        in priority order: users first, then groups, then containers. Any entry not
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
            ...     container_objectclasses=client-aOudMigConstants.ORG_UNIT_CLASSES
            ... )

        """
        from flext_ldif.filters import FlextLdifFilters

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

            # Update summary counts
            categorized.update_summary()

            return FlextResult[FlextLdifModels.CategorizedEntries].ok(categorized)

        except Exception as e:
            return FlextResult[FlextLdifModels.CategorizedEntries].fail(
                f"Failed to categorize entries: {e}"
            )

    # =========================================================================
    # QUIRKS MANAGEMENT
    # =========================================================================

    def register_quirk(
        self,
        quirk: object,
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
        registry = cast("FlextLdifQuirksRegistry", registry_result.unwrap())

        # Call appropriate registration method based on type
        if quirk_type == "schema":
            return registry.register_schema_quirk(
                cast("FlextLdifQuirksBase.BaseSchemaQuirk", quirk)
            )
        if quirk_type == "acl":
            return registry.register_acl_quirk(
                cast("FlextLdifQuirksBase.BaseAclQuirk", quirk)
            )
        if quirk_type == "entry":
            return registry.register_entry_quirk(
                cast("FlextLdifQuirksBase.BaseEntryQuirk", quirk)
            )
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
        # Type narrowing: _config is guaranteed non-None after initialization
        if self._config is None:
            # This should never happen, but handle it properly for production
            msg = "Configuration initialization failed unexpectedly"
            raise RuntimeError(msg)
        return self._config

    @property
    def handlers(self) -> FlextLdifTypes.Dict:
        """Access to initialized CQRS handlers."""
        return self._handlers

    @property
    def container(self) -> FlextContainer:
        """Access to dependency injection container with lazy initialization."""
        if self._container is None:
            self._container = FlextContainer.get_global()
        return self._container

    @property
    def context(self) -> FlextContext:
        """Access to execution context with lazy initialization."""
        if self._context is None:
            self._context = FlextContext({"config": self.config})
        return self._context

    @property
    def bus(self) -> FlextBus:
        """Access to event bus with lazy initialization."""
        if self._bus is None:
            self._bus = FlextBus()
        return cast("FlextBus", self._bus)


__all__ = ["FlextLdifClient"]
