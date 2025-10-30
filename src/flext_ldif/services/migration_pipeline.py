"""Generic LDIF Migration Pipeline - RFC-first with Quirk Composition.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Implements a generic LDIF migration pipeline that uses RFC-compliant base parsers
with composable server-specific quirks for maximum flexibility and reusability.

Architecture:
- Phase 1: Parse source LDIF using RFC base + source quirks
- Phase 2: Convert to RFC-compliant intermediate format
- Phase 3: Generate target LDIF using RFC base + target quirks
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from flext_core import FlextResult, FlextService

from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers import (
    FlextLdifServersOid,
    FlextLdifServersOud,
)
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.services.registry import FlextLdifRegistry
from flext_ldif.services.writer import FlextLdifWriterService


class _QuirkRegistrationService:
    """Service for registering server-specific quirks.

    Consolidates quirk registration logic with automatic server detection
    and single responsibility.
    """

    @staticmethod
    def register_quirks_for_server(
        registry: FlextLdifRegistry,
        server_type: str,
    ) -> None:
        """Register all quirks (schema, ACL, entry) for a server type.

        Args:
        registry: QuirkRegistry to register quirks with
        server_type: Server type (oid, oud, etc.)

        """
        if server_type == FlextLdifConstants.ServerTypes.OID:
            schema_quirks = registry.get_schema_quirks(server_type)
            if not schema_quirks:
                registry.register_schema_quirk(FlextLdifServersOid.Schema())

            acl_quirks = registry.get_acl_quirks(server_type)
            if not acl_quirks:
                registry.register_acl_quirk(FlextLdifServersOid.Acl())

            entry_quirks = registry.get_entry_quirks(server_type)
            if not entry_quirks:
                registry.register_entry_quirk(FlextLdifServersOid.Entry())

        elif server_type == FlextLdifConstants.ServerTypes.OUD:
            schema_quirks = registry.get_schema_quirks(server_type)
            if not schema_quirks:
                registry.register_schema_quirk(FlextLdifServersOud.Schema())

            acl_quirks = registry.get_acl_quirks(server_type)
            if not acl_quirks:
                registry.register_acl_quirk(FlextLdifServersOud.Acl())

            entry_quirks = registry.get_entry_quirks(server_type)
            if not entry_quirks:
                registry.register_entry_quirk(FlextLdifServersOud.Entry())


class _QuirkIterationChain:
    """Chain for applying quirks to entries with batch processing.

    Consolidates source and target quirk application logic.
    """

    @staticmethod
    def apply_source_quirks(
        entry: dict[str, object],
        quirks: Sequence[FlextLdifServersBase.Entry] | None,
    ) -> FlextResult[dict[str, object]]:
        """Apply source quirks to normalize entry to RFC format.

        Args:
        entry: Entry dictionary to transform
        quirks: List of source quirks to apply

        Returns:
        FlextResult with normalized entry

        """
        normalized = entry.copy()
        if not quirks:
            return FlextResult[dict[str, object]].ok(normalized)

        for quirk in quirks:
            entry_dn = str(normalized.get(FlextLdifConstants.DictKeys.DN, ""))
            entry_attrs = normalized.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
            if not isinstance(entry_attrs, dict):
                entry_attrs = {}

            if (
                hasattr(quirk, "can_handle_entry")
                and quirk.can_handle_entry(entry_dn, entry_attrs)
                and hasattr(quirk, "convert_entry_to_rfc")
            ):
                convert_result = quirk.convert_entry_to_rfc(normalized)
                if convert_result.is_success:
                    normalized = convert_result.unwrap()
                    break

        return FlextResult[dict[str, object]].ok(normalized)

    @staticmethod
    def apply_target_quirks(
        entry: dict[str, object],
        quirks: Sequence[FlextLdifServersBase.Entry] | None,
    ) -> FlextResult[dict[str, object]]:
        """Apply target quirks to transform entry from RFC format.

        Args:
        entry: Entry dictionary to transform
        quirks: List of target quirks to apply

        Returns:
        FlextResult with target-formatted entry

        """
        target_entry = entry.copy()
        if not quirks:
            return FlextResult[dict[str, object]].ok(target_entry)

        for quirk in quirks:
            entry_dn = str(target_entry.get(FlextLdifConstants.DictKeys.DN, ""))
            entry_attrs = target_entry.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
            if not isinstance(entry_attrs, dict):
                entry_attrs = {}

            if hasattr(quirk, "can_handle_entry") and quirk.can_handle_entry(
                entry_dn,
                entry_attrs,
            ):
                # Target quirks transform from RFC to target format
                break

        return FlextResult[dict[str, object]].ok(target_entry)


class _EntryFileProcessing:
    """Processor for entry file iteration and parsing.

    Consolidates entry file processing logic with functional composition.
    """

    def __init__(
        self,
        quirk_registry: FlextLdifRegistry,
        logger_obj: object = None,
    ) -> None:
        """Initialize entry file processor.

        Args:
        quirk_registry: Registry with quirks
        logger_obj: Optional logger instance

        """
        self._quirk_registry = quirk_registry
        self._logger = logger_obj
        super().__init__()

    def process_entry_file(self, entry_file: Path) -> FlextResult[list[object]]:
        """Process single entry file and return entries.

        Args:
        entry_file: Path to entry file

        Returns:
        FlextResult with parsed entries

        """
        try:
            if self._logger and hasattr(self._logger, "info"):
                dk = FlextLdifConstants.DictKeys
                # Type narrowing: _logger has info method after hasattr check
                self._logger.info(
                    f"Processing entry file: {entry_file.name}",
                    extra={dk.SOURCE_SERVER: FlextLdifConstants.ServerTypes.RFC},
                )

            # Use unified FlextLdifParserService for entry parsing
            from flext_ldif.services.parser import FlextLdifParserService

            parser = FlextLdifParserService()
            parse_result = parser.parse(entry_file)

            if parse_result.is_failure:
                return FlextResult[list[object]].fail(
                    f"LDIF parsing failed: {parse_result.error}",
                )

            # Parser returns Entry models directly
            entries = parse_result.unwrap()
            # Convert Entry models to dict objects for compatibility
            entry_dicts = [entry.model_dump() for entry in entries]
            return FlextResult[list[object]].ok(entry_dicts)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[list[object]].fail(f"Entry file processing failed: {e}")

    def _schema_data_to_entries(
        self,
        schema_data: dict[str, object],
    ) -> list[FlextLdifModels.Entry]:
        """Convert schema data dict to Entry objects for writing.

        Args:
            schema_data: Schema data dict from parser

        Returns:
            List of Entry objects representing schema

        """
        entries: list[FlextLdifModels.Entry] = []

        try:
            # Create schema entry with DN = cn=schema
            schema_dn = FlextLdifModels.DistinguishedName("cn=schema")

            # Schema entry contains all schema attributes
            schema_attrs = FlextLdifModels.Attributes({
                "objectClass": ["top", "subschema"],
                "attributeTypes": (
                    schema_data.get("attributes", {})
                    if isinstance(schema_data.get("attributes"), dict)
                    else {}
                ),
                "objectClasses": (
                    schema_data.get("objectClasses", {})
                    if isinstance(schema_data.get("objectClasses"), dict)
                    else {}
                ),
            })

            schema_entry = FlextLdifModels.Entry(dn=schema_dn, attributes=schema_attrs)
            entries.append(schema_entry)

        except Exception as e:
            if self.logger:
                self.logger.warning("Failed to convert schema data to entries: %s", e)

        return entries


class FlextLdifMigrationPipeline(FlextService[FlextLdifModels.MigrationPipelineResult]):
    """Generic LDIF Migration Pipeline Service.

    Provides server-agnostic LDIF migration using RFC-compliant base parsers
    with composable quirks for server-specific features.

    This service enables migrations between any LDAP server types by:
    1. Parsing source LDIF with RFC parsers + source quirks
    2. Converting to RFC-compliant intermediate format via universal conversion matrix
    3. Generating target LDIF with RFC parsers + target quirks
    4. Tracking DN case consistency for OUD compatibility
    5. Providing detailed statistics and error reporting

    Supported migration patterns:
    - OID → OUD (Oracle Internet Directory to Unified Directory)
    - OID → OpenLDAP (1.x and 2.x)
    - OpenLDAP → OUD
    - Any server combination via extensible quirk registration
    - RFC → RFC (pure standards compliance transformations)

    Features:
    - Memory-efficient processing with configurable batch sizes
    - Complete error handling with detailed failure reporting
    - Progress tracking and statistics collection
    - Schema and entry processing with separate pipelines

    Example usage:
        params = {
            FlextLdifConstants.DictKeys.INPUT_DIR: "data/input",
            FlextLdifConstants.DictKeys.OUTPUT_DIR: "data/output",
            FlextLdifConstants.DictKeys.PROCESS_SCHEMA: True,
            FlextLdifConstants.DictKeys.PROCESS_ENTRIES: True,
        }
        pipeline = FlextLdifMigrationPipeline(
            params=params,
            source_server_type=FlextLdifConstants.ServerTypes.OID,
            target_server_type=FlextLdifConstants.ServerTypes.OUD
        )
        result = pipeline.execute()
        if result.is_success:
            stats = result.value[FlextLdifConstants.DictKeys.STATS]
            print(f"Migrated {stats['total_entries']} entries")
    """

    def __init__(
        self,
        *,
        params: dict[str, object],
        source_server_type: str,
        target_server_type: str,
        quirk_registry: FlextLdifRegistry | None = None,
    ) -> None:
        """Initialize generic LDIF migration pipeline.

        Args:
            params: Pipeline parameters (input_dir, output_dir,
                process_schema, process_entries)
            source_server_type: Source server type (e.g., "oid",
                "openldap")
            target_server_type: Target server type (e.g., "oud",
                "openldap")
            quirk_registry: Optional quirk registry (uses global if
                not provided)

        """
        super().__init__()
        self._params = params
        self._source_server_type = source_server_type
        self._target_server_type = target_server_type

        # Use global registry or provided one
        self._quirk_registry = quirk_registry or FlextLdifRegistry()

        # Delegate quirk registration to specialized service
        _QuirkRegistrationService.register_quirks_for_server(
            self._quirk_registry,
            source_server_type,
        )
        _QuirkRegistrationService.register_quirks_for_server(
            self._quirk_registry,
            target_server_type,
        )

        # RFC-First Architecture: Use unified FlextLdifParserService with quirks
        from flext_ldif.services.parser import FlextLdifParserService

        self._parser_service = FlextLdifParserService()
        self._writer_class: type[FlextLdifWriterService] = FlextLdifWriterService
        self._config = FlextLdifConfig()  # Configuration for unified writer

        if self.logger:
            self.logger.info(
                "Using RFC-first parsers with quirks",
                extra={
                    FlextLdifConstants.DictKeys.SOURCE_SERVER: source_server_type,
                    FlextLdifConstants.DictKeys.TARGET_SERVER: target_server_type,
                },
            )
            self.logger.info(
                "Initialized LDIF migration pipeline",
                extra={
                    FlextLdifConstants.DictKeys.SOURCE_SERVER: source_server_type,
                    FlextLdifConstants.DictKeys.TARGET_SERVER: target_server_type,
                },
            )

    @property
    def input_dir(self) -> Path:
        """Get pipeline input directory."""
        input_dir_str = self._params.get("input_dir", "")
        if not isinstance(input_dir_str, str):
            input_dir_str = str(input_dir_str)
        return Path(input_dir_str)

    @property
    def output_dir(self) -> Path:
        """Get pipeline output directory."""
        output_dir_str = self._params.get("output_dir", "")
        if not isinstance(output_dir_str, str):
            output_dir_str = str(output_dir_str)
        return Path(output_dir_str)

    @property
    def source_server_type(self) -> str:
        """Get source server type."""
        return self._source_server_type

    @property
    def target_server_type(self) -> str:
        """Get target server type."""
        return self._target_server_type

    def migrate_entries(
        self,
        *,
        entries: list[object],
        source_format: str,
        target_format: str,
        _quirks: list[str] | None = None,
    ) -> FlextResult[list[object]]:
        """Migrate entries between formats using quirk-based transformation.

        Uses delegated quirk application logic for clean transformation:
        1. Apply source quirks to normalize entries to RFC
        2. Apply target quirks to transform from RFC to target

        Args:
            entries: List of entry dictionaries to migrate
            source_format: Source format (e.g., "oid", "rfc", "oud")
            target_format: Target format (e.g., "oid", "rfc", "oud")
            _quirks: Optional list of quirk names (not used, for compat)

        Returns:
            FlextResult containing migrated entries

        """
        try:
            if not entries:
                return FlextResult[list[object]].ok([])

            if self.logger:
                self.logger.info(
                    "Starting entry migration: %s → %s",
                    source_format,
                    target_format,
                    extra={
                        FlextLdifConstants.DictKeys.TOTAL_ENTRIES: len(entries),
                        FlextLdifConstants.DictKeys.SOURCE_FORMAT: source_format,
                        FlextLdifConstants.DictKeys.TARGET_FORMAT: target_format,
                    },
                )

            # Get source and target quirks from registry
            source_quirks = self._quirk_registry.get_entry_quirks(source_format)
            target_quirks = self._quirk_registry.get_entry_quirks(target_format)

            # Use batch_process for functional entry transformation
            def transform_entry(entry: object) -> FlextResult[object]:
                """Transform single entry through quirk pipeline.

                Args:
                entry: Entry to transform

                Returns:
                FlextResult with transformed entry

                """
                if not isinstance(entry, dict):
                    return FlextResult[object].fail("Entry must be dictionary")

                # Apply source quirks (normalize to RFC)
                source_result = _QuirkIterationChain.apply_source_quirks(
                    entry,
                    source_quirks,
                )
                if source_result.is_failure:
                    return FlextResult[object].fail(source_result.error)

                normalized_entry = source_result.unwrap()

                # Apply target quirks (transform from RFC to target)
                target_result = _QuirkIterationChain.apply_target_quirks(
                    normalized_entry,
                    target_quirks,
                )
                if target_result.is_failure:
                    return FlextResult[object].fail(target_result.error)

                return FlextResult[object].ok(target_result.unwrap())

            # Process all entries with batch_process (non-failing)
            migrated_list, failures = FlextResult.batch_process(
                entries,
                transform_entry,
            )

            if self.logger and failures:
                self.logger.debug(
                    "Entry migration with failures detected",
                    extra={"failed_count": len(failures)},
                )

            if self.logger:
                migrated_count = len(migrated_list)
                self.logger.info(
                    "Migrated %s entries from %s to %s",
                    migrated_count,
                    source_format,
                    target_format,
                    extra={
                        FlextLdifConstants.DictKeys.SOURCE_FORMAT: source_format,
                        FlextLdifConstants.DictKeys.TARGET_FORMAT: target_format,
                        FlextLdifConstants.DictKeys.TOTAL_MIGRATED: migrated_count,
                    },
                )

            return FlextResult[list[object]].ok(migrated_list)

        except (ValueError, TypeError, AttributeError) as e:
            error_msg = f"Entry migration failed: {e}"
            if self.logger:
                self.logger.exception(error_msg)
            return FlextResult[list[object]].fail(error_msg)

    def execute(self) -> FlextResult[FlextLdifModels.MigrationPipelineResult]:
        """Execute generic LDIF migration pipeline.

        Returns:
            FlextResult with MigrationPipelineResult model containing:
            - migrated_schema: Migrated schema data
            - entries: Migrated entry data
            - stats: Migration statistics (MigrationStatistics model)
            - output_files: Generated output file paths

        """
        try:
            # Validate parameters
            input_dir_str = self._params.get(FlextLdifConstants.DictKeys.INPUT_DIR, "")
            if not input_dir_str:
                return FlextResult[FlextLdifModels.MigrationPipelineResult].fail(
                    "input_dir parameter is required",
                )

            output_dir_str = self._params.get(
                FlextLdifConstants.DictKeys.OUTPUT_DIR,
                "",
            )
            if not output_dir_str:
                return FlextResult[FlextLdifModels.MigrationPipelineResult].fail(
                    "output_dir parameter is required",
                )

            # Type narrow directory paths
            if not isinstance(input_dir_str, str):
                return FlextResult[FlextLdifModels.MigrationPipelineResult].fail(
                    f"input_dir must be string, got {type(input_dir_str).__name__}",
                )
            if not isinstance(output_dir_str, str):
                return FlextResult[FlextLdifModels.MigrationPipelineResult].fail(
                    f"output_dir must be string, got {type(output_dir_str).__name__}",
                )

            input_dir = Path(input_dir_str)
            output_dir = Path(output_dir_str)

            if not input_dir.exists():
                return FlextResult[FlextLdifModels.MigrationPipelineResult].fail(
                    f"Input directory not found: {input_dir}",
                )

            # Create output directory
            output_dir.mkdir(parents=True, exist_ok=True)

            process_schema = self._params.get(
                FlextLdifConstants.DictKeys.PROCESS_SCHEMA,
                True,
            )
            process_entries = self._params.get(
                FlextLdifConstants.DictKeys.PROCESS_ENTRIES,
                True,
            )

            if self.logger:
                dk = FlextLdifConstants.DictKeys
                self.logger.info(
                    "Starting generic LDIF migration",
                    extra={
                        dk.INPUT_DIR: str(input_dir),
                        dk.OUTPUT_DIR: str(output_dir),
                        dk.SOURCE_SERVER: self._source_server_type,
                        dk.TARGET_SERVER: self._target_server_type,
                        dk.PROCESS_SCHEMA: process_schema,
                        dk.PROCESS_ENTRIES: process_entries,
                    },
                )

            # Initialize result data - use Pydantic models internally
            migrated_schema: dict[str, object] = {}
            migrated_entries: list[object] = []
            output_files_list: list[str] = []

            # Track statistics during migration
            stats_counts = {
                FlextLdifConstants.DictKeys.TOTAL_SCHEMA_ATTRIBUTES: 0,
                FlextLdifConstants.DictKeys.TOTAL_SCHEMA_OBJECTCLASSES: 0,
                FlextLdifConstants.DictKeys.TOTAL_ENTRIES: 0,
            }

            # Phase 1: Process schema if requested
            if process_schema:
                schema_result = self._process_schema_migration(input_dir, output_dir)
                if schema_result.is_failure:
                    return FlextResult[FlextLdifModels.MigrationPipelineResult].fail(
                        f"Schema migration failed: {schema_result.error}",
                    )

                schema_data = schema_result.unwrap()
                migrated_schema = schema_data

                # Update statistics
                attributes = schema_data.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
                objectclasses = schema_data.get(
                    FlextLdifConstants.DictKeys.OBJECTCLASSES,
                    {},
                )
                if isinstance(attributes, dict):
                    stats_counts[
                        FlextLdifConstants.DictKeys.TOTAL_SCHEMA_ATTRIBUTES
                    ] = len(attributes)
                if isinstance(objectclasses, dict):
                    stats_counts[
                        FlextLdifConstants.DictKeys.TOTAL_SCHEMA_OBJECTCLASSES
                    ] = len(objectclasses)

            # Phase 2: Process entries if requested
            if process_entries:
                entries_result = self._process_entries_migration(input_dir, output_dir)
                if entries_result.is_failure:
                    return FlextResult[FlextLdifModels.MigrationPipelineResult].fail(
                        f"Entries migration failed: {entries_result.error}",
                    )

                entries_data = entries_result.unwrap()
                migrated_entries = entries_data

                # Update statistics
                stats_counts[FlextLdifConstants.DictKeys.TOTAL_ENTRIES] = len(
                    entries_data,
                )

            # Create statistics model with computed fields
            migration_stats = FlextLdifModels.MigrationStatistics(
                total_schema_attributes=stats_counts[
                    FlextLdifConstants.DictKeys.TOTAL_SCHEMA_ATTRIBUTES
                ],
                total_schema_objectclasses=stats_counts[
                    FlextLdifConstants.DictKeys.TOTAL_SCHEMA_OBJECTCLASSES
                ],
                total_entries=stats_counts[FlextLdifConstants.DictKeys.TOTAL_ENTRIES],
            )

            # Create complete migration result model
            migration_result = FlextLdifModels.MigrationPipelineResult(
                migrated_schema=migrated_schema,
                entries=migrated_entries,
                stats=migration_stats,
                output_files=output_files_list,
            )

            # Log completion with computed fields
            if self.logger:
                dk = FlextLdifConstants.DictKeys
                self.logger.info(
                    "LDIF migration completed successfully",
                    extra={
                        dk.SOURCE_SERVER: self._source_server_type,
                        dk.TARGET_SERVER: self._target_server_type,
                        "total_items": migration_stats.total_items,
                        "success_rate": migration_stats.success_rate,
                    },
                )

            # Return model directly wrapped in FlextResult
            return FlextResult[FlextLdifModels.MigrationPipelineResult].ok(
                migration_result,
            )

        except (ValueError, TypeError, AttributeError) as e:
            error_msg = f"LDIF migration pipeline failed: {e}"
            if self.logger:
                self.logger.exception(error_msg)
            return FlextResult[FlextLdifModels.MigrationPipelineResult].fail(error_msg)

    def _process_schema_migration(
        self,
        input_dir: Path,
        output_dir: Path,
    ) -> FlextResult[dict[str, object]]:
        """Process schema migration using RFC parsers with quirks.

        Args:
        input_dir: Input directory containing schema files
        output_dir: Output directory for migrated schema

        Returns:
        FlextResult with migrated schema data

        """
        try:
            # Find schema files in input directory
            schema_files = list(input_dir.glob("*schema*.ldif"))
            if not schema_files:
                if self.logger:
                    self.logger.debug("No schema files found in input directory")
                return FlextResult[dict[str, object]].ok({
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                    FlextLdifConstants.DictKeys.OBJECTCLASSES: {},
                })

            # Use the first schema file found
            schema_file = schema_files[0]

            if self.logger:
                dk = FlextLdifConstants.DictKeys
                self.logger.info(
                    f"Processing schema file: {schema_file.name}",
                    extra={dk.SOURCE_SERVER: self._source_server_type},
                )

            # Parse schema using unified FlextLdifParserService
            parse_result = self._parser_service.parse_schema_ldif(
                schema_file,
                parse_attributes=True,
                parse_objectclasses=True,
            )

            if parse_result.is_failure:
                return FlextResult[dict[str, object]].fail(
                    f"Schema parsing failed: {parse_result.error}",
                )

            schema_data = parse_result.unwrap()

            # Convert schema data to Entry objects for unified writer
            schema_entries = self._schema_data_to_entries(schema_data)

            # Write migrated schema to output directory using unified writer
            output_schema_file = (
                output_dir / f"migrated_schema_{self._target_server_type}.ldif"
            )

            writer = self._writer_class(
                config=self._config,
                quirk_registry=self._quirk_registry,
                target_server_type=self._target_server_type,
            )

            # Write schema entries using unified writer
            write_result = writer.write_to_file(
                entries=schema_entries,
                output_path=output_schema_file,
            )
            if write_result.is_failure:
                return FlextResult[dict[str, object]].fail(
                    f"Schema writing failed: {write_result.error}",
                )

            if self.logger:
                # Type narrow schema data
                attributes_raw: object = schema_data.get(
                    FlextLdifConstants.DictKeys.ATTRIBUTES,
                    {},
                )
                attributes: dict[str, object] = (
                    attributes_raw if isinstance(attributes_raw, dict) else {}
                )

                objectclasses_raw: object = schema_data.get(
                    FlextLdifConstants.DictKeys.OBJECTCLASSES,
                    {},
                )
                objectclasses: dict[str, object] = (
                    objectclasses_raw if isinstance(objectclasses_raw, dict) else {}
                )

                self.logger.info(
                    "Schema migration completed",
                    extra={
                        FlextLdifConstants.DictKeys.ATTRIBUTES_COUNT: len(attributes),
                        FlextLdifConstants.DictKeys.OBJECTCLASSES_COUNT: len(
                            objectclasses,
                        ),
                        FlextLdifConstants.DictKeys.OUTPUT_FILE: str(
                            output_schema_file,
                        ),
                    },
                )

            return FlextResult[dict[str, object]].ok(schema_data)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[dict[str, object]].fail(f"Schema migration failed: {e}")

    def _process_entries_migration(
        self,
        input_dir: Path,
        output_dir: Path,
    ) -> FlextResult[list[object]]:
        """Process entries migration using RFC parsers with quirks.

        Uses batch_process for functional file processing with consolidated
        entry file handling via _EntryFileProcessing.

        Args:
        input_dir: Input directory containing entry files
        output_dir: Output directory for migrated entries

        Returns:
        FlextResult with migrated entries

        """
        try:
            # Find entry files (exclude schema and ACI files)
            entry_files = [
                f
                for f in input_dir.glob("*.ldif")
                if "schema" not in f.name.lower() and "aci" not in f.name.lower()
            ]

            if not entry_files:
                if self.logger:
                    self.logger.debug("No entry files found in input directory")
                return FlextResult[list[object]].ok([])

            # Create file processor with consolidated logic
            file_processor = _EntryFileProcessing(
                self._quirk_registry,
                self.logger,
            )

            # Use batch_process to consolidate file processing loop
            def process_file(f: Path) -> FlextResult[list[object]]:
                """Process single entry file."""
                return file_processor.process_entry_file(f)

            file_results, file_failures = FlextResult.batch_process(
                entry_files,
                process_file,
            )

            # Log file processing failures
            if self.logger and file_failures:
                self.logger.debug(
                    f"Entry file processing: {len(file_failures)} files failed",
                )

            # Flatten all successfully processed entries
            all_entries: list[object] = []
            for file_entries in file_results:
                if isinstance(file_entries, list):
                    all_entries.extend(file_entries)

            # Write migrated entries to output using unified writer
            output_entries_file = (
                output_dir / f"migrated_entries_{self._target_server_type}.ldif"
            )

            writer = self._writer_class(
                config=self._config,
                quirk_registry=self._quirk_registry,
                target_server_type=self._target_server_type,
            )

            # Entries writing using unified writer interface
            write_result = writer.write_to_file(
                entries=all_entries,
                output_path=output_entries_file,
            )
            if write_result.is_failure:
                return FlextResult[list[object]].fail(
                    f"Entries writing failed: {write_result.error}",
                )

            if self.logger:
                self.logger.info(
                    "Entries migration completed",
                    extra={
                        FlextLdifConstants.DictKeys.TOTAL_ENTRIES: len(all_entries),
                        FlextLdifConstants.DictKeys.OUTPUT_FILE: str(
                            output_entries_file,
                        ),
                    },
                )

            return FlextResult[list[object]].ok(all_entries)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[list[object]].fail(f"Entries migration failed: {e}")


__all__ = ["FlextLdifMigrationPipeline"]
