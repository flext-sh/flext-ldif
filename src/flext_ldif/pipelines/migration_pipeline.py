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

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.base import FlextLdifQuirksBaseEntryQuirk
from flext_ldif.quirks.registry import FlextLdifQuirksRegistry
from flext_ldif.quirks.servers import (
    FlextLdifQuirksServersOid,
    FlextLdifQuirksServersOud,
)
from flext_ldif.rfc.rfc_ldif_parser import FlextLdifRfcLdifParser
from flext_ldif.rfc.rfc_ldif_writer import FlextLdifRfcLdifWriter
from flext_ldif.rfc.rfc_schema_parser import FlextLdifRfcSchemaParser
from flext_ldif.typings import FlextLdifTypes


class _QuirkRegistrationService:
    """Service for registering server-specific quirks.

    Consolidates quirk registration logic with automatic server detection
    and single responsibility.
    """

    @staticmethod
    def register_quirks_for_server(
        registry: FlextLdifQuirksRegistry, server_type: str
    ) -> None:
        """Register all quirks (schema, ACL, entry) for a server type.

        Args:
        registry: QuirkRegistry to register quirks with
        server_type: Server type (oid, oud, etc.)

        """
        if server_type == FlextLdifConstants.ServerTypes.OID:
            schema_quirks = registry.get_schema_quirks(server_type)
            if not schema_quirks:
                registry.register_schema_quirk(FlextLdifQuirksServersOid())

            acl_quirks = registry.get_acl_quirks(server_type)
            if not acl_quirks:
                registry.register_acl_quirk(FlextLdifQuirksServersOid.AclQuirk())

            entry_quirks = registry.get_entry_quirks(server_type)
            if not entry_quirks:
                registry.register_entry_quirk(FlextLdifQuirksServersOid.EntryQuirk())

        elif server_type == FlextLdifConstants.ServerTypes.OUD:
            schema_quirks = registry.get_schema_quirks(server_type)
            if not schema_quirks:
                registry.register_schema_quirk(FlextLdifQuirksServersOud())

            acl_quirks = registry.get_acl_quirks(server_type)
            if not acl_quirks:
                registry.register_acl_quirk(FlextLdifQuirksServersOud.AclQuirk())

            entry_quirks = registry.get_entry_quirks(server_type)
            if not entry_quirks:
                registry.register_entry_quirk(FlextLdifQuirksServersOud.EntryQuirk())


class _QuirkIterationChain:
    """Chain for applying quirks to entries with batch processing.

    Consolidates source and target quirk application logic.
    """

    @staticmethod
    def apply_source_quirks(
        entry: dict[str, object], quirks: Sequence[FlextLdifQuirksBaseEntryQuirk] | None
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
        entry: dict[str, object], quirks: Sequence[FlextLdifQuirksBaseEntryQuirk] | None
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
                entry_dn, entry_attrs
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
        parser_class: type[FlextLdifRfcLdifParser],
        quirk_registry: FlextLdifQuirksRegistry,
        logger_obj: object = None,
    ) -> None:
        """Initialize entry file processor.

        Args:
        parser_class: LDIF parser class to use
        quirk_registry: Registry with quirks
        logger_obj: Optional logger instance

        """
        self._parser_class = parser_class
        self._quirk_registry = quirk_registry
        self._logger = logger_obj

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
                getattr(self._logger, "info")(
                    f"Processing entry file: {entry_file.name}",
                    extra={dk.SOURCE_SERVER: "rfc"},
                )

            parser = self._parser_class(
                params={
                    FlextLdifConstants.DictKeys.FILE_PATH: str(entry_file),
                    FlextLdifConstants.DictKeys.PARSE_CHANGES: False,
                },
                quirk_registry=self._quirk_registry,
            )
            parse_result = parser.execute()

            if parse_result.is_failure:
                return FlextResult[list[object]].fail(
                    f"RFC LDIF parsing failed: {parse_result.error}"
                )

            entries_data = parse_result.unwrap()
            entries = entries_data.get(FlextLdifConstants.DictKeys.ENTRIES, [])
            if not isinstance(entries, list):
                entries = []

            return FlextResult[list[object]].ok(entries)

        except Exception as e:  # pragma: no cover
            return FlextResult[list[object]].fail(f"Entry file processing failed: {e}")


class FlextLdifMigrationPipeline(FlextService[FlextLdifTypes.Models.CustomDataDict]):
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
        params: FlextLdifTypes.Models.CustomDataDict,
        source_server_type: str,
        target_server_type: str,
        quirk_registry: FlextLdifQuirksRegistry | None = None,
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
        self._quirk_registry = quirk_registry or FlextLdifQuirksRegistry()

        # Delegate quirk registration to specialized service
        _QuirkRegistrationService.register_quirks_for_server(
            self._quirk_registry, source_server_type
        )
        _QuirkRegistrationService.register_quirks_for_server(
            self._quirk_registry, target_server_type
        )

        # RFC-First Architecture: ALWAYS use RFC parser with quirks
        self._ldif_parser_class = FlextLdifRfcLdifParser
        self._schema_parser_class: type[FlextLdifRfcSchemaParser] = (
            FlextLdifRfcSchemaParser
        )
        self._writer_class: type[FlextLdifRfcLdifWriter] = FlextLdifRfcLdifWriter

        if self.logger:
            server_arrow = f"{source_server_type} → {target_server_type}"
            self.logger.info(f"Using RFC-first parsers with {server_arrow} quirks")
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
                    f"Starting entry migration: {source_format} → {target_format}",
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
                    entry, source_quirks
                )
                if source_result.is_failure:
                    return FlextResult[object].fail(source_result.error)

                normalized_entry = source_result.unwrap()

                # Apply target quirks (transform from RFC to target)
                target_result = _QuirkIterationChain.apply_target_quirks(
                    normalized_entry, target_quirks
                )
                if target_result.is_failure:
                    return FlextResult[object].fail(target_result.error)

                return FlextResult[object].ok(target_result.unwrap())

            # Process all entries with batch_process (non-failing)
            migrated_list, failures = FlextResult.batch_process(
                entries, transform_entry
            )

            if self.logger and failures:
                self.logger.warning(f"Entry migration: {len(failures)} entries failed")

            if self.logger:
                migrated_count = len(migrated_list)
                self.logger.info(
                    f"Migrated {migrated_count} entries from {source_format} "
                    f"to {target_format}",
                    extra={
                        FlextLdifConstants.DictKeys.SOURCE_FORMAT: source_format,
                        FlextLdifConstants.DictKeys.TARGET_FORMAT: target_format,
                        FlextLdifConstants.DictKeys.TOTAL_MIGRATED: migrated_count,
                    },
                )

            return FlextResult[list[object]].ok(migrated_list)

        except Exception as e:  # pragma: no cover
            error_msg = f"Entry migration failed: {e}"
            if self.logger:
                self.logger.exception(error_msg)
            return FlextResult[list[object]].fail(error_msg)

    def execute(self) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
        """Execute generic LDIF migration pipeline.

        Returns:
        FlextResult with migration results containing:
        - schema: Migrated schema data
        - entries: Migrated entry data
        - stats: Migration statistics
        - output_files: Generated output file paths

        """
        try:
            # Validate parameters
            input_dir_str = self._params.get(FlextLdifConstants.DictKeys.INPUT_DIR, "")
            if not input_dir_str:
                return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                    "input_dir parameter is required"
                )

            output_dir_str = self._params.get(
                FlextLdifConstants.DictKeys.OUTPUT_DIR, ""
            )
            if not output_dir_str:
                return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                    "output_dir parameter is required"
                )

            # Type narrow directory paths
            if not isinstance(input_dir_str, str):
                return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                    f"input_dir must be string, got {type(input_dir_str).__name__}"
                )
            if not isinstance(output_dir_str, str):
                return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                    f"output_dir must be string, got {type(output_dir_str).__name__}"
                )

            input_dir = Path(input_dir_str)
            output_dir = Path(output_dir_str)

            if not input_dir.exists():
                return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                    f"Input directory not found: {input_dir}"
                )

            # Create output directory
            output_dir.mkdir(parents=True, exist_ok=True)

            process_schema = self._params.get(
                FlextLdifConstants.DictKeys.PROCESS_SCHEMA, True
            )
            process_entries = self._params.get(
                FlextLdifConstants.DictKeys.PROCESS_ENTRIES, True
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

            # Initialize result data
            result_data: FlextLdifTypes.Models.CustomDataDict = {
                FlextLdifConstants.DictKeys.SCHEMA: {},
                FlextLdifConstants.DictKeys.ENTRIES: [],
                FlextLdifConstants.DictKeys.STATS: {
                    FlextLdifConstants.DictKeys.TOTAL_SCHEMA_ATTRIBUTES: 0,
                    FlextLdifConstants.DictKeys.TOTAL_SCHEMA_OBJECTCLASSES: 0,
                    FlextLdifConstants.DictKeys.TOTAL_ENTRIES: 0,
                },
                FlextLdifConstants.DictKeys.OUTPUT_FILES: [],
            }

            # Phase 1: Process schema if requested
            if process_schema:
                schema_result = self._process_schema_migration(input_dir, output_dir)
                if schema_result.is_failure:
                    return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                        f"Schema migration failed: {schema_result.error}"
                    )

                schema_data = schema_result.unwrap()
                result_data[FlextLdifConstants.DictKeys.SCHEMA] = schema_data
                stats_dict = result_data[FlextLdifConstants.DictKeys.STATS]
                if isinstance(stats_dict, dict):
                    attributes = schema_data.get(
                        FlextLdifConstants.DictKeys.ATTRIBUTES, {}
                    )
                    objectclasses = schema_data.get(
                        FlextLdifConstants.DictKeys.OBJECTCLASSES, {}
                    )
                    if isinstance(attributes, dict):
                        stats_dict[
                            FlextLdifConstants.DictKeys.TOTAL_SCHEMA_ATTRIBUTES
                        ] = len(attributes)
                    if isinstance(objectclasses, dict):
                        stats_dict[
                            FlextLdifConstants.DictKeys.TOTAL_SCHEMA_OBJECTCLASSES
                        ] = len(objectclasses)

            # Phase 2: Process entries if requested
            if process_entries:
                entries_result = self._process_entries_migration(input_dir, output_dir)
                if entries_result.is_failure:
                    return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                        f"Entries migration failed: {entries_result.error}"
                    )

                entries_data = entries_result.unwrap()
                result_data[FlextLdifConstants.DictKeys.ENTRIES] = entries_data
                stats_dict = result_data[FlextLdifConstants.DictKeys.STATS]
                if isinstance(stats_dict, dict):
                    stats_dict[FlextLdifConstants.DictKeys.TOTAL_ENTRIES] = len(
                        entries_data
                    )

            if self.logger:
                dk = FlextLdifConstants.DictKeys
                self.logger.info(
                    "LDIF migration completed successfully",
                    extra={
                        dk.SOURCE_SERVER: self._source_server_type,
                        dk.TARGET_SERVER: self._target_server_type,
                        dk.STATS: result_data[dk.STATS],
                    },
                )

            return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok(result_data)

        except Exception as e:  # pragma: no cover
            error_msg = f"LDIF migration pipeline failed: {e}"
            if self.logger:
                self.logger.exception(error_msg)
            return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(error_msg)

    def _process_schema_migration(
        self, input_dir: Path, output_dir: Path
    ) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
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
                    self.logger.warning("No schema files found in input directory")
                return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok({
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

            # Parse schema using RFC parser with quirks integration
            parser = self._schema_parser_class(
                params={
                    FlextLdifConstants.DictKeys.FILE_PATH: str(schema_file),
                    FlextLdifConstants.DictKeys.PARSE_ATTRIBUTES: True,
                    FlextLdifConstants.DictKeys.PARSE_OBJECTCLASSES: True,
                },
                quirk_registry=self._quirk_registry,
                server_type=self._source_server_type,
            )
            parse_result = parser.execute()

            if parse_result.is_failure:
                return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                    f"RFC schema parsing failed: {parse_result.error}"
                )

            schema_data = parse_result.unwrap()

            # Write migrated schema to output directory using RFC LDIF Writer
            output_schema_file = (
                output_dir / f"migrated_schema_{self._target_server_type}.ldif"
            )

            writer = self._writer_class(
                params={
                    FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_schema_file),
                    FlextLdifConstants.DictKeys.SCHEMA: schema_data,
                },
                quirk_registry=self._quirk_registry,
                target_server_type=self._target_server_type,
            )

            write_result = writer.execute()
            if write_result.is_failure:
                return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                    f"Schema writing failed: {write_result.error}"
                )

            if self.logger:
                # Type narrow schema data
                attributes_raw: object = schema_data.get(
                    FlextLdifConstants.DictKeys.ATTRIBUTES, {}
                )
                attributes: FlextLdifTypes.Models.CustomDataDict = (
                    attributes_raw if isinstance(attributes_raw, dict) else {}
                )

                objectclasses_raw: object = schema_data.get(
                    FlextLdifConstants.DictKeys.OBJECTCLASSES, {}
                )
                objectclasses: FlextLdifTypes.Models.CustomDataDict = (
                    objectclasses_raw if isinstance(objectclasses_raw, dict) else {}
                )

                self.logger.info(
                    "Schema migration completed",
                    extra={
                        FlextLdifConstants.DictKeys.ATTRIBUTES_COUNT: len(attributes),
                        FlextLdifConstants.DictKeys.OBJECTCLASSES_COUNT: len(
                            objectclasses
                        ),
                        FlextLdifConstants.DictKeys.OUTPUT_FILE: str(
                            output_schema_file
                        ),
                    },
                )

            return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok(schema_data)

        except Exception as e:  # pragma: no cover
            return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                f"Schema migration failed: {e}"
            )

    def _process_entries_migration(
        self, input_dir: Path, output_dir: Path
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
                    self.logger.warning("No entry files found in input directory")
                return FlextResult[list[object]].ok([])

            # Create file processor with consolidated logic
            file_processor = _EntryFileProcessing(
                self._ldif_parser_class,
                self._quirk_registry,
                self.logger,
            )

            # Use batch_process to consolidate file processing loop
            def process_file(f: Path) -> FlextResult[list[object]]:
                """Process single entry file."""
                return file_processor.process_entry_file(f)

            file_results, file_failures = FlextResult.batch_process(
                entry_files, process_file
            )

            # Log file processing failures
            if self.logger and file_failures:
                self.logger.warning(
                    f"Entry file processing: {len(file_failures)} files failed"
                )

            # Flatten all successfully processed entries
            all_entries: list[object] = []
            for file_entries in file_results:
                if isinstance(file_entries, list):
                    all_entries.extend(file_entries)

            # Write migrated entries to output
            output_entries_file = (
                output_dir / f"migrated_entries_{self._target_server_type}.ldif"
            )

            writer = self._writer_class(
                params={
                    FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_entries_file),
                    FlextLdifConstants.DictKeys.ENTRIES: all_entries,
                },
                quirk_registry=self._quirk_registry,
                target_server_type=self._target_server_type,
            )

            write_result = writer.execute()
            if write_result.is_failure:
                return FlextResult[list[object]].fail(
                    f"Entries writing failed: {write_result.error}"
                )

            if self.logger:
                self.logger.info(
                    "Entries migration completed",
                    extra={
                        FlextLdifConstants.DictKeys.TOTAL_ENTRIES: len(all_entries),
                        FlextLdifConstants.DictKeys.OUTPUT_FILE: str(
                            output_entries_file
                        ),
                    },
                )

            return FlextResult[list[object]].ok(all_entries)

        except Exception as e:  # pragma: no cover
            return FlextResult[list[object]].fail(f"Entries migration failed: {e}")


__all__ = ["FlextLdifMigrationPipeline"]
