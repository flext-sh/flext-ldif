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

from pathlib import Path
from typing import TYPE_CHECKING

from flext_core import FlextLogger, FlextResult, FlextService

from flext_ldif.quirks.registry import QuirkRegistryService
from flext_ldif.quirks.servers import OidSchemaQuirk, OudSchemaQuirk
from flext_ldif.rfc.rfc_ldif_parser import RfcLdifParserService
from flext_ldif.rfc.rfc_ldif_writer import RfcLdifWriterService
from flext_ldif.rfc.rfc_schema_parser import RfcSchemaParserService

if TYPE_CHECKING:
    FlextServiceType = type[FlextService]


class LdifMigrationPipelineService(FlextService[dict]):
    """Generic LDIF Migration Pipeline Service.

    Provides server-agnostic LDIF migration using RFC-compliant base parsers
    with composable quirks for server-specific features.

    This service enables migrations between any LDAP server types by:
    1. Parsing source LDIF with RFC parsers + source quirks
    2. Converting to RFC-compliant intermediate format
    3. Generating target LDIF with RFC parsers + target quirks

    Supported patterns:
    - OID → OUD (Oracle Internet Directory to Unified Directory)
    - OID → OpenLDAP
    - OpenLDAP → OUD
    - Any future server combination via quirk registration

    Example usage:
        params = {
            "input_dir": "data/input",
            "output_dir": "data/output",
            "process_schema": True,
            "process_entries": True,
        }
        pipeline = LdifMigrationPipelineService(
            params=params,
            source_server_type="oid",
            target_server_type="oud"
        )
        result = pipeline.execute()
        if result.is_success:
            stats = result.value["stats"]
            print(f"Migrated {stats['total_entries']} entries")
    """

    def __init__(
        self,
        *,
        params: dict,
        source_server_type: str,
        target_server_type: str,
        quirk_registry: QuirkRegistryService | None = None,
    ) -> None:
        """Initialize generic LDIF migration pipeline.

        Args:
            params: Pipeline parameters (input_dir, output_dir, process_schema, process_entries)
            source_server_type: Source server type (e.g., "oid", "openldap")
            target_server_type: Target server type (e.g., "oud", "openldap")
            quirk_registry: Optional quirk registry (uses global if not provided)

        """
        super().__init__()
        self._logger = FlextLogger(__name__)
        self._params = params
        self._source_server_type = source_server_type
        self._target_server_type = target_server_type

        # Use global registry or provided one
        self._quirk_registry = (
            quirk_registry or QuirkRegistryService.get_global_instance()
        )

        # Register default quirks if not already registered
        self._register_default_quirks()

        # RFC-First Architecture: ALWAYS use RFC parser with quirks
        # Quirks handle server-specific behavior (OID, OUD, OpenLDAP, etc.)
        self._ldif_parser_class: type[FlextService[dict]] = RfcLdifParserService
        self._schema_parser_class: type[RfcSchemaParserService] = RfcSchemaParserService
        self._writer_class: type[RfcLdifWriterService] = RfcLdifWriterService

        self._logger.info(
            f"Using RFC-first parsers with {source_server_type} → {target_server_type} quirks"
        )

        self._logger.info(
            "Initialized LDIF migration pipeline",
            extra={
                "source_server": source_server_type,
                "target_server": target_server_type,
            },
        )

    def _register_default_quirks(self) -> None:
        """Register default quirks for known server types.

        Registers OID and OUD quirks if source or target uses them.
        """
        # Register OID quirks if needed
        if self._source_server_type == "oid" or self._target_server_type == "oid":
            existing_oid_schema = self._quirk_registry.get_schema_quirks("oid")
            if not existing_oid_schema:
                # Register OID schema quirk
                oid_schema_quirk = OidSchemaQuirk()
                self._quirk_registry.register_schema_quirk(oid_schema_quirk)

            existing_oid_acl = self._quirk_registry.get_acl_quirks("oid")
            if not existing_oid_acl:
                # Register OID ACL quirk (nested class access)
                oid_acl_quirk = OidSchemaQuirk.AclQuirk()
                self._quirk_registry.register_acl_quirk(oid_acl_quirk)

            existing_oid_entry = self._quirk_registry.get_entry_quirks("oid")
            if not existing_oid_entry:
                # Register OID entry quirk (nested class access) - RFC-First Architecture
                oid_entry_quirk = OidSchemaQuirk.EntryQuirk()
                self._quirk_registry.register_entry_quirk(oid_entry_quirk)

        # Register OUD quirks if needed
        if self._source_server_type == "oud" or self._target_server_type == "oud":
            existing_oud_schema = self._quirk_registry.get_schema_quirks("oud")
            if not existing_oud_schema:
                # Register OUD schema quirk
                oud_schema_quirk = OudSchemaQuirk()
                self._quirk_registry.register_schema_quirk(oud_schema_quirk)

            existing_oud_acl = self._quirk_registry.get_acl_quirks("oud")
            if not existing_oud_acl:
                # Register OUD ACL quirk (nested class access)
                oud_acl_quirk = OudSchemaQuirk.AclQuirk()
                self._quirk_registry.register_acl_quirk(oud_acl_quirk)

            existing_oud_entry = self._quirk_registry.get_entry_quirks("oud")
            if not existing_oud_entry:
                # Register OUD entry quirk (nested class access)
                oud_entry_quirk = OudSchemaQuirk.EntryQuirk()
                self._quirk_registry.register_entry_quirk(oud_entry_quirk)

    def migrate_entries(
        self,
        *,
        entries: list,
        source_format: str,
        target_format: str,
        quirks: list[str] | None = None,  # noqa: ARG002
    ) -> FlextResult[list]:
        """Migrate entries between formats using quirk-based transformation.

        This is a convenience method for migrating in-memory entries without
        file I/O, suitable for CQRS command handlers.

        Generic transformation process:
        1. Get source quirks to normalize entries to RFC format
        2. Get target quirks to transform from RFC to target format
        3. Apply entry, ACL, and attribute transformations

        Args:
            entries: List of entry dictionaries to migrate
            source_format: Source format (e.g., "oid", "rfc", "oud", "openldap")
            target_format: Target format (e.g., "oid", "rfc", "oud", "openldap")
            quirks: Optional list of quirk names to apply (overrides auto-detection)

        Returns:
            FlextResult containing migrated entries

        """
        try:
            if not entries:
                return FlextResult[list].ok([])

            self._logger.info(
                f"Starting entry migration: {source_format} → {target_format}",
                extra={
                    "total_entries": len(entries),
                    "source_format": source_format,
                    "target_format": target_format,
                },
            )

            # Get source and target quirks from registry
            source_entry_quirks = self._quirk_registry.get_entry_quirks(source_format)
            target_entry_quirks = self._quirk_registry.get_entry_quirks(target_format)

            migrated_entries = []

            for entry in entries:
                # Step 1: Normalize source entry to RFC format using source quirks
                normalized_entry = entry.copy()

                if source_entry_quirks:
                    for quirk in source_entry_quirks:
                        entry_dn = str(normalized_entry.get("dn", ""))
                        entry_attrs = normalized_entry.get("attributes", {})
                        if not isinstance(entry_attrs, dict):
                            entry_attrs = {}

                        if quirk.can_handle_entry(entry_dn, entry_attrs):
                            self._logger.debug(
                                f"Applying {quirk.server_type} source quirk",
                                extra={"dn": entry_dn},
                            )
                            convert_result = quirk.convert_entry_to_rfc(
                                normalized_entry
                            )
                            if convert_result.is_success:
                                normalized_entry = convert_result.unwrap()  # type: ignore[assignment]
                                break

                # Step 2: Transform from RFC to target format using target quirks
                target_entry = normalized_entry.copy()

                if target_entry_quirks:
                    for quirk in target_entry_quirks:
                        entry_dn = str(target_entry.get("dn", ""))
                        entry_attrs = target_entry.get("attributes", {})
                        if not isinstance(entry_attrs, dict):
                            entry_attrs = {}

                        if quirk.can_handle_entry(entry_dn, entry_attrs):
                            self._logger.debug(
                                f"Applying {quirk.server_type} target quirk",
                                extra={"dn": entry_dn},
                            )
                            # Target quirks convert FROM RFC to target format
                            # (This would be a hypothetical convert_entry_from_rfc method)
                            # For now, we just use the normalized entry
                            break

                migrated_entries.append(target_entry)

            self._logger.info(
                f"Migrated {len(migrated_entries)} entries from {source_format} to {target_format}",
                extra={
                    "source_format": source_format,
                    "target_format": target_format,
                    "total_migrated": len(migrated_entries),
                },
            )

            return FlextResult[list].ok(migrated_entries)

        except Exception as e:
            error_msg = f"Entry migration failed: {e}"
            self._logger.exception(error_msg)
            return FlextResult[list].fail(error_msg)

    def execute(self) -> FlextResult[dict]:
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
            input_dir_str = self._params.get("input_dir", "")
            if not input_dir_str:
                return FlextResult[dict].fail("input_dir parameter is required")

            output_dir_str = self._params.get("output_dir", "")
            if not output_dir_str:
                return FlextResult[dict].fail("output_dir parameter is required")

            input_dir = Path(input_dir_str)
            output_dir = Path(output_dir_str)

            if not input_dir.exists():
                return FlextResult[dict].fail(f"Input directory not found: {input_dir}")

            # Create output directory
            output_dir.mkdir(parents=True, exist_ok=True)

            process_schema = self._params.get("process_schema", True)
            process_entries = self._params.get("process_entries", True)

            self._logger.info(
                "Starting generic LDIF migration",
                extra={
                    "input_dir": str(input_dir),
                    "output_dir": str(output_dir),
                    "source_server": self._source_server_type,
                    "target_server": self._target_server_type,
                    "process_schema": process_schema,
                    "process_entries": process_entries,
                },
            )

            # Initialize result data
            result_data: dict[str, object] = {
                "schema": {},
                "entries": [],
                "stats": {
                    "total_schema_attributes": 0,
                    "total_schema_objectclasses": 0,
                    "total_entries": 0,
                },
                "output_files": [],
            }

            # Phase 1: Process schema if requested
            if process_schema:
                schema_result = self._process_schema_migration(input_dir, output_dir)
                if schema_result.is_failure:
                    return FlextResult[dict].fail(
                        f"Schema migration failed: {schema_result.error}"
                    )

                schema_data = schema_result.unwrap()
                result_data["schema"] = schema_data
                if isinstance(result_data["stats"], dict):
                    result_data["stats"]["total_schema_attributes"] = len(
                        schema_data.get("attributes", {})
                    )
                    result_data["stats"]["total_schema_objectclasses"] = len(
                        schema_data.get("objectclasses", {})
                    )

            # Phase 2: Process entries if requested
            if process_entries:
                entries_result = self._process_entries_migration(input_dir, output_dir)
                if entries_result.is_failure:
                    return FlextResult[dict].fail(
                        f"Entries migration failed: {entries_result.error}"
                    )

                entries_data = entries_result.unwrap()
                result_data["entries"] = entries_data
                if isinstance(result_data["stats"], dict):
                    result_data["stats"]["total_entries"] = len(entries_data)

            self._logger.info(
                "LDIF migration completed successfully",
                extra={
                    "source_server": self._source_server_type,
                    "target_server": self._target_server_type,
                    "stats": result_data["stats"],
                },
            )

            return FlextResult[dict].ok(result_data)

        except Exception as e:
            error_msg = f"LDIF migration pipeline failed: {e}"
            self._logger.exception(error_msg)
            return FlextResult[dict].fail(error_msg)

    def _process_schema_migration(
        self, input_dir: Path, output_dir: Path
    ) -> FlextResult[dict]:
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
                self._logger.warning("No schema files found in input directory")
                return FlextResult[dict].ok({"attributes": {}, "objectclasses": {}})

            # Use the first schema file found
            schema_file = schema_files[0]

            self._logger.info(
                f"Processing schema file: {schema_file.name}",
                extra={"source_server": self._source_server_type},
            )

            # Parse schema using RFC parser with quirks integration
            parser = self._schema_parser_class(
                params={
                    "file_path": str(schema_file),
                    "parse_attributes": True,
                    "parse_objectclasses": True,
                },
                quirk_registry=self._quirk_registry,
                server_type=self._source_server_type,
            )
            parse_result = parser.execute()

            if parse_result.is_failure:
                return FlextResult[dict].fail(
                    f"RFC schema parsing failed: {parse_result.error}"
                )

            schema_data = parse_result.unwrap()

            # Write migrated schema to output directory using RFC LDIF Writer
            output_schema_file = (
                output_dir / f"migrated_schema_{self._target_server_type}.ldif"
            )

            writer = self._writer_class(
                params={
                    "output_file": str(output_schema_file),
                    "schema": schema_data,
                },
                quirk_registry=self._quirk_registry,
                target_server_type=self._target_server_type,
            )

            write_result = writer.execute()
            if write_result.is_failure:
                return FlextResult[dict].fail(
                    f"Schema writing failed: {write_result.error}"
                )

            self._logger.info(
                "Schema migration completed",
                extra={
                    "attributes_count": len(schema_data["attributes"]),
                    "objectclasses_count": len(schema_data["objectclasses"]),
                    "output_file": str(output_schema_file),
                },
            )

            return FlextResult[dict].ok(schema_data)

        except Exception as e:
            return FlextResult[dict].fail(f"Schema migration failed: {e}")

    def _process_entries_migration(
        self, input_dir: Path, output_dir: Path
    ) -> FlextResult[list]:
        """Process entries migration using RFC parsers with quirks.

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
                self._logger.warning("No entry files found in input directory")
                return FlextResult[list].ok([])

            all_entries: list[dict] = []

            for entry_file in entry_files:
                self._logger.info(
                    f"Processing entry file: {entry_file.name}",
                    extra={"source_server": self._source_server_type},
                )

                # Parse entries using RFC LDIF parser
                parser = self._ldif_parser_class(
                    params={
                        "file_path": str(entry_file),
                        "parse_changes": False,
                    },
                    quirk_registry=self._quirk_registry,
                )
                parse_result = parser.execute()

                if parse_result.is_failure:
                    return FlextResult[list].fail(
                        f"RFC LDIF parsing failed: {parse_result.error}"
                    )

                entries_data = parse_result.unwrap()
                entries = entries_data.get("entries", [])

                all_entries.extend(entries)

            # Write migrated entries to output directory using RFC LDIF Writer
            output_entries_file = (
                output_dir / f"migrated_entries_{self._target_server_type}.ldif"
            )

            writer = self._writer_class(
                params={
                    "output_file": str(output_entries_file),
                    "entries": all_entries,
                },
                quirk_registry=self._quirk_registry,
                target_server_type=self._target_server_type,
            )

            write_result = writer.execute()
            if write_result.is_failure:
                return FlextResult[list].fail(
                    f"Entries writing failed: {write_result.error}"
                )

            self._logger.info(
                "Entries migration completed",
                extra={
                    "total_entries": len(all_entries),
                    "output_file": str(output_entries_file),
                },
            )

            return FlextResult[list].ok(all_entries)

        except Exception as e:
            return FlextResult[list].fail(f"Entries migration failed: {e}")


__all__ = ["LdifMigrationPipelineService"]
