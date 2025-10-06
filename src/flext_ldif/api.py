"""FLEXT-LDIF API - Thin Facade for LDIF Operations.

This module provides the primary entry point for all LDIF processing operations.
The FlextLdif class serves as a thin facade exposing all functionality through
a clean, unified interface that delegates to the FlextLdifClient implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import override

from flext_core import FlextResult, FlextService

from flext_ldif.acl.service import FlextLdifAclService
from flext_ldif.client import FlextLdifClient
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.entry.builder import FlextLdifEntryBuilder
from flext_ldif.exceptions import FlextLdifExceptions
from flext_ldif.mixins import FlextLdifMixins
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.schema.builder import FlextLdifSchemaBuilder
from flext_ldif.schema.validator import FlextLdifSchemaValidator
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdif(FlextService[FlextLdifTypes.Dict]):
    r"""Thin facade for all LDIF processing operations.

    Provides unified access to:
    - RFC-compliant LDIF parsing and writing
    - Server-specific quirks and migrations
    - Validation and analytics
    - All infrastructure (Models, Config, Constants, etc.)

    This class follows the Facade pattern, providing a simplified interface
    to the complex subsystem of LDIF processing services by delegating
    all operations to the FlextLdifClient implementation.

    Example:
        # Basic usage
        ldif = FlextLdif()

        # Parse LDIF content
        result = ldif.parse("dn: cn=test,dc=example,dc=com\ncn: test\n")
        if result.is_success:
            entries = result.unwrap()

        # Write LDIF entries
        write_result = ldif.write(entries)

        # Migrate between servers
        migration_result = ldif.migrate(
            entries=entries,
            from_server="oid",
            to_server="oud"
        )

        # Access infrastructure
        config = ldif.config
        models = ldif.Models
        entry = ldif.Models.Entry(dn="cn=test", attributes={})

    """

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize LDIF facade with optional configuration.

        Args:
            config: Optional LDIF configuration. If not provided,
                   uses global singleton instance.

        """
        super().__init__()
        self._client = FlextLdifClient(config)

    @override
    def execute(self) -> FlextResult[FlextLdifTypes.Dict]:
        """Execute facade self-check and return status.

        Returns:
            FlextResult containing facade status and configuration

        """
        return self._client.execute()

    def parse(
        self, source: str | Path, server_type: str = "rfc"
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        r"""Parse LDIF from file or content string.

        Args:
            source: Either a file path (Path object) or LDIF content string
            server_type: Server type for quirk selection ("rfc", "oid", "oud", etc.)

        Returns:
            FlextResult with list of parsed Entry models

        Example:
            # Parse from string
            result = ldif.parse("dn: cn=test\ncn: test\n")

            # Parse from file
            result = ldif.parse(Path("data.ldif"))

            # Parse with server-specific quirks
            result = ldif.parse(Path("oid.ldif"), server_type="oid")

        """
        return self._client.parse_ldif(source, server_type)

    def write(
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

        Example:
            # Write to string
            result = ldif.write(entries)
            if result.is_success:
                ldif_content = result.unwrap()

            # Write to file
            result = ldif.write(entries, Path("output.ldif"))

        """
        return self._client.write_ldif(entries, output_path)

    def validate_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Validate LDIF entries against RFC and business rules.

        Args:
            entries: List of entries to validate

        Returns:
            FlextResult containing validation report with details

        Example:
            result = ldif.validate_entries(entries)
            if result.is_success:
                report = result.unwrap()
                print(f"Valid: {report['is_valid']}")
                print(f"Errors: {report['errors']}")

        """
        return self._client.validate_entries(entries)

    def migrate(
        self,
        input_dir: Path,
        output_dir: Path,
        from_server: str,
        to_server: str,
        *,
        process_schema: bool = True,
        process_entries: bool = True,
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Migrate LDIF data between different LDAP server types.

        Args:
            input_dir: Directory containing source LDIF files
            output_dir: Directory for migrated LDIF files
            from_server: Source server type ("oid", "oud", "openldap", etc.)
            to_server: Target server type
            process_schema: Whether to process schema files
            process_entries: Whether to process entry files

        Returns:
            FlextResult containing migration statistics and output files

        Example:
            result = ldif.migrate(
                input_dir=Path("data/oid"),
                output_dir=Path("data/oud"),
                from_server="oid",
                to_server="oud",
                process_schema=True,
                process_entries=True
            )
            if result.is_success:
                stats = result.unwrap()
                print(f"Migrated {stats['total_entries']} entries")

        """
        return self._client.migrate_files(
            input_dir,
            output_dir,
            from_server,
            to_server,
            process_schema=process_schema,
            process_entries=process_entries,
        )

    def analyze(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Analyze LDIF entries and generate statistics.

        Args:
            entries: List of entries to analyze

        Returns:
            FlextResult containing analysis statistics

        Example:
            result = ldif.analyze(entries)
            if result.is_success:
                stats = result.unwrap()
                print(f"Total entries: {stats['total_entries']}")
                print(f"Entry types: {stats['entry_types']}")

        """
        return self._client.analyze_entries(entries)

    def filter_by_objectclass(
        self, entries: list[FlextLdifModels.Entry], objectclass: str
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by object class.

        Args:
            entries: List of LDIF entries to filter
            objectclass: Object class to filter by

        Returns:
            FlextResult containing filtered entries

        """
        return self._client.filter_by_objectclass(entries, objectclass)

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

        Example:
            custom_quirk = MyCustomQuirk()
            result = ldif.register_quirk(custom_quirk, quirk_type="schema")

        """
        return self._client.register_quirk(quirk, quirk_type)

    # =========================================================================
    # BUILDERS & SERVICES (Direct Access)
    # =========================================================================

    @property
    def entry_builder(self) -> type[FlextLdifEntryBuilder]:
        """Access to LDIF entry builder for constructing entries.

        Returns:
            FlextLdifEntryBuilder class for creating person, group, OU, and custom entries

        Example:
            builder = ldif.EntryBuilder()
            person = builder.build_person_entry(
                cn="John Doe",
                sn="Doe",
                base_dn="ou=people,dc=example,dc=com",
                mail="john@example.com"
            )

        """
        return FlextLdifEntryBuilder

    @property
    def schema_builder(self) -> type[FlextLdifSchemaBuilder]:
        """Access to LDIF schema builder for constructing schemas.

        Returns:
            FlextLdifSchemaBuilder class for building schema definitions

        Example:
            builder = ldif.SchemaBuilder(server_type="rfc")
            builder.add_attribute("cn", "commonName")
            schema = builder.build()

        """
        return FlextLdifSchemaBuilder

    @property
    def acl_service(self) -> type[FlextLdifAclService]:
        """Access to ACL service for extracting and processing ACLs.

        Returns:
            FlextLdifAclService class for ACL operations

        Example:
            acl_service = ldif.AclService()
            acls = acl_service.extract_acls_from_entry(entry)

        """
        return FlextLdifAclService

    @property
    def schema_validator(self) -> type[FlextLdifSchemaValidator]:
        """Access to schema validator for validating entries.

        Returns:
            FlextLdifSchemaValidator class for schema validation

        Example:
            validator = ldif.SchemaValidator()
            result = validator.execute({"entries": entries})

        """
        return FlextLdifSchemaValidator

    # =========================================================================
    # INFRASTRUCTURE ACCESS (Properties)
    # =========================================================================

    @property
    def models(self) -> type[FlextLdifModels]:
        """Access to all LDIF Pydantic models.

        Returns:
            FlextLdifModels class containing all LDIF domain models

        Example:
            entry = ldif.Models.Entry(dn="cn=test", attributes={})
            schema = ldif.Models.SchemaObjectClass(name="person")

        """
        return FlextLdifModels

    @property
    def config(self) -> FlextLdifConfig:
        """Access to LDIF configuration instance.

        Returns:
            Current FlextLdifConfig instance

        Example:
            encoding = ldif.config.ldif_encoding
            max_workers = ldif.config.max_workers

        """
        return self._client.config

    @property
    def constants(self) -> type[FlextLdifConstants]:
        """Access to LDIF constants.

        Returns:
            FlextLdifConstants class containing all constant values

        Example:
            max_line = ldif.Constants.Format.MAX_LINE_LENGTH
            encoding = ldif.Constants.Encoding.UTF8

        """
        return FlextLdifConstants

    @property
    def types(self) -> type[FlextLdifTypes]:
        """Access to LDIF type definitions.

        Returns:
            FlextLdifTypes class containing all type aliases

        Example:
            # Use types for type hints
            entry_config: ldif.Types.Entry.EntryConfiguration = {}

        """
        return FlextLdifTypes

    @property
    def protocols(self) -> type[FlextLdifProtocols]:
        """Access to LDIF protocols for duck typing.

        Returns:
            FlextLdifProtocols class containing all protocol definitions

        Example:
            def process(processor: ldif.Protocols.LdifProcessorProtocol):
                result = processor.parse(content)

        """
        return FlextLdifProtocols

    @property
    def exceptions(self) -> type[FlextLdifExceptions]:
        """Access to LDIF exception factory methods.

        Returns:
            FlextLdifExceptions class with error creation methods

        Example:
            error = ldif.Exceptions.validation_error("Invalid DN")
            parse_error = ldif.Exceptions.parse_error("Malformed LDIF")

        """
        return FlextLdifExceptions

    @property
    def mixins(self) -> type[FlextLdifMixins]:
        """Access to LDIF mixins for reusable functionality.

        Returns:
            FlextLdifMixins class containing all mixin classes

        Example:
            validator = ldif.Mixins.ValidationMixin()
            is_valid = validator.validate_dn_format("cn=test")

        """
        return FlextLdifMixins

    @property
    def utilities(self) -> type[FlextLdifUtilities]:
        """Access to LDIF utility functions.

        Returns:
            FlextLdifUtilities class containing all utility methods

        Example:
            timestamp = ldif.Utilities.TimeUtilities.get_timestamp()
            size = ldif.Utilities.TextUtilities.format_byte_size(1024)

        """
        return FlextLdifUtilities

    @property
    def processors(self) -> type[FlextLdifUtilities.Processors]:
        """Access to LDIF processing utilities using FlextProcessors.

        Returns:
            FlextLdifUtilities.Processors class with processing methods

        Example:
            # Create processor and register function
            processors = ldif.Processors.create_processor()

            def validate_entry(entry: dict) -> dict:
                # Validation logic
                return entry

            result = ldif.Processors.register_processor(
                "validate", validate_entry, processors
            )

            # Batch processing with registered processor
            batch_result = ldif.Processors.process_entries_batch(
                "validate", entries, processors
            )

            # Parallel processing with registered processor
            parallel_result = ldif.Processors.process_entries_parallel(
                "validate", entries, processors
            )

        """
        return FlextLdifUtilities.Processors

    # =========================================================================


__all__ = ["FlextLdif"]
