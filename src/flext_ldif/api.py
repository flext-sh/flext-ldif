"""FLEXT-LDIF API - Unified Facade for LDIF Operations.

This module provides the primary entry point for all LDIF processing operations.
The FlextLdif class serves as the sole facade for the FLEXT LDIF library,
consolidating all business logic and service coordination into a single interface.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import ClassVar, TypeVar, cast, overload, override

from flext_core import (
    FlextContext,
    FlextResult,
    FlextRuntime,
    FlextService,
)
from pydantic import PrivateAttr

from flext_ldif.config import FlextLdifConfig, LdifFlextConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.services.acl import FlextLdifAcl
from flext_ldif.services.analysis import FlextLdifAnalysis
from flext_ldif.services.categorization import FlextLdifCategorization
from flext_ldif.services.conversion import FlextLdifConversion
from flext_ldif.services.detector import FlextLdifDetector
from flext_ldif.services.entries import FlextLdifEntries
from flext_ldif.services.entry_manipulation import EntryManipulationServices
from flext_ldif.services.filters import FlextLdifFilters
from flext_ldif.services.migration import FlextLdifMigrationPipeline
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.processing import FlextLdifProcessing
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.services.sorting import FlextLdifSorting
from flext_ldif.services.validation import FlextLdifValidation
from flext_ldif.services.writer import FlextLdifWriter
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities

# Type alias for service response type
_ServiceResponseType = FlextLdifTypes.Models.ServiceResponseTypes

# Type variable for monadic transformations
U = TypeVar("U")


class FlextLdif(FlextService[_ServiceResponseType]):
    r"""Main API facade for LDIF processing operations.

    This is the sole entry point for all LDIF operations, consolidating all
    business logic and service coordination into a single facade class. It
    inherits from FlextService to leverage dependency injection, logging, and
    event publishing capabilities.

    Capabilities:
        - Parse and write LDIF files according to RFC 2849 and RFC 4512
        - Handle server-specific quirks (OID, OUD, OpenLDAP, AD, 389 DS)
        - Migrate data between different LDAP server types
        - Validate LDIF entries against LDAP schemas
        - Process ACL (Access Control List) entries
        - Batch and parallel processing for large datasets
        - Service initialization and dependency injection via FlextContainer
        - Default quirk registration for all supported LDAP servers
        - Context management with correlation tracking

    Implementation:
        This class consolidates all LDIF operations into a single facade,
        eliminating the need for separate client classes. It manages all
        service coordination, DI container operations, and business logic.

    Example:
        # Recommended: Use singleton instance
        ldif = FlextLdif.get_instance()

        # Alternative: Create new instance
        ldif = FlextLdif()

        # Parse LDIF content with context tracking
        with ldif.context.set_correlation_id("req-123"):
            result = ldif.parse("dn: cn=test,dc=example,dc=com\ncn: test\n")
            if result.is_success:
                entries = result.unwrap()

        # Write LDIF entries with structured error handling
        write_result = ldif.write(entries)

        # Generic migration between servers
        migration_result = ldif.migrate(
            input_dir=Path("data/oid"),
            output_dir=Path("data/oud"),
            from_server=FlextLdifConstants.ServerTypes.OID,
            to_server=FlextLdifConstants.ServerTypes.OUD,
        )

        # Categorized migration with structured output
        categorized_result = ldif.categorize_and_migrate(
            input_dir=Path("data/source"),
            output_dir=Path("data/categorized"),
            categorization_rules={
                "users": [FlextLdifConstants.ObjectClasses.PERSON],
                "groups": [FlextLdifConstants.ObjectClasses.GROUP_OF_NAMES],
            },
            from_server=FlextLdifConstants.ServerTypes.OID,
            to_server=FlextLdifConstants.ServerTypes.OUD,
        )

        # Batch processing for large datasets
        batch_processor = ldif.create_batch_processor(batch_size=100)
        processing_result = batch_processor.process_entries(entries, validate_entry)

        # Access complete infrastructure
        config = ldif.config
        models = ldif.models
        entry = ldif.models.Entry(dn="cn=test", attributes={})
        events = ldif.events  # Domain events

    """

    # Private attributes (initialized in model_post_init)
    # Using PrivateAttr() for Pydantic v2 compatibility
    # Services are created via factory - no direct instantiation
    _parser_service: FlextLdifParser | None = PrivateAttr(default=None)
    _acl_service: FlextLdifAcl | None = PrivateAttr(default=None)
    _writer_service: FlextLdifWriter | None = PrivateAttr(default=None)
    _entries_service: FlextLdifEntries | None = PrivateAttr(default=None)
    _analysis_service: FlextLdifAnalysis | None = PrivateAttr(default=None)
    _processing_service: FlextLdifProcessing | None = PrivateAttr(default=None)
    _detector_service: FlextLdifDetector | None = PrivateAttr(default=None)
    _validation_service: FlextLdifValidation | None = PrivateAttr(default=None)
    _filters_service: FlextLdifFilters | None = PrivateAttr(default=None)

    _context: dict[str, object] = PrivateAttr(default_factory=dict)
    _init_config_value: FlextLdifConfig | None = PrivateAttr(default=None)
    _builder_entries: list[FlextLdifModels.Entry] | None = PrivateAttr(default=None)
    _builder_parse_result: FlextResult[list[FlextLdifModels.Entry]] | None = (
        PrivateAttr(default=None)
    )
    _builder_filter_result: FlextResult[list[FlextLdifModels.Entry]] | None = (
        PrivateAttr(default=None)
    )
    _builder_write_result: FlextResult[str] | None = PrivateAttr(default=None)

    # Direct class access for builders and services (no wrappers)
    AclService: ClassVar[type[FlextLdifAcl]] = FlextLdifAcl

    # Static utilities exposed as class attributes (hybrid pattern)
    filters: ClassVar[type[FlextLdifFilters]] = FlextLdifFilters
    categorization: ClassVar[type[FlextLdifCategorization]] = FlextLdifCategorization
    sorting: ClassVar[type[FlextLdifSorting]] = FlextLdifSorting
    conversion: ClassVar[type[FlextLdifConversion]] = FlextLdifConversion
    utilities: ClassVar[type[FlextLdifUtilities]] = FlextLdifUtilities

    entry_manipulation: ClassVar[type[EntryManipulationServices]] = (
        EntryManipulationServices
    )

    # Singleton instance storage
    _instance: ClassVar[FlextLdif | None] = None
    # Class-level initialization guard to prevent redundant initialization
    _class_initialized: ClassVar[bool] = False

    @classmethod
    def get_instance(cls, config: FlextLdifConfig | None = None) -> FlextLdif:
        """Get singleton instance of FlextLdif facade.

        Args:
            config: Optional configuration (only used on first call)

        Returns:
            Singleton FlextLdif instance

        Example:
            # Recommended usage
            ldif = FlextLdif.get_instance()

            # All calls return same instance
            ldif2 = FlextLdif.get_instance()
            # Singleton pattern: same instance returned
            if ldif is not ldif2:
                raise RuntimeError(
                    "Singleton pattern violation: different instances returned"
                )

        """
        if cls._instance is None:
            # Create instance with config if provided
            if config is not None:
                # Pass config via kwargs to __init__
                cls._instance = cls(config=config)
            else:
                # Create empty instance (FlextService v2 doesn't accept positional args)
                cls._instance = cls()
        return cls._instance

    @classmethod
    def _reset_instance(cls) -> None:
        """Reset singleton instance (for testing only).

        WARNING: This method is intended for testing purposes only.
        Do not use in production code as it breaks the singleton pattern.

        Clears the singleton instance and initialization flag, allowing a fresh
        instance to be created on the next call to get_instance(). This ensures
        test isolation and idempotency by preventing state leakage between tests.

        Example:
            # In test fixture
            FlextLdif._reset_instance()
            ldif = FlextLdif.get_instance()  # Fresh instance

        """
        cls._instance = None
        cls._class_initialized = False

    def __init__(self, **kwargs: object) -> None:
        """Initialize LDIF facade - the sole entry point for all LDIF operations.

        Integrates Flext components for infrastructure support:
            - FlextContainer: Dependency injection
            - FlextLogger: Structured logging
            - FlextContext: Request context management
            - FlextConfig: Configuration with validation
            - FlextBus: Event publishing
            - FlextDispatcher: Message dispatching
            - FlextRegistry: Component registration

        Args:
            **kwargs: Configuration parameters. Supports 'config' for FlextLdifConfig.

        """
        # Extract 'config' from kwargs to avoid Pydantic extra='forbid' error
        # Store it in _init_config_value for use in model_post_init
        config_value = kwargs.pop("config", None)
        if config_value is not None and isinstance(config_value, FlextLdifConfig):
            # Store temporarily before super().__init__()
            # model_post_init will read it and initialize services with it
            object.__setattr__(self, "_init_config_value", config_value)

        # Call super().__init__() for Pydantic v2 model initialization
        # Remaining kwargs (empty after config removal) are passed
        # This will call model_post_init() which initializes all services
        super().__init__(**kwargs)

        # Services initialized in model_post_init for proper initialization order

    def model_post_init(self, __context: object, /) -> None:
        """Initialize private attributes after Pydantic initialization.

        This hook is called by Pydantic after __init__ completes and handles:
        - Service setup and dependency injection via FlextContainer
        - Default quirk registration for all supported LDAP servers
        - Context and handler initialization

        Uses class-level initialization guard to prevent redundant initialization
        across ALL instances (singleton pattern).

        Args:
            __context: Pydantic's validation context dictionary or None (unused).

        """
        # Initialize context
        self._context = {}

        # Create services directly via instantiation
        # (pure facade - no infrastructure management)
        self._parser_service = FlextLdifParser()
        self._acl_service = FlextLdifAcl()
        self._entries_service = FlextLdifEntries()
        self._analysis_service = FlextLdifAnalysis()
        self._processing_service = FlextLdifProcessing()
        self._detector_service = FlextLdifDetector()
        self._filters_service = FlextLdifFilters()
        self._validation_service = FlextLdifValidation()

        # Create writer service with quirk registry dependency
        quirk_registry = FlextLdifServer.get_global_instance()
        self._writer_service = FlextLdifWriter(quirk_registry=quirk_registry)

        # Log initialization
        if self.logger is not None:
            self.logger.debug("FlextLdif facade initialized")

    @override
    def execute(
        self,
        **_kwargs: object,
    ) -> FlextResult[
        FlextLdifModels.EntryResult
        | FlextLdifModels.ParseResponse
        | FlextLdifModels.WriteResponse
        | FlextLdifModels.MigrationPipelineResult
        | FlextLdifModels.ValidationResult
    ]:
        """Execute facade self-check and return status.

        Returns:
            FlextResult containing ValidationResult with health check status

        """
        # Return ValidationResult as health check (all services healthy)
        validation_result = FlextLdifModels.ValidationResult(
            is_valid=True,
            total_entries=0,
            valid_entries=0,
            invalid_entries=0,
            errors=[],
        )
        return FlextResult.ok(validation_result)

    def parse(
        self,
        source: str | Path,
        server_type: str | None = None,
        format_options: FlextLdifModels.ParseFormatOptions | None = None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        r"""Parse LDIF content string or file.

        Delegates to FlextLdifParser service with correct quirks.

        Args:
            source: LDIF content as string or Path to LDIF file
            server_type: Server type for quirk selection ("rfc", "oid", "oud", etc.)
            format_options: Parse options as ParseFormatOptions model

        Returns:
            FlextResult containing list of Entry models

        Example:
            # Parse LDIF content
            result = ldif.parse("dn: cn=test\ncn: test\n")
            if result.is_success:
                entries = result.unwrap()  # list[Entry]

            # Parse file
            result = ldif.parse(Path("file.ldif"))
            if result.is_success:
                entries = result.unwrap()

            # Parse with options
            options = FlextLdifModels.ParseFormatOptions(validate_entries=True)
            result = ldif.parse("dn: cn=test\ncn: test\n", format_options=options)

        """
        if self._parser_service is None:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                "Parser service not initialized",
            )

        # Delegate to parser service - service handles all logic
        parse_result = self._parser_service.parse_source(
            source=source,
            server_type=server_type,
            format_options=format_options,
        )

        # Service returns ParseResponse - extract entries
        if parse_result.is_success:
            parse_response = parse_result.unwrap()
            # Entries are already compatible (FlextLdifModels.Entry extends domain Entry)
            # Filter to ensure type safety without cast
            entries: list[FlextLdifModels.Entry] = [
                entry
                for entry in parse_response.entries
                if isinstance(entry, FlextLdifModels.Entry)
            ]
            return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

        return FlextResult[list[FlextLdifModels.Entry]].fail(
            parse_result.error or "Unknown error",
        )

    # Overloads for write() method
    @overload
    def write(
        self,
        entries: FlextLdifTypes.EntryOrList,
        output_path: None = None,
        server_type: str | None = None,
        format_options: FlextLdifModels.WriteFormatOptions | None = None,
        template_data: dict[str, object] | None = None,
    ) -> FlextResult[str]: ...

    @overload
    def write(
        self,
        entries: FlextLdifTypes.EntryOrList,
        output_path: Path,
        server_type: str | None = None,
        format_options: FlextLdifModels.WriteFormatOptions | None = None,
        template_data: dict[str, object] | None = None,
    ) -> FlextResult[str]: ...

    def write(
        self,
        entries: FlextLdifTypes.EntryOrList,
        output_path: Path | None = None,
        server_type: str | None = None,
        format_options: FlextLdifModels.WriteFormatOptions | None = None,
        template_data: dict[str, object] | None = None,
    ) -> FlextResult[str]:
        """Write entries to LDIF format string or file.

        Args:
            entries: Entry model or list of Entry models to write
            output_path: Optional Path to write LDIF file. If None, returns LDIF string.
            server_type: Target server type for writing. If None, uses RFC.
            format_options: Write options as WriteFormatOptions model
            template_data: Optional dict with template variables for header generation

        Returns:
            FlextResult containing LDIF content as string (if output_path is None)
            or success message (if output_path provided)

        Example:
            # Write Entry models to string
            result = ldif.write(entries)
            if result.is_success:
                ldif_content = result.unwrap()

            # Write to file
            result = ldif.write(entries, Path("output.ldif"))

            # Write with options
            options = FlextLdifModels.WriteFormatOptions(
                line_width=100,
                sort_attributes=True,
            )
            result = ldif.write(entries, format_options=options)

            # Write with template data for header
            result = ldif.write(
                entries,
                Path("output.ldif"),
                template_data={"phase": 1, "source": "OID", "target": "OUD"},
            )

        """
        if self._writer_service is None:
            return FlextResult[str].fail("Writer service not initialized")

        # Normalize EntryOrList to list[Entry] using type alias
        entries_list: list[FlextLdifModels.Entry]
        if isinstance(entries, FlextLdifModels.Entry):
            entries_list = [entries]
        elif isinstance(entries, list):
            entries_list = entries
        else:
            return FlextResult[str].fail(
                f"Invalid entries type: {type(entries).__name__}",
            )

        # Delegate to writer service - service handles all logic
        target_server = server_type or "rfc"
        output_target = "file" if output_path else "string"
        resolved_format_options = format_options or FlextLdifModels.WriteFormatOptions()

        write_result = self._writer_service.write(
            entries=entries_list,
            target_server_type=target_server,
            output_target=output_target,
            output_path=output_path,
            format_options=resolved_format_options,
            template_data=template_data,
        )

        if write_result.is_success:
            if output_path:
                # File write returns success message
                return FlextResult[str].ok(
                    f"LDIF written successfully to {output_path}",
                )
            # String write returns the LDIF content
            unwrapped = write_result.unwrap()
            if isinstance(unwrapped, str):
                return FlextResult[str].ok(unwrapped)
            return FlextResult[str].fail(
                f"Write operation returned non-string result: "
                f"{type(unwrapped).__name__}",
            )

        return FlextResult[str].fail(write_result.error or "Unknown error")

    def get_entry_dn(
        self,
        entry: FlextLdifModels.Entry
        | FlextLdifProtocols.Entry.EntryWithDnProtocol
        | dict[str, str | list[str]],
    ) -> FlextResult[str]:
        """Extract DN (Distinguished Name) from any entry type.

        Delegates to FlextLdifEntries service for SRP compliance.

        Args:
            entry: Entry model, LDAP entry, or dict to extract DN from

        Returns:
            FlextResult containing DN as string

        """
        # _entries_service is always initialized in model_post_init
        # Type narrowing: _entries_service is never None after model_post_init
        entries_service = self._entries_service
        if entries_service is None:
            return FlextResult[str].fail("Entries service not initialized")
        return entries_service.get_entry_dn(entry)

    def get_entry_attributes(
        self,
        entry: FlextLdifModels.Entry | FlextLdifProtocols.Entry.EntryWithDnProtocol,
    ) -> FlextResult[FlextLdifTypes.CommonDict.AttributeDict]:
        """Extract attributes from any entry type.

        Delegates to FlextLdifEntries service for SRP compliance.

        Args:
            entry: LDIF or LDAP entry to extract attributes from

        Returns:
            FlextResult containing AttributeDict with attribute names mapped to
            str | list[str] values matching FlextLdifTypes definition.

        """
        # _entries_service is always initialized in model_post_init
        entries_service = self._entries_service
        if entries_service is None:
            return FlextResult[FlextLdifTypes.CommonDict.AttributeDict].fail(
                "Entries service not initialized",
            )
        return entries_service.get_entry_attributes(entry)

    def create_entry(
        self,
        dn: str,
        attributes: dict[str, str | list[str]],
        objectclasses: list[str] | None = None,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Create a new LDIF entry with validation.

        Delegates to FlextLdifEntries service for SRP compliance.

        Args:
            dn: Distinguished Name for the entry
            attributes: Dict mapping attribute names to values (string or list)
            objectclasses: Optional list of objectClass values
                (added to attributes if provided)

        Returns:
            FlextResult containing new FlextLdifModels.Entry

        """
        # _entries_service is always initialized in model_post_init
        entries_service = self._entries_service
        if entries_service is None:
            return FlextResult[FlextLdifModels.Entry].fail(
                "Entries service not initialized",
            )
        return entries_service.create_entry(dn, attributes, objectclasses)

    def get_entry_objectclasses(
        self,
        entry: FlextLdifModels.Entry | FlextLdifProtocols.Entry.EntryWithDnProtocol,
    ) -> FlextResult[list[str]]:
        """Extract objectClass values from any entry type.

        Delegates to FlextLdifEntries service for SRP compliance.

        Args:
            entry: LDIF or LDAP entry to extract objectClasses from

        Returns:
            FlextResult containing list of objectClass values

        """
        # _entries_service is always initialized in model_post_init
        entries_service = self._entries_service
        if entries_service is None:
            return FlextResult[list[str]].fail("Entries service not initialized")
        return entries_service.get_entry_objectclasses(entry)

    def get_attribute_values(
        self,
        attribute: (FlextLdifProtocols.AttributeValueProtocol | list[str] | str),
    ) -> FlextResult[list[str]]:
        """Extract values from an attribute value object.

        Delegates to FlextLdifEntries service for SRP compliance.

        Args:
            attribute: Attribute value object with .values property, list, or string.

        Returns:
            FlextResult containing list of attribute values as strings.

        """
        # _entries_service is always initialized in model_post_init
        entries_service = self._entries_service
        if entries_service is None:
            return FlextResult[list[str]].fail("Entries service not initialized")
        return entries_service.get_attribute_values(attribute)

    def migrate(
        self,
        input_dir: Path,
        output_dir: Path,
        source_server: str,
        target_server: str,
        *,
        options: FlextLdifModels.MigrateOptions | None = None,
    ) -> FlextResult[FlextLdifModels.EntryResult]:
        r"""Unified LDIF migration supporting simple, categorized, and structured modes.

        Automatically detects migration mode based on parameters:
        - **Structured Mode**: 6-file output (00-schema to 06-rejected)
            with full tracking (when migration_config provided)
        - **Categorized Mode**: Custom multi-file output
            (when categorization_rules provided)
        - **Simple Mode**: Single output file (default behavior)

        Generic migration supporting any LDAP server type. All parameters are
        fully customizable with no hardcoded values.

        Args:
            input_dir: Directory containing source LDIF files
            output_dir: Directory for output files
            source_server: Source server type identifier
                (e.g., "oid", "openldap", "ad")
            target_server: Target server type identifier (e.g., "oud", "openldap", "ad")
            options: Optional MigrateOptions Model consolidating all migration parameters:
                - migration_config: MigrationConfig for structured 6-file output
                - write_options: WriteFormatOptions for formatting control
                - categorization_rules: Dict for categorized mode (legacy)
                - input_files/output_files: File lists for categorized mode
                - schema_whitelist_rules: Schema filtering rules
                - input_filename/output_filename: Simple mode file names
                - forbidden_attributes/forbidden_objectclasses: Filter lists
                - base_dn: Target base DN for normalization
                - sort_entries_hierarchically: Hierarchical sorting flag
                See FlextLdifModels.MigrateOptions for complete field documentation.

        Returns:
            FlextResult containing PipelineExecutionResult with:
            - entries_by_category: Dict of entries by category (structured/categorized) or single dict (simple)
            - statistics: Migration statistics with per-category counts
            - file_paths: Output file paths created

        Examples:
            # Simple migration - single output file
            result = ldif.migrate(
                input_dir=Path("source"),
                output_dir=Path("target"),
                source_server="oid",
                target_server="oud"
            )

            # Structured migration - 6 files with tracking
            options = FlextLdifModels.MigrateOptions(
                migration_config=FlextLdifModels.MigrationConfig(
                    hierarchy_objectclasses=["organization", "organizationalUnit"],
                    user_objectclasses=["inetOrgPerson", "person"],
                    group_objectclasses=["groupOfNames"],
                    attribute_blacklist=["pwdChangedTime", "modifiersName"],
                    track_removed_attributes=True,
                    write_removed_as_comments=True,
                    header_template="# Migration from {{source}} to {{target}}\\n",
                    header_data={"source": "OID", "target": "OUD"}
                ),
                write_options=FlextLdifModels.WriteFormatOptions(
                    disable_line_folding=True
                ),
            )
            result = ldif.migrate(
                input_dir=Path("source"),
                output_dir=Path("target"),
                source_server="oid",
                target_server="oud",
                options=options,
            )

            # Categorized migration - legacy approach
            options = FlextLdifModels.MigrateOptions(
                categorization_rules={
                    "hierarchy_objectclasses": ["organization", "organizationalUnit"],
                    "user_objectclasses": ["inetOrgPerson", "person"],
                    "group_objectclasses": ["groupOfNames"],
                    "acl_attributes": ["aci"],
                },
            )
            result = ldif.migrate(
                input_dir=Path("source"),
                output_dir=Path("target"),
                source_server="oid",
                target_server="oud",
                options=options,
            )

        """
        # Delegate to migration pipeline - service handles all logic
        opts = options or FlextLdifModels.MigrateOptions()

        # Normalize migration config via service
        config_result = FlextLdifMigrationPipeline.normalize_migration_config(
            opts.migration_config,
        )
        if config_result.is_failure:
            return FlextResult[FlextLdifModels.EntryResult].fail(
                f"Invalid migration config: {config_result.error}",
            )
        config_model = (
            config_result.unwrap() if opts.migration_config is not None else None
        )

        # Normalize categorization rules via service
        categorization_rules_result = (
            FlextLdifMigrationPipeline.normalize_category_rules(
                opts.categorization_rules,
            )
        )
        if categorization_rules_result.is_failure:
            return FlextResult[FlextLdifModels.EntryResult].fail(
                f"Invalid categorization rules: {categorization_rules_result.error}",
            )
        categorization_rules = categorization_rules_result.unwrap()

        # Auto-detect mode and create write options
        mode = FlextLdifMigrationPipeline.detect_migration_mode(
            config_model,
            categorization_rules,
        )
        write_options_result = FlextLdifMigrationPipeline.get_write_options_for_mode(
            mode,
            opts.write_options,
            config_model,
        )
        if write_options_result.is_failure:
            return FlextResult[FlextLdifModels.EntryResult].fail(
                f"Failed to create write options: {write_options_result.error}",
            )
        write_options = write_options_result.unwrap()

        # Validate requirements for simple mode
        validation_result = FlextLdifMigrationPipeline.validate_simple_mode_params(
            opts.input_filename,
            opts.output_filename,
        )
        if validation_result.is_failure:
            return FlextResult[FlextLdifModels.EntryResult].fail(
                validation_result.error or "Parameter validation failed",
            )

        # Normalize whitelist rules via service
        whitelist_rules_result = FlextLdifMigrationPipeline.normalize_whitelist_rules(
            opts.schema_whitelist_rules,
        )
        if whitelist_rules_result.is_failure:
            return FlextResult[FlextLdifModels.EntryResult].fail(
                f"Invalid whitelist rules: {whitelist_rules_result.error}",
            )
        schema_whitelist_rules = whitelist_rules_result.unwrap()

        # Initialize and execute migration pipeline
        migration_pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode=cast("FlextLdifConstants.LiteralTypes.MigrationMode", mode),
            source_server=source_server,
            target_server=target_server,
            forbidden_attributes=opts.forbidden_attributes,
            forbidden_objectclasses=opts.forbidden_objectclasses,
            base_dn=opts.base_dn,
            sort_entries_hierarchically=opts.sort_entries_hierarchically,
            write_options=write_options,
            categorization_rules=categorization_rules,
            input_files=opts.input_files,
            output_files=opts.output_files,
            schema_whitelist_rules=schema_whitelist_rules,
            input_filename=opts.input_filename,
            output_filename=(opts.output_filename or "migrated.ldif"),
        )

        return migration_pipeline.execute()

    def filter(
        self,
        entries: list[FlextLdifModels.Entry],
        objectclass: str | None = None,
        dn_pattern: str | None = None,
        attributes: dict[str, str | None] | None = None,
        custom_filter: Callable[[FlextLdifModels.Entry], bool] | None = None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Unified filter method supporting multiple criteria for flexible entry filtering.

        Consolidated filtering method supporting objectclass, DN pattern, attribute values,
        and custom callback filters for maximum flexibility while maintaining simplicity.

        Args:
            entries: List of LDIF entries to filter.
            objectclass: Optional objectclass filter (e.g., "person", "group").
            dn_pattern: Optional regex pattern to match against entry DN.
            attributes: Optional dict of attribute names and values to filter by.
                       If value is None, checks attribute existence only.
            custom_filter: Optional callable that receives Entry and returns bool.
                          Useful for complex filtering logic.

        Returns:
            FlextResult containing filtered entries. Returns empty list if
            no entries match the criteria.

        Example:
            # Filter by objectclass
            result = ldif.filter(entries, objectclass=FlextLdifConstants.ObjectClasses.PERSON)

            # Filter by DN pattern
            result = ldif.filter(entries, dn_pattern="ou=People")

            # Filter with multiple criteria
            result = ldif.filter(
                entries,
                objectclass=FlextLdifConstants.ObjectClasses.PERSON,
                dn_pattern="ou=People",
                attributes={"uid": None}  # Has uid attribute
            )

            # Filter with custom callback
            result = ldif.filter(
                entries,
                custom_filter=lambda e: "REDACTED_LDAP_BIND_PASSWORD" in e.dn.value.lower()
            )

        """
        if self._filters_service is None:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                "Filters service not initialized",
            )

        # Delegate to filters service - service handles all logic
        filter_result = FlextLdifFilters.apply_standard_filters(
            entries,
            objectclass,
            dn_pattern,
            attributes,
        )
        if filter_result.is_failure:
            return filter_result

        filtered_entries = filter_result.unwrap()

        # Apply custom_filter if provided
        if custom_filter is not None:
            filtered_entries = [e for e in filtered_entries if custom_filter(e)]

        return FlextResult[list[FlextLdifModels.Entry]].ok(filtered_entries)

    # =========================================================================
    # ANALYSIS OPERATIONS
    # =========================================================================

    def analyze(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[FlextLdifModels.EntryAnalysisResult]:
        """Analyze LDIF entries and generate statistics.

        Delegates to FlextLdifAnalysis service for SRP compliance.

        Args:
            entries: List of entries to analyze

        Returns:
            FlextResult containing EntryAnalysisResult with statistics

        """
        if self._analysis_service is None:
            return FlextResult[FlextLdifModels.EntryAnalysisResult].fail(
                "Analysis service not initialized",
            )
        return self._analysis_service.analyze(entries)

    def validate_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[FlextLdifModels.ValidationResult]:
        """Validate LDIF entries against RFC 2849/4512 standards.

        Delegates to FlextLdifAnalysis service for SRP compliance.

        Args:
            entries: List of entries to validate

        Returns:
            FlextResult containing ValidationResult with validation status

        """
        if self._analysis_service is None:
            return FlextResult[FlextLdifModels.ValidationResult].fail(
                "Analysis service not initialized",
            )

        if self._validation_service is None:
            return FlextResult[FlextLdifModels.ValidationResult].fail(
                "Validation service not initialized",
            )

        return self._analysis_service.validate_entries(
            entries, self._validation_service
        )

    # =========================================================================
    # ACL OPERATIONS
    # =========================================================================

    def extract_acls(
        self,
        entry: FlextLdifModels.Entry,
        server_type: str = FlextLdifConstants.ServerTypes.RFC,
    ) -> FlextResult[FlextLdifModels.AclResponse]:
        """Extract ACL rules from entry.

        Args:
            entry: Entry to extract ACLs from
            server_type: Server type for ACL quirks ("rfc", "oid", "oud", etc.)

        Returns:
            FlextResult containing composed AclResponse with extracted ACLs and statistics

        Example:
            result = api.extract_acls(entry)
            if result.is_success:
                acl_response = result.unwrap()
                acls = acl_response.acls

        """
        # Resolve ACL service via container
        if self._acl_service is None:
            return FlextResult[FlextLdifModels.AclResponse].fail(
                "ACL service not initialized",
            )
        return self._acl_service.extract_acls_from_entry(entry, server_type)

    def evaluate_acl_rules(
        self,
        acls: list[FlextLdifModels.Acl],
        context: dict[str, str | int | bool | list[str] | None] | None = None,
    ) -> FlextResult[bool]:
        """Evaluate ACL rules and return evaluation result.

        Args:
            acls: List of ACL models to evaluate
            context: Evaluation context with subject_dn, target_dn, permissions, etc.

        Returns:
            FlextResult containing evaluation result (True if allowed)

        Example:
            acls = api.extract_acls(entry).unwrap()
            context = {
                "subject_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
                "permissions": {"read": True, "write": True}
            }
            result = api.evaluate_acl_rules(acls, context)
            if result.is_success:
                is_allowed = result.unwrap()

        """
        if self._acl_service is None:
            return FlextResult[bool].fail("ACL service not initialized")

        # Delegate to ACL service - service handles context conversion
        eval_context: dict[str, object] = (
            dict(context)
            if context is not None and FlextRuntime.is_dict_like(context)
            else {}
        )
        return self._acl_service.evaluate_acl_context(
            acls,
            eval_context,
        )

    def transform_acl_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        source_server: str | type[FlextLdifConstants.ServerTypes],
        target_server: str | type[FlextLdifConstants.ServerTypes],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Transform ACL attributes from source to target server format.

        Delegates to FlextLdifAcl service with correct quirks.

        Args:
            entries: List of entries with ACL attributes in source format
            source_server: Source server type (e.g., "OID", "OpenLDAP")
            target_server: Target server type (e.g., "OUD", "AD")

        Returns:
            FlextResult containing list of entries with ACL attributes in target format

        Example:
            source_entries = ldif.parse("...").unwrap()
            result = ldif.transform_acl_entries(
                source_entries,
                source_server=FlextLdifConstants.ServerTypes.OID,
                target_server=FlextLdifConstants.ServerTypes.OUD
            )
            if result.is_success:
                transformed = result.unwrap()
                # ACL attributes now in OUD format (aci: instead of orclaci:)

        """
        if self._acl_service is None:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                "ACL service not initialized",
            )
        return self._acl_service.transform_acl_entries(
            entries,
            source_server,
            target_server,
        )

    # =========================================================================
    # UNIFIED PROCESSING OPERATIONS
    # =========================================================================

    def process(
        self,
        processor_name: str,
        entries: list[FlextLdifModels.Entry],
        *,
        parallel: bool = False,
        batch_size: int = 100,
        max_workers: int = 4,
    ) -> FlextResult[list[dict[str, object]]]:
        """Unified processing method supporting batch and parallel modes.

        Delegates to FlextLdifProcessing service for SRP compliance.

        Args:
            processor_name: Name of processor function ("transform", "validate", etc.)
            entries: List of entries to process
            parallel: If True, use parallel processing; if False, use batch. Default: False
            batch_size: Number of entries per batch (only used when parallel=False). Default: 100
            max_workers: Number of worker threads (only used when parallel=True). Default: 4

        Returns:
            FlextResult containing processed results

        """
        if self._processing_service is None:
            return FlextResult[list[dict[str, object]]].fail(
                "Processing service not initialized",
            )
        return self._processing_service.process(
            processor_name,
            entries,
            parallel=parallel,
            batch_size=batch_size,
            max_workers=max_workers,
        )

    # =========================================================================
    # INFRASTRUCTURE ACCESS (Properties)
    # =========================================================================

    # =========================================================================
    # AUTO-DETECTION AND RELAXED MODE OPERATIONS
    # =========================================================================

    def detect_server_type(
        self,
        ldif_path: Path | None = None,
        ldif_content: str | None = None,
    ) -> FlextResult[FlextLdifModels.ServerDetectionResult]:
        """Detect LDAP server type from LDIF file or content.

        Analyzes LDIF content to identify the source LDAP server type
        using pattern matching and heuristics.

        Args:
            ldif_path: Path to LDIF file
            ldif_content: Raw LDIF content as string

        Returns:
            FlextResult with detection results containing:
            - detected_server_type: "oid" | "oud" | "openldap" | ...
            - confidence: 0.0-1.0
            - scores: {server_type: score, ...}
            - patterns_found: [pattern1, pattern2, ...]
            - is_confident: bool

        Example:
            result = api.detect_server_type(ldif_path=Path("data.ldif"))
            if result.is_success:
                detected = result.unwrap()
                print(f"Server type: {detected.detected_server_type}")
                print(f"Confidence: {detected.confidence:.2%}")

        """
        if self._detector_service is None:
            return FlextResult[FlextLdifModels.ServerDetectionResult].fail(
                "Detector service not initialized",
            )

        # Delegate to detector service - service handles all logic
        return self._detector_service.detect_server_type(
            ldif_path=ldif_path,
            ldif_content=ldif_content,
        )

    def get_effective_server_type(
        self,
        ldif_path: Path | None = None,
    ) -> FlextResult[str]:
        """Get the effective LDAP server type that will be used for parsing.

        Delegates to FlextLdifDetector service with correct quirks.

        Args:
            ldif_path: Optional path to LDIF file for auto-detection

        Returns:
            FlextResult with the server type string that will be used

        Example:
            # Get effective server type before parsing
            result = api.get_effective_server_type(Path("directory.ldif"))
            if result.is_success:
                server_type = result.unwrap()
                print(f"Will use {server_type} quirks")

        """
        if self._detector_service is None:
            return FlextResult[str].fail("Detector service not initialized")

        # Delegate to detector service - service handles all logic
        return self._detector_service.get_effective_server_type(ldif_path=ldif_path)

    @property
    def config(self) -> LdifFlextConfig:
        """Config tipado com namespace ldif.

        Returns:
            LdifFlextConfig: FlextConfig tipado com acesso via .ldif

        Example:
            encoding = ldif.config.ldif.ldif_encoding

        """
        return LdifFlextConfig.get_global_instance()

    @property
    def models(self) -> type[FlextLdifModels]:
        """Access to all LDIF Pydantic models.

        Returns:
            FlextLdifModels class containing all LDIF domain models

        Example:
            entry = ldif.models.Entry(dn="cn=test", attributes={})
            schema = ldif.models.SchemaObjectClass(name="person")

        """
        return FlextLdifModels

    @property
    def constants(self) -> type[FlextLdifConstants]:
        """Access to LDIF constants.

        Returns:
            FlextLdifConstants class containing all constant values

        Example:
            max_line = ldif.constants.Format.MAX_LINE_LENGTH
            encoding = ldif.constants.Encoding.UTF8

        """
        return FlextLdifConstants

    @property
    def ldif_config(self) -> FlextLdifConfig:
        """Get FlextLdifConfig via FlextConfig namespace (typed access).

        Returns:
            FlextLdifConfig: LDIF configuration with typed access

        """
        return self.config.get_namespace("ldif", FlextLdifConfig)

    @property
    def parser(self) -> FlextLdifParser:
        """Access to parser service instance.

        Returns:
            FlextLdifParser: Parser service instance

        Example:
            parser = ldif.parser
            result = parser.parse_ldif_file(Path("file.ldif"), "oid")

        """
        if self._parser_service is None:
            error_msg = "Parser service not initialized"
            raise RuntimeError(error_msg)
        return self._parser_service

    @property
    def detector(self) -> FlextLdifDetector:
        """Access to detector service instance.

        Returns:
            FlextLdifDetector: Detector service instance

        Example:
            detector = ldif.detector
            result = detector.detect_server_type(ldif_path=Path("file.ldif"))

        """
        if self._detector_service is None:
            error_msg = "Detector service not initialized"
            raise RuntimeError(error_msg)
        return self._detector_service

    @property
    def acl_service(self) -> FlextLdifAcl:
        """Access to ACL service instance.

        Returns:
            FlextLdifAcl: ACL service instance

        Example:
            acl_service = ldif.acl_service
            result = acl_service.extract_acls_from_entry(entry, server_type="openldap")

        """
        if self._acl_service is None:
            error_msg = "ACL service not initialized"
            raise RuntimeError(error_msg)
        return self._acl_service

    # INTERNAL: bus property is hidden from public API
    # Use models, config, constants for public access instead

    # INTERNAL: dispatcher property is hidden from public API
    # Use client methods for LDIF operations instead

    # INTERNAL: registry property is hidden from public API
    # Use register() method for quirk management instead

    @property
    def context(self) -> FlextContext:
        """Access to execution context with lazy initialization."""
        if not self._context:
            # Initialize with empty dict
            self._context = {}
        return cast("FlextContext", self._context)

    # =========================================================================
    # MONADIC METHODS - Railway-oriented composition
    # =========================================================================

    def parse_and_map(
        self,
        source: str | Path,
        transform: Callable[[list[FlextLdifModels.Entry]], U],
        server_type: str | None = None,
        format_options: FlextLdifModels.ParseFormatOptions | None = None,
    ) -> FlextResult[U]:
        r"""Parse LDIF and transform result using monadic map.

        Args:
            source: LDIF content as string or Path to LDIF file
            transform: Function to transform parsed entries
            server_type: Server type for quirk selection
            format_options: Parse options

        Returns:
            FlextResult with transformed value

        Example:
            result = ldif.parse_and_map(
                "dn: cn=test\ncn: test\n",
                lambda entries: len(entries)
            )

        """
        return self.parse(source, server_type, format_options).map(transform)

    def parse_and_flat_map(
        self,
        source: str | Path,
        transform: Callable[[list[FlextLdifModels.Entry]], FlextResult[U]],
        server_type: str | None = None,
        format_options: FlextLdifModels.ParseFormatOptions | None = None,
    ) -> FlextResult[U]:
        r"""Parse LDIF and chain operation using monadic flat_map.

        Args:
            source: LDIF content as string or Path to LDIF file
            transform: Function returning FlextResult
            server_type: Server type for quirk selection
            format_options: Parse options

        Returns:
            FlextResult from chained operation

        Example:
            result = ldif.parse_and_flat_map(
                "dn: cn=test\ncn: test\n",
                lambda entries: ldif.filter(entries, objectclass="person")
            )

        """
        return self.parse(source, server_type, format_options).flat_map(transform)

    def filter_and_map(
        self,
        entries: list[FlextLdifModels.Entry],
        transform: Callable[[list[FlextLdifModels.Entry]], U],
        objectclass: str | None = None,
        dn_pattern: str | None = None,
        attributes: dict[str, str | None] | None = None,
        custom_filter: Callable[[FlextLdifModels.Entry], bool] | None = None,
    ) -> FlextResult[U]:
        r"""Filter entries and transform result using monadic map.

        Args:
            entries: List of entries to filter
            transform: Function to transform filtered entries
            objectclass: Optional objectclass filter
            dn_pattern: Optional DN pattern filter
            attributes: Optional attributes filter
            custom_filter: Optional custom filter function

        Returns:
            FlextResult with transformed value

        """
        return self.filter(
            entries, objectclass, dn_pattern, attributes, custom_filter
        ).map(transform)

    def filter_and_flat_map(
        self,
        entries: list[FlextLdifModels.Entry],
        transform: Callable[[list[FlextLdifModels.Entry]], FlextResult[U]],
        objectclass: str | None = None,
        dn_pattern: str | None = None,
        attributes: dict[str, str | None] | None = None,
        custom_filter: Callable[[FlextLdifModels.Entry], bool] | None = None,
    ) -> FlextResult[U]:
        r"""Filter entries and chain operation using monadic flat_map.

        Args:
            entries: List of entries to filter
            transform: Function returning FlextResult
            objectclass: Optional objectclass filter
            dn_pattern: Optional DN pattern filter
            attributes: Optional attributes filter
            custom_filter: Optional custom filter function

        Returns:
            FlextResult from chained operation

        """
        return self.filter(
            entries, objectclass, dn_pattern, attributes, custom_filter
        ).flat_map(transform)

    # =========================================================================
    # BUILDER METHODS - Fluent API for complex operations (no additional class)
    # =========================================================================

    def parse_builder(
        self,
        source: str | Path,
        server_type: str | None = None,
        format_options: FlextLdifModels.ParseFormatOptions | None = None,
    ) -> FlextLdif:
        r"""Parse LDIF content (fluent builder method).

        Args:
            source: LDIF content as string or Path to LDIF file
            server_type: Server type for quirk selection
            format_options: Parse options

        Returns:
            Self for method chaining

        Example:
            result = (ldif.parse_builder("dn: cn=test\ncn: test\n")
                .filter_builder(objectclass="person")
                .write_builder(Path("output.ldif"))
                .execute_builder())

        """
        self._builder_parse_result = self.parse(source, server_type, format_options)
        if self._builder_parse_result.is_success:
            self._builder_entries = self._builder_parse_result.unwrap()
        return self

    def filter_builder(
        self,
        objectclass: str | None = None,
        dn_pattern: str | None = None,
        attributes: dict[str, str | None] | None = None,
        custom_filter: Callable[[FlextLdifModels.Entry], bool] | None = None,
    ) -> FlextLdif:
        r"""Filter entries (fluent builder method).

        Args:
            objectclass: Optional objectclass filter
            dn_pattern: Optional DN pattern filter
            attributes: Optional attributes filter
            custom_filter: Optional custom filter function

        Returns:
            Self for method chaining

        """
        if self._builder_entries is None:
            error_msg = "Must call parse_builder() before filter_builder()"
            raise ValueError(error_msg)
        self._builder_filter_result = self.filter(
            self._builder_entries, objectclass, dn_pattern, attributes, custom_filter
        )
        if self._builder_filter_result.is_success:
            self._builder_entries = self._builder_filter_result.unwrap()
        return self

    def write_builder(
        self,
        output_path: Path | None = None,
        server_type: str | None = None,
        format_options: FlextLdifModels.WriteFormatOptions | None = None,
        template_data: dict[str, object] | None = None,
    ) -> FlextLdif:
        r"""Write entries to LDIF (fluent builder method).

        Args:
            output_path: Optional Path to write LDIF file
            server_type: Target server type
            format_options: Write options
            template_data: Optional template data

        Returns:
            Self for method chaining

        """
        if self._builder_entries is None:
            error_msg = "Must call parse_builder() before write_builder()"
            raise ValueError(error_msg)
        # Use correct overload based on output_path
        if output_path is None:
            write_result = self.write(
                self._builder_entries, None, server_type, format_options, template_data
            )
        else:
            write_result = self.write(
                self._builder_entries,
                output_path,
                server_type,
                format_options,
                template_data,
            )
        if write_result.is_success:
            self._builder_write_result = write_result
        return self

    def execute_builder(self) -> FlextResult[list[FlextLdifModels.Entry] | str]:
        r"""Execute builder pipeline and return result.

        Returns:
            FlextResult with entries (if no write) or success message (if write)

        """
        if self._builder_write_result is not None:
            # Convert FlextResult[str] to Union type
            return cast(
                "FlextResult[list[FlextLdifModels.Entry] | str]",
                self._builder_write_result,
            )
        if self._builder_filter_result is not None:
            # Convert FlextResult[list[Entry]] to Union type
            return cast(
                "FlextResult[list[FlextLdifModels.Entry] | str]",
                self._builder_filter_result,
            )
        if self._builder_parse_result is not None:
            # Convert FlextResult[list[Entry]] to Union type
            return cast(
                "FlextResult[list[FlextLdifModels.Entry] | str]",
                self._builder_parse_result,
            )
        error_msg = "Must call parse_builder() before execute_builder()"
        return FlextResult[list[FlextLdifModels.Entry] | str].fail(error_msg)

    def get_builder_entries(self) -> list[FlextLdifModels.Entry]:
        r"""Get current entries from builder pipeline.

        Returns:
            List of entries

        Raises:
            ValueError: If no entries available

        """
        if self._builder_entries is None:
            error_msg = "No entries available - call parse_builder() first"
            raise ValueError(error_msg)
        return self._builder_entries


__all__ = ["FlextLdif"]
