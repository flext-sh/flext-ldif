"""LDIF Migration Pipeline - Direct Implementation.

Zero private methods - everything delegates to public services.
Pure railway-oriented programming with FlextResult chains.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Final, cast

from flext_core import (
    FlextLogger,
    FlextResult,
    t,
    u,
)
from pydantic import PrivateAttr

from flext_ldif._models.config import FlextLdifModelsConfig
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif._models.results import (
    FlextLdifModelsResults,
    _CategoryPaths,
    _FlexibleCategories,
)
from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.categorization import FlextLdifCategorization
from flext_ldif.services.filters import FlextLdifFilters
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.sorting import FlextLdifSorting
from flext_ldif.services.writer import FlextLdifWriter
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities

logger: Final = FlextLogger(__name__)


class FlextLdifMigrationPipeline(FlextLdifServiceBase[FlextLdifModels.EntryResult]):
    """LDIF Migration Pipeline - Direct Implementation.

    Business Rule: Migration pipeline orchestrates complete LDIF migration workflow:
    parse → validate → categorize → filter → sort → write. All operations use public
    service APIs via dependency injection. Pipeline supports categorized output mode
    (separate files per category) and unified mode (single output file).

    Implication: Pipeline enables end-to-end migration with comprehensive error handling.
    All operations maintain RFC compliance while adapting to server-specific requirements.
    Events are emitted for audit trail and monitoring.

    Zero private methods - pure service orchestration.
    All logic delegated to public service methods.

    Design:
    - FlextLdifParser: parse files
    - FlextLdifCategorization: validate, categorize, filter
    - FlextLdifSorting: sort entries
    - FlextLdifWriter: write outputs
    - FlextLdifUtilities: events

    Example:
        pipeline = FlextLdifMigrationPipeline(
            input_dir=Path("source"),
            output_dir=Path("target"),
            mode="categorized",
            categorization_rules={
                "hierarchy_objectclasses": ["organizationalUnit"],
                "user_objectclasses": ["inetOrgPerson"],
                "group_objectclasses": ["groupOfNames"],
                "acl_attributes": ["aci"],
            },
            source_server=FlextLdifConstants.ServerTypes.OID,
            target_server=FlextLdifConstants.ServerTypes.OUD,
        )
        result = pipeline.execute()

    """

    # Private attributes for frozen model compatibility
    # Business Rule: PrivateAttr requires default values for Pydantic v2 compatibility.
    # All values are set via object.__setattr__() in __init__ for frozen model support.
    # Defaults here are placeholders that get overwritten during initialization.
    _mode: FlextLdifConstants.LiteralTypes.MigrationModeLiteral = PrivateAttr(
        default="simple",
    )
    _input_dir: Path = PrivateAttr(default_factory=Path)
    _output_dir: Path = PrivateAttr(default_factory=Path)
    _input_filename: str | None = PrivateAttr(default=None)
    _output_filename: str = PrivateAttr(default="migrated.ldif")
    _input_files: list[str] = PrivateAttr(default_factory=list)
    _output_files: dict[FlextLdifConstants.Categories, str] = PrivateAttr(
        default_factory=dict,
    )
    _source_server: FlextLdifConstants.LiteralTypes.ServerTypeLiteral = PrivateAttr(
        default="rfc",
    )
    _target_server: FlextLdifConstants.LiteralTypes.ServerTypeLiteral = PrivateAttr(
        default="rfc",
    )
    _sort_hierarchically: bool = PrivateAttr(default=False)
    _write_opts: FlextLdifModels.WriteFormatOptions = PrivateAttr(
        default_factory=FlextLdifModels.WriteFormatOptions,
    )
    # Service instances - initialized in __init__ via object.__setattr__
    # Using default_factory with lambda to create valid instances for type safety
    # __init__ overwrites these with properly configured instances
    _categorization: FlextLdifCategorization = PrivateAttr(
        default_factory=FlextLdifCategorization,
    )
    _parser: FlextLdifParser = PrivateAttr(default_factory=FlextLdifParser)
    _writer: FlextLdifWriter = PrivateAttr(default_factory=FlextLdifWriter)
    _dn_registry: FlextLdifModels.DnRegistry = PrivateAttr(
        default_factory=FlextLdifModels.DnRegistry,
    )

    @staticmethod
    def normalize_migration_config(
        migration_config: (
            FlextLdifModels.MigrationConfig
            | FlextLdifTypes.Migration.MigrationConfigDict
            | None
        ),
    ) -> FlextResult[FlextLdifModels.MigrationConfig]:
        """Convert dict to MigrationConfig model using FlextResult.

        Uses FlextResult for error handling - no None returns.

        Args:
            migration_config: MigrationConfig model, dict, or None

        Returns:
            FlextResult with MigrationConfig model or error if None/invalid

        """
        if migration_config is None:
            return FlextResult[FlextLdifModels.MigrationConfig].fail(
                "MigrationConfig cannot be None",
            )
        if isinstance(migration_config, FlextLdifModels.MigrationConfig):
            return FlextResult[FlextLdifModels.MigrationConfig].ok(migration_config)
        if isinstance(migration_config, dict):
            try:
                model = FlextLdifModels.MigrationConfig.model_validate(migration_config)
                return FlextResult[FlextLdifModels.MigrationConfig].ok(model)
            except Exception as e:
                return FlextResult[FlextLdifModels.MigrationConfig].fail(
                    f"Failed to validate MigrationConfig from dict: {e}",
                )
        return FlextResult[FlextLdifModels.MigrationConfig].fail(
            f"Invalid MigrationConfig type: {type(migration_config).__name__}",
        )

    @staticmethod
    def detect_migration_mode(
        config_model: FlextLdifModels.MigrationConfig | None,
        categorization_rules: FlextLdifModels.CategoryRules | None,
    ) -> FlextLdifConstants.LiteralTypes.MigrationModeLiteral:
        """Auto-detect migration mode based on parameters.

        Returns:
            MigrationModeLiteral: One of "simple", "categorized", or "structured"

        """
        if config_model is not None:
            return "structured"
        if categorization_rules is not None:
            return "categorized"
        return "simple"

    @staticmethod
    def _get_default_write_options() -> FlextLdifModels.WriteFormatOptions:
        """Get default WriteFormatOptions with common settings."""
        return FlextLdifModels.WriteFormatOptions(
            line_width=78,
            respect_attribute_order=True,
            sort_attributes=False,
            write_hidden_attributes_as_comments=False,
            write_metadata_as_comments=False,
            include_version_header=True,
            include_timestamps=False,
            base64_encode_binary=False,
            restore_original_format=False,
            write_empty_values=True,
            normalize_attribute_names=False,
            include_dn_comments=False,
            write_migration_header=False,
            migration_header_template=None,
            write_rejection_reasons=False,
            write_transformation_comments=False,
            include_removal_statistics=False,
            ldif_changetype=None,
            ldif_modify_operation="add",
            write_original_entry_as_comment=False,
            entry_category=None,
            acl_attribute_names=frozenset(),
            comment_acl_in_non_acl_phases=True,
            use_rfc_attribute_order=False,
            rfc_order_priority_attributes=["objectClass"],
        )

    @staticmethod
    def get_write_options_for_mode(
        mode: FlextLdifConstants.LiteralTypes.MigrationModeLiteral,
        write_options: (
            FlextLdifModels.WriteFormatOptions
            | FlextLdifModelsConfig.WriteFormatOptions
            | FlextLdifTypes.Migration.WriteFormatOptionsDict
            | None
        ),
        config_model: FlextLdifModels.MigrationConfig | None,
        **format_kwargs: (
            t.ScalarValue
            | list[str]
            | frozenset[str]
            | dict[str, t.ScalarValue | list[str]]
        ),
    ) -> FlextResult[FlextLdifModels.WriteFormatOptions]:
        """Set default write options for structured and categorized modes using FlextResult.

        Architecture:
            - Uses u.build_options_from_kwargs for automatic conversion
            - FlextLdifConfig is the source of truth for all write options
            - This method allows CLI overrides via write_options parameter or **format_kwargs
            - If no override, gets from config and applies mode-specific settings
            - Always returns WriteFormatOptions Pydantic model (never dict)

        Uses FlextResult for error handling - no None returns.

        Args:
            mode: Migration mode ("structured", "categorized", or "simple")
            write_options: WriteFormatOptions model, dict, or None (CLI override)
            config_model: MigrationConfig model or None
            **format_kwargs: Individual option overrides (snake_case field names)

        Returns:
            FlextResult with WriteFormatOptions Pydantic model or error

        """
        # Use u.build_options_from_kwargs for automatic conversion
        default_factory = FlextLdifMigrationPipeline._get_default_write_options
        mode_overrides: FlextLdifTypes.Migration.WriteFormatOptionsDict = {}

        # Apply mode-specific overrides
        match mode:
            case "structured":
                if config_model is None:
                    return FlextResult[FlextLdifModels.WriteFormatOptions].fail(
                        "MigrationConfig required for structured mode",
                    )
                mode_overrides = {
                    "fold_long_lines": False,
                    "write_removed_attributes_as_comments": config_model.write_removed_as_comments,
                }
            case "categorized":
                mode_overrides = {"fold_long_lines": False}
            case "simple":
                mode_overrides = {"fold_long_lines": True}
            case _:
                return FlextResult[FlextLdifModels.WriteFormatOptions].fail(
                    f"Invalid migration mode: {mode}",
                )

        # Merge all overrides: mode_overrides < format_kwargs < explicit write_options
        # Convert frozenset to list for t.GeneralValueType compatibility
        all_kwargs: dict[
            str,
            t.ScalarValue
            | list[str]
            | dict[str, t.ScalarValue | list[str]],
        ] = {}
        for k, v in {**mode_overrides, **format_kwargs}.items():
            if isinstance(v, frozenset):
                all_kwargs[k] = list(v)
            else:
                all_kwargs[k] = v

        # Type narrowing: convert dict to WriteFormatOptions if needed
        explicit_options_typed: FlextLdifModels.WriteFormatOptions | None = None
        if write_options is not None:
            if isinstance(write_options, FlextLdifModels.WriteFormatOptions):
                explicit_options_typed = write_options
            elif isinstance(write_options, dict):
                # Convert dict to WriteFormatOptions model
                explicit_options_typed = (
                    FlextLdifModels.WriteFormatOptions.model_validate(write_options)
                )
            else:
                msg = f"Expected WriteFormatOptions | dict, got {type(write_options)}"
                raise TypeError(msg)

        # Use build_options_from_kwargs for automatic conversion
        return u.build_options_from_kwargs(
            model_class=FlextLdifModels.WriteFormatOptions,
            explicit_options=explicit_options_typed,
            default_factory=default_factory,
            **all_kwargs,
        )

    @staticmethod
    def validate_simple_mode_params(
        input_filename: str | None,
        output_filename: str | None,
    ) -> FlextResult[bool]:
        """Validate requirements for simple mode."""
        if input_filename is not None and output_filename is None:
            return FlextResult[bool].fail(
                "output_filename is required when input_filename is specified",
            )
        return FlextResult[bool].ok(True)

    @staticmethod
    def normalize_category_rules(
        categorization_rules: (
            FlextLdifModels.CategoryRules
            | FlextLdifTypes.Migration.CategoryRulesDict
            | None
        ),
    ) -> FlextResult[FlextLdifModels.CategoryRules | None]:
        """Normalize categorization rules to CategoryRules model.

        Args:
            categorization_rules: CategoryRules model, dict, or None

        Returns:
            FlextResult with CategoryRules model or None

        """
        if categorization_rules is None:
            return FlextResult[FlextLdifModels.CategoryRules | None].ok(None)
        if isinstance(categorization_rules, FlextLdifModels.CategoryRules):
            return FlextResult[FlextLdifModels.CategoryRules | None].ok(
                categorization_rules,
            )
        if isinstance(categorization_rules, dict):
            try:
                model = FlextLdifModels.CategoryRules.model_validate(
                    categorization_rules,
                )
                return FlextResult[FlextLdifModels.CategoryRules | None].ok(model)
            except Exception as e:
                return FlextResult[FlextLdifModels.CategoryRules | None].fail(
                    f"Failed to validate CategoryRules: {e}",
                )
        # Try model_dump if it's a Pydantic model (not a dict)
        if not isinstance(categorization_rules, dict) and hasattr(
            categorization_rules, "model_dump"
        ):
            try:
                model = FlextLdifModels.CategoryRules.model_validate(
                    categorization_rules.model_dump(),
                )
                return FlextResult[FlextLdifModels.CategoryRules | None].ok(model)
            except Exception as e:
                return FlextResult[FlextLdifModels.CategoryRules | None].fail(
                    f"Failed to validate CategoryRules from model_dump: {e}",
                )
        return FlextResult[FlextLdifModels.CategoryRules | None].fail(
            f"Invalid CategoryRules type: {type(categorization_rules).__name__}",
        )

    @staticmethod
    def normalize_whitelist_rules(
        schema_whitelist_rules: (
            FlextLdifModels.WhitelistRules
            | FlextLdifTypes.Migration.WhitelistRulesDict
            | None
        ),
    ) -> FlextResult[FlextLdifModels.WhitelistRules | None]:
        """Normalize whitelist rules to WhitelistRules model.

        Args:
            schema_whitelist_rules: WhitelistRules model, dict, or None

        Returns:
            FlextResult with WhitelistRules model or None

        """
        if schema_whitelist_rules is None:
            return FlextResult[FlextLdifModels.WhitelistRules | None].ok(None)
        if isinstance(schema_whitelist_rules, FlextLdifModels.WhitelistRules):
            return FlextResult[FlextLdifModels.WhitelistRules | None].ok(
                schema_whitelist_rules,
            )
        if isinstance(schema_whitelist_rules, dict):
            try:
                model = FlextLdifModels.WhitelistRules.model_validate(
                    schema_whitelist_rules,
                )
                return FlextResult[FlextLdifModels.WhitelistRules | None].ok(model)
            except Exception as e:
                return FlextResult[FlextLdifModels.WhitelistRules | None].fail(
                    f"Failed to validate WhitelistRules: {e}",
                )
        # Try model_dump if it's a Pydantic model (not a dict)
        if not isinstance(schema_whitelist_rules, dict) and hasattr(
            schema_whitelist_rules, "model_dump"
        ):
            try:
                model = FlextLdifModels.WhitelistRules.model_validate(
                    schema_whitelist_rules.model_dump(),
                )
                return FlextResult[FlextLdifModels.WhitelistRules | None].ok(model)
            except Exception as e:
                return FlextResult[FlextLdifModels.WhitelistRules | None].fail(
                    f"Failed to validate WhitelistRules from model_dump: {e}",
                )
        return FlextResult[FlextLdifModels.WhitelistRules | None].fail(
            f"Invalid WhitelistRules type: {type(schema_whitelist_rules).__name__}",
        )

    def __init__(
        self,
        input_dir: str | Path,
        output_dir: str | Path,
        mode: FlextLdifConstants.LiteralTypes.MigrationModeLiteral = "simple",
        input_filename: str | None = None,
        output_filename: str = "migrated.ldif",
        categorization_rules: (
            FlextLdifModels.CategoryRules
            | FlextLdifTypes.Migration.CategoryRulesDict
            | None
        ) = None,
        input_files: list[str] | None = None,
        output_files: dict[FlextLdifConstants.Categories, str] | None = None,
        schema_whitelist_rules: FlextLdifModels.WhitelistRules | None = None,
        source_server: FlextLdifConstants.LiteralTypes.ServerTypeLiteral = "rfc",
        target_server: FlextLdifConstants.LiteralTypes.ServerTypeLiteral = "rfc",
        forbidden_attributes: list[str] | None = None,
        forbidden_objectclasses: list[str] | None = None,
        base_dn: str | None = None,
        *,
        sort_entries_hierarchically: bool = False,
        write_options: FlextLdifModels.WriteFormatOptions | None = None,
    ) -> None:
        """Initialize pipeline.

        Business Rule: Pipeline initialization validates mode and required parameters.
        Categorized mode requires categorization_rules. All private attributes use
        object.__setattr__ for frozen model compatibility. Service instances are
        created via dependency injection for testability.

        Implication: Pipeline configuration enables flexible migration workflows.
        Service instances are created once and reused throughout migration execution.

        Args:
            input_dir: Input directory containing LDIF files
            output_dir: Output directory for migrated files
            mode: Migration mode ("simple" or "categorized")
            input_filename: Optional single input file (simple mode)
            output_filename: Output filename (simple mode, default: "migrated.ldif")
            categorization_rules: Category rules for categorized mode
            input_files: Optional list of input files to process
            output_files: Optional dict mapping categories to output filenames
            schema_whitelist_rules: Optional schema whitelist rules
            source_server: Source server type (default: "rfc")
            target_server: Target server type (default: "rfc")
            forbidden_attributes: Optional list of forbidden attributes
            forbidden_objectclasses: Optional list of forbidden objectClasses
            base_dn: Optional base DN for filtering
            sort_entries_hierarchically: Whether to sort entries hierarchically
            write_options: Optional write format options

        """
        super().__init__()

        # Validate
        if mode not in {"simple", "categorized"}:
            msg = f"Invalid mode: {mode}"
            raise ValueError(msg)
        if mode == "categorized" and not categorization_rules:
            msg = "Categorized mode requires categorization_rules"
            raise ValueError(msg)

        # Store parameters as private instance attributes
        # Business Rule: Private attributes use object.__setattr__ for frozen model compatibility
        object.__setattr__(self, "_mode", mode)
        object.__setattr__(self, "_input_dir", Path(input_dir))
        object.__setattr__(self, "_output_dir", Path(output_dir))
        object.__setattr__(self, "_input_filename", input_filename)
        object.__setattr__(self, "_output_filename", output_filename)
        # Validate input_files - use empty list if None, but preserve actual list
        # Business Rule: Input files list uses PrivateAttr for frozen model compatibility
        # Use object.__setattr__ for PrivateAttr in frozen models
        if input_files is None:
            object.__setattr__(self, "_input_files", [])
        else:
            object.__setattr__(self, "_input_files", input_files)
        # Validate output_files - use defaults if None
        # Business Rule: Output files dict uses object.__setattr__ for frozen model compatibility
        if output_files is None:
            object.__setattr__(
                self,
                "_output_files",
                {
                    FlextLdifConstants.Categories.SCHEMA: "00-schema.ldif",
                    FlextLdifConstants.Categories.HIERARCHY: "01-hierarchy.ldif",
                    FlextLdifConstants.Categories.USERS: "02-users.ldif",
                    FlextLdifConstants.Categories.GROUPS: "03-groups.ldif",
                    FlextLdifConstants.Categories.ACL: "04-acl.ldif",
                    FlextLdifConstants.Categories.REJECTED: "05-rejected.ldif",
                },
            )
        else:
            object.__setattr__(self, "_output_files", output_files)
        object.__setattr__(self, "_source_server", source_server)
        object.__setattr__(self, "_target_server", target_server)
        object.__setattr__(self, "_sort_hierarchically", sort_entries_hierarchically)
        # Architecture: Model defaults are used, CLI can override via write_options
        if write_options is not None:
            object.__setattr__(self, "_write_opts", write_options)
        else:
            # Use model defaults (Field(default=...) definitions)
            object.__setattr__(
                self, "_write_opts", FlextLdifModels.WriteFormatOptions()
            )

        # Create service instances (all public APIs)
        # Business Rule: Service instances use object.__setattr__ for frozen model compatibility
        object.__setattr__(
            self,
            "_categorization",
            FlextLdifCategorization(
                categorization_rules=categorization_rules,
                schema_whitelist_rules=schema_whitelist_rules,
                forbidden_attributes=forbidden_attributes,
                forbidden_objectclasses=forbidden_objectclasses,
                base_dn=base_dn,
                server_type=source_server,
            ),
        )
        object.__setattr__(self, "_parser", FlextLdifParser())
        object.__setattr__(self, "_writer", FlextLdifWriter())
        # Create DN registry for case normalization during migration
        object.__setattr__(self, "_dn_registry", FlextLdifModels.DnRegistry())

    def _create_output_directory(self) -> FlextResult[bool]:
        """Create output directory with proper error handling.

        Business Rule: Output directory creation uses Path.mkdir with parents=True and
        exist_ok=True to ensure directory exists. Errors are captured and returned as
        FlextResult failures.

        Implication: Safe directory creation that handles existing directories gracefully.
        Parent directories are created automatically if needed.

        Returns:
            FlextResult with True on success, error message on failure

        """
        try:
            self._output_dir.mkdir(parents=True, exist_ok=True)
            return FlextResult[bool].ok(True)
        except OSError as e:
            return FlextResult[bool].fail(f"Failed to create output dir: {e}")

    def _determine_files(self) -> list[str]:
        """Determine which LDIF files to parse based on mode.

        Business Rule: File determination follows mode-specific logic. Simple mode uses
        input_filename if provided, otherwise globs all .ldif files in input_dir. Categorized
        mode uses input_files list if provided, otherwise globs all .ldif files. Files are
        sorted alphabetically for deterministic processing.

        Implication: Flexible file selection supports both explicit file lists and automatic
        discovery. Sorting ensures consistent processing order across runs.

        Returns:
            List of LDIF filenames to process

        """
        if self._mode == "simple":
            return (
                [self._input_filename]
                if self._input_filename
                else sorted([f.name for f in self._input_dir.glob("*.ldif")])
            )
        return self._input_files or sorted(
            [f.name for f in self._input_dir.glob("*.ldif")],
        )

    def _parse_files(
        self,
        files: list[str],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse all input LDIF files using parser service.

        Business Rule: File parsing iterates through input files, validates existence,
        and delegates to FlextLdifParser.parse_ldif_file() with normalized server type.
        All entries from multiple files are aggregated into a single list. Missing files
        are logged as warnings but do not fail the entire operation.

        Implication: Robust parsing that handles missing files gracefully. Server type
        normalization ensures consistent parsing behavior across different server types.

        Args:
            files: List of LDIF filenames to parse

        Returns:
            FlextResult with aggregated list of entries from all files

        """
        all_entries: list[FlextLdifModels.Entry] = []

        for filename in files:
            file_path = self._input_dir / filename
            if not file_path.exists():
                logger.warning(
                    "LDIF file not found, skipping",
                    file_path=str(file_path),
                    filename=filename,
                )
                continue

            # Normalize server type to ServerTypeLiteral
            normalized_source = FlextLdifConstants.normalize_server_type(
                str(self._source_server),
            )
            parse_result = self._parser.parse_ldif_file(
                file_path,
                server_type=normalized_source,
            )
            if parse_result.is_failure:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Parse failed: {parse_result.error}",
                )

            parse_response = parse_result.unwrap()
            # parse_response is always ParseResponse with entries attribute
            if isinstance(parse_response, FlextLdifModels.ParseResponse):
                # ParseResponse.entries is list[FlextLdifModelsDomains.Entry]
                # which is compatible with list[FlextLdifModels.Entry] (inheritance)
                response_entries = parse_response.entries
                # Convert to list[FlextLdifModels.Entry] explicitly
                entries: list[FlextLdifModels.Entry] = [
                    entry
                    for entry in response_entries
                    if isinstance(entry, FlextLdifModels.Entry)
                ]
            else:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Unexpected parse response type: {type(parse_response).__name__}",
                )
            # Register all DNs in registry for case normalization
            # entries is list[FlextLdifModels.Entry]

            def register_dn(entry: FlextLdifModels.Entry) -> None:
                """Register DN in registry."""
                if entry.dn and entry.dn.value:
                    _ = self._dn_registry.register_dn(entry.dn.value)

            _ = u.process(
                entries,
                register_dn,
                on_error="skip",
            )
            all_entries.extend(entries)
            logger.info(
                "Parsed entries from file",
                filename=filename,
                entries_count=len(entries),
            )

        logger.info(
            "Parsed all files",
            total_entries=len(all_entries),
            files_processed=len(files),
        )
        return FlextResult[list[FlextLdifModels.Entry]].ok(all_entries)

    def _categorize_entries_chain(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[FlextLdifModels.FlexibleCategories]:
        """Categorize entries using categorization service.

        Business Rule: Entry categorization delegates to FlextLdifCategorization.categorize_entries()
        with configured rules. Categories include schema, hierarchy, users, groups, acl, and rejected.
        Categorization uses objectClass and attribute matching rules defined during initialization.

        Implication: Consistent categorization across migration pipeline. Categories enable
        separate processing and output files for different entry types.

        Args:
            entries: List of entries to categorize

        Returns:
            FlextResult with FlexibleCategories mapping categories to entry lists

        """
        """Apply categorization chain using railway pattern."""
        # Apply categorization chain: validate -> categorize -> filter
        validate_result = self._categorization.validate_dns(entries)
        if validate_result.is_failure:
            return FlextResult[FlextLdifModels.FlexibleCategories].fail(
                validate_result.error or "DN validation failed",
            )
        validated_entries = validate_result.unwrap()

        categorize_result = self._categorization.categorize_entries(validated_entries)
        if categorize_result.is_failure:
            return FlextResult[FlextLdifModels.FlexibleCategories].fail(
                categorize_result.error or "Categorization failed",
            )
        categories = categorize_result.unwrap()

        # Filter by base DN (returns FlexibleCategories directly)
        filtered_categories = self._categorization.filter_by_base_dn(categories)

        return FlextResult[FlextLdifModels.FlexibleCategories].ok(filtered_categories)

    def _filter_forbidden_attributes(
        self,
        categories: FlextLdifModels.FlexibleCategories,
    ) -> None:
        """Remove forbidden attributes and objectclasses from entries."""
        forbidden_attrs = self._categorization.forbidden_attributes
        forbidden_ocs = self._categorization.forbidden_objectclasses

        if not forbidden_attrs and not forbidden_ocs:
            return

        for category, cat_entries in categories.items():
            # Don't modify rejected entries (audit trail)
            if category == FlextLdifConstants.Categories.REJECTED:
                continue

            def filter_entry(entry: FlextLdifModels.Entry) -> FlextLdifModels.Entry:
                """Filter entry attributes and objectClasses."""
                filtered_entry = entry

                # Apply attribute filtering
                if forbidden_attrs:
                    # filtered_entry is already FlextLdifModels.Entry from categories
                    attr_result = FlextLdifFilters.remove_attributes(
                        filtered_entry,
                        forbidden_attrs,
                    )
                    if attr_result.is_success:
                        filtered_entry = attr_result.unwrap()

                # Apply objectClass filtering
                if forbidden_ocs:
                    # filtered_entry is already FlextLdifModels.Entry
                    oc_result = FlextLdifFilters.remove_objectclasses(
                        filtered_entry,
                        forbidden_ocs,
                    )
                    if oc_result.is_success:
                        filtered_entry = oc_result.unwrap()

                return filtered_entry

            batch_result = u.process(
                cat_entries,
                filter_entry,
                on_error="skip",
            )
            filtered_entries = cast("list[FlextLdifModels.Entry]", batch_result.value["results"])

            # Replace category entries with filtered entries
            categories[category] = filtered_entries

    def _filter_schema_by_oids(
        self,
        categories: FlextLdifModels.FlexibleCategories,
    ) -> None:
        """Filter schema entries by OIDs if needed."""
        if FlextLdifConstants.Categories.SCHEMA not in categories:
            return

        # categories[SCHEMA] already returns list[FlextLdifModels.Entry]
        schema_result = self._categorization.filter_schema_by_oids(
            categories[FlextLdifConstants.Categories.SCHEMA],
        )
        if schema_result.is_success:
            # Type narrowing: Result returns public models
            # FlexibleCategories now uses FlextLdifModels.Entry directly
            public_entries = schema_result.unwrap()
            categories[FlextLdifConstants.Categories.SCHEMA] = public_entries

    def _duplicate_acl_entries(
        self,
        categories: FlextLdifModels.FlexibleCategories,
    ) -> None:
        """Duplicate entries with ACL attributes to ACL category."""
        acl_attr_names = {"aci"}  # Normalized ACL attribute names
        acl_categories = [
            FlextLdifConstants.Categories.HIERARCHY,
            FlextLdifConstants.Categories.USERS,
            FlextLdifConstants.Categories.GROUPS,
        ]

        for category in acl_categories:
            if category not in categories:
                continue

            for entry in categories[category]:
                # Check if entry has ACL attributes
                if not entry.attributes:
                    continue

                attrs_dict = entry.attributes.attributes
                has_acl = any(
                    attr_name in acl_attr_names for attr_name in attrs_dict
                )

                if has_acl:
                    # Duplicate entry to ACL category (deep copy to avoid shared references)
                    acl_copy = entry.model_copy(deep=True)
                    if FlextLdifConstants.Categories.ACL not in categories:
                        categories[FlextLdifConstants.Categories.ACL] = []
                    categories[FlextLdifConstants.Categories.ACL].append(acl_copy)

    def _apply_categorization(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[FlextLdifModels.FlexibleCategories]:
        """Apply categorization chain using railway pattern."""
        # Step 1: Categorize entries
        categorize_result = self._categorize_entries_chain(entries)
        if categorize_result.is_failure:
            return categorize_result

        categories = categorize_result.unwrap()

        # Step 2: Filter forbidden attributes/objectclasses
        self._filter_forbidden_attributes(categories)

        # Step 3: Filter schema by OIDs
        self._filter_schema_by_oids(categories)

        # Step 4: Duplicate entries with ACL attributes
        self._duplicate_acl_entries(categories)

        return FlextResult[FlextLdifModels.FlexibleCategories].ok(categories)

    def _sort_categories(
        self,
        categories: FlextLdifModels.FlexibleCategories,
    ) -> None:
        """Sort hierarchical categories in-place if configured."""
        if not self._sort_hierarchically:
            return

        for cat in {
            FlextLdifConstants.Categories.HIERARCHY,
            FlextLdifConstants.Categories.USERS,
            FlextLdifConstants.Categories.GROUPS,
        }:
            cat_entries = categories.get(cat)
            if cat_entries:
                # FlexibleCategories uses FlextLdifModels.Entry directly
                sort_result = FlextLdifSorting.sort(
                    entries=cat_entries,
                    target="entries",
                    by="hierarchy",
                )
                if sort_result.is_success:
                    categories[cat] = sort_result.unwrap()
                else:
                    logger.warning(
                        "Failed to sort category entries",
                        category=cat,
                        error=sort_result.error,
                    )
                logger.info(
                    "Sorted category entries hierarchically",
                    category=cat,
                    entries_count=len(cat_entries),
                )

    def _write_simple_mode(
        self,
        categories: FlextLdifModels.FlexibleCategories,
    ) -> FlextResult[tuple[dict[str, str], dict[str, int]]]:
        """Write all entries to a single output file (simple mode).

        Business Rule: Simple mode aggregates all categorized entries into a single list
        and writes to output_filename. Entries are sorted hierarchically if configured.
        Write operation delegates to FlextLdifWriter.write() with target server type
        and format options.

        Implication: Single-file output simplifies migration for simple use cases.
        Hierarchical sorting ensures parent entries precede children for LDAP import.

        Args:
            categories: Categorized entries by category

        Returns:
            FlextResult with tuple of (file_paths dict, entry_counts dict)

        """
        """Write all entries to a single file in simple mode."""
        output_path = self._output_dir / self._output_filename
        all_output_entries = [
            entry for entries in categories.values() for entry in entries
        ]

        # Normalize server type to ServerTypeLiteral
        normalized_target = FlextLdifConstants.normalize_server_type(
            str(self._target_server),
        )
        # all_output_entries is already list[FlextLdifModels.Entry] from categories.values()
        # FlextLdifWriter.write() accepts output_path for file output
        # (output_target parameter is not supported)
        write_result = self._writer.write(
            entries=all_output_entries,
            target_server_type=normalized_target,
            output_path=output_path,
            format_options=self._write_opts,
        )

        if write_result.is_failure:
            return FlextResult[tuple[dict[str, str], dict[str, int]]].fail(
                f"Write failed: {write_result.error}",
            )

        file_paths: dict[str, str] = {"output": str(output_path)}
        entry_counts: dict[str, int] = {"output": len(all_output_entries)}

        logger.info(
            "Wrote entries to file",
            output_path=str(output_path),
            entries_count=len(all_output_entries),
            target_server=self._target_server,
        )

        return FlextResult.ok((file_paths, entry_counts))

    def _build_template_data(
        self,
        category: FlextLdifConstants.Categories,
        phase_num: int,
        entries: list[FlextLdifModels.Entry],
    ) -> dict[str, FlextLdifTypes.TemplateValue]:
        """Build template data for migration headers.

        Business Rule: Template data provides migration metadata for header generation.
        Values include phase numbers, timestamps, server types, entry counts, and
        configuration flags. All values conform to TemplateValue type (ScalarValue | list[str]).

        Implication: Template data enables dynamic header generation with migration context.
        Timestamps use ISO 8601 format for consistency. Server types and categories are
        included for audit trail.

        Args:
            category: Entry category (schema, hierarchy, users, groups, acl, rejected)
            phase_num: Migration phase number (0-5)
            entries: List of entries for this category

        Returns:
            Dictionary mapping template variable names to values

        """
        # Validate base_dn - use empty string if None
        base_dn_value = self._categorization.base_dn
        if base_dn_value is None:
            base_dn_value = ""
        elif not isinstance(base_dn_value, str):
            # Convert to string if not already (defensive programming)
            base_dn_value = str(base_dn_value)

        return {
            "phase": phase_num,
            "phase_name": category.upper(),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source_server": self._source_server,
            "target_server": self._target_server,
            "base_dn": base_dn_value,
            "total_entries": len(entries),
            "processed_entries": len(entries),
            "rejected_entries": 0,
            "schema_whitelist_enabled": bool(
                self._categorization.schema_whitelist_rules is not None,
            ),
            "sort_entries_hierarchically": self._sort_hierarchically,
            "server_type": self._target_server,
        }

    def _prepare_acl_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> list[FlextLdifModels.Entry]:
        """Prepare ACL entries with metadata for DN normalization.

        Business Rule: ACL entries require special metadata preparation for DN normalization.
        Base DN and DN registry flags are added to entry metadata extensions. This enables
        DN case normalization during ACL processing while maintaining entry immutability.

        Implication: ACL entries are prepared with migration context for proper DN handling.
        Metadata extensions preserve original entry structure while adding migration-specific
        information.

        Args:
            entries: List of ACL entries to prepare

        Returns:
            List of entries with updated metadata extensions

        """
        base_dn = self._categorization.base_dn
        entries_with_metadata = []
        for entry in entries:
            # Type narrowing: metadata is always initialized via model_validator
            if entry.metadata is None:
                entries_with_metadata.append(entry)
                continue
            # Build new extensions with base_dn
            extension_updates: dict[str, str | list[str] | None] = {}
            if base_dn:
                extension_updates["base_dn"] = base_dn
            # Store dn_registry reference as string key (retrieve from self at ACL time)
            extension_updates["dn_registry_enabled"] = "true"
            # Create new extensions via model_copy
            new_extensions = entry.metadata.extensions.model_copy(
                update=extension_updates,
            )
            # Update entry with new extensions
            new_metadata = entry.metadata.model_copy(
                update={"extensions": new_extensions},
            )
            updated_entry = entry.model_copy(
                update={"metadata": new_metadata},
            )
            entries_with_metadata.append(updated_entry)
        return entries_with_metadata

    def _write_structured_mode(
        self,
        categories: FlextLdifModels.FlexibleCategories,
    ) -> FlextResult[tuple[dict[str, str], dict[str, int]]]:
        """Write categorized entries to multiple files in structured mode.

        Business Rule: Structured mode writes each category to a separate output file
        with category-specific filenames. Template data is generated for each category
        with phase numbers, timestamps, and migration context. ACL entries receive
        special preparation with DN normalization metadata.

        Implication: Multi-file output enables phased migration with separate files for
        schema, hierarchy, users, groups, ACL, and rejected entries. Template data
        provides migration context in file headers.

        Args:
            categories: Categorized entries by category

        Returns:
            FlextResult with tuple of (file_paths dict, entry_counts dict)

        """
        file_paths: dict[str, str] = {}
        entry_counts: dict[str, int] = {}

        # Map categories to phase numbers for migration headers
        category_to_phase = {
            FlextLdifConstants.Categories.SCHEMA: 0,
            FlextLdifConstants.Categories.HIERARCHY: 1,
            FlextLdifConstants.Categories.USERS: 2,
            FlextLdifConstants.Categories.GROUPS: 3,
            FlextLdifConstants.Categories.ACL: 4,
            FlextLdifConstants.Categories.REJECTED: 5,
        }

        for category, entries in categories.items():
            if not entries:
                continue

            # Type narrowing: ensure category is Categories enum
            if not isinstance(category, FlextLdifConstants.Categories):
                continue

            output_filename = self._output_files.get(category)
            if not output_filename:
                continue

            output_path = self._output_dir / output_filename
            phase_num = category_to_phase.get(category, -1)
            # Type narrowing: entries from Categories are domain models, cast to public
            template_data = self._build_template_data(
                category,
                phase_num,
                entries,
            )

            # Create category-specific WriteFormatOptions for phase-aware processing
            category_write_opts = self._write_opts.model_copy(
                update={"entry_category": category},
            )

            # Prepare entries (add metadata for ACL category)
            # entries is already list[FlextLdifModels.Entry] from categories
            processed_entries = entries
            if category == FlextLdifConstants.Categories.ACL:
                processed_entries = self._prepare_acl_entries(processed_entries)

            # Normalize server type to ServerTypeLiteral
            normalized_target = FlextLdifConstants.normalize_server_type(
                self._target_server,
            )
            # Type narrowing: processed_entries may be mixed type, cast to public for writer
            write_result = self._writer.write(
                entries=processed_entries,
                target_server_type=normalized_target,
                # FlextLdifWriter.write() accepts output_path for file output
                output_path=output_path,
                format_options=category_write_opts,
                _template_data=template_data,
            )

            if write_result.is_failure:
                return FlextResult[tuple[dict[str, str], dict[str, int]]].fail(
                    f"Write {category} failed: {write_result.error}",
                )

            file_paths[category] = str(output_path)
            entry_counts[category] = len(entries)
            logger.info(
                "Wrote entries to category file",
                output_path=str(output_path),
                category=category,
                entries_count=len(entries),
                target_server=self._target_server,
            )

        return FlextResult.ok((file_paths, entry_counts))

    def _write_categories(
        self,
        categories: FlextLdifModels.FlexibleCategories,
    ) -> FlextResult[tuple[dict[str, str], dict[str, int]]]:
        """Write categorized entries to output files.

        Business Rule: Write operation routes to simple or structured mode based on
        pipeline mode configuration. Simple mode writes to single file, structured mode
        writes to multiple category-specific files.

        Implication: Unified write interface that adapts to migration mode. File paths
        and entry counts are tracked for audit and monitoring.

        Args:
            categories: Categorized entries by category

        Returns:
            FlextResult with tuple of (file_paths dict, entry_counts dict)

        """
        if self._mode == "simple":
            return self._write_simple_mode(categories)
        return self._write_structured_mode(categories)

    def execute(self) -> FlextResult[FlextLdifModels.EntryResult]:
        """Execute migration - pure railway pattern with public services.

        Business Rule: Migration execution follows strict workflow: create output directory,
        determine input files, parse entries, categorize/filter, sort (if enabled), and write
        to output files. All steps use Railway-Oriented Programming with FlextResult for
        error handling. Pipeline supports simple mode (single file) and categorized mode
        (multiple files by category).

        Implication: Complete migration workflow with comprehensive error handling and
        event emission. All operations maintain RFC compliance while adapting to server-specific
        requirements. Statistics and file paths are tracked for audit and monitoring.

        Returns:
            FlextResult with EntryResult containing migration statistics and file paths

        """
        start_time = time.time()

        # Step 1: Create output directory
        dir_result = self._create_output_directory()
        if dir_result.is_failure:
            return FlextResult[FlextLdifModels.EntryResult].fail(
                dir_result.error or "Unknown error",
            )

        # Step 2: Determine files to parse
        files = self._determine_files()

        # Step 3: Parse all input files
        entries_result = self._parse_files(files)
        if entries_result.is_failure:
            return FlextResult[FlextLdifModels.EntryResult].fail(
                entries_result.error or "Unknown error",
            )

        # Step 4: Apply categorization chain
        categories_result = self._apply_categorization(entries_result.unwrap())
        if categories_result.is_failure:
            return FlextResult[FlextLdifModels.EntryResult].fail(
                categories_result.error or "Unknown error",
            )

        categories = categories_result.unwrap()

        # Step 5: Sort hierarchically if configured
        self._sort_categories(categories)

        # Step 6: Write output files
        write_result = self._write_categories(categories)
        if write_result.is_failure:
            return FlextResult[FlextLdifModels.EntryResult].fail(
                write_result.error or "Unknown error",
            )

        file_paths, entry_counts = write_result.unwrap()

        # Step 7: Build statistics and emit event
        duration_ms = int((time.time() - start_time) * 1000)
        total_entries = sum(entry_counts.values())
        total_rejected = sum(
            len(v) for v in self._categorization.rejection_tracker.values()
        )
        total_processed = total_entries - entry_counts.get(
            FlextLdifConstants.Categories.REJECTED,
            0,
        )

        error_details = []
        for reason, entries in self._categorization.rejection_tracker.items():
            context = FlextLdifModelsMetadata.DynamicMetadata()
            context.update({"reason": reason, "count": len(entries)})
            # ErrorDetail is in FlextLdifModelsDomains, not FlextLdifModels
            error_details.append(
                FlextLdifModelsDomains.ErrorDetail(
                    item=f"rejected_{reason}",
                    error=f"Rejected {len(entries)} entries: {reason}",
                    context=context,
                ),
            )
        # Create migration event config
        migration_config = FlextLdifModels.MigrationEventConfig(
            migration_operation=f"pipeline_{self._mode}",
            source_server=self._source_server,
            target_server=self._target_server,
            entries_processed=total_entries + total_rejected,
            entries_migrated=total_processed,
            entries_failed=total_rejected,
            migration_duration_ms=duration_ms,
            error_details=error_details,
        )
        event = FlextLdifUtilities.Events.log_and_emit_migration_event(
            logger=logger,
            config=migration_config,
        )

        # Create statistics model
        # Statistics is a PEP 695 type alias - use the underlying class directly
        statistics = FlextLdifModelsResults.Statistics(events=[event])

        # Convert file_paths dict to _CategoryPaths model
        category_paths = _CategoryPaths()
        for category, path in file_paths.items():
            category_paths.set_path(str(category), str(path))

        # Return EntryResult with proper types
        return FlextResult[FlextLdifModels.EntryResult].ok(
            FlextLdifModels.EntryResult(
                entries_by_category=_FlexibleCategories(),  # Empty - data in files
                statistics=statistics,
                file_paths=category_paths,
            ),
        )
