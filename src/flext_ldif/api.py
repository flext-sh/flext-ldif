"""Public facade that wires LDIF services and quirk discovery."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path
from typing import ClassVar, Literal, TypeVar, cast, overload, override

from flext_core import (
    FlextConfig,
    FlextContext,
    FlextResult,
    FlextService,
    FlextTypes,
    FlextUtilities,
)
from pydantic import PrivateAttr

from flext_ldif._models.config import FlextLdifModelsConfig
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif._models.processing import ProcessingResult
from flext_ldif.config import FlextLdifConfigModule
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.servers.base import FlextLdifServersBase
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
from flext_ldif.services.registry import FlextLdifServiceRegistry
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.services.sorting import FlextLdifSorting
from flext_ldif.services.syntax import FlextLdifSyntax
from flext_ldif.services.validation import FlextLdifValidation
from flext_ldif.services.writer import FlextLdifWriter
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities

# Alias for backward compatibility - no circular import
FlextLdifConfig = FlextLdifConfigModule.FlextLdifConfig

# Type variable for monadic transformations
U = TypeVar("U")

# Singleton instance storage (module-level to avoid ModelMetaclass issues)
_instance: FlextLdif | None = None


def _create_filter_service() -> FlextLdifProtocols.Services.FilterServiceProtocol:
    """Return a filter service instance that satisfies the filter protocol."""
    return cast("FlextLdifProtocols.Services.FilterServiceProtocol", FlextLdifFilters())


def _create_categorization_service(
    server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral | str,
) -> FlextLdifProtocols.Services.CategorizationServiceProtocol:
    """Return a categorization service configured for the server type."""
    return cast(
        "FlextLdifProtocols.Services.CategorizationServiceProtocol",
        FlextLdifCategorization(
            server_type=FlextLdifConstants.normalize_server_type(server_type),
        ),
    )


FlextLdifServiceRegistry.register_filter_factory(_create_filter_service)
FlextLdifServiceRegistry.register_categorization_factory(_create_categorization_service)


class FlextLdif(FlextService[FlextLdifTypes.Models.ServiceResponseTypes]):
    """Coordinate LDIF services and quirks behind a single facade.

    The facade owns the service registry, initializes services lazily based on
    :attr:`SERVICE_MAPPING`, and exposes builder helpers that reuse those
    services for parse/filter/write flows without re-instantiation.
    """

    # Service mapping for DRY initialization and access
    SERVICE_MAPPING: ClassVar[dict[FlextLdifConstants.ServiceType, type]] = {
        FlextLdifConstants.ServiceType.PARSER: FlextLdifParser,
        FlextLdifConstants.ServiceType.ACL: FlextLdifAcl,
        FlextLdifConstants.ServiceType.WRITER: FlextLdifWriter,
        FlextLdifConstants.ServiceType.ENTRIES: FlextLdifEntries,
        FlextLdifConstants.ServiceType.ANALYSIS: FlextLdifAnalysis,
        FlextLdifConstants.ServiceType.PROCESSING: FlextLdifProcessing,
        FlextLdifConstants.ServiceType.DETECTOR: FlextLdifDetector,
        FlextLdifConstants.ServiceType.FILTERS: FlextLdifFilters,
        FlextLdifConstants.ServiceType.CATEGORIZATION: FlextLdifCategorization,
        FlextLdifConstants.ServiceType.CONVERSION: FlextLdifConversion,
        FlextLdifConstants.ServiceType.VALIDATION: FlextLdifValidation,
        FlextLdifConstants.ServiceType.SYNTAX: FlextLdifSyntax,
    }

    # Private attributes - dynamically initialized from SERVICE_MAPPING
    # Python 3.13+ best practice: Use union type for service instances
    type ServiceInstance = (
        FlextLdifParser
        | FlextLdifAcl
        | FlextLdifWriter
        | FlextLdifEntries
        | FlextLdifAnalysis
        | FlextLdifProcessing
        | FlextLdifDetector
        | FlextLdifFilters
        | FlextLdifCategorization
        | FlextLdifConversion
        | FlextLdifValidation
        | FlextLdifSyntax
    )
    _services: dict[FlextLdifConstants.ServiceType, ServiceInstance] = PrivateAttr(
        default_factory=dict,
    )

    _context: FlextContext | None = PrivateAttr(default=None)
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

    # Class-level initialization guard to prevent redundant initialization
    _class_initialized: ClassVar[bool] = False

    @classmethod
    def get_instance(cls, config: FlextLdifConfig | None = None) -> FlextLdif:
        """Return the process-wide singleton, creating it on first use."""
        global _instance  # noqa: PLW0603
        if _instance is None:
            # Create instance with config if provided
            if config is not None:
                instance = cls()
                object.__setattr__(instance, "_init_config_value", config)
                _instance = instance
            else:
                # Create empty instance (FlextService v2 doesn't accept positional args)
                _instance = cls()
        # Type narrowing: _instance is not None after check
        if _instance is None:
            msg = "Singleton instance creation failed"
            raise RuntimeError(msg)
        return _instance

    @classmethod
    def _reset_instance(cls) -> None:
        """Reset the cached singleton (testing helper)."""
        global _instance  # noqa: PLW0603
        _instance = None
        # ClassVar can be set directly even in frozen models
        # Use setattr to avoid pyrefly false positive
        setattr(cls, "_class_initialized", False)

    def __init__(self, **kwargs: FlextTypes.GeneralValueType) -> None:
        """Initialize the facade and capture optional LDIF configuration."""
        # Extract 'config' from kwargs to avoid Pydantic extra='forbid' error
        # Store it in _init_config_value for use in model_post_init
        config_value = kwargs.pop("config", None)
        if config_value is not None and isinstance(config_value, FlextLdifConfig):
            # Store temporarily before super().__init__()
            # model_post_init will read it and initialize services with it
            # Use object.__setattr__ for PrivateAttr assignment in frozen models
            object.__setattr__(self, "_init_config_value", config_value)

        # Convert remaining kwargs to dict for FlextService compatibility
        # FlextService.__init__ accepts **data: FlextTypes.GeneralValueType
        # Filter to only scalar values (GeneralValueType includes dict/Sequence)
        service_kwargs: dict[str, FlextTypes.ScalarValue] = {
            k: v
            for k, v in kwargs.items()
            if isinstance(v, (str, int, float, bool, type(None)))
        }

        # Call super().__init__() for Pydantic v2 model initialization
        # This will call model_post_init() which initializes all services
        super().__init__(**service_kwargs)

        # Services initialized in model_post_init for proper initialization order

    def model_post_init(
        self,
        _context: FlextTypes.Metadata | None,
        /,
    ) -> None:
        """Populate service instances after Pydantic initialization."""
        # Initialize context (inherited from FlextService)
        # Context is already initialized by FlextService.__init__()

        # DRY service initialization using mapping
        for service_type, service_class in self.SERVICE_MAPPING.items():
            if service_type == FlextLdifConstants.ServiceType.WRITER:
                # Special case for writer with dependency
                quirk_registry = FlextLdifServer.get_global_instance()
                self._services[service_type] = service_class(
                    server=quirk_registry,
                )
            else:
                self._services[service_type] = service_class()

        # Log initialization
        self.logger.debug("FlextLdif facade initialized")

    @overload
    def _get_service(
        self,
        service_type: Literal[FlextLdifConstants.ServiceType.PARSER],
    ) -> FlextLdifParser: ...

    @overload
    def _get_service(
        self,
        service_type: Literal[FlextLdifConstants.ServiceType.WRITER],
    ) -> FlextLdifWriter: ...

    @overload
    def _get_service(
        self,
        service_type: Literal[FlextLdifConstants.ServiceType.DETECTOR],
    ) -> FlextLdifDetector: ...

    @overload
    def _get_service(
        self,
        service_type: Literal[FlextLdifConstants.ServiceType.ACL],
    ) -> FlextLdifAcl: ...

    @overload
    def _get_service(
        self,
        service_type: Literal[FlextLdifConstants.ServiceType.ANALYSIS],
    ) -> FlextLdifAnalysis: ...

    @overload
    def _get_service(
        self,
        service_type: Literal[FlextLdifConstants.ServiceType.CATEGORIZATION],
    ) -> FlextLdifCategorization: ...

    @overload
    def _get_service(
        self,
        service_type: Literal[FlextLdifConstants.ServiceType.CONVERSION],
    ) -> FlextLdifConversion: ...

    @overload
    def _get_service(
        self,
        service_type: Literal[FlextLdifConstants.ServiceType.ENTRIES],
    ) -> FlextLdifEntries: ...

    @overload
    def _get_service(
        self,
        service_type: Literal[FlextLdifConstants.ServiceType.FILTERS],
    ) -> FlextLdifFilters: ...

    @overload
    def _get_service(
        self,
        service_type: Literal[FlextLdifConstants.ServiceType.PROCESSING],
    ) -> FlextLdifProcessing: ...

    @overload
    def _get_service(
        self,
        service_type: Literal[FlextLdifConstants.ServiceType.VALIDATION],
    ) -> FlextLdifValidation: ...

    @overload
    def _get_service(
        self,
        service_type: Literal[FlextLdifConstants.ServiceType.SYNTAX],
    ) -> FlextLdifSyntax: ...

    def _get_service(
        self,
        service_type: FlextLdifConstants.ServiceType,
    ) -> (
        FlextLdifParser
        | FlextLdifWriter
        | FlextLdifEntries
        | FlextLdifValidation
        | FlextLdifSyntax
        | FlextLdifAcl
        | FlextLdifAnalysis
        | FlextLdifCategorization
        | FlextLdifConversion
        | FlextLdifDetector
        | FlextLdifFilters
        | FlextLdifMigrationPipeline
        | FlextLdifProcessing
        | FlextLdifServer
        | FlextLdifSorting
        | EntryManipulationServices
    ):
        """Get service instance with type safety and error handling.

        DRY helper for service access, eliminating repetitive None checks.

        Args:
            service_type: Type of service to retrieve

        Returns:
            Service instance

        Raises:
            RuntimeError: If service not initialized

        """
        service = self._services.get(service_type)
        if service is None:
            service_name = service_type.value
            msg = f"Service {service_name} not initialized"
            raise RuntimeError(msg)
        return service

    @override
    def execute(
        self,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[FlextLdifTypes.Models.ServiceResponseTypes]:
        """Execute facade self-check and return status.

        Returns:
            FlextResult containing status string

        """
        # Return status string as health check
        status = "FlextLdif facade healthy - all services initialized"
        return FlextResult.ok(status)

    def parse(
        self,
        source: str | Path,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral | None = None,
        format_options: FlextLdifModels.ParseFormatOptions | None = None,
        **format_kwargs: str | float | bool | None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF content from text or file using the parser service."""
        parser_service = self._get_service(FlextLdifConstants.ServiceType.PARSER)

        # Architecture: Options+kwargs pattern
        # - Model provides defaults via Field(default=...) definitions
        # - format_options can override (explicit options pattern)
        # - format_kwargs can override individual options (kwargs pattern)
        options_result = FlextUtilities.Configuration.build_options_from_kwargs(
            model_class=FlextLdifModels.ParseFormatOptions,
            explicit_options=format_options,
            default_factory=FlextLdifModels.ParseFormatOptions,
            **format_kwargs,
        )
        if options_result.is_failure:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Invalid format options: {options_result.error}",
            )
        # Note: format_options validated but not passed to parse() - parser service handles format internally

        # Delegate to parser service - service handles all logic
        parse_result = parser_service.parse(
            source=source,
            server_type=server_type,
        )

        # Service returns ParseResponse - extract entries
        if parse_result.is_success:
            parse_response = parse_result.unwrap()
            # ParseResponse.entries is list[FlextLdifModelsDomains.Entry]
            # FlextLdifModels.Entry extends FlextLdifModelsDomains.Entry
            # Convert domain entries to public Entry models if needed
            entries_raw: list[FlextLdifModelsDomains.Entry] = getattr(
                parse_response, "entries", []
            )
            entries: list[FlextLdifModels.Entry] = [
                (
                    entry
                    if isinstance(entry, FlextLdifModels.Entry)
                    else FlextLdifModels.Entry.model_validate(entry.model_dump())
                )
                for entry in entries_raw
            ]
            return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

        return FlextResult[list[FlextLdifModels.Entry]].fail(
            parse_result.error or "Unknown error",
        )

    # Overloads for write() method
    @overload
    def write(
        self,
        entries: FlextLdifModels.Entry | list[FlextLdifModels.Entry],
        output_path: None = None,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral | None = None,
        format_options: FlextLdifModels.WriteFormatOptions | None = None,
        template_data: FlextLdifTypes.MetadataDictMutable | None = None,
        **format_kwargs: FlextTypes.MetadataAttributeValue,
    ) -> FlextResult[str]: ...

    @overload
    def write(
        self,
        entries: FlextLdifModels.Entry | list[FlextLdifModels.Entry],
        output_path: Path,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral | None = None,
        format_options: FlextLdifModels.WriteFormatOptions | None = None,
        template_data: FlextLdifTypes.MetadataDictMutable | None = None,
        **format_kwargs: FlextTypes.MetadataAttributeValue,
    ) -> FlextResult[str]: ...

    def write(
        self,
        entries: FlextLdifModels.Entry | list[FlextLdifModels.Entry],
        output_path: Path | None = None,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral | None = None,
        format_options: FlextLdifModels.WriteFormatOptions | None = None,
        template_data: FlextLdifTypes.MetadataDictMutable | None = None,
        **format_kwargs: FlextTypes.MetadataAttributeValue,
    ) -> FlextResult[str]:
        """Write entries to LDIF format string or file.

        Args:
            entries: Entry model or list of Entry models to write
            output_path: Optional Path to write LDIF file. If None, returns LDIF string.
            server_type: Target server type for writing. If None, uses RFC.
            format_options: Write options as WriteFormatOptions model
            template_data: Optional dict with template variables for header generation
            **format_kwargs: Individual format option overrides (e.g., line_width=100)

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

            # Write with options model (old pattern - still works)
            options = FlextLdifModels.WriteFormatOptions(
                line_width=100,
                sort_attributes=True,
            )
            result = ldif.write(entries, format_options=options)

            # Write with kwargs (new pattern - more convenient)
            result = ldif.write(entries, line_width=100, sort_attributes=True)

            # Write with template data for header
            result = ldif.write(
                entries,
                Path("output.ldif"),
                template_data={"phase": 1, "source": "OID", "target": "OUD"},
            )

        """
        writer_service = self._get_service(FlextLdifConstants.ServiceType.WRITER)

        # Normalize Entry | list[Entry] to list[Entry]
        entries_list: list[FlextLdifModels.Entry] = (
            [entries] if not isinstance(entries, list) else entries
        )

        # Delegate to writer service - service handles all logic
        target_server = server_type or "rfc"
        output_target: FlextLdifConstants.LiteralTypes.WriterOutputTargetLiteral = (
            "file" if output_path else "string"
        )

        # Architecture: Options+kwargs pattern
        # - Model provides defaults via Field(default=...) definitions
        # - format_options can override (explicit options pattern)
        # - format_kwargs can override individual options (kwargs pattern)
        options_result = FlextUtilities.Configuration.build_options_from_kwargs(
            model_class=FlextLdifModels.WriteFormatOptions,
            explicit_options=format_options,
            default_factory=FlextLdifModels.WriteFormatOptions,
            **format_kwargs,
        )
        if options_result.is_failure:
            return FlextResult[str].fail(
                f"Invalid format options: {options_result.error}",
            )
        resolved_format_options_raw = options_result.unwrap()
        # Writer service accepts WriteFormatOptions directly (not WriteOptions)
        # No conversion needed - writer uses WriteFormatOptions which has all fields including ldif_changetype
        resolved_format_options: (
            FlextLdifModels.WriteFormatOptions
            | FlextLdifModelsDomains.WriteOptions
            | None
        ) = resolved_format_options_raw

        # Convert template_data to correct type if provided
        template_data_converted: (
            dict[str, FlextTypes.ScalarValue | list[str]] | None
        ) = None
        if template_data is not None:
            converted_dict: dict[str, FlextTypes.ScalarValue | list[str]] = {}
            for k, v in template_data.items():
                if isinstance(v, (str, int, float, bool, type(None))):
                    converted_dict[k] = v
                elif isinstance(v, list):
                    # Ensure all items are strings for list[str] type
                    str_list: list[str] = [
                        str(item) for item in v if isinstance(item, str)
                    ]
                    if str_list:
                        converted_dict[k] = str_list
            template_data_converted = converted_dict or None

        write_result = writer_service.write(
            entries=entries_list,
            target_server_type=target_server,
            _output_target=output_target,
            output_path=output_path,
            format_options=resolved_format_options,
            _template_data=template_data_converted,
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
        entry: (
            FlextLdifModels.Entry
            | FlextLdifProtocols.Models.EntryProtocol
            | FlextLdifProtocols.Models.EntryWithDnProtocol
            | dict[str, str | list[str]]
        ),
    ) -> FlextResult[str]:
        """Extract DN (Distinguished Name) from any entry type.

        Delegates to FlextLdifEntries service for SRP compliance.

        Args:
            entry: Entry model, LDAP entry, or dict to extract DN from

        Returns:
            FlextResult containing DN as string

        """
        entries_service = self._get_service(FlextLdifConstants.ServiceType.ENTRIES)
        return entries_service.get_entry_dn(entry)

    def get_entry_attributes(
        self,
        entry: FlextLdifModels.Entry | FlextLdifProtocols.Models.EntryProtocol,
    ) -> FlextResult[FlextLdifTypes.CommonDict.AttributeDict]:
        """Extract attributes from any entry type.

        Delegates to FlextLdifEntries service for SRP compliance.

        Args:
            entry: LDIF or LDAP entry to extract attributes from

        Returns:
            FlextResult containing AttributeDict with attribute names mapped to
            str | list[str] values matching FlextLdifTypes definition.

        """
        entries_service = self._get_service(FlextLdifConstants.ServiceType.ENTRIES)
        # Type narrowing: ensure entry is FlextLdifModels.Entry
        if not isinstance(entry, FlextLdifModels.Entry):
            return FlextResult.fail("Entry must be FlextLdifModels.Entry instance")
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
        entries_service = self._get_service(FlextLdifConstants.ServiceType.ENTRIES)
        return entries_service.create_entry(dn, attributes, objectclasses)

    def get_entry_objectclasses(
        self,
        entry: FlextLdifModels.Entry | FlextLdifProtocols.Models.EntryProtocol,
    ) -> FlextResult[list[str]]:
        """Extract objectClass values from any entry type.

        Delegates to FlextLdifEntries service for SRP compliance.

        Args:
            entry: LDIF or LDAP entry to extract objectClasses from

        Returns:
            FlextResult containing list of objectClass values

        """
        entries_service = self._get_service(FlextLdifConstants.ServiceType.ENTRIES)
        # Type narrowing: ensure entry is FlextLdifModels.Entry
        if not isinstance(entry, FlextLdifModels.Entry):
            return FlextResult.fail("Entry must be FlextLdifModels.Entry instance")
        return entries_service.get_entry_objectclasses(entry)

    def get_attribute_values(
        self,
        attribute: list[str] | str,
    ) -> FlextResult[list[str]]:
        """Extract values from an attribute value object.

        Delegates to FlextLdifEntries service for SRP compliance.

        Args:
            attribute: Attribute value with .values property, list, or string.

        Returns:
            FlextResult containing list of attribute values as strings.

        """
        entries_service = self._get_service(FlextLdifConstants.ServiceType.ENTRIES)
        return entries_service.get_attribute_values(attribute)

    @staticmethod
    def _convert_mode_to_typed(
        mode: str,
    ) -> FlextLdifConstants.LiteralTypes.MigrationModeLiteral:
        """Validate and narrow string mode to typed MigrationMode literal.

        Uses type narrowing with validation instead of manual conversion.
        detect_migration_mode already returns MigrationModeLiteral, so this
        is only needed when mode comes from other sources.
        """
        valid_modes: frozenset[str] = frozenset({"simple", "categorized", "structured"})
        if mode not in valid_modes:
            msg = f"Expected 'simple' | 'categorized' | 'structured', got {mode}"
            raise ValueError(msg)
        # Type narrowing: mode is validated against MigrationModeLiteral values
        # Use type guard pattern for proper narrowing
        if mode == "simple":
            return "simple"
        if mode == "categorized":
            return "categorized"
        if mode == "structured":
            return "structured"
        # This should never be reached due to validation above
        msg = f"Invalid mode: {mode}"
        raise ValueError(msg)

    @staticmethod
    def _narrow_migration_types(
        migration_tuple_raw: tuple[
            FlextLdifModelsConfig.MigrateOptions,
            FlextLdifModels.MigrationConfig,
            FlextLdifModels.CategoryRules,
            FlextLdifModels.WhitelistRules,
        ],
    ) -> tuple[
        FlextLdifModelsConfig.MigrateOptions,
        FlextLdifModels.MigrationConfig,
        FlextLdifModels.CategoryRules,
        FlextLdifModels.WhitelistRules,
    ]:
        """Narrow types for migration tuple from railway pattern result."""
        if (
            not isinstance(migration_tuple_raw, tuple)
            or len(migration_tuple_raw) != FlextLdifConstants.TUPLE_LEN_4
        ):
            msg = f"Expected tuple of length 4, got {type(migration_tuple_raw)}"
            raise TypeError(msg)

        opts, config_model, categorization_rules, schema_whitelist_rules = (
            migration_tuple_raw
        )

        # Type narrowing: opts is already validated by isinstance above
        if config_model is not None and not isinstance(
            config_model,
            FlextLdifModels.MigrationConfig,
        ):
            msg = f"Expected MigrationConfig | None, got {type(config_model)}"
            raise TypeError(msg)
        if categorization_rules is not None and not isinstance(
            categorization_rules,
            FlextLdifModels.CategoryRules,
        ):
            msg = f"Expected CategoryRules | None, got {type(categorization_rules)}"
            raise TypeError(msg)
        if schema_whitelist_rules is not None and not isinstance(
            schema_whitelist_rules,
            FlextLdifModels.WhitelistRules,
        ):
            msg = f"Expected WhitelistRules | None, got {type(schema_whitelist_rules)}"
            raise TypeError(msg)

        # Type narrowing: ensure all values are not None
        if config_model is None:
            msg = "MigrationConfig cannot be None"
            raise TypeError(msg)
        if categorization_rules is None:
            msg = "CategoryRules cannot be None"
            raise TypeError(msg)
        if schema_whitelist_rules is None:
            msg = "WhitelistRules cannot be None"
            raise TypeError(msg)

        return (opts, config_model, categorization_rules, schema_whitelist_rules)

    @staticmethod
    def _normalize_category_rules_for_migrate(
        t: tuple[FlextLdifModelsConfig.MigrateOptions, FlextLdifModels.MigrationConfig],
    ) -> FlextResult[
        tuple[
            FlextLdifModelsConfig.MigrateOptions,
            FlextLdifModels.MigrationConfig,
            FlextLdifModels.CategoryRules,
        ]
    ]:
        """Normalize category rules with type narrowing for migrate method."""
        if not isinstance(t, tuple) or len(t) != FlextLdifConstants.TUPLE_LEN_2:
            return FlextResult.fail("Invalid tuple")
        opts_t, config_t = t
        if not isinstance(config_t, FlextLdifModels.MigrationConfig):
            return FlextResult.fail("Invalid MigrationConfig")
        if not isinstance(opts_t, FlextLdifModelsConfig.MigrateOptions):
            return FlextResult.fail("Invalid MigrateOptions")
        # Use CategoryRules directly - no conversion needed
        # Both config and models use same CategoryRules type
        categorization_rules_input = opts_t.categorization_rules
        # Convert FlextLdifModelsConfig.CategoryRules to FlextLdifModels.CategoryRules if needed
        if categorization_rules_input is not None and not isinstance(
            categorization_rules_input, FlextLdifModels.CategoryRules
        ):
            # Convert config CategoryRules to models CategoryRules using model_validate
            if hasattr(categorization_rules_input, "model_dump"):
                rules_dict: FlextLdifTypes.Migration.CategoryRulesDict = (
                    categorization_rules_input.model_dump()
                )
            elif isinstance(categorization_rules_input, dict):
                rules_dict = categorization_rules_input
            else:
                return FlextResult.fail("Invalid categorization_rules type")
            categorization_rules_input = FlextLdifModels.CategoryRules.model_validate(
                rules_dict
            )
        rules_result = FlextLdifMigrationPipeline.normalize_category_rules(
            categorization_rules_input,
        )
        if rules_result.is_failure:
            return FlextResult.fail(rules_result.error or "Failed to normalize rules")
        rules_normalized = rules_result.unwrap()
        if rules_normalized is None:
            return FlextResult.fail("Category rules cannot be None")
        return FlextResult.ok((opts_t, config_t, rules_normalized))

    @staticmethod
    def _validate_simple_mode_params_for_migrate(
        t: tuple[
            FlextLdifModelsConfig.MigrateOptions,
            FlextLdifModels.MigrationConfig,
            FlextLdifModels.CategoryRules,
        ],
    ) -> FlextResult[
        tuple[
            FlextLdifModelsConfig.MigrateOptions,
            FlextLdifModels.MigrationConfig,
            FlextLdifModels.CategoryRules,
        ]
    ]:
        """Validate simple mode params with type narrowing for migrate method."""
        if not isinstance(t, tuple) or len(t) != FlextLdifConstants.TUPLE_LEN_3:
            return FlextResult.fail("Invalid tuple")
        opts_t, config_t, rules_t = t
        if not isinstance(opts_t, FlextLdifModelsConfig.MigrateOptions):
            return FlextResult.fail("Invalid MigrateOptions")
        return FlextLdifMigrationPipeline.validate_simple_mode_params(
            opts_t.input_filename,
            opts_t.output_filename,
        ).map(lambda _: (opts_t, config_t, rules_t))

    @staticmethod
    def _normalize_whitelist_rules_for_migrate(
        t: tuple[
            FlextLdifModelsConfig.MigrateOptions,
            FlextLdifModels.MigrationConfig,
            FlextLdifModels.CategoryRules,
        ],
    ) -> FlextResult[
        tuple[
            FlextLdifModelsConfig.MigrateOptions,
            FlextLdifModels.MigrationConfig,
            FlextLdifModels.CategoryRules,
            FlextLdifModels.WhitelistRules,
        ]
    ]:
        """Normalize whitelist rules with type narrowing for migrate method."""
        if not isinstance(t, tuple) or len(t) != FlextLdifConstants.TUPLE_LEN_3:
            return FlextResult.fail("Invalid tuple")
        opts_t, config_t, rules_t = t
        if not isinstance(opts_t, FlextLdifModelsConfig.MigrateOptions):
            return FlextResult.fail("Invalid MigrateOptions")
        # Convert FlextLdifModelsConfig.WhitelistRules to FlextLdifModels.WhitelistRules if needed
        whitelist_rules_input = opts_t.schema_whitelist_rules
        if whitelist_rules_input is not None and not isinstance(
            whitelist_rules_input, FlextLdifModels.WhitelistRules
        ):
            # Convert config WhitelistRules to models WhitelistRules using model_validate
            if hasattr(whitelist_rules_input, "model_dump"):
                rules_dict: FlextLdifTypes.Migration.WhitelistRulesDict = (
                    whitelist_rules_input.model_dump()
                )
            elif isinstance(whitelist_rules_input, dict):
                rules_dict = whitelist_rules_input
            else:
                return FlextResult.fail("Invalid whitelist_rules type")
            whitelist_rules_input = FlextLdifModels.WhitelistRules.model_validate(
                rules_dict
            )
        whitelist_result = FlextLdifMigrationPipeline.normalize_whitelist_rules(
            whitelist_rules_input,
        )
        if whitelist_result.is_failure:
            return FlextResult.fail(
                whitelist_result.error or "Failed to normalize whitelist rules",
            )
        whitelist_normalized = whitelist_result.unwrap()
        if whitelist_normalized is None:
            return FlextResult.fail("Whitelist rules cannot be None")
        return FlextResult.ok((opts_t, config_t, rules_t, whitelist_normalized))

    def migrate(
        self,
        input_dir: Path,
        output_dir: Path,
        source_server: FlextLdifConstants.LiteralTypes.ServerTypeLiteral,
        target_server: FlextLdifConstants.LiteralTypes.ServerTypeLiteral,
        *,
        options: FlextLdifModelsConfig.MigrateOptions | None = None,
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
                (use FlextLdifConstants.ServerTypes)
            target_server: Target server type identifier (use FlextLdifConstants.ServerTypes)
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
                See FlextLdifModelsConfig.MigrateOptions for complete field documentation.

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
            options = FlextLdifModelsConfig.MigrateOptions(
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
            options = FlextLdifModelsConfig.MigrateOptions(
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
        # DRY migration setup using service normalization methods
        opts = options or FlextLdifModelsConfig.MigrateOptions()

        # Chain validation steps using railway pattern with extracted methods
        # opts.migration_config type is compatible with MigrationConfig | MigrationConfigDict | None
        migration_config_raw = opts.migration_config
        migration_config_input: (
            FlextLdifModels.MigrationConfig
            | FlextLdifTypes.Migration.MigrationConfigDict
            | None
        ) = None
        if migration_config_raw is None:
            migration_config_input = None
        elif isinstance(migration_config_raw, FlextLdifModels.MigrationConfig):
            migration_config_input = migration_config_raw
        elif isinstance(migration_config_raw, dict):
            # Convert dict to MigrationConfigDict type
            migration_config_input = cast(
                "FlextLdifTypes.Migration.MigrationConfigDict", migration_config_raw
            )
        # Convert to dict if it's a model with model_dump
        elif hasattr(migration_config_raw, "model_dump"):
            migration_config_input = migration_config_raw.model_dump()
        else:
            migration_config_input = None

        migration_setup = (
            FlextResult.ok(opts)
            .flat_map(
                lambda o: FlextLdifMigrationPipeline.normalize_migration_config(
                    migration_config_input,
                ).map(lambda c: (o, c)),
            )
            .flat_map(self._normalize_category_rules_for_migrate)
            .flat_map(self._validate_simple_mode_params_for_migrate)
            .flat_map(self._normalize_whitelist_rules_for_migrate)
        )

        if migration_setup.is_failure:
            return FlextResult[FlextLdifModels.EntryResult].fail(
                migration_setup.error or "Migration setup failed",
            )

        # Extract and type-narrow results from railway pattern
        opts, config_model_typed, categorization_rules_typed, schema_whitelist_rules = (
            self._narrow_migration_types(migration_setup.unwrap())
        )

        # Auto-detect mode and create write options
        # config_model_typed is MigrationConfig from the tuple
        mode = FlextLdifMigrationPipeline.detect_migration_mode(
            config_model_typed,
            categorization_rules_typed,
        )
        write_options_result = FlextLdifMigrationPipeline.get_write_options_for_mode(
            mode,
            opts.write_options,
            config_model_typed,
        )

        if write_options_result.is_failure:
            return FlextResult[FlextLdifModels.EntryResult].fail(
                f"Failed to create write options: {write_options_result.error}",
            )

        write_options = write_options_result.unwrap()

        # Convert mode string to typed literal
        mode_typed = self._convert_mode_to_typed(mode)

        # Initialize and execute migration pipeline with all normalized parameters
        migration_pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode=mode_typed,
            source_server=source_server,
            target_server=target_server,
            forbidden_attributes=opts.forbidden_attributes,
            forbidden_objectclasses=opts.forbidden_objectclasses,
            base_dn=opts.base_dn,
            sort_entries_hierarchically=opts.sort_entries_hierarchically,
            write_options=write_options,
            categorization_rules=categorization_rules_typed,
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
        attributes: (FlextLdifTypes.CommonDict.AttributeDictReadOnly | None) = None,
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
        # Delegate to filters service - service handles all logic
        # Convert attributes to dict[str, str | None] | None if needed
        attributes_converted: dict[str, str | None] | None = None
        if attributes is not None:
            if isinstance(attributes, dict):
                attributes_converted = {
                    k: (v[0] if isinstance(v, Sequence) and len(v) > 0 else None)
                    if v is not None
                    else None
                    for k, v in attributes.items()
                }
            else:
                attributes_converted = None

        filter_result = FlextLdifFilters.apply_standard_filters(
            entries,
            objectclass,
            dn_pattern,
            attributes_converted,
        )
        if filter_result.is_failure:
            return filter_result

        filtered_entries = filter_result.unwrap()

        # Apply custom_filter if provided (DRY pattern)
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
        analysis_service = self._get_service(FlextLdifConstants.ServiceType.ANALYSIS)
        return analysis_service.analyze(entries)

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
        analysis_service = self._get_service(FlextLdifConstants.ServiceType.ANALYSIS)
        validation_service = self._get_service(
            FlextLdifConstants.ServiceType.VALIDATION,
        )

        return analysis_service.validate_entries(entries, validation_service)

    # =========================================================================
    # ACL OPERATIONS
    # =========================================================================

    def extract_acls(
        self,
        entry: FlextLdifModels.Entry,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral = "rfc",
    ) -> FlextResult[FlextLdifModels.AclResponse]:
        """Extract ACL rules from entry.

        Args:
            entry: Entry to extract ACLs from
            server_type: Server type for ACL quirks (use FlextLdifConstants.ServerTypes)

        Returns:
            FlextResult containing composed AclResponse with extracted ACLs and statistics

        Example:
            result = api.extract_acls(entry)
            if result.is_success:
                acl_response = result.unwrap()
                acls = acl_response.acls

        """
        return self._get_service(
            FlextLdifConstants.ServiceType.ACL
        ).extract_acls_from_entry(entry, server_type)

    def evaluate_acl_rules(
        self,
        acls: list[FlextLdifModelsDomains.Acl],
        context: FlextLdifTypes.Acl.EvaluationContextDict | None = None,
    ) -> FlextResult[bool]:
        """Evaluate ACL rules and return evaluation result.

        Args:
            acls: List of ACL models to evaluate
            context: Evaluation context with subject_dn, target_dn, operation, attributes

        Returns:
            FlextResult containing evaluation result (True if allowed)

        Example:
            acls = api.extract_acls(entry).unwrap()
            context: FlextLdifTypes.Acl.EvaluationContextDict = {
                "subject_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
                "operation": "read",
            }
            result = api.evaluate_acl_rules(acls, context)
            if result.is_success:
                is_allowed = result.unwrap()

        """
        # Note: evaluate_acl_context doesn't exist - use evaluate_acl_rules instead
        # For now, return failure until proper method is implemented
        return FlextResult.fail("ACL evaluation not yet implemented in service")

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
        # ACL transformation is handled via conversion service
        # Convert entries one by one using conversion service
        conversion_service = self._get_service(
            FlextLdifConstants.ServiceType.CONVERSION
        )
        # Convert server types to strings if needed
        source_str: str = (
            source_server
            if isinstance(source_server, str)
            else getattr(source_server, "__name__", str(source_server))
        )
        target_str: str = (
            target_server
            if isinstance(target_server, str)
            else getattr(target_server, "__name__", str(target_server))
        )
        converted_entries: list[FlextLdifModels.Entry] = []
        for entry in entries:
            # Entry is ConvertibleModel (Entry is in the union type)
            # Use cast to satisfy type checker - Entry is part of ConvertibleModel union
            from typing import cast

            entry_as_convertible: FlextLdifTypes.ConvertibleModel = cast(
                "FlextLdifTypes.ConvertibleModel", entry
            )
            convert_result = conversion_service.convert(
                source=source_str,
                target=target_str,
                model_instance=entry_as_convertible,
            )
            if convert_result.is_failure:
                return FlextResult.fail(
                    f"Failed to convert ACL entry: {convert_result.error}"
                )
            converted_entry_raw = convert_result.unwrap()
            # Type narrowing: converted_entry should be Entry for ACL transformation
            if isinstance(converted_entry_raw, FlextLdifModels.Entry):
                converted_entries.append(converted_entry_raw)
            else:
                return FlextResult.fail(
                    f"Unexpected conversion result type: {type(converted_entry_raw)}"
                )
        return FlextResult.ok(converted_entries)

    def migrate_acl_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        source_server: FlextLdifConstants.LiteralTypes.ServerTypeLiteral,
        target_server: FlextLdifConstants.LiteralTypes.ServerTypeLiteral,
    ) -> FlextResult[tuple[list[FlextLdifModels.Entry], list[FlextLdifModels.Entry]]]:
        r"""Migrate ACL entries from source to target server format with separate ACL pipeline.

        Generic ACL migration that extracts ACL attributes from entries, creates separate ACL-only entries,
        removes ACL attributes from original entries, and transforms ACL values to target server format.
        This enables independent ACL processing pipelines while preserving original entries.

        Args:
            entries: List of entries containing ACL attributes in source format
            source_server: Source server type (e.g., "oid", "openldap")
            target_server: Target server type (e.g., "oud", "ad")

        Returns:
            FlextResult containing tuple of (modified_entries, acl_only_entries):
            - modified_entries: Original entries with ACL attributes removed and metadata tracked
            - acl_only_entries: New ACL-only entries with transformed ACL values

        Example:
            # Parse LDIF content with ACL attributes
            ldif_text = r"dn: cn=test\ncn: test\norclaci: (target=ldap:///cn=test)"
            source_entries = ldif.parse(ldif_text).unwrap()
            result = ldif.migrate_acl_entries(
                source_entries,
                source_server="oid",
                target_server="oud"
            )
            if result.is_success:
                modified_entries, acl_entries = result.unwrap()
                # modified_entries: Entries with ACL attributes removed, metadata tracked
                # acl_entries: New entries with "aci" attributes in OUD format

        """
        # Get ACL attribute names for source server
        source_acl_attributes_result = self._get_acl_attributes_for_server(
            source_server,
        )
        if source_acl_attributes_result.is_failure:
            return FlextResult[
                tuple[list[FlextLdifModels.Entry], list[FlextLdifModels.Entry]]
            ].fail(
                source_acl_attributes_result.error
                or "Failed to get source ACL attributes",
            )
        source_acl_attributes = source_acl_attributes_result.unwrap()

        if not source_acl_attributes:
            # No ACL attributes for this server type, return unchanged
            return FlextResult[
                tuple[list[FlextLdifModels.Entry], list[FlextLdifModels.Entry]]
            ].ok((entries, []))

        modified_entries = []
        acl_only_entries = []

        for original_entry in entries:
            if (
                not original_entry.attributes
                or not original_entry.attributes.attributes
            ):
                modified_entries.append(original_entry)
                continue

            # Extract ACL data from this entry
            extracted_acl_data = self._extract_acl_data_from_entry(
                original_entry,
                source_acl_attributes,
            )

            if not extracted_acl_data:
                # No ACL attributes found, keep entry unchanged
                modified_entries.append(original_entry)
                continue

            # Remove ACL attributes from original entry and track in metadata
            modified_entry_result = self._remove_acl_attributes_and_track(
                original_entry,
                extracted_acl_data,
            )

            if modified_entry_result.is_failure:
                self.logger.warning(
                    "Failed to remove ACL attributes from entry",
                    dn=original_entry.dn.value if original_entry.dn else "",
                    error=modified_entry_result.error,
                )
                modified_entries.append(original_entry)
                continue

            modified_entry = modified_entry_result.unwrap()
            modified_entries.append(modified_entry)

            # Transform ACL values to target server format
            transformed_acl_values = self._transform_acl_values_for_server(
                extracted_acl_data,
                source_server,
                target_server,
            )

            if transformed_acl_values:
                # Create ACL-only entry with transformed values
                acl_entry_result = self._create_acl_only_entry(
                    modified_entry,
                    transformed_acl_values,
                    extracted_acl_data,
                )

                if acl_entry_result.is_success:
                    acl_only_entries.append(acl_entry_result.unwrap())

        return FlextResult[
            tuple[list[FlextLdifModels.Entry], list[FlextLdifModels.Entry]]
        ].ok((modified_entries, acl_only_entries))

    def _get_acl_attributes_for_server(
        self,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral,
    ) -> FlextResult[frozenset[str]]:
        """Get ACL attribute names for a specific server type."""
        # Use constants directly for ACL attribute registry
        acl_attrs = FlextLdifConstants.AclAttributeRegistry.get_acl_attributes(
            server_type,
        )
        # Convert list to frozenset for return type
        return FlextResult.ok(frozenset(acl_attrs))

    def _extract_acl_data_from_entry(
        self,
        entry: FlextLdifModels.Entry,
        acl_attributes: frozenset[str],
    ) -> FlextLdifTypes.CommonDict.AttributeDict:
        """Extract ACL data from a single entry."""
        extracted_acl_attrs: FlextLdifTypes.CommonDict.AttributeDict = {}

        for acl_attr in acl_attributes:
            values = entry.get_attribute_values(acl_attr)
            if values:
                extracted_acl_attrs[acl_attr] = values

        return extracted_acl_attrs

    def _remove_acl_attributes_and_track(
        self,
        entry: FlextLdifModels.Entry,
        acl_data: FlextLdifTypes.CommonDict.AttributeDict,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove ACL attributes from entry and track in metadata."""
        acl_attr_names = list(acl_data.keys())
        if not acl_attr_names:
            return FlextResult.ok(entry)

        remove_result = self.filters.remove_attributes(entry, acl_attr_names)
        if remove_result.is_failure:
            return FlextResult[FlextLdifModels.Entry].fail(
                remove_result.error or "Failed to remove ACL attributes",
            )

        updated_entry = remove_result.unwrap()

        # Track ACL removal in metadata
        if updated_entry.metadata:
            for acl_attr_name, acl_values in acl_data.items():
                self.utilities.Metadata.track_transformation(
                    metadata=updated_entry.metadata,
                    original_name=acl_attr_name,
                    target_name=None,
                    original_values=acl_values,
                    target_values=None,
                    transformation_type="removed",
                    reason="ACL moved to separate phase",
                )

        return FlextResult.ok(updated_entry)

    def _transform_acl_values_for_server(
        self,
        acl_data: FlextLdifTypes.CommonDict.AttributeDict,
        source_server: FlextLdifConstants.LiteralTypes.ServerTypeLiteral,
        target_server: FlextLdifConstants.LiteralTypes.ServerTypeLiteral,
    ) -> list[str]:
        """Transform ACL values from source to target server format."""
        all_acl_values = []
        for values in acl_data.values():
            all_acl_values.extend(values)

        if not all_acl_values:
            return []

        # Use ACL service to transform values
        # Create temporary entry with ACL values for transformation
        temp_entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=temp"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={"temp": all_acl_values},
            ),
        )
        transform_result = self.transform_acl_entries(
            [temp_entry],
            source_server,
            target_server,
        )

        if transform_result.is_failure:
            self.logger.warning(
                "Failed to transform ACL values",
                error=transform_result.error,
            )
            return []

        transformed_entries = transform_result.unwrap()
        if not transformed_entries:
            return []

        # Extract transformed ACL values from the first entry
        entry = transformed_entries[0]
        if not entry.attributes or not entry.attributes.attributes:
            return []

        # Get the transformed ACL attribute (target server's ACL attribute)
        target_acl_attrs = FlextLdifConstants.AclAttributeRegistry.get_acl_attributes(
            target_server,
        )
        for attr_name in target_acl_attrs:
            if attr_name in entry.attributes.attributes:
                return entry.attributes.attributes[attr_name]

        return []

    def _create_acl_only_entry(
        self,
        original_entry: FlextLdifModels.Entry,
        acl_values: list[str],
        original_acl_data: FlextLdifTypes.CommonDict.AttributeDict,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Create a new ACL-only entry with transformed ACL values."""
        # Get target ACL attribute name
        target_acl_attr = "aci"  # Default for most servers, could be parameterized

        create_result = self.create_entry(
            dn=original_entry.dn.value if original_entry.dn else "",
            attributes={target_acl_attr: acl_values},
        )

        if create_result.is_failure:
            return create_result

        acl_entry = create_result.unwrap()

        # Configure metadata for ACL entry
        if original_entry.metadata and original_entry.metadata.extensions:
            if not acl_entry.metadata:
                acl_entry.metadata = FlextLdifModels.QuirkMetadata.create_for("oud")

            if not acl_entry.metadata.extensions:
                acl_entry.metadata.extensions = FlextLdifModels.DynamicMetadata()

            # Copy relevant extensions
            mk = FlextLdifConstants.MetadataKeys
            # Type narrowing: metadata.extensions is not None after check above
            if acl_entry.metadata and acl_entry.metadata.extensions:
                original_extensions = original_entry.metadata.extensions
                if original_extensions is not None:
                    if hasattr(original_extensions, "model_dump"):
                        ext_dict = original_extensions.model_dump()
                    else:
                        # Convert to dict if it's a mapping
                        ext_dict = dict(original_extensions)

                    for key, value in ext_dict.items():
                        if key != mk.ORIGINAL_ATTRIBUTES_COMPLETE:
                            if (
                                acl_entry.metadata
                                and acl_entry.metadata.extensions is not None
                                and isinstance(
                                    acl_entry.metadata.extensions,
                                    FlextLdifModelsMetadata.DynamicMetadata,
                                )
                            ):
                                acl_entry.metadata.extensions[key] = value

        # Track attribute transformation
        if acl_entry.metadata:
            for original_attr, original_values in original_acl_data.items():
                self.utilities.Metadata.track_transformation(
                    metadata=acl_entry.metadata,
                    original_name=original_attr,
                    target_name=target_acl_attr,
                    original_values=original_values,
                    target_values=acl_values,
                    transformation_type="renamed",
                    reason=f"ACL transformation {original_attr} → {target_acl_attr}",
                )

        return FlextResult.ok(acl_entry)

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
    ) -> FlextResult[list[ProcessingResult]]:
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
        processing_service = self._get_service(
            FlextLdifConstants.ServiceType.PROCESSING,
        )
        return processing_service.process(
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
            - detected_server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral
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
        detector_service = self._get_service(FlextLdifConstants.ServiceType.DETECTOR)

        # Delegate to detector service - service handles all logic
        return detector_service.detect_server_type(
            ldif_path=ldif_path,
            ldif_content=ldif_content,
        )

    def get_effective_server_type(
        self,
        ldif_path: Path | None = None,
    ) -> FlextResult[FlextLdifConstants.LiteralTypes.ServerTypeLiteral]:
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
        detector_service = self._get_service(FlextLdifConstants.ServiceType.DETECTOR)

        # Delegate to detector service - service handles all logic
        return detector_service.get_effective_server_type(ldif_path=ldif_path)

    # =========================================================================
    # SYNTAX SERVICE OPERATIONS
    # =========================================================================

    def validate_syntax_oid(self, oid: str) -> FlextResult[bool]:
        """Validate OID format compliance with LDAP OID syntax.

        Delegates to FlextLdifSyntax service for SRP compliance.

        Args:
            oid: OID string to validate

        Returns:
            FlextResult containing True if valid OID format, False otherwise

        Example:
            result = api.validate_syntax_oid("1.3.6.1.4.1.1466.115.121.1.15")
            if result.is_success:
                is_valid = result.unwrap()

        """
        syntax_service = self._get_service(FlextLdifConstants.ServiceType.SYNTAX)
        return syntax_service.validate_oid(oid)

    def is_rfc4517_syntax(self, oid: str) -> FlextResult[bool]:
        """Check if OID is a standard RFC 4517 syntax OID.

        Delegates to FlextLdifSyntax service for SRP compliance.

        Args:
            oid: OID string to check

        Returns:
            FlextResult containing True if RFC 4517 standard OID, False otherwise

        Example:
            result = api.is_rfc4517_syntax("1.3.6.1.4.1.1466.115.121.1.15")
            if result.is_success:
                is_standard = result.unwrap()

        """
        syntax_service = self._get_service(FlextLdifConstants.ServiceType.SYNTAX)
        return syntax_service.is_rfc4517_standard(oid)

    def lookup_syntax_oid(self, oid: str) -> FlextResult[str]:
        """Look up syntax name for a given OID.

        Delegates to FlextLdifSyntax service for SRP compliance.

        Args:
            oid: OID to look up

        Returns:
            FlextResult[str] containing syntax name if found, fails if not found

        Example:
            result = api.lookup_syntax_oid("1.3.6.1.4.1.1466.115.121.1.15")
            if result.is_success:
                syntax_name = result.unwrap()

        """
        syntax_service = self._get_service(FlextLdifConstants.ServiceType.SYNTAX)
        return syntax_service.lookup_oid(oid)

    def lookup_syntax_name(self, name: str) -> FlextResult[str]:
        """Look up OID for a given syntax name.

        Delegates to FlextLdifSyntax service for SRP compliance.

        Args:
            name: Syntax name to look up (case-sensitive)

        Returns:
            FlextResult containing OID if found, failure otherwise

        Example:
            result = api.lookup_syntax_name("Directory String")
            if result.is_success:
                oid = result.unwrap()

        """
        syntax_service = self._get_service(FlextLdifConstants.ServiceType.SYNTAX)
        return syntax_service.lookup_name(name)

    def resolve_syntax(
        self,
        oid: str,
        name: str | None = None,
        desc: str | None = None,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral = "rfc",
    ) -> FlextResult[FlextLdifModelsDomains.Syntax]:
        """Resolve OID to complete Syntax model with validation.

        Delegates to FlextLdifSyntax service for SRP compliance.

        Args:
            oid: Syntax OID (required, must be valid format)
            name: Human-readable syntax name (optional, auto-looked-up if not provided)
            desc: Syntax description (optional)
            server_type: LDAP server type for quirk metadata

        Returns:
            FlextResult containing fully resolved Syntax model

        Example:
            result = api.resolve_syntax("1.3.6.1.4.1.1466.115.121.1.15")
            if result.is_success:
                syntax = result.unwrap()

        """
        syntax_service = self._get_service(FlextLdifConstants.ServiceType.SYNTAX)
        return syntax_service.resolve_syntax(oid, name, desc, server_type)

    def validate_syntax_value(
        self,
        value: str,
        syntax_oid: str,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral = "rfc",
    ) -> FlextResult[bool]:
        """Validate a value against its syntax type.

        Delegates to FlextLdifSyntax service for SRP compliance.

        Args:
            value: Value to validate
            syntax_oid: Syntax OID that defines validation rules
            server_type: LDAP server type for quirk metadata

        Returns:
            FlextResult containing True if value is valid for syntax, False otherwise

        Example:
            result = api.validate_syntax_value("TRUE", "1.3.6.1.4.1.1466.115.121.1.7")
            if result.is_success:
                is_valid = result.unwrap()

        """
        syntax_service = self._get_service(FlextLdifConstants.ServiceType.SYNTAX)
        return syntax_service.validate_value(value, syntax_oid, server_type)

    def get_syntax_category(self, oid: str) -> FlextResult[str]:
        """Get type category for a syntax OID.

        Delegates to FlextLdifSyntax service for SRP compliance.

        Args:
            oid: Syntax OID

        Returns:
            FlextResult containing type category

        Example:
            result = api.get_syntax_category("1.3.6.1.4.1.1466.115.121.1.15")
            if result.is_success:
                category = result.unwrap()

        """
        syntax_service = self._get_service(FlextLdifConstants.ServiceType.SYNTAX)
        return syntax_service.get_syntax_category(oid)

    def list_common_syntaxes(self) -> FlextResult[list[str]]:
        """List all supported RFC 4517 syntax OIDs.

        Delegates to FlextLdifSyntax service for SRP compliance.

        Returns:
            FlextResult containing sorted list of OIDs

        Example:
            result = api.list_common_syntaxes()
            if result.is_success:
                syntax_oids = result.unwrap()

        """
        syntax_service = self._get_service(FlextLdifConstants.ServiceType.SYNTAX)
        return syntax_service.list_common_syntaxes()

    # =========================================================================
    # CONVERSION SERVICE OPERATIONS
    # =========================================================================

    def validate_oud_conversion(self) -> FlextResult[bool]:
        """Validate DN case consistency for OUD target conversion.

        Delegates to FlextLdifConversion service for SRP compliance.

        Returns:
            FlextResult[bool]: Validation result with any inconsistencies in metadata

        Example:
            result = api.validate_oud_conversion()
            if result.is_success:
                is_valid = result.unwrap()

        """
        conversion_service = self._get_service(
            FlextLdifConstants.ServiceType.CONVERSION,
        )
        return conversion_service.validate_oud_conversion()

    def reset_dn_registry(self) -> None:
        """Clear DN registry for new conversion session.

        Delegates to FlextLdifConversion service for SRP compliance.

        Call this between independent conversion operations to avoid
        DN case pollution from previous conversions.

        Example:
            api.reset_dn_registry()

        """
        conversion_service = self._get_service(
            FlextLdifConstants.ServiceType.CONVERSION,
        )
        conversion_service.reset_dn_registry()

    def get_supported_conversions(
        self,
        quirk: FlextLdifServersBase,
    ) -> FlextLdifTypes.CommonDict.DistributionDict:
        """Check which data types a quirk supports for conversion.

        Delegates to FlextLdifConversion service for SRP compliance.

        Args:
            quirk: Quirk instance to check

        Returns:
            Dictionary mapping data_type to support status (bool as int)

        Example:
            from flext_ldif.servers import FlextLdifServersOud
            oud_quirk = FlextLdifServersOud()
            supported = api.get_supported_conversions(oud_quirk)

        """
        conversion_service = self._get_service(
            FlextLdifConstants.ServiceType.CONVERSION,
        )
        return conversion_service.get_supported_conversions(quirk)

    @property
    def config(self) -> FlextConfig:
        """Config tipado com namespace ldif.

        Returns:
            FlextConfig: FlextConfig tipado com acesso via .ldif

        Example:
            encoding = ldif.config.ldif.ldif_encoding

        """
        return FlextConfig.get_global_instance()

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
            max_line = ldif.constants.LdifFormatting.MAX_LINE_WIDTH
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
            result = parser.parse_ldif_file(
                Path("file.ldif"), FlextLdifConstants.ServerTypes.OID
            )

        """
        return self._get_service(FlextLdifConstants.ServiceType.PARSER)

    @property
    def detector(self) -> FlextLdifDetector:
        """Access to detector service instance.

        Returns:
            FlextLdifDetector: Detector service instance

        Example:
            detector = ldif.detector
            result = detector.detect_server_type(ldif_path=Path("file.ldif"))

        """
        return self._get_service(FlextLdifConstants.ServiceType.DETECTOR)

    @property
    def acl_service(self) -> FlextLdifAcl:
        """Access to ACL service instance.

        Returns:
            FlextLdifAcl: ACL service instance

        Example:
            acl_service = ldif.acl_service
            result = acl_service.extract_acls_from_entry(
                entry, server_type=FlextLdifConstants.ServerTypes.OPENLDAP
            )

        """
        return self._get_service(FlextLdifConstants.ServiceType.ACL)

    def get_server_acl_quirk(
        self,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral,
    ) -> FlextLdifProtocols.Quirks.AclProtocol | None:
        """Get ACL quirk for a specific server type.

        Architecture: Public facade method to access server-specific ACL quirks
        without exposing internal FlextLdifServer registry.

        Args:
            server_type: Server type (e.g., 'oid', 'oud', 'rfc', 'openldap')

        Returns:
            ACL quirk instance for the server type, or None if not found

        Example:
            rfc_acl_quirk = ldif.get_server_acl_quirk('rfc')
            result = rfc_acl_quirk.write(acl_model)

        """
        server = FlextLdifServer.get_global_instance()
        quirk_result = server.quirk(server_type)
        if quirk_result.is_failure:
            return None
        quirk_base = quirk_result.unwrap()
        # acl_quirk already implements AclProtocol via structural typing
        # No cast needed - isinstance check not required for protocols
        acl_quirk = quirk_base.acl_quirk
        if acl_quirk is None:
            return None
        # Type narrowing: acl_quirk satisfies AclProtocol by implementation
        # Cast to protocol type for type checker
        from typing import cast

        return cast("FlextLdifProtocols.Quirks.AclProtocol", acl_quirk)

    # INTERNAL: bus property is hidden from public API
    # Use models, config, constants for public access instead

    # INTERNAL: dispatcher property is hidden from public API
    # Use client methods for LDIF operations instead

    # INTERNAL: registry property is hidden from public API
    # Use register() method for quirk management instead

    @property
    def context(self) -> FlextContext:
        """Access to execution context with lazy initialization."""
        # Create FlextContext instance from dict
        context_instance = FlextContext()
        if self._context is not None:
            for key, value in self._context.items():
                context_instance.set(key, value)
        return context_instance

    # =========================================================================
    # MONADIC METHODS - Railway-oriented composition
    # =========================================================================

    def parse_and_map(
        self,
        source: str | Path,
        transform: Callable[[list[FlextLdifModels.Entry]], U],
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral | None = None,
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
        # Transform parse result using monadic map
        parse_result = self.parse(source, server_type, format_options)
        if parse_result.is_failure:
            return FlextResult[U].fail(parse_result.error or "Parse failed")
        entries = parse_result.unwrap()
        transformed = transform(entries)
        return FlextResult[U].ok(transformed)

    def parse_and_flat_map(
        self,
        source: str | Path,
        transform: Callable[[list[FlextLdifModels.Entry]], FlextResult[U]],
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral | None = None,
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
        # Chain parse result using monadic flat_map
        parse_result = self.parse(source, server_type, format_options)
        if parse_result.is_failure:
            return FlextResult[U].fail(parse_result.error or "Parse failed")
        entries = parse_result.unwrap()
        transform_result = transform(entries)
        if transform_result.is_failure:
            return FlextResult[U].fail(transform_result.error or "Transform failed")
        transformed = transform_result.unwrap()
        return FlextResult[U].ok(transformed)

    def filter_and_map(
        self,
        entries: list[FlextLdifModels.Entry],
        transform: Callable[[list[FlextLdifModels.Entry]], U],
        objectclass: str | None = None,
        dn_pattern: str | None = None,
        attributes: (FlextLdifTypes.CommonDict.AttributeDictReadOnly | None) = None,
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
        # Transform parse result using monadic map
        filter_result = self.filter(
            entries,
            objectclass,
            dn_pattern,
            attributes,
            custom_filter,
        )
        if filter_result.is_failure:
            return FlextResult[U].fail(filter_result.error or "Filter failed")
        filtered_entries = filter_result.unwrap()
        transformed = transform(filtered_entries)
        return FlextResult[U].ok(transformed)

    def filter_and_flat_map(
        self,
        entries: list[FlextLdifModels.Entry],
        transform: Callable[[list[FlextLdifModels.Entry]], FlextResult[U]],
        objectclass: str | None = None,
        dn_pattern: str | None = None,
        attributes: (FlextLdifTypes.CommonDict.AttributeDictReadOnly | None) = None,
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
        # Chain parse result using monadic flat_map
        filter_result = self.filter(
            entries,
            objectclass,
            dn_pattern,
            attributes,
            custom_filter,
        )
        if filter_result.is_failure:
            return FlextResult[U].fail(filter_result.error or "Filter failed")
        filtered_entries = filter_result.unwrap()
        transform_result = transform(filtered_entries)
        if transform_result.is_failure:
            return FlextResult[U].fail(transform_result.error or "Transform failed")
        transformed = transform_result.unwrap()
        return FlextResult[U].ok(transformed)

    # =========================================================================
    # BUILDER METHODS - Fluent API for complex operations (no additional class)
    # =========================================================================

    def parse_builder(
        self,
        source: str | Path,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral | None = None,
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
        parse_result = self.parse(source, server_type, format_options)
        object.__setattr__(self, "_builder_parse_result", parse_result)
        if parse_result.is_success:
            object.__setattr__(self, "_builder_entries", parse_result.unwrap())
        return self

    def filter_builder(
        self,
        objectclass: str | None = None,
        dn_pattern: str | None = None,
        attributes: (FlextLdifTypes.CommonDict.AttributeDictReadOnly | None) = None,
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
        filter_result = self.filter(
            self._builder_entries,
            objectclass,
            dn_pattern,
            attributes,
            custom_filter,
        )
        object.__setattr__(self, "_builder_filter_result", filter_result)
        if filter_result.is_success:
            object.__setattr__(self, "_builder_entries", filter_result.unwrap())
        return self

    def write_builder(
        self,
        output_path: Path | None = None,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral | None = None,
        format_options: FlextLdifModels.WriteFormatOptions | None = None,
        template_data: FlextLdifTypes.MetadataDictMutable | None = None,
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
                self._builder_entries,
                None,
                server_type,
                format_options,
                template_data,
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
            object.__setattr__(self, "_builder_write_result", write_result)
        return self

    def execute_builder(self) -> FlextResult[list[FlextLdifModels.Entry] | str]:
        r"""Execute builder pipeline and return result.

        Returns:
            FlextResult with entries (if no write) or success message (if write)

        """
        if self._builder_write_result is not None:
            # Type narrowing: convert FlextResult[str] to Union type
            write_result = self._builder_write_result
            if write_result.is_success:
                value_str = write_result.unwrap()
                if not isinstance(value_str, str):
                    msg = f"Expected str, got {type(value_str)}"
                    raise TypeError(msg)
                return FlextResult[list[FlextLdifModels.Entry] | str].ok(value_str)
            return FlextResult[list[FlextLdifModels.Entry] | str].fail(
                write_result.error or "Write failed",
            )
        if self._builder_filter_result is not None:
            # Type narrowing: convert FlextResult[list[Entry]] to Union type
            filter_result = self._builder_filter_result
            if filter_result.is_success:
                value_entries = filter_result.unwrap()
                if not isinstance(value_entries, list):
                    msg = f"Expected list[Entry], got {type(value_entries)}"
                    raise TypeError(msg)
                return FlextResult[list[FlextLdifModels.Entry] | str].ok(value_entries)
            return FlextResult[list[FlextLdifModels.Entry] | str].fail(
                filter_result.error or "Filter failed",
            )
        if self._builder_parse_result is not None:
            # Type narrowing: convert FlextResult[list[Entry]] to Union type
            parse_result = self._builder_parse_result
            if parse_result.is_success:
                value_entries = parse_result.unwrap()
                if not isinstance(value_entries, list):
                    msg = f"Expected list[Entry], got {type(value_entries)}"
                    raise TypeError(msg)
                return FlextResult[list[FlextLdifModels.Entry] | str].ok(value_entries)
            return FlextResult[list[FlextLdifModels.Entry] | str].fail(
                parse_result.error or "Parse failed",
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
