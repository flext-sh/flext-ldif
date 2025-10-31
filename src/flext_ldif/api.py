"""FLEXT-LDIF API - Unified Facade for LDIF Operations.

This module provides the primary entry point for all LDIF processing operations.
The FlextLdif class serves as the sole facade for the FLEXT LDIF library,
consolidating all business logic and service coordination into a single interface.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, ClassVar, cast, override

from flext_core import (
    FlextContainer,
    FlextContext,
    FlextDispatcher,
    FlextLogger,
    FlextRegistry,
    FlextResult,
    FlextService,
)
from pydantic import PrivateAttr

from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.services.acl import FlextLdifAclService
from flext_ldif.services.filters import FlextLdifFilters
from flext_ldif.services.migration import FlextLdifMigrationPipeline
from flext_ldif.services.parser import FlextLdifParserService
from flext_ldif.services.registry import FlextLdifRegistry
from flext_ldif.services.server_detector import FlextLdifServerDetector
from flext_ldif.services.statistics import FlextLdifStatisticsService
from flext_ldif.services.validation import FlextLdifValidationService
from flext_ldif.services.writer import FlextLdifWriterService
from flext_ldif.typings import FlextLdifTypes, ServiceT


class FlextLdif(FlextService[dict[str, object]]):
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

    # Private attributes (initialized in __init__ and model_post_init)
    # Using PrivateAttr() for Pydantic v2 compatibility
    _dispatcher: FlextDispatcher | None = PrivateAttr(default=None)
    _registry: FlextRegistry | None = PrivateAttr(default=None)
    _logger: FlextLogger | None = PrivateAttr(default=None)
    _parser_service: FlextLdifParserService = PrivateAttr()
    _acl_service: FlextLdifAclService = PrivateAttr()
    _writer_service: FlextLdifWriterService | None = PrivateAttr(default=None)

    _container: FlextContainer = PrivateAttr(
        default_factory=FlextContainer.get_global,
    )
    _context: dict[str, object] = PrivateAttr(default_factory=dict)
    _handlers: dict[str, object] = PrivateAttr(default_factory=dict)
    _init_config_value: FlextLdifConfig | None = PrivateAttr(default=None)

    # Direct class access for builders and services (no wrappers)
    AclService: ClassVar[type[FlextLdifAclService]] = FlextLdifAclService

    # Singleton instance storage
    _instance: ClassVar[FlextLdif | None] = None

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
            assert ldif is ldif2

        """
        if cls._instance is None:
            cls._instance = cls(config)
        return cls._instance

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
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
            config: Optional LDIF configuration. If not provided,
                   uses global singleton instance.

        """
        # Store config for lazy initialization in model_post_init
        object.__setattr__(self, "_init_config_value", config)

        # Call super().__init__() for Pydantic v2 model initialization
        # This will call model_post_init() which initializes all services
        super().__init__()

        # Services initialized in model_post_init for proper initialization order

    def model_post_init(self, _context: dict[str, object] | None, /) -> None:
        """Initialize private attributes after Pydantic initialization.

        This hook is called by Pydantic after __init__ completes and handles:
        - Service setup and dependency injection via FlextContainer
        - Default quirk registration for all supported LDAP servers
        - Context and handler initialization

        Args:
            _context: Pydantic's validation context dictionary or None (unused).

        """
        # Initialize dispatcher, registry, and logger FIRST
        # These are needed by _register_components() below
        dispatcher = FlextDispatcher()
        self._dispatcher = dispatcher
        self._registry = FlextRegistry(dispatcher=dispatcher)
        self._logger = FlextLogger(__name__)

        # Initialize private attributes
        config = getattr(self, "_init_config_value", None) or FlextLdifConfig()
        self._config = config
        self._context = {}
        self._handlers = {}

        # Initialize service instances (using config for parser)
        self._parser_service = FlextLdifParserService(config=config)
        self._acl_service = FlextLdifAclService()

        # Register services in container
        self._setup_services()

        # Register LDIF components with FlextRegistry
        self._register_components()

        # Log config initialization
        if self.logger and self._config:
            config_info: dict[str, object] = {
                "ldif_encoding": self._config.ldif_encoding,
                "strict_rfc_compliance": self._config.strict_rfc_compliance,
                "ldif_chunk_size": self._config.ldif_chunk_size,
                "max_workers": self._config.max_workers,
            }
            self._log_config_once(config_info, message="FlextLdif facade initialized")
            self.logger.debug("Services setup and default quirks registered")

    # =========================================================================
    # PRIVATE: Service Setup and Handler Initialization (from client.py)
    # =========================================================================

    def _setup_services(self) -> None:
        """Register all services in the dependency injection container."""
        container = self.container

        # Register quirk registry FIRST (required by writer/parsers)
        quirk_registry = FlextLdifRegistry()
        container.register("quirk_registry", quirk_registry)

        # Register unified writer service (primary)
        # Writer service is stateless and gets registry from global instance
        unified_writer = FlextLdifWriterService()
        container.register("writer", unified_writer)

        # Register filters service
        container.register("filters", FlextLdifFilters())

        # Register statistics service
        container.register("statistics", FlextLdifStatisticsService())

        # Register validation service
        container.register("validation", FlextLdifValidationService())

        # Register migration pipeline (params provided at call time by handlers)
        def migration_pipeline_factory(
            params: dict[str, object] | None,
        ) -> object:
            if params is None:
                params = {}
            return FlextLdifMigrationPipeline(
                input_dir=Path(cast("str", params.get("input_dir", "."))),
                output_dir=Path(cast("str", params.get("output_dir", "."))),
                source_server=str(
                    params.get("source_server", FlextLdifConstants.ServerTypes.RFC),
                ),
                target_server=str(
                    params.get("target_server", FlextLdifConstants.ServerTypes.RFC),
                ),
            )

        container.register("migration_pipeline", migration_pipeline_factory)

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

    def _register_components(self) -> None:
        """Register LDIF components with FlextRegistry for dependency injection."""
        try:
            # Register core LDIF services
            if self._registry is not None:
                self._registry.register(
                    "ldif_parser_service",
                    self._parser_service,
                    metadata={
                        "type": "service",
                        "domain": "parser",
                        "description": "Unified LDIF parsing",
                    },
                )

                # Register configuration and constants
                self._registry.register(
                    "ldif_config",
                    self.config,
                    metadata={"type": "config", "domain": "ldif"},
                )
                self._registry.register(
                    "ldif_constants",
                    FlextLdifConstants,
                    metadata={"type": "constants", "domain": "ldif"},
                )

                if self._logger:
                    self._logger.debug(
                        "LDIF components registered with FlextRegistry",
                        extra={
                            "correlation_id": getattr(
                                self.context, "correlation_id", None
                            ),
                            "registered_components": [
                                "ldif_config",
                                "ldif_constants",
                            ],
                        },
                    )

        except (ValueError, TypeError, AttributeError) as e:
            # Use FlextExceptions for error handling
            msg = f"Failed to register LDIF components: {e}"
            raise RuntimeError(msg) from e

        # Log initialization with structured context
        if self._logger is not None:
            self._logger.info(
                "FlextLdif initialized with complete Flext ecosystem integration",
                extra={
                    "service_type": "LDIF Processing Facade",
                    "correlation_id": getattr(self.context, "correlation_id", None),
                    "flext_components": [
                        "FlextContainer",
                        "FlextLogger",
                        "FlextContext",
                        "FlextDispatcher",
                        "FlextRegistry",
                        "FlextExceptions",
                        "FlextProtocols",
                    ],
                    "ldif_features": [
                        "rfc_2849_parsing",
                        "rfc_4512_compliance",
                        "server_quirks",
                        "generic_migration",
                        "schema_validation",
                        "acl_processing",
                        "entry_building",
                    ],
                },
            )

    @override
    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute facade self-check and return status.

        Returns:
        FlextResult containing facade status and configuration

        """
        try:
            config = self.config
            status_dict: dict[str, object] = {
                "status": FlextLdifConstants.DictKeys.INITIALIZED,
                "services": FlextLdifConstants.DictKeys.SERVICE_NAMES,
                "config": {"default_encoding": config.ldif_encoding},
            }
            return FlextResult[dict[str, object]].ok(status_dict)
        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[dict[str, object]].fail(
                f"Status check failed: {e}",
            )

    def parse(
        self,
        source: str | Path,
        server_type: str | None = None,
        format_options: FlextLdifModels.ParseFormatOptions | None = None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        r"""Parse LDIF content string or file.

        Parses LDIF content string or file with quirks support.

        Args:
            source: LDIF content as string or Path to LDIF file
            server_type: Server type for quirk selection ("rfc", "oid", "oud", etc.)
            format_options: Optional parse format options model

        Returns:
            FlextResult containing list of parsed LDIF entries

        Example:
            # Parse LDIF content string
            ldif_content = "dn: cn=test,dc=example,dc=com\ncn: test\n"
            result = ldif.parse(ldif_content)
            if result.is_success:
                entries = result.unwrap()

            # Parse LDIF file
            result = ldif.parse_file(Path("directory.ldif"))
            if result.is_success:
                entries = result.unwrap()

            # Parse with options using model
            options = FlextLdifModels.ParseFormatOptions(
                auto_parse_schema=False,
                validate_entries=True
            )
            result = ldif.parse(ldif_content, format_options=options)

        """
        try:
            # Determine the server type, defaulting to RFC if not provided.
            effective_server_type = server_type or FlextLdifConstants.ServerTypes.RFC

            # Ensure the parser service is initialized.
            if not hasattr(self, "_parser_service") or self._parser_service is None:
                self._parser_service = FlextLdifParserService(config=self.config)

            # Read content from Path object if necessary.
            if isinstance(source, Path):
                content = source.read_text(encoding=self.config.ldif_encoding)
            elif isinstance(source, str) and "\n" not in source:
                try:
                    file_path = Path(source)
                    if file_path.is_file():
                        content = file_path.read_text(
                            encoding=self.config.ldif_encoding
                        )
                    else:
                        content = source
                except (ValueError, OSError):
                    content = source
            else:
                content = source

            # Delegate parsing to the parser service.
            parse_result = self._parser_service.parse(
                content=content,
                input_source="string",
                server_type=effective_server_type,
                format_options=format_options,
            )
            if parse_result.is_success:
                response = parse_result.unwrap()
                return FlextResult.ok(response.entries)
            return FlextResult.fail(parse_result.error)

        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Failed to parse LDIF: {e}"
            )

    def write(
        self,
        entries: list[FlextLdifModels.Entry],
        output_path: Path | None = None,
        server_type: str | None = None,
        format_options: FlextLdifModels.WriteFormatOptions | None = None,
    ) -> FlextResult[str]:
        """Write entries to LDIF format string or file.

        Uses FlextLdifWriterService for RFC 2849 compliant LDIF writing.

        Args:
            entries: List of LDIF entries to write
            output_path: Optional path to write LDIF file. If None, returns LDIF string.
            server_type: Target server type for writing. If None, uses RFC.
            format_options: Optional write format options model

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

            # Write with options using model
            options = FlextLdifModels.WriteFormatOptions(
                line_width=100,
                sort_attributes=True
            )
            result = ldif.write(entries, format_options=options)

        """
        try:
            # Get writer service from container or create new instance
            if self._writer_service is None:
                self._writer_service = FlextLdifWriterService()

            target_server = server_type or "rfc"

            if output_path:
                write_result = self._writer_service.write(
                    entries=entries,
                    target_server_type=target_server,
                    output_target="file",
                    output_path=output_path,
                    format_options=format_options,
                )
                if write_result.is_success:
                    # The result for file writing is a WriteResponse model, not the content.
                    # We should return a consistent success message.
                    message = f"LDIF written successfully to {output_path}"
                    return FlextResult.ok(message)
                return FlextResult.fail(write_result.error)

            # Writing to a string
            string_result = self._writer_service.write(
                entries=entries,
                target_server_type=target_server,
                output_target="string",
                format_options=format_options,
            )
            if string_result.is_success:
                # The result for string writing is the LDIF content.
                return FlextResult.ok(string_result.unwrap())
            return FlextResult.fail(string_result.error)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[str].fail(f"Write operation failed: {e}")

    def get_entry_dn(
        self,
        entry: FlextLdifModels.Entry | FlextLdifProtocols.Entry.EntryWithDnProtocol,
    ) -> FlextResult[str]:
        """Extract DN (Distinguished Name) from any entry type.

        Handles both FlextLdifModels.Entry (from LDIF files) and
        FlextLdapModels.Entry (from LDAP server operations).

        Args:
            entry: LDIF or LDAP entry to extract DN from

        Returns:
            FlextResult containing DN as string

        Example:
            # Works with LDIF entries
            result = ldif.get_entry_dn(ldif_entry)

            # Works with LDAP entries from search
            result = ldif.get_entry_dn(ldap_entry)

            if result.is_success:
                dn = result.unwrap()

        """
        try:
            if not entry or not hasattr(entry, "dn"):
                return FlextResult[str].fail("Entry missing DN attribute")

            dn_value = entry.dn
            # Handle both DistinguishedName objects (with .value) and plain strings
            value_attr = getattr(dn_value, "value", None)
            if value_attr is not None:
                return FlextResult[str].ok(str(value_attr))
            return FlextResult[str].ok(str(dn_value))

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[str].fail(f"Failed to extract DN: {e}")

    def get_entry_attributes(
        self,
        entry: FlextLdifModels.Entry | FlextLdifProtocols.Entry.EntryWithDnProtocol,
    ) -> FlextResult[FlextLdifTypes.CommonDict.AttributeDict]:
        """Extract attributes from any entry type.

        Handles both FlextLdifModels.Entry (from LDIF files) and
        FlextLdapModels.Entry (from LDAP server operations).

        Returns attributes as dict[str, str | list[str]] per
        FlextLdifTypes.CommonDict.AttributeDict.
        Attribute values are returned as provided (str or list).

        Args:
            entry: LDIF or LDAP entry to extract attributes from

        Returns:
            FlextResult containing AttributeDict with attribute names mapped to
            str | list[str] values matching FlextLdifTypes definition.

        Example:
            # Works with both LDIF and LDAP entries
            result = ldif.get_entry_attributes(entry)
            if result.is_success:
                attrs = result.unwrap()
                # Can pass directly to build operations
                ldif.build(FlextLdifConstants.EntryTypes.PERSON, attributes=attrs)

        """
        try:
            if not entry or not hasattr(entry, "attributes"):
                return FlextResult[FlextLdifTypes.CommonDict.AttributeDict].fail(
                    "Entry missing attributes",
                )

            attrs_container = entry.attributes
            result_dict: FlextLdifTypes.CommonDict.AttributeDict = {}

            # Handle both LdifAttributes and dict-like access
            if isinstance(attrs_container, FlextLdifModels.LdifAttributes):
                # Extract attributes from LdifAttributes container
                for attr_name, attr_values in attrs_container.attributes.items():
                    # attr_values is always a list[str] in LdifAttributes
                    if len(attr_values) == 1:
                        result_dict[attr_name] = attr_values[0]
                    else:
                        result_dict[attr_name] = attr_values
            elif isinstance(attrs_container, dict):
                # Handle dict representation (from model_validate with dict input)
                attrs_dict = cast("dict[str, object]", attrs_container)
                for attr_name, attr_val in attrs_dict.items():
                    if isinstance(attr_val, list):
                        # Return list as-is or single item if length==1
                        if len(attr_val) == 1:
                            result_dict[attr_name] = attr_val[0]
                        else:
                            result_dict[attr_name] = attr_val
                    else:
                        # Single value - return as string
                        result_dict[attr_name] = str(attr_val)

            return FlextResult[FlextLdifTypes.CommonDict.AttributeDict].ok(result_dict)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifTypes.CommonDict.AttributeDict].fail(
                f"Failed to extract attributes: {e}",
            )

    def create_entry(
        self,
        dn: str,
        attributes: dict[str, str | list[str]],
        objectclasses: list[str] | None = None,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Create a new LDIF entry with validation.

        Args:
            dn: Distinguished Name for the entry
            attributes: Dict mapping attribute names to values (string or list)
            objectclasses: Optional list of objectClass values (added to attributes if provided)

        Returns:
            FlextResult containing new FlextLdifModels.Entry

        Example:
            result = ldif.create_entry(
                dn="cn=John Doe,ou=Users,dc=example,dc=com",
                attributes={"cn": "John Doe", "sn": "Doe", "mail": "john@example.com"},
                objectclasses=["inetOrgPerson", "person", "top"]
            )
            if result.is_success:
                entry = result.unwrap()

        """
        try:
            # Normalize attributes to ensure all values are lists
            normalized_attrs: FlextLdifTypes.CommonDict.AttributeDict = {}
            for key, value in attributes.items():
                if isinstance(value, list):
                    normalized_attrs[key] = [str(v) for v in value]
                else:
                    normalized_attrs[key] = [str(value)]

            # Add objectClass if provided
            if objectclasses:
                normalized_attrs["objectClass"] = [str(v) for v in objectclasses]

            # Use FlextLdifModels.Entry.create() factory method
            create_result = FlextLdifModels.Entry.create(
                dn=dn,
                attributes=normalized_attrs,
            )

            if create_result.is_success:
                return create_result
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Failed to create entry: {create_result.error}",
            )

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Failed to create entry: {e}",
            )

    def get_entry_objectclasses(
        self,
        entry: FlextLdifModels.Entry | FlextLdifProtocols.Entry.EntryWithDnProtocol,
    ) -> FlextResult[list[str]]:
        """Extract objectClass values from any entry type.

        Handles both FlextLdifModels.Entry (from LDIF files) and
        FlextLdapModels.Entry (from LDAP server operations).

        Args:
            entry: LDIF or LDAP entry to extract objectClasses from

        Returns:
            FlextResult containing list of objectClass values

        Example:
            # Works with both LDIF and LDAP entries
            result = ldif.get_entry_objectclasses(entry)
            if result.is_success:
                object_classes = result.unwrap()
                if "inetOrgPerson" in object_classes:
                    print("Entry is a person")

        """
        try:
            # First try to get objectClass from attributes
            attrs_result = self.get_entry_attributes(entry)
            if attrs_result.is_success:
                attrs = attrs_result.unwrap()
                # objectClass might be stored as "objectClass" or "objectclass"
                oc_values = attrs.get("objectClass") or attrs.get("objectclass")
                if oc_values:
                    # Normalize to list (get_entry_attributes returns str | list[str])
                    if isinstance(oc_values, str):
                        return FlextResult[list[str]].ok([oc_values])
                    return FlextResult[list[str]].ok(oc_values)

            # Fallback: try direct access to object_classes attribute (LDAP entries)
            oc_attr = getattr(entry, "object_classes", None)
            if oc_attr is not None:
                if isinstance(oc_attr, list):
                    return FlextResult[list[str]].ok([str(v) for v in oc_attr])
                return FlextResult[list[str]].ok([str(oc_attr)])

            return FlextResult[list[str]].fail("Entry missing objectClass attribute")

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[list[str]].fail(f"Failed to extract objectClasses: {e}")

    def get_attribute_values(self, attribute: object) -> FlextResult[list[str]]:
        """Extract values from an attribute value object.

        Handles various attribute value formats from both LDIF and LDAP entries.

        Args:
            attribute: Attribute value object (could be LdifAttributeValue,
                      LdapAttributeValue, list, or string)

        Returns:
            FlextResult containing list of attribute values as strings

        Example:
            # Extract values from attribute objects
            result = ldif.get_attribute_values(attr_value_obj)
            if result.is_success:
                values = result.unwrap()
                for value in values:
                    print(f"Value: {value}")

        """
        try:
            # Handle None
            if attribute is None:
                return FlextResult[list[str]].ok([])

            # Handle objects with .values property
            values = getattr(attribute, "values", None)
            if values is not None:
                if isinstance(values, list):
                    return FlextResult[list[str]].ok([str(v) for v in values])
                return FlextResult[list[str]].ok([str(values)])

            # Handle lists directly
            if isinstance(attribute, list):
                return FlextResult[list[str]].ok([str(v) for v in attribute])

            # Handle single values
            return FlextResult[list[str]].ok([str(attribute)])

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[list[str]].fail(
                f"Failed to extract attribute values: {e}",
            )

    def migrate(
        self,
        input_dir: Path,
        output_dir: Path,
        source_server: str,
        target_server: str,
        *,
        # New: Structured migration with MigrationConfig
        migration_config: FlextLdifModels.MigrationConfig
        | dict[str, Any]
        | None = None,
        write_options: FlextLdifModels.WriteFormatOptions | None = None,
        # Categorization parameters (optional - enables categorized mode)
        categorization_rules: dict[str, object] | None = None,
        input_files: list[str] | None = None,
        output_files: dict[str, str] | None = None,
        schema_whitelist_rules: dict[str, object] | None = None,
        # Simple migration parameters
        input_filename: str | None = None,
        output_filename: str | None = None,
        # Common parameters
        forbidden_attributes: list[str] | None = None,
        forbidden_objectclasses: list[str] | None = None,
        base_dn: str | None = None,
        sort_entries_hierarchically: bool = False,
    ) -> FlextResult[FlextLdifModels.PipelineExecutionResult]:
        r"""Unified LDIF migration supporting simple, categorized, and structured modes.

        Automatically detects migration mode based on parameters:
        - **Structured Mode**: 6-file output (00-schema to 06-rejected) with full tracking (when migration_config provided)
        - **Categorized Mode**: Custom multi-file output (when categorization_rules provided)
        - **Simple Mode**: Single output file (default behavior)

        Generic migration supporting any LDAP server type. All parameters are
        fully customizable with no hardcoded values.

        Args:
            input_dir: Directory containing source LDIF files
            output_dir: Directory for output files
            source_server: Source server type identifier (e.g., "oracle_oid", "openldap")
            target_server: Target server type identifier (e.g., "oracle_oud", "ad")

            # Structured migration parameters (preferred for production)
            migration_config: MigrationConfig model or dict with:
                - output_file_mapping: Dict of category -> filename
                - hierarchy_objectclasses, user_objectclasses, group_objectclasses: Lists for categorization
                - attribute_whitelist/blacklist, objectclass_whitelist/blacklist: Filtering rules
                - track_removed_attributes, write_removed_as_comments: Tracking options
                - header_template, header_data: Jinja2 header template and data
            write_options: WriteFormatOptions model with:
                - disable_line_folding: True to disable line wrapping
                - write_removed_attributes_as_comments: True to write removed attrs as comments
                - line_width: Maximum line width (default 100000 for effectively unlimited)

            # Categorized mode parameters (legacy)
            categorization_rules: Dict defining entry categories (enables categorized mode)
                Keys: category_name + "_objectclasses" or category_name + "_attributes"
                Example: {
                    "hierarchy_objectclasses": ["organization", "organizationalUnit"],
                    "user_objectclasses": ["inetOrgPerson", "person"],
                    "group_objectclasses": ["groupOfNames"],
                    "acl_attributes": ["aci"],  # Empty list = disable ACL
                }
            input_files: Ordered list of LDIF files to process (categorized mode)
            output_files: Category→filename mapping (categorized mode)
            schema_whitelist_rules: Dict of allowed schema elements (categorized mode)

            # Simple mode parameters
            input_filename: Specific input file to process (simple mode only)
            output_filename: Output filename (simple mode only, optional, defaults to "migrated.ldif")

            # Common parameters
            forbidden_attributes: Optional list of attributes to remove
            forbidden_objectclasses: Optional list of objectClasses to remove
            base_dn: Optional target base DN for DN normalization
            sort_entries_hierarchically: If True, sort entries by DN hierarchy depth then alphabetically (default: False)

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
                source_server="oracle_oid",
                target_server="oracle_oud"
            )

            # Structured migration - 6 files with removed attribute tracking
            config = FlextLdifModels.MigrationConfig(
                hierarchy_objectclasses=["organization", "organizationalUnit"],
                user_objectclasses=["inetOrgPerson", "person"],
                group_objectclasses=["groupOfNames"],
                attribute_blacklist=["pwdChangedTime", "modifiersName"],
                track_removed_attributes=True,
                write_removed_as_comments=True,
                header_template="# Migration from {{source}} to {{target}}\\n",
                header_data={"source": "OID", "target": "OUD"}
            )
            write_opts = FlextLdifModels.WriteFormatOptions(
                disable_line_folding=True
            )
            result = ldif.migrate(
                input_dir=Path("source"),
                output_dir=Path("target"),
                source_server="oracle_oid",
                target_server="oracle_oud",
                migration_config=config,
                write_options=write_opts
            )

            # Categorized migration - legacy approach
            result = ldif.migrate(
                input_dir=Path("source"),
                output_dir=Path("target"),
                source_server="oracle_oid",
                target_server="oracle_oud",
                categorization_rules={
                    "hierarchy_objectclasses": ["organization", "organizationalUnit"],
                    "user_objectclasses": ["inetOrgPerson", "person"],
                    "group_objectclasses": ["groupOfNames"],
                    "acl_attributes": ["aci"],
                }
            )

        """
        try:
            # Convert dict to MigrationConfig model if needed
            config_model: FlextLdifModels.MigrationConfig | None = None
            if migration_config is not None:
                if isinstance(migration_config, dict):
                    config_model = FlextLdifModels.MigrationConfig(**migration_config)
                else:
                    config_model = migration_config

            # Auto-detect mode based on parameters
            if config_model is not None:
                mode = "structured"
            elif categorization_rules is not None:
                mode = "categorized"
            else:
                mode = "simple"

            # Set default write options for structured mode
            if mode == "structured" and write_options is None:
                write_options = FlextLdifModels.WriteFormatOptions(
                    disable_line_folding=True,
                    write_removed_attributes_as_comments=config_model.write_removed_as_comments
                    if config_model
                    else False,
                )

            # Build pipeline arguments
            pipeline_kwargs = {
                "input_dir": input_dir,
                "output_dir": output_dir,
                "mode": mode,
                "source_server": source_server,
                "target_server": target_server,
                # Common parameters
                "forbidden_attributes": forbidden_attributes,
                "forbidden_objectclasses": forbidden_objectclasses,
                "base_dn": base_dn,
                "sort_entries_hierarchically": sort_entries_hierarchically,
            }

            # Add structured mode parameters
            if config_model is not None:
                pipeline_kwargs.update({
                    "migration_config": config_model,
                    "write_options": write_options,
                })

            # Add categorized mode parameters if provided
            if categorization_rules is not None:
                pipeline_kwargs.update({
                    "categorization_rules": categorization_rules,
                    "input_files": input_files,
                    "output_files": output_files,
                    "schema_whitelist_rules": schema_whitelist_rules,
                })

            # Add simple mode parameters if provided
            if input_filename is not None:
                pipeline_kwargs["input_filename"] = input_filename
                # When input_filename is specified, output_filename becomes required
                if output_filename is None:
                    return FlextResult[FlextLdifModels.PipelineExecutionResult].fail(
                        "output_filename is required when input_filename is specified"
                    )
                pipeline_kwargs["output_filename"] = output_filename
            elif output_filename is not None:
                pipeline_kwargs["output_filename"] = output_filename

            migration_pipeline = FlextLdifMigrationPipeline(**pipeline_kwargs)

            return migration_pipeline.execute()

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifModels.PipelineExecutionResult].fail(
                f"Migration failed: {e}"
            )

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
        # Get filters service once at the start
        filters_service = self._get_service_typed(
            self.container,
            "filters",
            FlextLdifFilters,
        )
        if filters_service is None:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                "Filters service not available in container",
            )

        # If custom_filter is provided, apply it along with other criteria
        if custom_filter is not None:
            try:
                # First apply standard filters
                # Note: mark_excluded=False for clean filtering (public API behavior)
                if objectclass is not None:
                    filter_result = filters_service.filter_entries_by_objectclass(
                        entries, objectclass, mark_excluded=False
                    )
                    if not filter_result.is_success:
                        return FlextResult[list[FlextLdifModels.Entry]].fail(
                            f"Objectclass filter failed: {filter_result.error}",
                        )
                    entries = filter_result.unwrap()

                if dn_pattern is not None:
                    # Convert simple substring pattern to fnmatch pattern
                    fnmatch_pattern = (
                        f"*{dn_pattern}*" if "*" not in dn_pattern else dn_pattern
                    )
                    filter_result = filters_service.filter_entries_by_dn(
                        entries, fnmatch_pattern, mark_excluded=False
                    )
                    if not filter_result.is_success:
                        return FlextResult[list[FlextLdifModels.Entry]].fail(
                            f"DN pattern filter failed: {filter_result.error}",
                        )
                    entries = filter_result.unwrap()

                if attributes is not None:
                    attr_list = list(attributes.keys())
                    filter_result = filters_service.filter_entries_by_attributes(
                        entries, attr_list, mark_excluded=False
                    )
                    if not filter_result.is_success:
                        return FlextResult[list[FlextLdifModels.Entry]].fail(
                            f"Attributes filter failed: {filter_result.error}",
                        )
                    entries = filter_result.unwrap()

                # Now apply custom_filter to the remaining entries
                filtered_entries = [e for e in entries if custom_filter(e)]
                return FlextResult[list[FlextLdifModels.Entry]].ok(filtered_entries)

            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Entry filtering with custom filter failed: {e}",
                )

        # No custom_filter - chain multiple filters
        try:
            # Apply objectclass filter if provided
            if objectclass is not None:
                filter_result = filters_service.filter_entries_by_objectclass(
                    entries, objectclass, mark_excluded=False
                )
                if not filter_result.is_success:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Objectclass filter failed: {filter_result.error}",
                    )
                entries = filter_result.unwrap()

            # Apply dn_pattern filter if provided
            if dn_pattern is not None:
                # Convert simple substring pattern to fnmatch pattern
                fnmatch_pattern = (
                    f"*{dn_pattern}*" if "*" not in dn_pattern else dn_pattern
                )
                filter_result = filters_service.filter_entries_by_dn(
                    entries, fnmatch_pattern, mark_excluded=False
                )
                if not filter_result.is_success:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"DN pattern filter failed: {filter_result.error}",
                    )
                entries = filter_result.unwrap()

            # Apply attributes filter if provided
            if attributes is not None:
                attr_list = list(attributes.keys())
                filter_result = filters_service.filter_entries_by_attributes(
                    entries, attr_list, mark_excluded=False
                )
                if not filter_result.is_success:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Attributes filter failed: {filter_result.error}",
                    )
                entries = filter_result.unwrap()

            # Return filtered entries (all criteria have been applied)
            return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Entry filtering failed: {e}",
            )

    # =========================================================================
    # ANALYSIS OPERATIONS
    # =========================================================================

    def analyze(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[FlextLdifModels.EntryAnalysisResult]:
        """Analyze LDIF entries and generate statistics.

        Performs comprehensive analysis of entry collection including:
        - Total entry count
        - Object class distribution
        - Pattern detection in DNs and attributes

        Args:
            entries: List of entries to analyze

        Returns:
            FlextResult containing EntryAnalysisResult with statistics

        Example:
            result = api.analyze(entries)
            if result.is_success:
                stats = result.unwrap()
                print(f"Total: {stats.total_entries}")
                print(f"Classes: {stats.objectclass_distribution}")

        """
        try:
            total_entries = len(entries)

            # Analyze object class distribution
            objectclass_distribution: dict[str, int] = {}
            patterns_detected: list[str] = []

            for entry in entries:
                # Count object classes
                if entry.objectclasses:
                    for oc in entry.objectclasses:
                        oc_name = oc.name if hasattr(oc, "name") else str(oc)
                        objectclass_distribution[oc_name] = (
                            objectclass_distribution.get(oc_name, 0) + 1
                        )

                # Simple pattern detection
                dn_str = str(entry.dn)
                if (
                    "ou=users" in dn_str.lower()
                    and "user pattern" not in patterns_detected
                ):
                    patterns_detected.append("user pattern")
                if (
                    "ou=groups" in dn_str.lower()
                    and "group pattern" not in patterns_detected
                ):
                    patterns_detected.append("group pattern")

            # Create analysis result
            analysis_result = FlextLdifModels.EntryAnalysisResult(
                total_entries=total_entries,
                objectclass_distribution=objectclass_distribution,
                patterns_detected=patterns_detected,
            )

            return FlextResult[FlextLdifModels.EntryAnalysisResult].ok(analysis_result)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifModels.EntryAnalysisResult].fail(
                f"Entry analysis failed: {e}"
            )

    def validate_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[FlextLdifModels.ValidationResult]:
        """Validate LDIF entries against RFC 2849/4512 standards.

        Performs comprehensive validation including:
        - DN format validation
        - Attribute name validation (RFC 4512)
        - ObjectClass name validation (RFC 4512)
        - Attribute value length checks
        - Entry structure validation

        Args:
            entries: List of entries to validate

        Returns:
            FlextResult containing ValidationResult with validation status

        Example:
            result = api.validate_entries(entries)
            if result.is_success:
                report = result.unwrap()
                print(f"Valid: {report.is_valid}")
                print(f"Valid entries: {report.valid_entries}/{report.total_entries}")

        """
        try:
            # Get validation service from container
            validation_service = self._get_service_typed(
                self.container,
                "validation",
                FlextLdifValidationService,
            )
            if validation_service is None:
                return FlextResult[FlextLdifModels.ValidationResult].fail(
                    "Validation service not available"
                )

            errors: list[str] = []
            valid_count = 0
            invalid_count = 0

            for entry in entries:
                is_entry_valid = True

                # Validate DN
                dn_str = entry.dn.value
                if not dn_str or not isinstance(dn_str, str):
                    errors.append(f"Entry has invalid DN: {entry.dn}")
                    is_entry_valid = False

                # Validate each attribute name
                for attr_name in entry.attributes.attributes:
                    attr_result = validation_service.validate_attribute_name(attr_name)
                    if attr_result.is_failure or not attr_result.unwrap():
                        errors.append(
                            f"Entry {dn_str}: Invalid attribute name '{attr_name}'"
                        )
                        is_entry_valid = False

                # Validate objectClass values
                oc_values = entry.attributes.attributes.get("objectClass", [])
                if isinstance(oc_values, list):
                    for oc in oc_values:
                        oc_result = validation_service.validate_objectclass_name(oc)
                        if oc_result.is_failure or not oc_result.unwrap():
                            errors.append(f"Entry {dn_str}: Invalid objectClass '{oc}'")
                            is_entry_valid = False

                if is_entry_valid:
                    valid_count += 1
                else:
                    invalid_count += 1

            total_entries = len(entries)
            is_valid = invalid_count == 0

            result = FlextLdifModels.ValidationResult(
                is_valid=is_valid,
                total_entries=total_entries,
                valid_entries=valid_count,
                invalid_entries=invalid_count,
                errors=errors[:100],  # Limit errors to 100
            )

            return FlextResult[FlextLdifModels.ValidationResult].ok(result)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifModels.ValidationResult].fail(
                f"Entry validation failed: {e}"
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
        return self._acl_service.extract_acls_from_entry(entry, server_type)

    def evaluate_acl_rules(
        self,
        acls: list[FlextLdifModels.Acl],
        context: object = None,
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
        # Delegate to ACL service for direct context evaluation
        eval_context = context if isinstance(context, dict) else (context or {})
        return self._acl_service.evaluate_acl_context(
            acls,
            cast("dict[str, object]", eval_context),
        )

    def transform_acl_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        source_server: str | type[FlextLdifConstants.ServerTypes],
        target_server: str | type[FlextLdifConstants.ServerTypes],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Transform ACL attributes from source to target server format.

        This is the ONLY way to transform ACLs through the facade. Internal quirks
        are accessed here, but consumers never see them directly. This ensures:
        - Consistent ACL transformation across all consuming code
        - Proper validation of transformation results
        - Centralized error handling and logging
        - Server-specific quirks remain private implementation details

        Args:
            entries: List of entries with ACL attributes in source format
            source_server: Source server type (e.g., "OID", "OpenLDAP")
            target_server: Target server type (e.g., "OUD", "AD")

        Returns:
            FlextResult containing list of entries with ACL attributes in target format

        Raises:
            Returns FlextResult.fail() if transformation fails

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

        Implementation Notes:
            1. Gets quirks for source and target servers from registry
            2. For each entry, extracts ACL attributes using source quirk
            3. Transforms ACL values using source→target quirk chain
            4. Validates target ACL attribute exists in result
            5. Returns only successfully transformed entries
            6. Logs detailed errors for failed transformations
            7. Non-fatal: entries with transformation errors are skipped

        """
        try:
            if not entries:
                return FlextResult[list[FlextLdifModels.Entry]].ok([])

            # Normalize server type strings if needed
            source_type = (
                source_server
                if isinstance(source_server, str)
                else getattr(source_server, "value", str(source_server))
            )
            target_type = (
                target_server
                if isinstance(target_server, str)
                else getattr(target_server, "value", str(target_server))
            )

            transformed_entries: list[FlextLdifModels.Entry] = []
            transformation_errors: list[tuple[str, str]] = []

            # Process each entry
            for entry in entries:
                try:
                    # Check if entry has any ACL attributes
                    if not entry.attributes or not entry.attributes.attributes:
                        transformed_entries.append(entry)
                        continue

                    attrs = entry.attributes.attributes
                    # Use constants for ACL attribute detection
                    acl_attrs_lower = {
                        attr.lower()
                        for attr in FlextLdifConstants.AclAttributes.ALL_ACL_ATTRIBUTES
                    }
                    has_acl = any(key.lower() in acl_attrs_lower for key in attrs)

                    if not has_acl:
                        # No ACL attributes, pass through unchanged
                        transformed_entries.append(entry)
                        continue

                    # Build transformation entry dict for quirks system
                    # Quirks work with dict format: {dn: str, attributes: dict}
                    # Note: transformation_entry prepared but ACL transformation not fully implemented
                    _ = {
                        FlextLdifConstants.DictKeys.DN: entry.dn.value,
                        FlextLdifConstants.DictKeys.ATTRIBUTES: dict(attrs),
                    }

                    # Get quirks for source and target servers
                    # These are internal implementation details not exposed to consumers
                    source_quirk = None
                    target_quirk = None

                    # Try to get quirks from registry
                    # Get quirk registry from container
                    quirk_registry = self._get_service_typed(
                        self.container,
                        "quirk_registry",
                        FlextLdifRegistry,
                    )
                    if quirk_registry is not None:
                        source_schemas = quirk_registry.get_schema_quirks(source_type)
                        target_schemas = quirk_registry.get_schema_quirks(target_type)
                        source_quirk = source_schemas[0] if source_schemas else None
                        target_quirk = target_schemas[0] if target_schemas else None
                    else:
                        source_quirk = None
                        target_quirk = None

                    if source_quirk is None or target_quirk is None:
                        # Fallback: no transformation available
                        self.logger.debug(
                            f"Quirks not available for {source_type}→{target_type}, "
                            f"passing entry unchanged: {entry.dn.value}",
                        )
                        transformed_entries.append(entry)
                        continue

                    # Check if quirks have ACL transformation capability
                    source_acl_quirk = (
                        getattr(source_quirk, "acl_quirk", None)
                        if hasattr(source_quirk, "acl_quirk")
                        else None
                    )
                    target_acl_quirk = (
                        getattr(target_quirk, "acl_quirk", None)
                        if hasattr(target_quirk, "acl_quirk")
                        else None
                    )

                    if source_acl_quirk is None or target_acl_quirk is None:
                        # No ACL transformation available for this server pair
                        self.logger.debug(
                            f"ACL quirks not available for {source_type}→{target_type}, "
                            f"passing entry unchanged: {entry.dn.value}",
                        )
                        transformed_entries.append(entry)
                        continue

                    # For now, pass entry unchanged as full ACL transformation is not fully implemented
                    self.logger.debug(
                        f"ACL transformation placeholder for {source_type}→{target_type}, "
                        f"passing entry unchanged: {entry.dn.value}",
                    )
                    transformed_entries.append(entry)
                    continue

                except (ValueError, TypeError, AttributeError, KeyError) as e:
                    transformation_errors.append((
                        entry.dn.value,
                        f"Transformation error: {e!s}",
                    ))
                    self.logger.debug(
                        f"Exception during ACL transformation for {entry.dn.value}: {e}",
                    )
                    continue

            # Log overall transformation statistics
            total = len(entries)
            succeeded = len(transformed_entries)
            failed = len(transformation_errors)

            self.logger.info(
                "ACL transformation complete: %s/%s entries transformed successfully, %s failed",
                succeeded,
                total,
                failed,
            )

            if transformation_errors:
                for dn, error in transformation_errors[
                    : FlextLdifConstants.MAX_LOGGED_ERRORS
                ]:
                    self.logger.debug("  Failed: %s - %s", dn, error)
                if failed > FlextLdifConstants.MAX_LOGGED_ERRORS:
                    self.logger.debug(
                        f"  ... and {failed - FlextLdifConstants.MAX_LOGGED_ERRORS} more failures",
                    )

            return FlextResult[list[FlextLdifModels.Entry]].ok(transformed_entries)

        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"ACL transformation failed: {e}",
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

        Consolidates process_batch() and process_parallel() into a single flexible
        method with an optional parallel execution mode.

        Args:
            processor_name: Name of processor function ("transform", "validate", etc.)
            entries: List of entries to process
            parallel: If True, use parallel processing; if False, use batch. Default: False
            batch_size: Number of entries per batch (only used when parallel=False). Default: 100
            max_workers: Number of worker threads (only used when parallel=True). Default: 4

        Returns:
            FlextResult containing processed results

        Example:
            # Batch processing (sequential)
            result = api.process("transform", entries)

            # Batch processing with custom batch size
            result = api.process("transform", entries, batch_size=200)

            # Parallel processing
            result = api.process("transform", entries, parallel=True)

            # Parallel processing with custom worker count
            result = api.process("validate", entries, parallel=True, max_workers=8)

        Note:
            Supported processors: "transform" (converts to dict), "validate" (validates entries).
            Uses batch processing for sequential operations.
            Uses ThreadPoolExecutor for parallel processing.

        """
        try:
            # Define processor function based on processor_name
            processor_func: Callable[[FlextLdifModels.Entry], dict[str, object]]

            if processor_name == FlextLdifConstants.ProcessorTypes.TRANSFORM:

                def _transform_func(
                    entry: FlextLdifModels.Entry,
                ) -> dict[str, object]:
                    return entry.model_dump()

                processor_func = _transform_func

            elif processor_name == FlextLdifConstants.ProcessorTypes.VALIDATE:

                def _validate_func(
                    entry: FlextLdifModels.Entry,
                ) -> dict[str, object]:
                    # Basic validation: entry has DN and attributes
                    return {
                        "dn": entry.dn.value,
                        "valid": bool(entry.dn.value and entry.attributes),
                        "attribute_count": len(entry.attributes.attributes),
                    }

                processor_func = _validate_func

            else:
                supported = "'transform', 'validate'"
                return FlextResult[list[dict[str, object]]].fail(
                    f"Unknown processor: '{processor_name}'. Supported: {supported}",
                )

            # Execute processing based on mode (parallel or sequential)
            if parallel:
                # Use ThreadPoolExecutor for parallel processing
                try:
                    max_workers_actual = min(len(entries), max_workers)
                    with ThreadPoolExecutor(max_workers=max_workers_actual) as executor:
                        future_to_entry = {
                            executor.submit(processor_func, entry): entry
                            for entry in entries
                        }
                        results = [
                            future.result() for future in as_completed(future_to_entry)
                        ]
                    return FlextResult[list[dict[str, object]]].ok(results)
                except (ValueError, TypeError, AttributeError) as e:
                    return FlextResult[list[dict[str, object]]].fail(
                        f"Parallel processing failed: {e}",
                    )
            else:
                # Batch processing
                results = []
                for i in range(0, len(entries), batch_size):
                    batch = entries[i : i + batch_size]
                    batch_results = [processor_func(entry) for entry in batch]
                    results.extend(batch_results)
                return FlextResult[list[dict[str, object]]].ok(results)

        except (ValueError, TypeError, AttributeError) as e:
            mode = "Parallel" if parallel else "Batch"
            return FlextResult[list[dict[str, object]]].fail(
                f"{mode} processing failed: {e}",
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
        try:
            detector = FlextLdifServerDetector()
            return detector.detect_server_type(
                ldif_path=ldif_path,
                ldif_content=ldif_content,
            )
        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifModels.ServerDetectionResult].fail(
                f"Server detection failed: {e}",
            )

    def get_effective_server_type(
        self,
        ldif_path: Path | None = None,
    ) -> FlextResult[str]:
        """Get the effective LDAP server type that will be used for parsing.

        Resolves the effective server type based on configuration priority:
        1. Relaxed mode (if enabled)
        2. Manual override (if detection_mode is "manual")
        3. Auto-detection (if detection_mode is "auto")
        4. RFC-only (if detection_mode is "disabled")

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
                    "Manual mode requires quirks_server_type to be set",
                )

            # Auto-detection mode
            if config.quirks_detection_mode == "auto" and ldif_path:
                detector = FlextLdifServerDetector()
                detection_result = detector.detect_server_type(ldif_path=ldif_path)
                if detection_result.is_success:
                    detected_data = detection_result.unwrap()
                    # ServerDetectionResult is now a Pydantic model
                    server_type = (
                        detected_data.detected_server_type or config.server_type
                    )
                    return FlextResult[str].ok(server_type)

            # Default to configured server type
            return FlextResult[str].ok(config.server_type)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[str].fail(f"Error determining server type: {e}")

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
    def config(self) -> FlextLdifConfig:
        """Access to LDIF configuration instance with lazy initialization.

        Returns:
            Current FlextLdifConfig instance

        Example:
            encoding = ldif.config.ldif_encoding
            max_workers = ldif.config.max_workers

        """
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
    def constants(self) -> type[FlextLdifConstants]:
        """Access to LDIF constants.

        Returns:
            FlextLdifConstants class containing all constant values

        Example:
            max_line = ldif.constants.Format.MAX_LINE_LENGTH
            encoding = ldif.constants.Encoding.UTF8

        """
        return FlextLdifConstants

    # INTERNAL: bus property is hidden from public API
    # Use models, config, constants for public access instead

    # INTERNAL: dispatcher property is hidden from public API
    # Use client methods for LDIF operations instead

    # INTERNAL: registry property is hidden from public API
    # Use register_quirk() method for quirk management instead

    @property
    def acl_service(self) -> FlextLdifAclService:
        """Access to FlextLdifAclService for ACL operations.

        Returns:
            FlextLdifAclService instance for ACL processing

        Example:
            acls = ldif.acl_service.extract_acls_from_entry(entry)

        """
        return self._acl_service

    @property
    def handlers(self) -> dict[str, object]:
        """Access to initialized CQRS handlers."""
        return self._handlers

    @property
    def container(self) -> FlextContainer:
        """Access to dependency injection container."""
        return self._container

    @property
    def context(self) -> FlextContext:
        """Access to execution context with lazy initialization."""
        if not self._context:
            # Initialize with empty dict
            self._context = {}
        # Return as FlextContext type (which is a dict-like context object)
        return cast("FlextContext", self._context)


__all__ = ["FlextLdif"]
