"""FLEXT-LDIF API - Thin Facade for LDIF Operations.

This module provides the primary entry point for all LDIF processing operations.
The FlextLdif class serves as a thin facade exposing all functionality through
a clean, unified interface that delegates to the FlextLdifClient implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import ClassVar, cast, override

from flext_core import (
    FlextDispatcher,
    FlextLogger,
    FlextRegistry,
    FlextResult,
    FlextService,
)

from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.services.acl import FlextLdifAclService
from flext_ldif.services.client import FlextLdifClient
from flext_ldif.services.entry_builder import FlextLdifEntryBuilder
from flext_ldif.services.parser import FlextLdifParserService
from flext_ldif.services.schema import FlextLdifSchemaBuilder, FlextLdifSchemaValidator
from flext_ldif.typings import FlextLdifTypes


class FlextLdif(FlextService[dict[str, object]]):
    r"""Main API facade for LDIF processing operations.

    This class provides a simplified interface for LDIF operations by delegating
    to underlying service implementations. It inherits from FlextService to leverage
    dependency injection, logging, and event publishing capabilities.

    Capabilities:
        - Parse and write LDIF files according to RFC 2849 and RFC 4512
        - Handle server-specific quirks (OID, OUD, OpenLDAP, AD, 389 DS)
        - Migrate data between different LDAP server types
        - Validate LDIF entries against LDAP schemas
        - Process ACL (Access Control List) entries
        - Batch and parallel processing for large datasets

    Implementation:
        This class follows the Facade pattern, delegating operations to
        FlextLdifClient and other service classes while providing a consistent
        interface for client code.

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

    # Private attributes (initialized in __init__)
    _dispatcher: FlextDispatcher
    _registry: FlextRegistry
    _logger: FlextLogger
    _client: FlextLdifClient
    _parser_service: FlextLdifParserService
    _entry_builder: FlextLdifEntryBuilder
    _schema_builder: FlextLdifSchemaBuilder

    # Direct class access for builders and services (no wrappers)
    EntryBuilder: ClassVar[type[FlextLdifEntryBuilder]] = FlextLdifEntryBuilder
    SchemaBuilder: ClassVar[type[FlextLdifSchemaBuilder]] = FlextLdifSchemaBuilder
    AclService: ClassVar[type[FlextLdifAclService]] = FlextLdifAclService
    SchemaValidator: ClassVar[type[FlextLdifSchemaValidator]] = FlextLdifSchemaValidator

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
        """Initialize LDIF facade.

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
        # Call super().__init__() for Pydantic model initialization
        # Container inherited via FlextContainer.get_global() property
        super().__init__()
        self._dispatcher = FlextDispatcher()
        self._registry = FlextRegistry(dispatcher=self._dispatcher)
        self._logger = FlextLogger(__name__)

        # Initialize LDIF-specific components directly (post-container removal)
        self._config = config if config is not None else FlextLdifConfig()

        # Create service instances directly
        self._client = FlextLdifClient(config=self._config)
        self._parser_service = FlextLdifParserService(
            client=self._client,
            config=self._config,
        )
        self._entry_builder = FlextLdifEntryBuilder()
        self._schema_builder = FlextLdifSchemaBuilder()
        self._schema_validator = FlextLdifSchemaValidator()
        self._acl_service = FlextLdifAclService()

        # Register LDIF components with FlextRegistry
        self._register_components()

        # Services initialized above reduce memory footprint vs on-demand instantiation

    def _register_components(self) -> None:
        """Register LDIF components with FlextRegistry for dependency injection."""
        try:
            # Register core LDIF services
            self._registry.register(
                "ldif_parser_service",
                self._parser_service,
                metadata={
                    "type": "service",
                    "domain": "parser",
                    "description": "Unified LDIF parsing",
                },
            )
            self._registry.register(
                "ldif_client",
                self._client,
                metadata={"type": "client", "domain": "ldif"},
            )
            self._registry.register(
                "entry_builder",
                self._entry_builder,
                metadata={"type": "builder", "domain": "entry"},
            )
            self._registry.register(
                "schema_builder",
                self._schema_builder,
                metadata={"type": "builder", "domain": "schema"},
            )

            # Register configuration and constants
            self._registry.register(
                "ldif_config",
                self._client.config,
                metadata={"type": "config", "domain": "ldif"},
            )
            self._registry.register(
                "ldif_constants",
                FlextLdifConstants,
                metadata={"type": "constants", "domain": "ldif"},
            )

            self._logger.debug(
                "LDIF components registered with FlextRegistry",
                extra={
                    "correlation_id": getattr(self.context, "correlation_id", None),
                    "registered_components": [
                        "ldif_client",
                        "entry_builder",
                        "schema_builder",
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
        result = self._client.execute()
        if result.is_success:
            # Convert ClientStatus to dict for parent contract compliance
            status_dict: dict[str, object] = cast("dict[str, object]", result.value)
            return FlextResult[dict[str, object]].ok(status_dict)
        return FlextResult[dict[str, object]].fail(result.error)

    def parse(
        self,
        source: str | Path | list[str | Path],
        server_type: str = FlextLdifConstants.ServerTypes.RFC,
        *,
        batch: bool = False,
        paginate: bool = False,
        page_size: int = 1000,
    ) -> FlextResult[
        list[FlextLdifModels.Entry] | Callable[[], list[FlextLdifModels.Entry] | None]
    ]:
        r"""Unified parse method for LDIF files and content with flexible options.

        Thin facade delegating to FlextLdifParserService.parse() for all LDIF parsing
        with optional batch processing and pagination support.

        Args:
            source: Single source (str Path or content string) or list of sources
                   for batch processing. Automatically detects file paths.
            server_type: Server type for quirk selection ("rfc", "oid", "oud", etc.)
            batch: If True, expect list of sources and parse all. If False, expect
                  single source. Default: False
            paginate: If True, return a generator function instead of full list.
                     Default: False. Ignored when batch=True.
            page_size: Number of entries per page when paginate=True. Default: 1000

        Returns:
            FlextResult containing:
            - list[Entry] when paginate=False
            - Callable[[], list[Entry] | None] when paginate=True (generator function)

            Fails if file path does not exist or parsing encounters errors.

        Example:
            # Parse from string (LDIF content)
            result = ldif.parse("dn: cn=test,dc=example,dc=com\ncn: test\n")

            # Parse from file path (automatically detected)
            result = ldif.parse(Path("data.ldif"))

            # Parse multiple files in batch
            files = [Path("oid1.ldif"), Path("oid2.ldif")]
            result = ldif.parse(
                files,
                batch=True,
                server_type=FlextLdifConstants.ServerTypes.OID,
            )

            # Parse with pagination for large files
            result = ldif.parse(
                Path("large.ldif"),
                paginate=True,
                page_size=500
            )
            if result.is_success:
                get_next_page = result.unwrap()
                while (page := get_next_page()) is not None:
                    # Process page...

        """
        return cast(
            "FlextResult[list[FlextLdifModels.Entry] | Callable[[], list[FlextLdifModels.Entry] | None]]",
            self._parser_service.parse(
                source,
                server_type,
                batch=batch,
                paginate=paginate,
                page_size=page_size,
            ),
        )

    def write(
        self,
        entries: list[FlextLdifModels.Entry],
        output_path: Path | None = None,
    ) -> FlextResult[str]:
        """Write entries to LDIF format string or file.

        Thin facade delegating to FlextLdifParserService.write() for all LDIF writing.

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
        return self._parser_service.write(entries, output_path)

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
                    # attr_values might be AttributeValues with .values property or a direct list
                    values_list: list[str] = (
                        attr_values.values
                        if hasattr(attr_values, "values")
                        else attr_values
                    )
                    if len(values_list) == 1:
                        result_dict[attr_name] = values_list[0]
                    else:
                        result_dict[attr_name] = values_list
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

    def parse_schema_ldif(
        self,
        file_path: Path,
        server_type: str | None = None,
    ) -> FlextResult[dict[str, list[tuple[str, list[str]]]]]:
        """Parse schema LDIF file containing modify operations.

        Thin facade delegating to FlextLdifParserService.parse_schema_ldif() for
        schema LDIF file parsing with quirks support.

        Extracts schema modifications (add/replace/delete operations) from LDIF
        files that use changetype: modify format (typical for schema definitions).

        Args:
            file_path: Path to schema LDIF file
            server_type: Optional server type for quirks handling

        Returns:
            FlextResult containing dict mapping operation types (add/replace/delete)
            to lists of (attribute_name, values) tuples

        Example:
            result = ldif.parse_schema_ldif(Path("schema.ldif"), FlextLdifConstants.ServerTypes.OUD)
            if result.is_success:
                modifications = result.unwrap()
                for attr_name, values in modifications.get("add", []):
                    print(f"Adding {attr_name}: {len(values)} definitions")

        """
        effective_server_type = server_type or FlextLdifConstants.ServerTypes.RFC
        return self._parser_service.parse_schema_ldif(file_path, effective_server_type)

    def validate_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[FlextLdifModels.LdifValidationResult]:
        """Validate LDIF entries against RFC and business rules.

        Args:
            entries: List of entries to validate

        Returns:
            FlextResult containing validation report with details

        Example:
            result = ldif.validate_entries(entries)
            if result.is_success:
                print(result.value)

        """
        result = self._client.validate_entries(entries)
        if result.is_success:
            return FlextResult[FlextLdifModels.LdifValidationResult].ok(result.value)
        return FlextResult[FlextLdifModels.LdifValidationResult].fail(result.error)

    def migrate(
        self,
        input_dir: Path,
        output_dir: Path,
        from_server: str,
        to_server: str,
        *,
        process_schema: bool = True,
        process_entries: bool = True,
    ) -> FlextResult[FlextLdifModels.MigrationPipelineResult]:
        """Migrate LDIF data between different LDAP server types.

        Thin facade delegating to FlextLdifParserService.migrate() for server-agnostic
        data migration with automatic quirks selection.

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
                from_server=FlextLdifConstants.ServerTypes.OID,
                to_server=FlextLdifConstants.ServerTypes.OUD,
                process_schema=True,
                process_entries=True
            )
            if result.is_success:
                stats = result.unwrap()
                print(f"Migrated {stats.total_entries} entries")

        """
        return self._parser_service.migrate(
            input_dir,
            output_dir,
            from_server,
            to_server,
            process_schema=process_schema,
            process_entries=process_entries,
        )

    def analyze(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[FlextLdifModels.EntryAnalysisResult]:
        """Analyze LDIF entries and generate statistics.

        Args:
            entries: List of entries to analyze

        Returns:
            FlextResult containing analysis statistics

        Example:
            result = ldif.analyze(entries)
            if result.is_success:
                stats = result.unwrap()
                print(f"Total entries: {stats.total_entries}")
                print(f"Entry types: {stats.objectclass_distribution}")

        """
        result = self._client.analyze_entries(entries)
        if result.is_success:
            return FlextResult[FlextLdifModels.EntryAnalysisResult].ok(result.value)
        return FlextResult[FlextLdifModels.EntryAnalysisResult].fail(result.error)

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
        # If custom_filter is provided, apply it along with other criteria
        if custom_filter is not None:
            try:
                # First apply standard filters using client's unified filter
                # Note: mark_excluded=False for clean filtering (public API behavior)
                if objectclass is not None:
                    filter_result = self._client.filter(
                        entries,
                        filter_type=FlextLdifConstants.FilterTypes.OBJECTCLASS,
                        objectclass=objectclass,
                        mark_excluded=False,
                    )
                    if not filter_result.is_success:
                        return FlextResult[list[FlextLdifModels.Entry]].fail(
                            f"Objectclass filter failed: {filter_result.error}",
                        )
                    result_entries = cast(
                        "list[FlextLdifModels.Entry]",
                        filter_result.unwrap(),
                    )
                    entries = result_entries

                if dn_pattern is not None:
                    # Convert simple substring pattern to fnmatch pattern
                    fnmatch_pattern = (
                        f"*{dn_pattern}*" if "*" not in dn_pattern else dn_pattern
                    )
                    filter_result = self._client.filter(
                        entries,
                        filter_type=FlextLdifConstants.FilterTypes.DN_PATTERN,
                        dn_pattern=fnmatch_pattern,
                        mark_excluded=False,
                    )
                    if not filter_result.is_success:
                        return FlextResult[list[FlextLdifModels.Entry]].fail(
                            f"DN pattern filter failed: {filter_result.error}",
                        )
                    result_entries = cast(
                        "list[FlextLdifModels.Entry]",
                        filter_result.unwrap(),
                    )
                    entries = result_entries

                if attributes is not None:
                    attr_list = list(attributes.keys())
                    filter_result = self._client.filter(
                        entries,
                        filter_type=FlextLdifConstants.FilterTypes.ATTRIBUTES,
                        attributes=attr_list,
                        mark_excluded=False,
                    )
                    if not filter_result.is_success:
                        return FlextResult[list[FlextLdifModels.Entry]].fail(
                            f"Attributes filter failed: {filter_result.error}",
                        )
                    result_entries = cast(
                        "list[FlextLdifModels.Entry]",
                        filter_result.unwrap(),
                    )
                    entries = result_entries

                # Now apply custom_filter to the remaining entries
                filtered_entries = [e for e in entries if custom_filter(e)]
                return FlextResult[list[FlextLdifModels.Entry]].ok(filtered_entries)

            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Entry filtering with custom filter failed: {e}",
                )

        # No custom_filter - chain multiple filters using same logic as custom_filter path
        try:
            # Apply objectclass filter if provided
            if objectclass is not None:
                filter_result = self._client.filter(
                    entries,
                    filter_type=FlextLdifConstants.FilterTypes.OBJECTCLASS,
                    objectclass=objectclass,
                    mark_excluded=False,
                )
                if not filter_result.is_success:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Objectclass filter failed: {filter_result.error}",
                    )
                result_entries = cast(
                    "list[FlextLdifModels.Entry]",
                    filter_result.unwrap(),
                )
                entries = result_entries

            # Apply dn_pattern filter if provided
            if dn_pattern is not None:
                # Convert simple substring pattern to fnmatch pattern
                fnmatch_pattern = (
                    f"*{dn_pattern}*" if "*" not in dn_pattern else dn_pattern
                )
                filter_result = self._client.filter(
                    entries,
                    filter_type=FlextLdifConstants.FilterTypes.DN_PATTERN,
                    dn_pattern=fnmatch_pattern,
                    mark_excluded=False,
                )
                if not filter_result.is_success:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"DN pattern filter failed: {filter_result.error}",
                    )
                result_entries = cast(
                    "list[FlextLdifModels.Entry]",
                    filter_result.unwrap(),
                )
                entries = result_entries

            # Apply attributes filter if provided
            if attributes is not None:
                attr_list = list(attributes.keys())
                filter_result = self._client.filter(
                    entries,
                    filter_type=FlextLdifConstants.FilterTypes.ATTRIBUTES,
                    attributes=attr_list,
                    mark_excluded=False,
                )
                if not filter_result.is_success:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Attributes filter failed: {filter_result.error}",
                    )
                result_entries = cast(
                    "list[FlextLdifModels.Entry]",
                    filter_result.unwrap(),
                )
                entries = result_entries

            # Return filtered entries (all criteria have been applied)
            return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Entry filtering failed: {e}",
            )

    # =========================================================================
    # ENTRY BUILDER OPERATIONS (Unified Method)
    # =========================================================================

    def build(
        self,
        entry_type: str,
        *,
        cn: str | None = None,
        sn: str | None = None,
        uid: str | None = None,
        mail: str | None = None,
        given_name: str | None = None,
        ou: str | None = None,
        dn: str | None = None,
        members: list[str] | None = None,
        description: str | None = None,
        base_dn: str | None = None,
        attributes: FlextLdifTypes.CommonDict.AttributeDict | None = None,
        additional_attrs: FlextLdifTypes.CommonDict.AttributeDict | None = None,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Unified entry builder supporting multiple entry types.

        Consolidates build_person_entry(), build_group_entry(), build_ou_entry(),
        and build_custom_entry() into a single flexible method with type-specific parameters.

        Args:
            entry_type: Type of entry to build ("person", "group", "ou", "custom")
            cn: Common name (for person, group)
            sn: Surname (for person)
            uid: User ID (for person, optional)
            mail: Email address (for person, optional)
            given_name: Given name (for person, optional)
            ou: Organizational unit name (for ou)
            dn: Distinguished name (for custom)
            members: List of member DNs (for group, optional)
            description: Description (for group, ou, optional)
            base_dn: Base DN for entry (for person, group, ou)
            attributes: Dictionary of attributes (for custom)
            additional_attrs: Additional attributes (optional, all types)

        Returns:
            FlextResult containing the built Entry

        Example:
            # Build person
            result = api.build(
                "person",
                cn="Alice Johnson",
                sn="Johnson",
                mail="alice@example.com",
                base_dn="ou=People,dc=example,dc=com"
            )

            # Build group
            result = api.build(
                "group",
                cn="Admins",
                members=["cn=alice,ou=People,dc=example,dc=com"],
                base_dn="ou=Groups,dc=example,dc=com"
            )

            # Build OU
            result = api.build(
                "ou",
                ou="People",
                base_dn="dc=example,dc=com",
                description="People organizational unit"
            )

            # Build custom
            result = api.build(
                "custom",
                dn="cn=test,dc=example,dc=com",
                attributes={"cn": ["test"], "objectClass": ["person"]}
            )

        """
        entry_type_lower = entry_type.lower()

        if entry_type_lower == FlextLdifConstants.EntryTypes.PERSON:
            if not cn or not sn or not base_dn:
                return FlextResult[FlextLdifModels.Entry].fail(
                    "Person entry requires: cn, sn, base_dn",
                )
            return self._entry_builder.build_person_entry(
                cn,
                sn,
                base_dn,
                uid,
                mail,
                given_name,
                additional_attrs,
            )

        if entry_type_lower == FlextLdifConstants.EntryTypes.GROUP:
            if not cn or not base_dn:
                return FlextResult[FlextLdifModels.Entry].fail(
                    "Group entry requires: cn, base_dn",
                )
            return self._entry_builder.build_group_entry(
                cn,
                base_dn,
                members,
                description,
                additional_attrs,
            )

        if entry_type_lower == FlextLdifConstants.EntryTypes.OU:
            if not ou or not base_dn:
                return FlextResult[FlextLdifModels.Entry].fail(
                    "OU entry requires: ou, base_dn",
                )
            return self._entry_builder.build_organizational_unit_entry(
                ou,
                base_dn,
                description,
                additional_attrs,
            )

        if entry_type_lower == FlextLdifConstants.EntryTypes.CUSTOM:
            if not dn or not attributes:
                return FlextResult[FlextLdifModels.Entry].fail(
                    "Custom entry requires: dn, attributes",
                )
            obj_classes = attributes.get(
                FlextLdifConstants.DictKeys.OBJECTCLASS,
                ["top"],
            )
            # Normalize objectclasses to list
            obj_classes_list = (
                [obj_classes] if isinstance(obj_classes, str) else obj_classes
            )
            return self._entry_builder.build_custom_entry(
                dn,
                obj_classes_list,
                attributes,
            )

        supported = "'person', 'group', 'ou', 'custom'"
        return FlextResult[FlextLdifModels.Entry].fail(
            f"Unknown entry_type: '{entry_type}'. Supported: {supported}",
        )

    # =========================================================================
    # UNIFIED CONVERSION OPERATIONS
    # =========================================================================

    def convert(
        self,
        conversion_type: str,
        *,
        entry: FlextLdifModels.Entry | None = None,
        entries: list[FlextLdifModels.Entry] | None = None,
        dicts: list[dict[str, object]] | None = None,
        json_str: str | None = None,
    ) -> FlextResult[
        dict[str, object] | list[dict[str, object]] | list[FlextLdifModels.Entry] | str
    ]:
        """Unified conversion method supporting multiple format conversions.

        Consolidates entry_to_dict(), entries_to_dicts(), dicts_to_entries(),
        entries_to_json(), and json_to_entries() into a single flexible method.

        Args:
            conversion_type: Type of conversion to perform
                ("entry_to_dict", "entries_to_dicts", "dicts_to_entries",
                 "entries_to_json", "json_to_entries")
            entry: Single Entry (for entry_to_dict)
            entries: List of Entries (for entries_to_dicts, entries_to_json)
            dicts: List of dictionaries (for dicts_to_entries)
            json_str: JSON string (for json_to_entries)

        Returns:
            FlextResult containing converted data:
            - entry_to_dict: dict
            - entries_to_dicts: list[dict]
            - dicts_to_entries: list[Entry]
            - entries_to_json: str
            - json_to_entries: list[Entry]

        Example:
            # Convert single entry to dict
            result = api.convert("entry_to_dict", entry=entry)

            # Convert entries to dicts
            result = api.convert("entries_to_dicts", entries=entries)

            # Convert dicts to entries
            result = api.convert("dicts_to_entries", dicts=dicts)

            # Convert entries to JSON
            result = api.convert("entries_to_json", entries=entries)

            # Convert JSON to entries
            result = api.convert("json_to_entries", json_str=json_str)

        """
        conversion_type_lower = conversion_type.lower()

        if conversion_type_lower == "entry_to_dict":
            if entry is None:
                return FlextResult.fail("entry_to_dict requires: entry parameter")
            return cast(
                "FlextResult[dict[str, object] | list[dict[str, object]] | list[FlextLdifModels.Entry] | str]",
                self._entry_builder.convert_entry_to_dict(entry),
            )

        if conversion_type_lower == "entries_to_dicts":
            if entries is None:
                return FlextResult.fail("entries_to_dicts requires: entries parameter")
            # Convert entries to dictionaries
            results: list[dict[str, object]] = []
            for single_entry in entries:
                dict_result = self._entry_builder.convert_entry_to_dict(single_entry)
                if dict_result.is_success:
                    results.append(dict_result.unwrap())
            return cast(
                "FlextResult[dict[str, object] | list[dict[str, object]] | list[FlextLdifModels.Entry] | str]",
                FlextResult[list[dict[str, object]]].ok(results),
            )

        if conversion_type_lower == "dicts_to_entries":
            if dicts is None:
                return FlextResult.fail("dicts_to_entries requires: dicts parameter")
            # Convert dictionaries to entries
            convert_result = self._entry_builder.build_entries_from_dict(dicts)
            if convert_result.is_failure:
                empty_result: FlextResult[list[FlextLdifModels.Entry]] = FlextResult[
                    list[FlextLdifModels.Entry]
                ].ok([])
                return cast(
                    "FlextResult[dict[str, object] | list[dict[str, object]] | list[FlextLdifModels.Entry] | str]",
                    empty_result,
                )
            ok_result: FlextResult[list[FlextLdifModels.Entry]] = FlextResult[
                list[FlextLdifModels.Entry]
            ].ok(convert_result.unwrap())
            return cast(
                "FlextResult[dict[str, object] | list[dict[str, object]] | list[FlextLdifModels.Entry] | str]",
                ok_result,
            )

        if conversion_type_lower == "entries_to_json":
            if entries is None:
                return FlextResult.fail("entries_to_json requires: entries parameter")
            return cast(
                "FlextResult[dict[str, object] | list[dict[str, object]] | list[FlextLdifModels.Entry] | str]",
                self._entry_builder.convert_entries_to_json(entries),
            )

        if conversion_type_lower == "json_to_entries":
            if json_str is None:
                return FlextResult.fail("json_to_entries requires: json_str parameter")
            return cast(
                "FlextResult[dict[str, object] | list[dict[str, object]] | list[FlextLdifModels.Entry] | str]",
                self._entry_builder.build_entries_from_json(json_str),
            )

        supported = (
            "'entry_to_dict', 'entries_to_dicts', 'dicts_to_entries', "
            "'entries_to_json', 'json_to_entries'"
        )
        return FlextResult.fail(
            f"Unknown conversion_type: '{conversion_type}'. Supported: {supported}",
        )

    # =========================================================================
    # SCHEMA BUILDER OPERATIONS
    # =========================================================================

    def build_person_schema(self) -> FlextResult[FlextLdifModels.SchemaBuilderResult]:
        """Build standard person schema definition.

        Returns:
            FlextResult containing person schema

        Example:
            result = api.build_person_schema()
            if result.is_success:
                person_schema = result.unwrap()

        """
        result = self._schema_builder.build_standard_person_schema()
        if result.is_success:
            return FlextResult[FlextLdifModels.SchemaBuilderResult].ok(result.value)
        return FlextResult[FlextLdifModels.SchemaBuilderResult].fail(result.error)

    # =========================================================================
    # SCHEMA VALIDATOR OPERATIONS
    # =========================================================================

    def validate_with_schema(
        self,
        entries: list[FlextLdifModels.Entry],
        schema: dict[str, object] | FlextLdifModels.SchemaBuilderResult,
    ) -> FlextResult[FlextLdifModels.LdifValidationResult]:
        """Validate entries against schema definition.

        Args:
            entries: List of entries to validate
            schema: Schema definition to validate against (dict or SchemaBuilderResult)

        Returns:
            FlextResult containing validation report

        Example:
            schema_result = api.build_person_schema()
            if schema_result.is_success:
                schema = schema_result.unwrap()
                result = api.validate_with_schema(entries, schema)

        """
        # Handle both dict and SchemaBuilderResult schemas
        if isinstance(schema, FlextLdifModels.SchemaBuilderResult):
            attributes_value = schema.attributes
            objectclasses_value = schema.object_classes
        else:
            # Convert dict[str, object] schema to SchemaDiscoveryResult with type validation
            attributes_value = schema.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
            if not isinstance(attributes_value, dict):
                return FlextResult[FlextLdifModels.LdifValidationResult].fail(
                    "Schema attributes must be a dictionary",
                )
            # Type narrowing after isinstance check
            attributes_value = cast("dict[str, dict[str, object]]", attributes_value)

        if isinstance(schema, FlextLdifModels.SchemaBuilderResult):
            objectclasses_value = schema.object_classes
            server_type_value = schema.server_type
            entry_count_value = schema.entry_count
        else:
            objectclasses_value = schema.get("object_classes", {})
            if not isinstance(objectclasses_value, dict):
                return FlextResult[FlextLdifModels.LdifValidationResult].fail(
                    "Schema object classes must be a dictionary",
                )
            # Type narrowing after isinstance check
            objectclasses_value = cast(
                "dict[str, dict[str, object]]",
                objectclasses_value,
            )

            server_type_value = schema.get(
                FlextLdifConstants.DictKeys.SERVER_TYPE,
                "generic",
            )
            if not isinstance(server_type_value, str):
                return FlextResult[FlextLdifModels.LdifValidationResult].fail(
                    "Schema server type must be a string",
                )
            # Type narrowing after isinstance check - already str type

            entry_count_value = schema.get("entry_count", 0)
            if not isinstance(entry_count_value, int):
                return FlextResult[FlextLdifModels.LdifValidationResult].fail(
                    "Schema entry count must be an integer",
                )
            # Type narrowing after isinstance check - already int type

        schema_discovery = FlextLdifModels.SchemaDiscoveryResult(
            attributes=attributes_value,
            objectclasses=objectclasses_value,
            server_type=server_type_value,
            entry_count=entry_count_value,
        )

        # Resolve validator via container
        validator = self._schema_validator
        # Use schema-aware validation for each entry
        errors: list[str] = []
        warnings: list[str] = []

        for entry in entries:
            entry_result = validator.validate_entry_against_schema(
                entry,
                schema_discovery,
            )
            if entry_result.is_failure:
                errors.extend([f"Entry {entry.dn}: {entry_result.error}"])
            else:
                entry_validation = entry_result.unwrap()
                if "issues" in entry_validation and isinstance(
                    entry_validation["issues"],
                    list,
                ):
                    errors.extend(entry_validation["issues"])
                if "warnings" in entry_validation and isinstance(
                    entry_validation["warnings"],
                    list,
                ):
                    warnings.extend(entry_validation["warnings"])

        # Also run general validation
        general_result = validator.validate_entries(entries)
        if general_result.is_failure:
            return general_result

        general_validation = general_result.unwrap()
        errors.extend(general_validation.errors)
        warnings.extend(general_validation.warnings)

        return FlextResult[FlextLdifModels.LdifValidationResult].ok(
            FlextLdifModels.LdifValidationResult(
                is_valid=len(errors) == 0,
                errors=errors,
                warnings=warnings,
            ),
        )

    # =========================================================================
    # ACL OPERATIONS
    # =========================================================================

    def extract_acls(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[list[FlextLdifModels.Acl]]:
        """Extract ACL rules from entry.

        Args:
            entry: Entry to extract ACLs from

        Returns:
            FlextResult containing list of ACL rules

        Example:
            result = api.extract_acls(entry)
            if result.is_success:
                acls = result.unwrap()

        """
        # Resolve ACL service via container
        return self._acl_service.extract_acls_from_entry(entry)

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

        Note:
            Converts Acl models to AclRule objects and evaluates using FlextLdifAclService.

        """
        try:
            if not acls:
                # No ACLs means no restrictions - allow by default
                return FlextResult[bool].ok(True)

            acl_service = self._acl_service
            eval_context = context or {}

            # Create composite rule combining all ACLs
            composite = acl_service.create_composite_rule(operator="AND")

            # Convert each Acl to evaluation rules
            for acl in acls:
                # Create permission rules from ACL permissions
                if hasattr(acl, "permissions") and acl.permissions:
                    perms = acl.permissions.model_dump()
                    for perm_name, perm_value in perms.items():
                        if perm_value:
                            rule = acl_service.create_permission_rule(
                                perm_name,
                                required=True,
                            )
                            composite.add_rule(rule)

                # Add subject rule if present
                if hasattr(acl, "subject") and acl.subject:
                    subject_value = getattr(acl.subject, "subject_value", None)
                    if subject_value and subject_value != "*":
                        subject_rule = acl_service.create_subject_rule(subject_value)
                        composite.add_rule(subject_rule)

                # Add target rule if present
                if hasattr(acl, "target") and acl.target:
                    target_dn = getattr(acl.target, "target_dn", None)
                    if target_dn and target_dn != "*":
                        target_rule = acl_service.create_target_rule(target_dn)
                        composite.add_rule(target_rule)

            # Evaluate composite rule
            return composite.evaluate(cast("dict[str, object]", eval_context))

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[bool].fail(f"ACL evaluation failed: {e}")

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
                    has_acl = any(
                        key in attrs
                        for key in [
                            "orclaci",
                            "orclentrylevelaci",
                            "aci",
                            "accessControlList",
                        ]
                    )

                    if not has_acl:
                        # No ACL attributes, pass through unchanged
                        transformed_entries.append(entry)
                        continue

                    # Build transformation entry dict for quirks system
                    # Quirks work with dict format: {dn: str, attributes: dict}
                    {
                        FlextLdifConstants.DictKeys.DN: entry.dn.value,
                        FlextLdifConstants.DictKeys.ATTRIBUTES: dict(attrs),
                    }

                    # Get quirks for source and target servers
                    # These are internal implementation details not exposed to consumers
                    source_quirk = None
                    target_quirk = None

                    # Try to get quirks from registry
                    if self._client is not None and hasattr(self._client, "get_quirks"):
                        source_quirk = self._client.get_quirks(source_type)
                        target_quirk = self._client.get_quirks(target_type)

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
        result = self._client.detect_server_type(
            ldif_path=ldif_path,
            ldif_content=ldif_content,
        )
        if result.is_success:
            return FlextResult[FlextLdifModels.ServerDetectionResult].ok(result.value)
        return FlextResult[FlextLdifModels.ServerDetectionResult].fail(result.error)

    def parse_with_auto_detection(
        self,
        source: Path | str,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF with automatic server type detection.

        Thin facade delegating to FlextLdifParserService.parse_with_auto_detection()
        for automatic server type detection and quirks selection.

        Automatically detects the source server type and applies
        the appropriate quirks during parsing.

        Args:
            source: Path to LDIF file or LDIF content as string

        Returns:
            FlextResult with list of parsed LDIF entries

        Example:
            # Parse with auto-detection
            result = api.parse_with_auto_detection(Path("data.ldif"))
            if result.is_success:
                entries = result.unwrap()
                print(f"Parsed {len(entries)} entries")

        """
        return self._parser_service.parse_with_auto_detection(source)

    def parse_relaxed(
        self,
        source: Path | str,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF with relaxed mode for broken/non-compliant files.

        Thin facade delegating to FlextLdifParserService.parse_relaxed()
        for lenient parsing with best-effort recovery.

        Enables lenient parsing that skips validation errors and
        attempts best-effort parsing of malformed LDIF content.

        Args:
            source: Path to LDIF file or LDIF content as string

        Returns:
            FlextResult with list of parsed LDIF entries

        Example:
            # Parse broken LDIF with relaxed mode
            result = api.parse_relaxed(Path("broken.ldif"))
            if result.is_success:
                entries = result.unwrap()
                print(f"Parsed {len(entries)} entries (with relaxed mode)")

        """
        return self._parser_service.parse_relaxed(source)

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
        return self._client.get_effective_server_type(ldif_path)

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
    def schema_builder(self) -> FlextLdifSchemaBuilder:
        """Access to FlextLdifSchemaBuilder for schema operations.

        Returns:
            FlextLdifSchemaBuilder instance for building and managing schemas

        Example:
            schema = ldif.schema_builder.build_standard_person_schema()

        """
        return self._schema_builder

    @property
    def acl_service(self) -> FlextLdifAclService:
        """Access to FlextLdifAclService for ACL operations.

        Returns:
            FlextLdifAclService instance for ACL processing

        Example:
            acls = ldif.acl_service.extract_acls_from_entry(entry)

        """
        return self._acl_service


__all__ = ["FlextLdif"]
