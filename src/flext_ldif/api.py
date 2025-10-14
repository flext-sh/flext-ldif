"""FLEXT-LDIF API - Thin Facade for LDIF Operations.

This module provides the primary entry point for all LDIF processing operations.
The FlextLdif class serves as a thin facade exposing all functionality through
a clean, unified interface that delegates to the FlextLdifClient implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar, override

from flext_core import FlextCore

from flext_ldif.acl.service import FlextLdifAclService
from flext_ldif.client import FlextLdifClient
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.containers import FlextLdifContainer
from flext_ldif.entry.builder import FlextLdifEntryBuilder
from flext_ldif.exceptions import FlextLdifExceptions
from flext_ldif.models import FlextLdifModels
from flext_ldif.schema.builder import FlextLdifSchemaBuilder
from flext_ldif.schema.validator import FlextLdifSchemaValidator


class FlextLdif(FlextCore.Service[FlextCore.Types.Dict]):
    r"""Unified LDIF processing facade with complete Flext ecosystem integration.

    This service inherits from FlextCore.Service and integrates the complete Flext ecosystem:
    - FlextCore.Container: Dependency injection and service management
    - FlextCore.Logger: Structured logging with correlation tracking
    - FlextCore.Context: Request context and correlation ID management
    - FlextCore.Config: Configuration management with validation
    - FlextCore.Bus: Event publishing for domain events
    - FlextCore.Dispatcher: Message dispatching for CQRS patterns
    - FlextCore.Registry: Component registration and discovery
    - FlextCore.Processors: Batch and parallel processing utilities
    - FlextCore.Exceptions: Structured error handling with correlation
    - FlextCore.Protocols: Type-safe interfaces and contracts

    Provides unified access to:
    - RFC-compliant LDIF parsing and writing (RFC 2849/4512)
    - Server-specific quirks and migrations (OID, OUD, OpenLDAP)
    - Generic server-agnostic migration pipeline
    - Schema validation and ACL processing
    - Entry building and transformation
    - All infrastructure (Models, Config, Constants, etc.)

    This class follows the Facade pattern, providing a simplified interface
    to the complex subsystem of LDIF processing services by delegating
    all operations to the FlextLdifClient implementation.

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

        # Migrate between servers with event publishing
        migration_result = ldif.migrate(
            entries=entries,
            from_server=FlextLdifConstants.ServerTypes.OID,
            to_server=FlextLdifConstants.ServerTypes.OUD
        )

        # Access complete infrastructure
        config = ldif.config
        models = ldif.models
        entry = ldif.models.Entry(dn="cn=test", attributes={})

    """

    # Private attributes (initialized in model_post_init)
    _container: FlextCore.Container
    _bus: object = None
    _dispatcher: FlextCore.Dispatcher
    _registry: FlextCore.Registry
    _processors: FlextCore.Processors
    _logger: FlextCore.Logger
    _client: FlextLdifClient
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
        """Initialize LDIF facade with complete Flext ecosystem integration.

        Integrates all Flext components for comprehensive infrastructure support:
        - FlextCore.Container: Global dependency injection container
        - FlextCore.Logger: Structured logging with correlation tracking
        - FlextCore.Context: Request context and correlation ID management
        - FlextCore.Config: Configuration management with validation
        - FlextCore.Bus: Event publishing for domain events
        - FlextCore.Dispatcher: Message dispatching for CQRS patterns
        - FlextCore.Registry: Component registration and discovery
        - FlextCore.Processors: Batch and parallel processing utilities
        - FlextCore.Exceptions: Structured error handling with correlation

        Args:
            config: Optional LDIF configuration. If not provided,
                   uses global singleton instance.

        """
        # Call super().__init__() FIRST for Pydantic model initialization
        super().__init__()

        # Initialize Flext ecosystem components AFTER super().__init__()
        # Type narrow container from get_global() which may return None or subclass
        container_raw = FlextCore.Container.get_global()
        if not isinstance(container_raw, FlextCore.Container):
            # Create new global container if none exists or wrong type
            self._container = FlextCore.Container()
        else:
            # Type narrowed: container_raw is FlextCore.Container
            self._container = container_raw
        self._bus = FlextCore.Bus()
        self._dispatcher = FlextCore.Dispatcher()
        self._registry = FlextCore.Registry(dispatcher=self._dispatcher)
        self._processors = FlextCore.Processors()
        self._logger = FlextCore.Logger(__name__)

        # Initialize flext-ldif dependency injection container
        self._ldif_container = FlextLdifContainer.get_global_container()

        # Override config provider if custom config provided
        if config is not None:
            self._ldif_container.config.override(config)

        # Initialize LDIF-specific components via dependency injection
        self._client = self._ldif_container.client()
        self._entry_builder = self._ldif_container.entry_builder()
        self._schema_builder = self._ldif_container.schema_builder()

        # Register LDIF components with FlextCore.Registry
        self._register_components()

        # Other services instantiated on-demand in methods that use them
        # This reduces memory footprint for unused services

    def _register_components(self) -> None:
        """Register LDIF components with FlextCore.Registry for dependency injection."""
        try:
            # Register core LDIF services
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
                "LDIF components registered with FlextCore.Registry",
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

        except Exception as e:
            # Use FlextCore.Exceptions for error handling
            error = FlextLdifExceptions.LdifConfigurationError(
                f"Failed to register LDIF components: {e}",
                correlation_id=getattr(self.context, "correlation_id", None),
                context={"component": "FlextLdif", "operation": "_register_components"},
            )
            self._logger.exception(
                str(error),
                extra={
                    "correlation_id": error.correlation_id,
                    "error_code": error.error_code,
                    "metadata": error.metadata,
                },
            )
            raise error from e

        # Log initialization with structured context
        self._logger.info(
            "FlextLdif initialized with complete Flext ecosystem integration",
            extra={
                "service_type": "LDIF Processing Facade",
                "correlation_id": getattr(self.context, "correlation_id", None),
                "flext_components": [
                    "FlextCore.Container",
                    "FlextCore.Logger",
                    "FlextCore.Context",
                    "FlextCore.Bus",
                    "FlextCore.Dispatcher",
                    "FlextCore.Registry",
                    "FlextCore.Processors",
                    "FlextCore.Exceptions",
                    "FlextCore.Protocols",
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
    def execute(self) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Execute facade self-check and return status.

        Returns:
            FlextCore.Result containing facade status and configuration

        """
        return self._client.execute()

    def parse(
        self, source: str | Path, server_type: str = "rfc"
    ) -> FlextCore.Result[list[FlextLdifModels.Entry]]:
        r"""Parse LDIF from file or content string.

        Args:
            source: Either a file path (Path object) or LDIF content string
            server_type: Server type for quirk selection ("rfc", "oid", "oud", etc.)

        Returns:
            FlextCore.Result with list of parsed Entry models

        Example:
            # Parse from string
            result = ldif.parse("dn: cn=test\ncn: test\n")

            # Parse from file
            result = ldif.parse(Path("data.ldif"))

            # Parse with server-specific quirks
            result = ldif.parse(Path("oid.ldif"), server_type=FlextLdifConstants.ServerTypes.OID)

        """
        return self._client.parse_ldif(source, server_type)

    def write(
        self,
        entries: list[FlextLdifModels.Entry],
        output_path: Path | None = None,
    ) -> FlextCore.Result[str]:
        """Write entries to LDIF format string or file.

        Args:
            entries: List of LDIF entries to write
            output_path: Optional path to write LDIF file. If None, returns LDIF string.

        Returns:
            FlextCore.Result containing LDIF content as string (if output_path is None)
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
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Validate LDIF entries against RFC and business rules.

        Args:
            entries: List of entries to validate

        Returns:
            FlextCore.Result containing validation report with details

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
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Migrate LDIF data between different LDAP server types.

        Args:
            input_dir: Directory containing source LDIF files
            output_dir: Directory for migrated LDIF files
            from_server: Source server type ("oid", "oud", "openldap", etc.)
            to_server: Target server type
            process_schema: Whether to process schema files
            process_entries: Whether to process entry files

        Returns:
            FlextCore.Result containing migration statistics and output files

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
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Analyze LDIF entries and generate statistics.

        Args:
            entries: List of entries to analyze

        Returns:
            FlextCore.Result containing analysis statistics

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
    ) -> FlextCore.Result[list[FlextLdifModels.Entry]]:
        """Filter entries by object class.

        Args:
            entries: List of LDIF entries to filter
            objectclass: Object class to filter by

        Returns:
            FlextCore.Result containing filtered entries

        """
        return self._client.filter_by_objectclass(entries, objectclass)

    def filter_persons(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextCore.Result[list[FlextLdifModels.Entry]]:
        """Filter entries to get only person entries.

        Args:
            entries: List of LDIF entries to filter

        Returns:
            FlextCore.Result containing person entries

        """
        return self.filter_by_objectclass(entries, "person")

    # =========================================================================
    # ENTRY BUILDER OPERATIONS (Direct Methods)
    # =========================================================================

    def build_person_entry(
        self,
        cn: str,
        sn: str,
        base_dn: str,
        uid: str | None = None,
        mail: str | None = None,
        given_name: str | None = None,
        additional_attrs: dict[str, FlextCore.Types.StringList] | None = None,
    ) -> FlextCore.Result[FlextLdifModels.Entry]:
        """Build a person entry with common attributes.

        Args:
            cn: Common name
            sn: Surname
            base_dn: Base DN for entry
            uid: User ID (optional)
            mail: Email address (optional)
            given_name: Given name (optional)
            additional_attrs: Additional attributes (optional)

        Returns:
            FlextCore.Result containing the built Entry

        Example:
            result = api.build_person_entry(
                cn="Alice Johnson",
                sn="Johnson",
                base_dn="ou=People,dc=example,dc=com",
                mail="alice@example.com"
            )

        """
        return self._entry_builder.build_person_entry(
            cn, sn, base_dn, uid, mail, given_name, additional_attrs
        )

    def build_group_entry(
        self,
        cn: str,
        base_dn: str,
        members: FlextCore.Types.StringList | None = None,
        description: str | None = None,
        additional_attrs: dict[str, FlextCore.Types.StringList] | None = None,
    ) -> FlextCore.Result[FlextLdifModels.Entry]:
        """Build a group entry with members.

        Args:
            cn: Common name (group name)
            base_dn: Base DN for entry
            members: List of member DNs
            description: Description (optional)
            additional_attrs: Additional attributes (optional)

        Returns:
            FlextCore.Result containing the built Entry

        Example:
            result = api.build_group_entry(
                cn="Admins",
                base_dn="ou=Groups,dc=example,dc=com",
                members=["cn=alice,ou=People,dc=example,dc=com"]
            )

        """
        return self._entry_builder.build_group_entry(
            cn, base_dn, members, description, additional_attrs
        )

    def build_organizational_unit(
        self,
        ou: str,
        base_dn: str,
        description: str | None = None,
        additional_attrs: dict[str, FlextCore.Types.StringList] | None = None,
    ) -> FlextCore.Result[FlextLdifModels.Entry]:
        """Build an organizational unit entry.

        Args:
            ou: Organizational unit name
            base_dn: Base DN for entry
            description: Description (optional)
            additional_attrs: Additional attributes (optional)

        Returns:
            FlextCore.Result containing the built Entry

        Example:
            result = api.build_organizational_unit(
                ou="People",
                base_dn="dc=example,dc=com"
            )

        """
        return self._entry_builder.build_organizational_unit_entry(
            ou, base_dn, description, additional_attrs
        )

    def build_custom_entry(
        self,
        dn: str,
        attributes: dict[str, FlextCore.Types.StringList],
    ) -> FlextCore.Result[FlextLdifModels.Entry]:
        """Build a custom entry with arbitrary attributes.

        Args:
            dn: Distinguished name
            attributes: Dictionary of attribute names to value lists

        Returns:
            FlextCore.Result containing the built Entry

        Example:
            result = api.build_custom_entry(
                dn="cn=test,dc=example,dc=com",
                attributes={FlextLdifConstants.DictKeys.OBJECTCLASS: ["top", "person"], "cn": ["test"]}
            )

        """
        objectclasses = attributes.get(FlextLdifConstants.DictKeys.OBJECTCLASS, ["top"])
        return self._entry_builder.build_custom_entry(dn, objectclasses, attributes)

    def entry_to_dict(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Convert entry to dictionary format.

        Args:
            entry: Entry model to convert

        Returns:
            FlextCore.Result containing dictionary representation

        Example:
            result = api.entry_to_dict(entry)
            if result.is_success:
                entry_dict = result.unwrap()

        """
        return self._entry_builder.convert_entry_to_dict(entry)

    # =========================================================================
    # BATCH CONVERSION OPERATIONS
    # =========================================================================

    def entries_to_dicts(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> list[FlextCore.Types.Dict]:
        """Convert list of entries to list of dictionaries.

        Args:
            entries: List of Entry models

        Returns:
            List of dictionaries (only successful conversions)

        Example:
            dicts = api.entries_to_dicts(entries)

        """
        # Convert entries to dictionaries
        results = []
        for entry in entries:
            result = self._entry_builder.convert_entry_to_dict(entry)
            if result.is_success:
                results.append(result.unwrap())
        return results

    def dicts_to_entries(
        self,
        dicts: list[dict[str, object]],
    ) -> list[FlextLdifModels.Entry]:
        """Convert list of dictionaries to list of entries using FlextCore.Processors.

        Args:
            dicts: List of entry dictionaries

        Returns:
            List of Entry models (only successful conversions)

        Example:
            entries = api.dicts_to_entries(dicts)

        """
        # Convert dictionaries to entries
        result = self._entry_builder.build_entries_from_dict(dicts)
        if result.is_failure:
            return []
        return result.unwrap()

    def entries_to_json(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextCore.Result[str]:
        """Convert list of entries to JSON string.

        Args:
            entries: List of Entry models

        Returns:
            FlextCore.Result containing JSON string

        Example:
            result = api.entries_to_json(entries)
            if result.is_success:
                json_str = result.unwrap()

        """
        return self._entry_builder.convert_entries_to_json(entries)

    def json_to_entries(
        self,
        json_str: str,
    ) -> FlextCore.Result[list[FlextLdifModels.Entry]]:
        """Convert JSON string to list of entries.

        Args:
            json_str: JSON string representation of entries

        Returns:
            FlextCore.Result containing list of Entry models

        Example:
            result = api.json_to_entries(json_str)
            if result.is_success:
                entries = result.unwrap()

        """
        return self._entry_builder.build_entries_from_json(json_str)

    # =========================================================================
    # SCHEMA BUILDER OPERATIONS
    # =========================================================================

    def build_person_schema(self) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Build standard person schema definition.

        Returns:
            FlextCore.Result containing person schema

        Example:
            result = api.build_person_schema()
            if result.is_success:
                person_schema = result.unwrap()

        """
        return self._schema_builder.build_standard_person_schema()

    # =========================================================================
    # SCHEMA VALIDATOR OPERATIONS
    # =========================================================================

    def validate_with_schema(
        self,
        entries: list[FlextLdifModels.Entry],
        schema: FlextCore.Types.Dict,
    ) -> FlextCore.Result[FlextLdifModels.LdifValidationResult]:
        """Validate entries against schema definition.

        Args:
            entries: List of entries to validate
            schema: Schema definition to validate against

        Returns:
            FlextCore.Result containing validation report

        Example:
            schema_result = api.build_person_schema()
            if schema_result.is_success:
                schema = schema_result.unwrap()
                result = api.validate_with_schema(entries, schema)

        """
        # Convert dict[str, object] schema to SchemaDiscoveryResult with type validation
        attributes_value = schema.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
        if not isinstance(attributes_value, dict):
            return FlextCore.Result[FlextLdifModels.LdifValidationResult].fail(
                "Schema attributes must be a dictionary"
            )

        objectclasses_value = schema.get("object_classes", {})
        if not isinstance(objectclasses_value, dict):
            return FlextCore.Result[FlextLdifModels.LdifValidationResult].fail(
                "Schema object classes must be a dictionary"
            )

        server_type_value = schema.get(
            FlextLdifConstants.DictKeys.SERVER_TYPE, "generic"
        )
        if not isinstance(server_type_value, str):
            return FlextCore.Result[FlextLdifModels.LdifValidationResult].fail(
                "Schema server type must be a string"
            )

        entry_count_value = schema.get("entry_count", 0)
        if not isinstance(entry_count_value, int):
            return FlextCore.Result[FlextLdifModels.LdifValidationResult].fail(
                "Schema entry count must be an integer"
            )

        schema_discovery = FlextLdifModels.SchemaDiscoveryResult(
            attributes=attributes_value,
            objectclasses=objectclasses_value,
            server_type=server_type_value,
            entry_count=entry_count_value,
        )

        validator = self._ldif_container.schema_validator()
        # Use schema-aware validation for each entry
        errors: FlextCore.Types.StringList = []
        warnings: FlextCore.Types.StringList = []

        for entry in entries:
            entry_result = validator.validate_entry_against_schema(
                entry, schema_discovery
            )
            if entry_result.is_failure:
                errors.extend([f"Entry {entry.dn}: {entry_result.error}"])
            else:
                entry_validation = entry_result.unwrap()
                if isinstance(entry_validation, dict):
                    if "issues" in entry_validation and isinstance(
                        entry_validation["issues"], list
                    ):
                        errors.extend(entry_validation["issues"])
                    if "warnings" in entry_validation and isinstance(
                        entry_validation["warnings"], list
                    ):
                        warnings.extend(entry_validation["warnings"])

        # Also run general validation
        general_result = validator.validate_entries(entries)
        if general_result.is_failure:
            return general_result

        general_validation = general_result.unwrap()
        errors.extend(general_validation.errors)
        warnings.extend(general_validation.warnings)

        return FlextCore.Result[FlextLdifModels.LdifValidationResult].ok(
            FlextLdifModels.LdifValidationResult(
                is_valid=len(errors) == 0,
                errors=errors,
                warnings=warnings,
            )
        )

    # =========================================================================
    # ACL OPERATIONS
    # =========================================================================

    def extract_acls(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextCore.Result[list[FlextLdifModels.Acl]]:
        """Extract ACL rules from entry.

        Args:
            entry: Entry to extract ACLs from

        Returns:
            FlextCore.Result containing list of ACL rules

        Example:
            result = api.extract_acls(entry)
            if result.is_success:
                acls = result.unwrap()

        """
        acl_service = self._ldif_container.acl_service()
        return acl_service.extract_acls_from_entry(entry)

    def evaluate_acl_rules(
        self,
        acls: list[FlextLdifModels.Acl],
        context: FlextCore.Types.Dict | None = None,
    ) -> FlextCore.Result[bool]:
        """Evaluate ACL rules and return evaluation result.

        Args:
            acls: List of ACL rules to evaluate (not yet implemented)
            context: Evaluation context (not yet implemented)

        Returns:
            FlextCore.Result containing evaluation result (True if allowed)

        Example:
            result = api.evaluate_acl_rules(acls)
            if result.is_success:
                is_allowed = result.unwrap()

        Note:
            ACL evaluation not yet implemented.
            Raises NotImplementedError for security - fail-safe approach.

        Raises:
            NotImplementedError: ACL evaluation not yet implemented

        """
        # Security: Fail-safe - do NOT allow by default
        msg = (
            "Acl evaluation not yet implemented. "
            "Use FlextLdifAclService.evaluate_acl_rules() for internal AclRule types."
        )
        raise NotImplementedError(msg)

    # =========================================================================
    # PROCESSOR OPERATIONS
    # =========================================================================

    def process_batch(
        self,
        processor_name: str,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextCore.Result[list[FlextCore.Types.Dict]]:
        """Process entries in batch mode using FlextCore.Processors.

        Args:
            processor_name: Name of processor to use (not yet implemented)
            entries: List of entries to process

        Returns:
            FlextCore.Result containing processed results

        Example:
            result = api.process_batch("transform", entries)
            if result.is_success:
                processed = result.unwrap()

        Note:
            Currently returns converted entries without processing.
            Processor-based batch processing will be implemented in future version.

        """
        msg = f"Processor '{processor_name}' not yet implemented. Batch processing will be available in future version."
        raise NotImplementedError(msg)

    def process_parallel(
        self,
        processor_name: str,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextCore.Result[list[FlextCore.Types.Dict]]:
        """Process entries in parallel mode using FlextCore.Processors.

        Args:
            processor_name: Name of processor to use (not yet implemented)
            entries: List of entries to process

        Returns:
            FlextCore.Result containing processed results

        Example:
            result = api.process_parallel("validate", entries)
            if result.is_success:
                processed = result.unwrap()

        Note:
            Currently returns converted entries without processing.
            Processor-based parallel processing will be implemented in future version.

        """
        msg = f"Processor '{processor_name}' not yet implemented. Batch processing will be available in future version."
        raise NotImplementedError(msg)

    # =========================================================================
    # INFRASTRUCTURE ACCESS (Properties)
    # =========================================================================

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

    @property
    def container(self) -> FlextCore.Container:
        """Access to global FlextCore.Container for dependency injection.

        Returns:
            Global FlextCore.Container singleton instance

        Example:
            service = ldif.container.resolve("my_service")

        """
        return self._container

    @property
    def bus(self) -> FlextCore.Bus:
        """Access to FlextCore.Bus for event publishing.

        Returns:
            FlextCore.Bus instance for publishing domain events

        Example:
            ldif.bus.publish("ldif.parsed", {"entry_count": 10})

        """
        # Type narrow _bus to FlextCore.Bus (initialized in __init__)
        if not isinstance(self._bus, FlextCore.Bus):
            # Fallback: create new Bus if somehow not initialized
            self._bus = FlextCore.Bus()
        return self._bus

    @property
    def dispatcher(self) -> FlextCore.Dispatcher:
        """Access to FlextCore.Dispatcher for message dispatching.

        Returns:
            FlextCore.Dispatcher instance for CQRS message routing

        Example:
            result = ldif.dispatcher.dispatch(command)

        """
        return self._dispatcher

    @property
    def registry(self) -> FlextCore.Registry:
        """Access to FlextCore.Registry for component management.

        Returns:
            FlextCore.Registry instance for component registration and discovery

        Example:
            component = ldif.registry.get("my_component")

        """
        return self._registry

    @property
    def processors(self) -> FlextCore.Processors:
        """Access to FlextCore.Processors for batch and parallel processing.

        Returns:
            FlextCore.Processors instance for processing utilities

        Example:
            result = ldif.processors.process_batch(entries, processor_func)

        """
        return self._processors

    # =========================================================================


__all__ = ["FlextLdif"]
