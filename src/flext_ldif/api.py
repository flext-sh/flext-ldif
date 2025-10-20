"""FLEXT-LDIF API - Thin Facade for LDIF Operations.

This module provides the primary entry point for all LDIF processing operations.
The FlextLdif class serves as a thin facade exposing all functionality through
a clean, unified interface that delegates to the FlextLdifClient implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar, cast, override

from flext_core import (
    FlextBus,
    FlextDispatcher,
    FlextLogger,
    FlextProcessors,
    FlextRegistry,
    FlextResult,
    FlextService,
)

from flext_ldif.acl.service import FlextLdifAclService
from flext_ldif.client import FlextLdifClient
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.containers import flext_ldif_container
from flext_ldif.entry.builder import FlextLdifEntryBuilder
from flext_ldif.models import FlextLdifModels
from flext_ldif.processors.ldif_processor import (
    LdifBatchProcessor,
    LdifParallelProcessor,
)
from flext_ldif.schema.builder import FlextLdifSchemaBuilder
from flext_ldif.schema.validator import FlextLdifSchemaValidator
from flext_ldif.typings import FlextLdifTypes


class FlextLdif(FlextService[FlextLdifTypes.Models.CustomDataDict]):
    r"""Unified LDIF processing facade with complete Flext ecosystem integration.

    This service inherits from FlextService and integrates the complete Flext ecosystem:
    - FlextContainer: Dependency injection and service management
    - FlextLogger: Structured logging with correlation tracking
    - FlextContext: Request context and correlation ID management
    - FlextConfig: Configuration management with validation
    - FlextBus: Event publishing for domain events
    - FlextDispatcher: Message dispatching for CQRS patterns
    - FlextRegistry: Component registration and discovery
    - FlextProcessors: Batch and parallel processing utilities
    - FlextExceptions: Structured error handling with correlation
    - FlextProtocols: Type-safe interfaces and contracts

    Provides unified access to:
    - RFC-compliant LDIF parsing and writing (RFC 2849/4512)
    - Server-specific quirks and migrations (OID, OUD, OpenLDAP, AD, 389-DS, etc.)
    - Generic server-agnostic migration pipeline
    - Categorized migration pipeline with structured LDIF output
    - Batch and parallel processing for large-scale operations
    - Event-driven architecture with domain events
    - Schema validation and ACL processing
    - Entry building and transformation
    - DN service and validation services
    - All infrastructure (Models, Config, Constants, Events, Processors, etc.)

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

        # Generic migration between servers
        migration_result = ldif.migrate(
            input_dir=Path("data/oid"),
            output_dir=Path("data/oud"),
            from_server="oid",
            to_server="oud"
        )

        # Categorized migration with structured output
        categorized_result = ldif.categorize_and_migrate(
            input_dir=Path("data/source"),
            output_dir=Path("data/categorized"),
            categorization_rules={"users": ["person"], "groups": ["groupOfNames"]},
            from_server="oid",
            to_server="oud"
        )

        # Batch processing for large datasets
        batch_processor = ldif.create_batch_processor(batch_size=100)
        processing_result = batch_processor.process_entries(entries, validate_entry)

        # Access complete infrastructure
        config = ldif.config
        models = ldif.models
        entry = ldif.models.Entry(dn="cn=test", attributes={})
        events = ldif.events  # Domain events
        processors = ldif.processors  # Processing utilities

    """

    # Private attributes (initialized in __init__)
    _dispatcher: FlextDispatcher
    _registry: FlextRegistry
    _processors: FlextProcessors
    _logger: FlextLogger
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
        - FlextContainer: Global dependency injection container
        - FlextLogger: Structured logging with correlation tracking
        - FlextContext: Request context and correlation ID management
        - FlextConfig: Configuration management with validation
        - FlextBus: Event publishing for domain events
        - FlextDispatcher: Message dispatching for CQRS patterns
        - FlextRegistry: Component registration and discovery
        - FlextProcessors: Batch and parallel processing utilities
        - FlextExceptions: Structured error handling with correlation

        Args:
            config: Optional LDIF configuration. If not provided,
                   uses global singleton instance.

        """
        # Call super().__init__() for Pydantic model initialization
        # Container is inherited from FlextMixins via property (FlextContainer.get_global())
        super().__init__()
        self._bus = FlextBus()
        self._dispatcher = FlextDispatcher()
        self._registry = FlextRegistry(dispatcher=self._dispatcher)
        self._processors = FlextProcessors()
        self._logger = FlextLogger(__name__)

        # Initialize LDIF-specific components using recovered container
        self._ldif_container = flext_ldif_container

        # Override config provider if custom config provided
        if config is not None:
            self._ldif_container.config.override(config)

        # Resolve instances from container providers
        self._client = self._ldif_container.client()
        self._entry_builder = self._ldif_container.entry_builder()
        self._schema_builder = self._ldif_container.schema_builder()

        # Register LDIF components with FlextRegistry
        self._register_components()

        # Other services instantiated on-demand in methods that use them
        # This reduces memory footprint for unused services

    def _register_components(self) -> None:
        """Register LDIF components with FlextRegistry for dependency injection."""
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

        except Exception as e:  # pragma: no cover
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
                    "FlextBus",
                    "FlextDispatcher",
                    "FlextRegistry",
                    "FlextProcessors",
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
    def execute(self) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
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
            result = ldif.parse_ldif_file(Path("data.ldif"))

            # Parse with server-specific quirks
            result = ldif.parse_ldif_file(Path("oid.ldif"), server_type=FlextLdifConstants.ServerTypes.OID)

        """
        return self._client.parse_ldif(source, server_type)

    def parse_ldif_file(
        self,
        path: Path | str,
        server_type: str = "rfc",
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF content from a file path using RFC-compliant parser."""
        file_path = Path(path)
        if not file_path.exists():
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"LDIF file not found: {file_path}",
            )

        return self.parse(file_path, server_type=server_type)

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
    ) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
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
    ) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
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
    ) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
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
        additional_attrs: FlextLdifTypes.CommonDict.AttributeDict | None = None,
    ) -> FlextResult[FlextLdifModels.Entry]:
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
            FlextResult containing the built Entry

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
        members: list[str] | None = None,
        description: str | None = None,
        additional_attrs: FlextLdifTypes.CommonDict.AttributeDict | None = None,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Build a group entry with members.

        Args:
            cn: Common name (group name)
            base_dn: Base DN for entry
            members: List of member DNs
            description: Description (optional)
            additional_attrs: Additional attributes (optional)

        Returns:
            FlextResult containing the built Entry

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
        additional_attrs: FlextLdifTypes.CommonDict.AttributeDict | None = None,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Build an organizational unit entry.

        Args:
            ou: Organizational unit name
            base_dn: Base DN for entry
            description: Description (optional)
            additional_attrs: Additional attributes (optional)

        Returns:
            FlextResult containing the built Entry

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
        attributes: FlextLdifTypes.CommonDict.AttributeDict,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Build a custom entry with arbitrary attributes.

        Args:
            dn: Distinguished name
            attributes: Dictionary of attribute names to value lists

        Returns:
            FlextResult containing the built Entry

        Example:
            result = api.build_custom_entry(
                dn="cn=test,dc=example,dc=com",
                attributes={FlextLdifConstants.DictKeys.OBJECTCLASS: ["top", "person"], FlextLdifConstants.DictKeys.CN: ["test"]}
            )

        """
        objectclasses = attributes.get(FlextLdifConstants.DictKeys.OBJECTCLASS, ["top"])
        return self._entry_builder.build_custom_entry(dn, objectclasses, attributes)

    def entry_to_dict(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
        """Convert entry to dictionary format.

        Args:
            entry: Entry model to convert

        Returns:
            FlextResult containing dictionary representation

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
    ) -> list[FlextLdifTypes.Models.CustomDataDict]:
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
        dicts: list[FlextLdifTypes.Models.CustomDataDict],
    ) -> list[FlextLdifModels.Entry]:
        """Convert list of dictionaries to list of entries using FlextProcessors.

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
    ) -> FlextResult[str]:
        """Convert list of entries to JSON string.

        Args:
            entries: List of Entry models

        Returns:
            FlextResult containing JSON string

        Example:
            result = api.entries_to_json(entries)
            if result.is_success:
                json_str = result.unwrap()

        """
        return self._entry_builder.convert_entries_to_json(entries)

    def json_to_entries(
        self,
        json_str: str,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Convert JSON string to list of entries.

        Args:
            json_str: JSON string representation of entries

        Returns:
            FlextResult containing list of Entry models

        Example:
            result = api.json_to_entries(json_str)
            if result.is_success:
                entries = result.unwrap()

        """
        return self._entry_builder.build_entries_from_json(json_str)

    # =========================================================================
    # SCHEMA BUILDER OPERATIONS
    # =========================================================================

    def build_person_schema(self) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
        """Build standard person schema definition.

        Returns:
            FlextResult containing person schema

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
        schema: FlextLdifTypes.Models.CustomDataDict,
    ) -> FlextResult[FlextLdifModels.LdifValidationResult]:
        """Validate entries against schema definition.

        Args:
            entries: List of entries to validate
            schema: Schema definition to validate against

        Returns:
            FlextResult containing validation report

        Example:
            schema_result = api.build_person_schema()
            if schema_result.is_success:
                schema = schema_result.unwrap()
                result = api.validate_with_schema(entries, schema)

        """
        # Convert FlextLdifTypes.Models.CustomDataDict schema to SchemaDiscoveryResult with type validation
        attributes_value = schema.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
        if not isinstance(attributes_value, dict):
            return FlextResult[FlextLdifModels.LdifValidationResult].fail(
                "Schema attributes must be a dictionary"
            )

        objectclasses_value = schema.get("object_classes", {})
        if not isinstance(objectclasses_value, dict):
            return FlextResult[FlextLdifModels.LdifValidationResult].fail(
                "Schema object classes must be a dictionary"
            )

        server_type_value = schema.get(
            FlextLdifConstants.DictKeys.SERVER_TYPE, "generic"
        )
        if not isinstance(server_type_value, str):
            return FlextResult[FlextLdifModels.LdifValidationResult].fail(
                "Schema server type must be a string"
            )

        entry_count_value = schema.get("entry_count", 0)
        if not isinstance(entry_count_value, int):
            return FlextResult[FlextLdifModels.LdifValidationResult].fail(
                "Schema entry count must be an integer"
            )

        schema_discovery = FlextLdifModels.SchemaDiscoveryResult(
            attributes=attributes_value,
            objectclasses=objectclasses_value,
            server_type=server_type_value,
            entry_count=entry_count_value,
        )

        # Resolve validator via container
        validator = self._ldif_container.schema_validator()
        # Use schema-aware validation for each entry
        errors: list[str] = []
        warnings: list[str] = []

        for entry in entries:
            entry_result = validator.validate_entry_against_schema(
                entry, schema_discovery
            )
            if entry_result.is_failure:
                errors.extend([f"Entry {entry.dn}: {entry_result.error}"])
            else:
                entry_validation = entry_result.unwrap()
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

        return FlextResult[FlextLdifModels.LdifValidationResult].ok(
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
    ) -> FlextResult[list[FlextLdifModels.AclBase]]:
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
        return self._ldif_container.acl_service().extract_acls_from_entry(entry)

    def evaluate_acl_rules(
        self,
        acls: list[FlextLdifModels.AclBase],
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
                "subject_dn": "cn=admin,dc=example,dc=com",
                "permissions": {"read": True, "write": True}
            }
            result = api.evaluate_acl_rules(acls, context)
            if result.is_success:
                is_allowed = result.unwrap()

        Note:
            Converts AclBase models to AclRule objects and evaluates using FlextLdifAclService.

        """
        try:
            if not acls:
                # No ACLs means no restrictions - allow by default
                return FlextResult[bool].ok(True)

            acl_service = self._ldif_container.acl_service()
            eval_context = context or {}

            # Create composite rule combining all ACLs
            composite = acl_service.create_composite_rule(operator="AND")

            # Convert each AclBase to evaluation rules
            for acl in acls:
                # Create permission rules from ACL permissions
                if hasattr(acl, "permissions") and acl.permissions:
                    perms = acl.permissions.model_dump()
                    for perm_name, perm_value in perms.items():
                        if perm_value:
                            rule = acl_service.create_permission_rule(
                                perm_name, required=True
                            )
                            composite.add_rule(rule)

                # Add subject rule if present
                if hasattr(acl, "subject") and acl.subject:
                    subject_value = getattr(acl.subject, "subject_value", None)
                    if subject_value and subject_value != "*":
                        rule = acl_service.create_subject_rule(subject_value)
                        composite.add_rule(rule)

                # Add target rule if present
                if hasattr(acl, "target") and acl.target:
                    target_dn = getattr(acl.target, "target_dn", None)
                    if target_dn and target_dn != "*":
                        rule = acl_service.create_target_rule(target_dn)
                        composite.add_rule(rule)

            # Evaluate composite rule
            return composite.evaluate(cast("dict[str, object]", eval_context))

        except Exception as e:
            return FlextResult[bool].fail(f"ACL evaluation failed: {e}")

    # =========================================================================
    # PROCESSOR OPERATIONS
    # =========================================================================

    def process_batch(
        self,
        processor_name: str,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifTypes.Models.CustomDataDict]]:
        """Process entries in batch mode using LdifBatchProcessor.

        Args:
            processor_name: Name of processor function ("transform", "validate", etc.)
            entries: List of entries to process

        Returns:
            FlextResult containing processed results

        Example:
            # Convert entries to dictionaries
            result = api.process_batch("transform", entries)
            if result.is_success:
                processed = result.unwrap()

        Note:
            Uses LdifBatchProcessor for memory-efficient batch processing.
            Currently supports "transform" (converts to dict) and "validate" (validates entries).

        """
        try:
            processor = LdifBatchProcessor(batch_size=100)

            # Define processor functions
            if processor_name == "transform":

                def transform_func(
                    entry: FlextLdifModels.Entry,
                ) -> FlextLdifTypes.Models.CustomDataDict:
                    return entry.model_dump()

                return processor.process_batch(entries, transform_func)

            if processor_name == "validate":

                def validate_func(
                    entry: FlextLdifModels.Entry,
                ) -> FlextLdifTypes.Models.CustomDataDict:
                    # Basic validation: entry has DN and attributes
                    return {
                        "dn": entry.dn.value,
                        "valid": bool(entry.dn.value and entry.attributes),
                        "attribute_count": len(entry.attributes.attributes),
                    }

                return processor.process_batch(entries, validate_func)

            supported = "'transform', 'validate'"
            return FlextResult[list[FlextLdifTypes.Models.CustomDataDict]].fail(
                f"Unknown processor: '{processor_name}'. Supported: {supported}"
            )

        except Exception as e:
            return FlextResult[list[FlextLdifTypes.Models.CustomDataDict]].fail(
                f"Batch processing failed: {e}"
            )

    def process_parallel(
        self,
        processor_name: str,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifTypes.Models.CustomDataDict]]:
        """Process entries in parallel mode using LdifParallelProcessor.

        Args:
            processor_name: Name of processor function ("transform", "validate", etc.)
            entries: List of entries to process

        Returns:
            FlextResult containing processed results

        Example:
            # Convert entries to dictionaries in parallel
            result = api.process_parallel("validate", entries)
            if result.is_success:
                processed = result.unwrap()

        Note:
            Uses LdifParallelProcessor with ThreadPoolExecutor for true parallel execution.
            Currently supports "transform" (converts to dict) and "validate" (validates entries).

        """
        try:
            processor = LdifParallelProcessor(max_workers=4)

            # Define processor functions
            if processor_name == "transform":

                def transform_func(
                    entry: FlextLdifModels.Entry,
                ) -> FlextLdifTypes.Models.CustomDataDict:
                    return entry.model_dump()

                return processor.process_parallel(entries, transform_func)

            if processor_name == "validate":

                def validate_func(
                    entry: FlextLdifModels.Entry,
                ) -> FlextLdifTypes.Models.CustomDataDict:
                    # Basic validation: entry has DN and attributes
                    return {
                        "dn": entry.dn.value,
                        "valid": bool(entry.dn.value and entry.attributes),
                        "attribute_count": len(entry.attributes.attributes),
                    }

                return processor.process_parallel(entries, validate_func)

            supported = "'transform', 'validate'"
            return FlextResult[list[FlextLdifTypes.Models.CustomDataDict]].fail(
                f"Unknown processor: '{processor_name}'. Supported: {supported}"
            )

        except Exception as e:
            return FlextResult[list[FlextLdifTypes.Models.CustomDataDict]].fail(
                f"Parallel processing failed: {e}"
            )

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
    def bus(self) -> FlextBus:
        """Access to FlextBus for event publishing.

        Returns:
            FlextBus instance for publishing domain events

        Example:
            ldif.bus.publish("ldif.parsed", {"entry_count": 10})

        """
        # Type narrow _bus to FlextBus (initialized in __init__)
        if not isinstance(self._bus, FlextBus):
            # Fallback: create new Bus if somehow not initialized
            self._bus = FlextBus()
        return self._bus

    @property
    def dispatcher(self) -> FlextDispatcher:
        """Access to FlextDispatcher for message dispatching.

        Returns:
            FlextDispatcher instance for CQRS message routing

        Example:
            result = ldif.dispatcher.dispatch(command)

        """
        return self._dispatcher

    @property
    def registry(self) -> FlextRegistry:
        """Access to FlextRegistry for component management.

        Returns:
            FlextRegistry instance for component registration and discovery

        Example:
            component = ldif.registry.get("my_component")

        """
        return self._registry

    @property
    def processors(self) -> FlextProcessors:
        """Access to FlextProcessors for batch and parallel processing.

        Returns:
            FlextProcessors instance for processing utilities

        Example:
            result = ldif.processors.process_batch(entries, processor_func)

        """
        return self._processors

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
        return self._ldif_container.acl_service()

    # =========================================================================


__all__ = ["FlextLdif"]
