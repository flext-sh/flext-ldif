"""FLEXT-LDIF API - Thin Facade for LDIF Operations.

This module provides the primary entry point for all LDIF processing operations.
The FlextLdif class serves as a thin facade exposing all functionality through
a clean, unified interface that delegates to the FlextLdifClient implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import warnings
from pathlib import Path
from typing import ClassVar, override

from flext_core import FlextProcessors, FlextResult, FlextService

from flext_ldif.acl.parser import FlextLdifAclParser
from flext_ldif.acl.service import FlextLdifAclService
from flext_ldif.acl.utils import FlextLdifAclUtils
from flext_ldif.client import FlextLdifClient
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.entry.builder import FlextLdifEntryBuilder
from flext_ldif.exceptions import FlextLdifExceptions
from flext_ldif.mixins import FlextLdifMixins
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.quirks.manager import FlextLdifQuirksManager
from flext_ldif.quirks.registry import FlextLdifQuirksRegistry
from flext_ldif.schema.builder import FlextLdifSchemaBuilder
from flext_ldif.schema.extractor import FlextLdifSchemaExtractor
from flext_ldif.schema.objectclass_manager import FlextLdifObjectClassManager
from flext_ldif.schema.validator import FlextLdifSchemaValidator
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdif(FlextService[FlextLdifTypes.Dict]):
    r"""Unified LDIF processing facade with FlextMixins.Service infrastructure.

    This service inherits from Flext.Service to demonstrate:
    - Inherited container property (FlextContainer singleton)
    - Inherited logger property (FlextLogger with service context)
    - Inherited context property (FlextContext for request/correlation)
    - Inherited config property (FlextConfig with LDIF settings)
    - Inherited metrics property (FlextMetrics for observability)

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
        """Initialize LDIF facade with inherited FlextMixins.Service infrastructure.

        Inherited properties (no manual instantiation needed):
        - self.logger: FlextLogger with service context (LDIF processing operations)
        - self.container: FlextContainer singleton (for service dependencies)
        - self.context: FlextContext (for correlation tracking)
        - self.config: FlextConfig (for LDIF configuration)
        - self.metrics: FlextMetrics (for LDIF observability)

        Args:
            config: Optional LDIF configuration. If not provided,
                   uses global singleton instance.

        """
        super().__init__()
        self._client = FlextLdifClient(config)

        # Initialize frequently-used services (entry builder used in many methods)
        self._entry_builder = FlextLdifEntryBuilder()
        self._schema_builder = FlextLdifSchemaBuilder()

        # Other services instantiated on-demand in methods that use them
        # This reduces memory footprint for unused services

        # Demonstrate inherited logger (no manual instantiation needed!)
        self.logger.info(
            "FlextLdif initialized with inherited infrastructure",
            extra={
                "service_type": "LDIF Processing Facade",
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
    # ENTRY BUILDER OPERATIONS (Direct Methods)
    # =========================================================================

    def build_person_entry(
        self,
        cn: str,
        sn: str,
        base_dn: str,
        **kwargs: str | list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Build a person entry with common attributes.

        Args:
            cn: Common name
            sn: Surname
            base_dn: Base DN for entry
            **kwargs: Additional attributes (mail, telephoneNumber, etc.)

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
        return self._entry_builder.build_person_entry(cn, sn, base_dn, **kwargs)

    def build_group_entry(
        self,
        cn: str,
        base_dn: str,
        members: list[str] | None = None,
        **kwargs: str | list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Build a group entry with members.

        Args:
            cn: Common name (group name)
            base_dn: Base DN for entry
            members: List of member DNs
            **kwargs: Additional attributes

        Returns:
            FlextResult containing the built Entry

        Example:
            result = api.build_group_entry(
                cn="Admins",
                base_dn="ou=Groups,dc=example,dc=com",
                members=["cn=alice,ou=People,dc=example,dc=com"]
            )

        """
        return self._entry_builder.build_group_entry(cn, base_dn, members, **kwargs)

    def build_organizational_unit(
        self,
        ou: str,
        base_dn: str,
        **kwargs: str | list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Build an organizational unit entry.

        Args:
            ou: Organizational unit name
            base_dn: Base DN for entry
            **kwargs: Additional attributes

        Returns:
            FlextResult containing the built Entry

        Example:
            result = api.build_organizational_unit(
                ou="People",
                base_dn="dc=example,dc=com"
            )

        """
        return self._entry_builder.build_organizational_unit_entry(ou, base_dn, **kwargs)

    def build_custom_entry(
        self,
        dn: str,
        attributes: dict[str, list[str]],
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
                attributes={"objectClass": ["top", "person"], "cn": ["test"]}
            )

        """
        objectclasses = attributes.get("objectClass", ["top"])
        return self._entry_builder.build_custom_entry(dn, objectclasses, attributes)

    def entry_to_dict(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[dict[str, object]]:
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
    ) -> list[dict[str, list[str]]]:
        """Convert list of entries to list of dictionaries using FlextProcessors.

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
        dicts: list[dict[str, list[str]]],
    ) -> list[FlextLdifModels.Entry]:
        """Convert list of dictionaries to list of entries using FlextProcessors.

        Args:
            dicts: List of entry dictionaries

        Returns:
            List of Entry models (only successful conversions)

        Example:
            entries = api.dicts_to_entries(dicts)

        """
        # Use FlextProcessors for batch transformation
        def convert_dict(entry_dict: dict) -> FlextResult[FlextLdifModels.Entry]:
            return self._entry_builder.convert_dict_to_entry(entry_dict)

        processor_result = FlextProcessors.create_processor()
        if processor_result.is_failure:
            return []  # Maintain backward compatibility (return empty on error)

        # Batch process with automatic error handling
        results = [convert_dict(d) for d in dicts]
        return [r.unwrap() for r in results if r.is_success]

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
        return self._entry_builder.convert_json_to_entries(json_str)

    # =========================================================================
    # SCHEMA BUILDER OPERATIONS
    # =========================================================================

    def build_person_schema(self) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Build standard person schema definition.

        Returns:
            FlextResult containing person schema

        Example:
            result = api.build_person_schema()
            if result.is_success:
                person_schema = result.unwrap()

        """
        return self._schema_builder.build_standard_person_schema()

    def build_group_schema(self) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Build standard group schema definition.

        Returns:
            FlextResult containing group schema

        Example:
            result = api.build_group_schema()
            if result.is_success:
                group_schema = result.unwrap()

        """
        return self._schema_builder.build_standard_group_schema()

    def add_schema_attribute(
        self,
        name: str,
        description: str | None = None,
    ) -> FlextResult[None]:
        """Add attribute to schema builder.

        Args:
            name: Attribute name
            description: Optional attribute description

        Returns:
            FlextResult indicating success or failure

        Example:
            result = api.add_schema_attribute("mail", "Email address")

        """
        return self._schema_builder.add_attribute(name, description)

    def build_schema(self) -> FlextResult[FlextLdifModels.Schema]:
        """Build complete schema from added attributes.

        Returns:
            FlextResult containing complete schema

        Example:
            api.add_schema_attribute("cn", "Common name")
            api.add_schema_attribute("sn", "Surname")
            result = api.build_schema()

        """
        return self._schema_builder.build()

    # =========================================================================
    # SCHEMA VALIDATOR OPERATIONS
    # =========================================================================

    def validate_with_schema(
        self,
        entries: list[FlextLdifModels.Entry],
        schema: FlextLdifModels.Schema,
    ) -> FlextResult[FlextLdifTypes.Dict]:
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
        validator = FlextLdifSchemaValidator()
        return validator.validate_entries_with_schema(entries, schema)

    def validate_entry_against_schema(
        self,
        entry: FlextLdifModels.Entry,
        schema: FlextLdifModels.Schema,
    ) -> FlextResult[bool]:
        """Validate single entry against schema definition.

        Args:
            entry: Entry to validate
            schema: Schema definition to validate against

        Returns:
            FlextResult containing boolean validation result

        Example:
            result = api.validate_entry_against_schema(entry, schema)
            if result.is_success:
                is_valid = result.unwrap()

        """
        validator = FlextLdifSchemaValidator()
        return validator.validate_entry(entry, schema)

    # =========================================================================
    # SCHEMA EXTRACTOR OPERATIONS
    # =========================================================================

    def extract_schema_from_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[FlextLdifModels.Schema]:
        """Extract schema definition from entries.

        Args:
            entries: List of entries to extract schema from

        Returns:
            FlextResult containing extracted schema

        Example:
            result = api.extract_schema_from_entries(entries)
            if result.is_success:
                schema = result.unwrap()

        """
        extractor = FlextLdifSchemaExtractor()
        return extractor.extract_from_entries(entries)

    def extract_attribute_usage(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Extract attribute usage statistics from entries.

        Args:
            entries: List of entries to analyze

        Returns:
            FlextResult containing attribute usage statistics

        Example:
            result = api.extract_attribute_usage(entries)
            if result.is_success:
                stats = result.unwrap()

        """
        extractor = FlextLdifSchemaExtractor()
        return extractor.extract_attribute_usage(entries)

    # =========================================================================
    # OBJECTCLASS MANAGER OPERATIONS
    # =========================================================================

    def resolve_objectclass_hierarchy(
        self,
        objectclasses: list[str],
    ) -> FlextResult[list[str]]:
        """Resolve objectClass hierarchy with inheritance.

        Args:
            objectclasses: List of objectClass names

        Returns:
            FlextResult containing complete hierarchy

        Example:
            result = api.resolve_objectclass_hierarchy(["inetOrgPerson"])
            if result.is_success:
                hierarchy = result.unwrap()  # ["top", "person", "inetOrgPerson"]

        """
        manager = FlextLdifObjectClassManager()
        return manager.resolve_objectclass_hierarchy(objectclasses)

    def get_required_attributes(
        self,
        objectclasses: list[str],
    ) -> FlextResult[list[str]]:
        """Get all required attributes for objectClasses.

        Args:
            objectclasses: List of objectClass names

        Returns:
            FlextResult containing required attribute names

        Example:
            result = api.get_required_attributes(["person"])
            if result.is_success:
                required = result.unwrap()  # ["cn", "sn"]

        """
        manager = FlextLdifObjectClassManager()
        return manager.get_all_required_attributes(objectclasses)

    def get_optional_attributes(
        self,
        objectclasses: list[str],
    ) -> FlextResult[list[str]]:
        """Get all optional attributes for objectClasses.

        Args:
            objectclasses: List of objectClass names

        Returns:
            FlextResult containing optional attribute names

        Example:
            result = api.get_optional_attributes(["person"])
            if result.is_success:
                optional = result.unwrap()

        """
        manager = FlextLdifObjectClassManager()
        return manager.get_all_optional_attributes(objectclasses)

    def validate_objectclass_combination(
        self,
        objectclasses: list[str],
    ) -> FlextResult[bool]:
        """Validate objectClass combination is valid.

        Args:
            objectclasses: List of objectClass names

        Returns:
            FlextResult containing boolean validation result

        Example:
            result = api.validate_objectclass_combination(
                ["top", "person", "inetOrgPerson"]
            )

        """
        manager = FlextLdifObjectClassManager()
        return manager.validate_objectclass_combination(objectclasses)

    # =========================================================================
    # ACL OPERATIONS
    # =========================================================================

    def extract_acls(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[list[FlextLdifModels.AclRule]]:
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
        acl_service = FlextLdifAclService()
        return acl_service.extract_acls_from_entry(entry)

    def evaluate_acl_rules(
        self,
        acls: list[FlextLdifModels.AclRule],
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Evaluate ACL rules and return evaluation report.

        Args:
            acls: List of ACL rules to evaluate

        Returns:
            FlextResult containing evaluation report

        Example:
            result = api.evaluate_acl_rules(acls)
            if result.is_success:
                report = result.unwrap()

        """
        acl_service = FlextLdifAclService()
        return acl_service.evaluate_acl_rules(acls)

    def parse_acl_string(
        self,
        acl_string: str,
    ) -> FlextResult[FlextLdifModels.AclRule]:
        """Parse ACL string into ACL rule model.

        Args:
            acl_string: ACL string to parse

        Returns:
            FlextResult containing parsed ACL rule

        Example:
            result = api.parse_acl_string('(target="ldap:///...")(...)...')

        """
        acl_parser = FlextLdifAclParser()
        return acl_parser.parse_acl(acl_string)

    def create_permission_rule(
        self,
        target: str,
        permissions: list[str],
        subject: str,
    ) -> FlextResult[FlextLdifModels.AclRule]:
        """Create ACL permission rule.

        Args:
            target: Target DN or filter
            permissions: List of permissions (read, write, etc.)
            subject: Subject DN or filter

        Returns:
            FlextResult containing created ACL rule

        Example:
            result = api.create_permission_rule(
                target="ldap:///ou=People,dc=example,dc=com",
                permissions=["read", "search"],
                subject="ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
            )

        """
        acl_utils = FlextLdifAclUtils()
        return acl_utils.create_permission_rule(target, permissions, subject)

    # =========================================================================
    # QUIRKS MANAGER OPERATIONS
    # =========================================================================

    def detect_server_type(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[str]:
        """Detect LDAP server type from entries.

        Args:
            entries: List of entries to analyze

        Returns:
            FlextResult containing detected server type

        Example:
            result = api.detect_server_type(entries)
            if result.is_success:
                server_type = result.unwrap()  # "oid", "oud", "openldap", etc.

        """
        registry = FlextLdifQuirksRegistry()
        manager = FlextLdifQuirksManager(registry=registry)
        return manager.detect_server_type(entries)

    def get_server_quirks(
        self,
        server_type: str,
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Get server-specific quirks configuration.

        Args:
            server_type: Server type ("oid", "oud", "openldap", etc.)

        Returns:
            FlextResult containing quirks configuration

        Example:
            result = api.get_server_quirks("oid")
            if result.is_success:
                quirks = result.unwrap()

        """
        registry = FlextLdifQuirksRegistry()
        manager = FlextLdifQuirksManager(registry=registry)
        return manager.get_server_quirks(server_type)

    def get_acl_attribute_name(
        self,
        server_type: str,
    ) -> FlextResult[str]:
        """Get ACL attribute name for server type.

        Args:
            server_type: Server type ("oid", "oud", "openldap", etc.)

        Returns:
            FlextResult containing ACL attribute name

        Example:
            result = api.get_acl_attribute_name("oid")
            if result.is_success:
                acl_attr = result.unwrap()  # "orclaci"

        """
        registry = FlextLdifQuirksRegistry()
        manager = FlextLdifQuirksManager(registry=registry)
        return manager.get_acl_attribute_name(server_type)

    # =========================================================================
    # PROCESSOR OPERATIONS
    # =========================================================================

    def process_batch(
        self,
        processor_name: str,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifTypes.Dict]]:
        """Process entries in batch mode using FlextProcessors.

        Args:
            processor_name: Name of processor to use
            entries: List of entries to process

        Returns:
            FlextResult containing processed results

        Example:
            result = api.process_batch("transform", entries)
            if result.is_success:
                processed = result.unwrap()

        """
        entry_dicts = self.entries_to_dicts(entries)
        processor_result = FlextProcessors.create_processor()
        if processor_result.is_failure:
            return FlextResult[list[FlextLdifTypes.Dict]].fail(
                f"Failed to create processor: {processor_result.error}"
            )

        processor = processor_result.unwrap()
        return processor.process_batch(processor_name, entry_dicts)

    def process_parallel(
        self,
        processor_name: str,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifTypes.Dict]]:
        """Process entries in parallel mode using FlextProcessors.

        Args:
            processor_name: Name of processor to use
            entries: List of entries to process

        Returns:
            FlextResult containing processed results

        Example:
            result = api.process_parallel("validate", entries)
            if result.is_success:
                processed = result.unwrap()

        """
        entry_dicts = self.entries_to_dicts(entries)
        processor_result = FlextProcessors.create_processor()
        if processor_result.is_failure:
            return FlextResult[list[FlextLdifTypes.Dict]].fail(
                f"Failed to create processor: {processor_result.error}"
            )

        processor = processor_result.unwrap()
        return processor.process_parallel(processor_name, entry_dicts)

    # =========================================================================
    # BUILDERS & SERVICES (Direct Access)
    # =========================================================================

    @property
    def entry_builder(self) -> type[FlextLdifEntryBuilder]:
        """Access to LDIF entry builder for constructing entries.

        .. deprecated:: 0.9.9
            Use direct methods like :meth:`build_person_entry`, :meth:`build_group_entry`,
            :meth:`build_organizational_unit`, :meth:`build_custom_entry` instead.

        Returns:
            FlextLdifEntryBuilder class for creating person, group, OU, and custom entries

        Example:
            # Old (deprecated):
            builder = ldif.EntryBuilder()
            person = builder.build_person_entry(...)

            # New (preferred):
            person_result = ldif.build_person_entry(...)

        """
        warnings.warn(
            "api.EntryBuilder() is deprecated. Use direct methods like "
            "api.build_person_entry(), api.build_group_entry() instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return FlextLdifEntryBuilder

    @property
    def schema_builder(self) -> type[FlextLdifSchemaBuilder]:
        """Access to LDIF schema builder for constructing schemas.

        .. deprecated:: 0.9.9
            Use direct methods like :meth:`build_person_schema`, :meth:`build_group_schema`,
            :meth:`add_schema_attribute`, :meth:`build_schema` instead.

        Returns:
            FlextLdifSchemaBuilder class for building schema definitions

        Example:
            # Old (deprecated):
            builder = ldif.SchemaBuilder(server_type="rfc")
            builder.add_attribute("cn", "commonName")
            schema = builder.build()

            # New (preferred):
            ldif.add_schema_attribute("cn", "commonName")
            schema_result = ldif.build_schema()

        """
        warnings.warn(
            "api.SchemaBuilder() is deprecated. Use direct methods like "
            "api.build_person_schema(), api.add_schema_attribute() instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return FlextLdifSchemaBuilder

    @property
    def acl_service(self) -> type[FlextLdifAclService]:
        """Access to ACL service for extracting and processing ACLs.

        .. deprecated:: 0.9.9
            Use direct methods like :meth:`extract_acls`, :meth:`evaluate_acl_rules`,
            :meth:`parse_acl_string`, :meth:`create_permission_rule` instead.

        Returns:
            FlextLdifAclService class for ACL operations

        Example:
            # Old (deprecated):
            acl_service = ldif.AclService()
            acls = acl_service.extract_acls_from_entry(entry)

            # New (preferred):
            acls_result = ldif.extract_acls(entry)

        """
        warnings.warn(
            "api.AclService() is deprecated. Use direct methods like "
            "api.extract_acls(), api.evaluate_acl_rules() instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return FlextLdifAclService

    @property
    def schema_validator(self) -> type[FlextLdifSchemaValidator]:
        """Access to schema validator for validating entries.

        .. deprecated:: 0.9.9
            Use direct methods like :meth:`validate_with_schema`,
            :meth:`validate_entry_against_schema` instead.

        Returns:
            FlextLdifSchemaValidator class for schema validation

        Example:
            # Old (deprecated):
            validator = ldif.SchemaValidator()
            result = validator.execute({"entries": entries})

            # New (preferred):
            result = ldif.validate_with_schema(entries, schema)

        """
        warnings.warn(
            "api.SchemaValidator() is deprecated. Use direct methods like "
            "api.validate_with_schema(), api.validate_entry_against_schema() instead.",
            DeprecationWarning,
            stacklevel=2,
        )
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
