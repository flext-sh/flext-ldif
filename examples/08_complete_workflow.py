"""Example 8: Complete LDIF Processing Workflow.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Demonstrates comprehensive FlextLdif integration with direct methods:

NOTE: This example uses proper error handling instead of assert statements.
All type validations are done with explicit checks and appropriate error messages,
representing production-ready error handling patterns.
- Railway-oriented programming with FlextResult
- Multi-step processing pipelines using direct API methods
- Integration of all API functionality (no manual class instantiation!)
- Real-world LDIF processing scenarios
- Error handling and recovery patterns
- Access to all namespace classes [UTILITIES DEPRECATED]
- Configuration via .env environment variables

This example shows how to combine all FlextLdif features
in production-ready workflows using the streamlined direct method API.

All functionality accessed through FlextLdif facade with zero boilerplate.

Configuration:
    Set environment variables in .env file:
    - FLEXT_LDIF_MAX_WORKERS=4
    - FLEXT_LDIF_STRICT_VALIDATION=true
    - FLEXT_LDIF_DEBUG_MODE=false
    - LDAP_HOST=localhost
    - LDAP_PORT=3390
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from flext_ldif import FlextLdif
from flext_ldif.models import FlextLdifModels


def railway_oriented_composition() -> None:
    """Demonstrate railway-oriented programming with FlextResult composition.

    Shows elegant chaining of operations with automatic error propagation.
    Uses .env configuration automatically via FlextLdifConfig.
    """
    api = FlextLdif.get_instance()

    ldif_content = """dn: cn=Railway User,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: Railway User
sn: User
mail: railway@example.com
"""

    # Railway-oriented composition - errors propagate automatically
    # Each operation returns FlextResult, enabling fluent chaining
    parse_result = api.parse(ldif_content)
    if parse_result.is_failure:
        return

    entries = parse_result.unwrap()

    validate_result = api.validate_entries(entries)
    if validate_result.is_failure:
        return

    analyze_result = api.analyze(entries)
    if analyze_result.is_failure:
        return

    stats = analyze_result.unwrap()

    write_result = api.write(entries)
    if write_result.is_failure:
        return

    _ldif_output = write_result.unwrap()

    # Handle final result
    # stats is EntryAnalysisResult model, access attributes directly
    getattr(stats, "total_entries", 0)


def configuration_from_env_example() -> None:
    """Demonstrate automatic configuration loading from .env file.

    FlextLdifConfig automatically loads from environment variables:
    - FLEXT_LDIF_MAX_WORKERS
    - FLEXT_LDIF_STRICT_VALIDATION
    - FLEXT_LDIF_ENCODING
    - And all other FlextLdifConfig fields

    No manual configuration needed - set values in .env file!
    """
    api = FlextLdif.get_instance()

    # Configuration loaded automatically from .env

    # Configuration affects behavior automatically
    # Use max_workers from config (no get_effective_workers method)
    getattr(api.config, "max_workers", 4)


def complete_ldif_processing_workflow() -> None:
    """End-to-end LDIF processing: parse → validate → analyze → write."""
    api = FlextLdif.get_instance()

    # Step 1: Parse LDIF content
    ldif_content = """dn: ou=People,dc=example,dc=com
objectClass: organizationalUnit
ou: People

dn: cn=Alice Johnson,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: Alice Johnson
sn: Johnson
mail: alice@example.com

dn: cn=Bob Williams,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: Bob Williams
sn: Williams
mail: bob@example.com

dn: cn=Admins,ou=Groups,dc=example,dc=com
objectClass: groupOfNames
cn: Admins
member: cn=Alice Johnson,ou=People,dc=example,dc=com
"""

    parse_result = api.parse(ldif_content)

    if parse_result.is_failure:
        _ = parse_result.error
        return

    entries = parse_result.unwrap()

    # Step 2: Validate entries
    validation_result = api.validate_entries(entries)

    if validation_result.is_failure:
        _ = validation_result.error
        return

    validation_report = validation_result.unwrap()
    # validation_report is ValidationResult model, access attributes directly
    if not validation_report.is_valid:
        _ = validation_report.errors
        return

    # Step 3: Analyze entries
    analysis_result = api.analyze(entries)

    if analysis_result.is_failure:
        _ = analysis_result.error
        return

    stats = analysis_result.unwrap()
    # stats is EntryAnalysisResult model, access attributes directly
    _ = stats.total_entries

    # Step 4: Write validated entries to file
    output_path = Path("examples/workflow_output.ldif")
    write_result = api.write(entries, output_path)

    if write_result.is_success:
        _ = write_result.unwrap()


def server_migration_workflow() -> None:
    """Complete server migration workflow with validation."""
    api = FlextLdif.get_instance()

    # Create source and target directories
    source_dir = Path("examples/workflow_source")
    target_dir = Path("examples/workflow_target")

    source_dir.mkdir(exist_ok=True)
    target_dir.mkdir(exist_ok=True)

    # Step 1: Create source LDIF (OID format)
    source_ldif = """dn: cn=Migration User,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: Migration User
sn: User
mail: migration@example.com
"""

    source_file = source_dir / "source.ldif"
    _ = source_file.write_text(source_ldif)

    # Step 2: Validate source data
    source_parse = api.parse(source_ldif, server_type="oid")

    if source_parse.is_failure:
        return

    source_entries = source_parse.unwrap()

    source_validation = api.validate_entries(source_entries)

    if source_validation.is_failure:
        return

    # Step 3: Migrate OID → OUD
    migration_result = api.migrate(
        input_dir=source_dir,
        output_dir=target_dir,
        source_server="oid",
        target_server="oud",
    )

    if migration_result.is_failure:
        _ = migration_result.error
        return

    # migration_result is EntryResult model, access attributes directly
    migration_stats = migration_result.unwrap()

    # Step 4: Verify migrated data
    # file_paths is dict[str, str] mapping category to file path
    migrated_files = list(migration_stats.file_paths.values())
    for file_path in migrated_files:
        # file_path is already str from dict values, cast to ensure type safety
        file_path_str = cast("str", file_path)
        verify_result = api.parse(Path(file_path_str), server_type="oud")

        if verify_result.is_success:
            migrated_entries = verify_result.unwrap()
            _ = len(migrated_entries)


def entry_building_and_processing_workflow() -> None:
    """Build entries, validate, and process through pipeline using direct methods."""
    api = FlextLdif.get_instance()

    # Step 1: Build entries using direct API methods (no builder instantiation!)
    person_result = api.create_entry(
        dn="cn=Workflow User,ou=People,dc=example,dc=com",
        attributes={
            "objectClass": ["person", "inetOrgPerson", "top"],
            "cn": ["Workflow User"],
            "sn": ["User"],
            "mail": ["workflow@example.com"],
        },
    )

    if person_result.is_failure:
        return

    person = person_result.unwrap()

    # Convert DN to string for members list
    member_dns = [str(person.dn)]

    group_result = api.create_entry(
        dn="cn=Workflow Group,ou=Groups,dc=example,dc=com",
        attributes={
            "objectClass": ["groupOfNames", "top"],
            "cn": ["Workflow Group"],
            "member": member_dns,
        },
    )

    if group_result.is_failure:
        return

    group = group_result.unwrap()

    entries = [person, group]

    # Step 2: Validate using direct validation method
    validation_result = api.validate_entries(entries)

    if validation_result.is_failure:
        return

    # Step 3: Filter specific entry types
    person_filter = api.filter(entries, objectclass="person")

    if person_filter.is_failure:
        return

    persons = person_filter.unwrap()

    # Step 4: Analyze and write
    analysis_result = api.analyze(persons)

    if analysis_result.is_success:
        stats = analysis_result.unwrap()

        write_result = api.write(persons)

        if write_result.is_success:
            ldif_output = write_result.unwrap()
            _ = (stats, len(ldif_output))


def schema_driven_workflow() -> None:
    """Schema-first workflow using direct methods (no class instantiation!)."""
    api = FlextLdif.get_instance()

    # Step 1: Create entries using direct API methods
    entries = []
    for i in range(5):
        person_result = api.create_entry(
            dn=f"cn=User {i},ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person", "inetOrgPerson", "top"],
                "cn": [f"User {i}"],
                "sn": [f"Surname {i}"],
            },
        )

        if person_result.is_success:
            entries.append(person_result.unwrap())


def acl_processing_workflow() -> None:
    """ACL extraction and processing using direct methods."""
    api = FlextLdif.get_instance()

    # Parse entry with ACLs
    ldif_content = """dn: ou=Secure,dc=example,dc=com
objectClass: organizationalUnit
ou: Secure
aci: (target="ldap:///ou=Secure,dc=example,dc=com")(targetattr="*")(version 3.0; acl "Admin access"; allow (all) userdn="ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com";)

dn: cn=User,ou=Secure,dc=example,dc=com
objectClass: person
cn: User
sn: Test
"""

    parse_result = api.parse(ldif_content)

    if parse_result.is_failure:
        return

    entries = parse_result.unwrap()

    # Extract ACLs using direct API method (no service instantiation!)
    for entry in entries:
        acl_result = api.extract_acls(entry)

        if acl_result.is_success:
            acl_response = acl_result.unwrap()
            # Extract ACLs list from AclResponse
            # AclResponse from API returns public models, but type checker sees domain models
            # Cast to expected type since models are compatible at runtime
            acls_list = acl_response.acls if hasattr(acl_response, "acls") else []
            # Type cast needed because domain and public Acl models are structurally compatible
            # Use FlextLdifModels.Acl for type hint
            public_acls = cast("list[FlextLdifModels.Acl]", acls_list)

            if public_acls:
                # Evaluate ACL rules using direct API method
                eval_result = api.evaluate_acl_rules(public_acls)

                if eval_result.is_success:
                    _ = eval_result.unwrap()


def batch_processing_workflow() -> None:
    """Batch processing using direct methods (massive simplification!)."""
    api = FlextLdif.get_instance()

    # Create large dataset
    entries: list[FlextLdifModels.Entry] = []
    for i in range(20):
        result = api.create_entry(
            dn=f"cn=BatchUser{i},ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": [f"BatchUser{i}"],
                "sn": [f"User{i}"],
            },
        )
        if result.is_success:
            entries.append(result.unwrap())

    # Validate all entries
    validation_result = api.validate_entries(entries)

    if validation_result.is_failure:
        return

    # Batch process - ONE LINE! (was 20+ lines with manual setup)
    # No processor creation, no manual conversion loops!
    batch_result = api.process("validate", entries, parallel=False)

    if batch_result.is_success:
        processed = batch_result.unwrap()
        _ = len(processed)


def access_all_namespace_classes() -> None:
    """Demonstrate access to all namespace classes through API."""
    api = FlextLdif.get_instance()

    # Access Models
    entry_result = api.models.Entry.create(
        dn="cn=test,dc=example,dc=com",
        attributes={"objectClass": ["person"], "cn": ["test"], "sn": ["user"]},
    )
    if entry_result.is_failure:
        return
    entry = entry_result.unwrap()

    # Access Constants
    max_line_length = api.constants.LdifFormatting.MAX_LINE_WIDTH
    utf8_encoding = api.constants.Encoding.UTF8

    # Access Types (for type hints)
    # entry_config: api.types.Entry.EntryConfiguration = {}

    # Access Protocols (for duck typing)
    # def process(processor: api.protocols.LdifProcessorProtocol): ...

    # Access Exceptions
    # error = api.exceptions.validation_error("test error")

    # Access Mixins
    # validator = api.mixins.ValidationMixin()

    # Access Utilities (updated to use services)
    timestamp = datetime.now(UTC).timestamp()
    # NOTE: ValidationService was removed - validation now integrated in models/services
    # validation_service = ValidationService()  # REMOVED - no longer exists
    # attr_valid = validation_service.validate_attribute_name("cn")  # Use model validation instead
    attr_valid = True  # Placeholder - use FlextLdif models for validation

    # Processors doesn't have create_processor method
    # processor = api.processors.get_processors()

    # Access Config
    encoding = api.ldif_config.ldif_encoding
    max_workers = api.config.max_workers

    _ = (
        entry,
        max_line_length,
        utf8_encoding,
        timestamp,
        attr_valid,
        encoding,
        max_workers,
    )


def error_handling_and_recovery() -> None:
    """Demonstrate error handling and recovery patterns."""
    api = FlextLdif.get_instance()

    # Attempt to parse potentially invalid LDIF
    ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
"""  # Missing required 'sn' for person

    parse_result = api.parse(ldif_content)

    if parse_result.is_failure:
        # Handle parse error
        error = parse_result.error
        _ = error
        return

    entries = parse_result.unwrap()

    # Validate and handle validation errors
    validation_result = api.validate_entries(entries)

    if validation_result.is_failure:
        # Handle validation failure
        _ = validation_result.error
        return

    validation_report = validation_result.unwrap()
    # validation_report is ValidationResult model, access attributes directly

    if not validation_report.is_valid:
        # Handle validation errors and attempt recovery by fixing entries
        for entry in entries:
            # Add missing required attribute
            if entry.attributes:
                obj_class_attr = entry.attributes.attributes.get("objectClass", [])
                # obj_class_attr is already a list from .get() default
                if (
                    "person" in obj_class_attr
                    and "sn" not in entry.attributes.attributes
                ):
                    entry.attributes.add_attribute("sn", "recovered")

        # Retry validation
        retry_result = api.validate_entries(entries)

        if retry_result.is_success:
            retry_report = retry_result.unwrap()
            # retry_report is ValidationResult model, access attributes directly
            _ = retry_report.is_valid
        else:
            # All entries valid
            _ = entries
