"""Example 8: Complete LDIF Processing Workflow.

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

from flext_ldif import FlextLdif


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
    result = (
        api.parse(ldif_content)
        .flat_map(lambda entries: api.validate_entries(entries).map(lambda _: entries))
        .flat_map(
            lambda entries: api.analyze(entries).map(lambda stats: (entries, stats)),
        )
        .flat_map(lambda data: api.write(data[0]).map(lambda ldif: (ldif, data[1])))
    )

    # Handle final result
    if result.is_success:
        ldif_output, stats = result.unwrap()
        print(f"✓ Processed {stats.get('total_entries', 0)} entries")
        print(f"✓ LDIF output: {len(ldif_output)} characters")
    else:
        print(f"✗ Processing failed: {result.error}")


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
    print(f"Encoding (from .env): {api.config.ldif_encoding}")
    print(f"Max Workers (from .env): {api.config.max_workers}")
    print(f"Strict Validation (from .env): {api.config.ldif_strict_validation}")
    print(f"Debug Mode (from .env): {api.config.debug}")

    # Configuration affects behavior automatically
    entries_count = 1000
    effective_workers = api.config.get_effective_workers(entries_count)
    print(f"Effective workers for {entries_count} entries: {effective_workers}")


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

    validation_report: dict[str, object] = validation_result.unwrap()

    if not validation_report.get("is_valid"):
        _ = validation_report.get("errors", [])
        return

    # Step 3: Analyze entries
    analysis_result = api.analyze(entries)

    if analysis_result.is_failure:
        _ = analysis_result.error
        return

    stats = analysis_result.unwrap()
    stats_dict: dict[str, object] = stats
    _ = stats_dict.get("total_entries", 0)

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

    (source_dir / "source.ldif").write_text(source_ldif)

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

    migration_stats: dict[str, object] = migration_result.unwrap()

    # Step 4: Verify migrated data
    migrated_files = migration_stats.get("output_files", [])
    if not isinstance(migrated_files, list):
        print(f"ERROR: Expected list migrated_files, got {type(migrated_files)}")
        return

    for file_path in migrated_files:
        if not isinstance(file_path, (str, Path)):
            print(f"ERROR: Expected str/Path file_path, got {type(file_path)}")
            continue
        verify_result = api.parse(Path(file_path), server_type="oud")

        if verify_result.is_success:
            migrated_entries = verify_result.unwrap()
            _ = len(migrated_entries)


def entry_building_and_processing_workflow() -> None:
    """Build entries, validate, and process through pipeline using direct methods."""
    api = FlextLdif.get_instance()

    # Step 1: Build entries using direct API methods (no builder instantiation!)
    person_result = api.build_person_entry(
        cn="Workflow User",
        sn="User",
        base_dn="ou=People,dc=example,dc=com",
        mail="workflow@example.com",
    )

    if person_result.is_failure:
        return

    person = person_result.unwrap()

    # Convert DN to string for members list
    member_dns = [str(person.dn)]

    group_result = api.build_group_entry(
        cn="Workflow Group",
        base_dn="ou=Groups,dc=example,dc=com",
        members=member_dns,
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

    # Step 1: Build schema using direct API method
    schema_result = api.build_person_schema()

    if schema_result.is_failure:
        return

    # Step 2: Create entries following schema using direct API methods
    entries = []
    for i in range(5):
        person_result = api.build_person_entry(
            cn=f"User {i}",
            sn=f"Surname {i}",
            base_dn="ou=People,dc=example,dc=com",
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
aci: (target="ldap:///ou=Secure,dc=example,dc=com")(targetattr="*")(version 3.0; acl "Admin access"; allow (all) userdn="ldap:///cn=admin,dc=example,dc=com";)

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
            acls = acl_result.unwrap()

            if acls:
                # Evaluate ACL rules using direct API method
                eval_result = api.evaluate_acl_rules(acls)

                if eval_result.is_success:
                    _ = eval_result.unwrap()


def batch_processing_workflow() -> None:
    """Batch processing using direct methods (massive simplification!)."""
    api = FlextLdif.get_instance()

    # Create large dataset
    entries = []
    for i in range(20):
        result = api.models.Entry.create(
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
    max_line_length = api.constants.Format.MAX_LINE_LENGTH
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
    encoding = api.config.ldif_encoding
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

    validation_report: dict[str, object] = validation_result.unwrap()

    if not validation_report.get("is_valid"):
        # Handle validation errors and attempt recovery by fixing entries
        for entry in entries:
            # Add missing required attribute
            obj_class_values = entry.attributes.get("objectClass", [])
            if not isinstance(obj_class_values, list):
                print(
                    f"ERROR: Expected list obj_class_values, got {type(obj_class_values)}",
                )
                continue
            if "person" in obj_class_values and "sn" not in entry.attributes.attributes:
                entry.attributes.add_attribute("sn", "recovered")

        # Retry validation
        retry_result = api.validate_entries(entries)

        if retry_result.is_success:
            retry_report = retry_result.unwrap()
            retry_report_dict: dict[str, object] = retry_report
            _ = retry_report_dict.get("is_valid", False)
        else:
            # All entries valid
            _ = entries
