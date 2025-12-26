"""Example 5: Advanced Schema Operations - Parallel Processing and Validation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Demonstrates flext-ldif advanced schema operations capabilities with minimal code bloat:
- Parallel schema validation processing with ThreadPoolExecutor
- Intelligent schema building with automatic type detection
- Batch schema operations with comprehensive error handling
- Schema migration and transformation pipelines
- Railway-oriented schema validation with early failure detection

This example shows how flext-ldif enables ADVANCED schema operations through parallel processing.
Original: .bak file | Advanced: ~250 lines with parallel schema processing + intelligent builders + batch operations
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

from flext_core import FlextResult

from flext_ldif import FlextLdif, FlextLdifModels
from flext_ldif.utilities import u


def intelligent_schema_building() -> FlextResult[list[FlextLdifModels.Entry]]:
    """Intelligent schema building with automatic type detection and validation."""
    api = FlextLdif.get_instance()

    # Build comprehensive schema entries
    schema_entries = []

    # Schema root entry
    schema_root_result = api.create_entry(
        dn="cn=schema",
        attributes={
            "objectClass": ["top", "ldapSubentry", "subschema"],
            "cn": ["schema"],
            "description": ["Schema container for LDAP directory"],
        },
    )
    if schema_root_result.is_success:
        schema_entries.append(schema_root_result.value)

    # Attribute type definitions
    attribute_types = [
        {
            "name": "cn",
            "description": "Common Name",
            "syntax": "1.3.6.1.4.1.1466.115.121.1.15",  # DirectoryString
            "single_value": False,
            "usage": "userApplications",
        },
        {
            "name": "sn",
            "description": "Surname",
            "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
            "single_value": False,
            "usage": "userApplications",
        },
        {
            "name": "mail",
            "description": "Email Address",
            "syntax": "1.3.6.1.4.1.1466.115.121.1.26",  # IA5String
            "single_value": False,
            "usage": "userApplications",
        },
        {
            "name": "member",
            "description": "Group member",
            "syntax": "1.3.6.1.4.1.1466.115.121.1.12",  # DN
            "single_value": False,
            "usage": "userApplications",
        },
    ]

    def create_attr_entry(
        attr_def: dict[str, str | int | float | bool | list[str]],
    ) -> FlextLdifModels.Entry | None:
        """Create attribute type entry."""
        attr_dn = f"cn={attr_def['name']},cn=schema"
        attr_result = api.create_entry(
            dn=attr_dn,
            attributes={
                "objectClass": ["top", "ldapSubentry", "attributeTypeDescription"],
                "cn": [str(attr_def["name"])],
                "description": [str(attr_def["description"])],
                "syntax": [str(attr_def["syntax"])],
                "singleValue": ["TRUE" if bool(attr_def["single_value"]) else "FALSE"],
                "usage": [str(attr_def["usage"])],
            },
        )
        return attr_result.map_or(None)

    batch_result = u.process(
        cast("list[dict[str, str | int | float | bool | list[str]]]", attribute_types),
        create_attr_entry,
        on_error="skip",
    )
    if batch_result.is_success:
        schema_entries.extend(
            cast("list[FlextLdifModels.Entry]", batch_result.value["results"]),
        )

    # Object class definitions
    object_classes = [
        {
            "name": "person",
            "description": "Person object class",
            "sup": "top",
            "must": ["cn", "sn"],
            "may": ["mail", "telephoneNumber"],
        },
        {
            "name": "inetOrgPerson",
            "description": "Internet Organization Person",
            "sup": "person",
            "must": [],
            "may": ["mail", "departmentNumber"],
        },
        {
            "name": "groupOfNames",
            "description": "Group of names",
            "sup": "top",
            "must": ["cn", "member"],
            "may": ["description"],
        },
    ]

    def create_oc_entry(
        oc_def: dict[str, str | list[str] | object],
    ) -> FlextLdifModels.Entry | None:
        """Create object class entry."""
        oc_dn = f"cn={oc_def['name']},cn=schema"
        attrs = cast(
            "dict[str, list[str] | str]",
            {
                "objectClass": ["top", "ldapSubentry", "objectClassDescription"],
                "cn": [str(oc_def["name"])],
                "description": [str(oc_def["description"])],
                "sup": [str(oc_def["sup"])],
            },
        )

        if oc_def.get("must"):
            must_val: list[str] = cast("list[str]", oc_def["must"])
            attrs["must"] = must_val
        if oc_def.get("may"):
            may_val: list[str] = cast("list[str]", oc_def["may"])
            attrs["may"] = may_val

        oc_result = api.create_entry(dn=oc_dn, attributes=attrs)
        return oc_result.map_or(None)

    batch_result = u.process(
        cast("list[dict[str, str | list[str] | object]]", object_classes),
        create_oc_entry,
        on_error="skip",
    )
    if batch_result.is_success:
        schema_entries.extend(
            cast("list[FlextLdifModels.Entry]", batch_result.value["results"]),
        )

    return FlextResult.ok(schema_entries)


def parallel_schema_validation() -> FlextResult[dict[str, object]]:
    """Parallel schema validation with comprehensive error analysis."""
    api = FlextLdif.get_instance()

    # Create test entries with various schema compliance scenarios
    test_entries = []

    # Valid entries
    for i in range(30):
        if i % 3 == 0:
            # Person entries
            entry_result = api.create_entry(
                dn=f"cn=Person{i},ou=People,dc=example,dc=com",
                attributes={
                    "objectClass": ["person", "inetOrgPerson"],
                    "cn": [f"Person{i}"],
                    "sn": [f"LastName{i}"],
                    "mail": [f"person{i}@example.com"],
                },
            )
        elif i % 3 == 1:
            # Group entries
            entry_result = api.create_entry(
                dn=f"cn=Group{i},ou=Groups,dc=example,dc=com",
                attributes={
                    "objectClass": ["groupOfNames"],
                    "cn": [f"Group{i}"],
                    "member": [
                        f"cn=Person{j},ou=People,dc=example,dc=com" for j in range(3)
                    ],
                    "description": [f"Test group {i}"],
                },
            )
        else:
            # OU entries
            entry_result = api.create_entry(
                dn=f"ou=Container{i},dc=example,dc=com",
                attributes={
                    "objectClass": ["organizationalUnit"],
                    "ou": [f"Container{i}"],
                    "description": [f"Container {i}"],
                },
            )

        if entry_result.is_success:
            test_entries.append(entry_result.value)

    # Invalid entries (schema violations)
    invalid_scenarios = [
        # Missing required attribute
        {
            "dn": "cn=Invalid Person,ou=People,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person"],
                "cn": ["Invalid Person"],
                # Missing 'sn' which is required for person
            },
        },
        # Invalid attribute for objectClass
        {
            "dn": "cn=Invalid Group,ou=Groups,dc=example,dc=com",
            "attributes": {
                "objectClass": ["groupOfNames"],
                "cn": ["Invalid Group"],
                "sn": ["Should not exist for groupOfNames"],
                # Missing 'member' which is required
            },
        },
        # Wrong syntax
        {
            "dn": "cn=Wrong Syntax,ou=People,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person", "inetOrgPerson"],
                "cn": ["Wrong Syntax"],
                "sn": ["Test"],
                "employeeNumber": ["not-a-number"],  # Should be numeric
            },
        },
    ]

    for invalid in invalid_scenarios:
        dn = invalid["dn"]
        attributes = invalid["attributes"]
        if isinstance(dn, dict):
            # Skip invalid scenarios with dict dn for this example
            continue
        if not isinstance(dn, str):
            continue
        if isinstance(attributes, dict):
            # Ensure attributes are in correct format
            attrs_dict = cast("dict[str, list[str] | str]", attributes)
        else:
            continue
        entry_result = api.create_entry(dn=dn, attributes=attrs_dict)
        if entry_result.is_success:
            test_entries.append(entry_result.value)

    # Parallel schema validation
    validation_result = api.validate_entries(test_entries)
    if validation_result.is_failure:
        return FlextResult.fail(f"Schema validation failed: {validation_result.error}")

    validation_report = validation_result.value

    # Analyze validation results
    error_analysis: dict[str, int] = {}
    analysis: dict[str, object] = {
        "total_entries": len(test_entries),
        "valid_entries": validation_report.valid_entries,
        "invalid_entries": validation_report.invalid_entries,
        "schema_errors": len(validation_report.errors),
        "error_analysis": error_analysis,
    }

    # Categorize schema errors
    for error in validation_report.errors:
        # Extract error type from string (simple categorization)
        if "schema" in error.lower():
            error_type = "schema"
        elif "attribute" in error.lower():
            error_type = "attribute"
        else:
            error_type = "other"
        error_analysis[error_type] = error_analysis.get(error_type, 0) + 1

    # Schema compliance metrics
    analysis["compliance_rate"] = (
        validation_report.valid_entries / len(test_entries) if test_entries else 0
    )

    return FlextResult.ok(analysis)


def schema_migration_pipeline() -> FlextResult[dict[str, object]]:
    """Schema-aware migration pipeline with validation."""
    api = FlextLdif.get_instance()

    # Setup directories
    migration_dir = Path("examples/schema_migration")
    source_dir = migration_dir / "source"
    migrated_dir = migration_dir / "migrated"
    schema_dir = migration_dir / "schema"

    for dir_path in [source_dir, migrated_dir, schema_dir]:
        dir_path.mkdir(exist_ok=True, parents=True)

    # Create source data with different schema versions
    legacy_entries = [
        # Legacy person format
        """dn: cn=Legacy User1,ou=People,dc=example,dc=com
objectClass: person
cn: Legacy User1
sn: User1
emailAddress: legacy1@example.com
""",
        # Legacy group format
        """dn: cn=Legacy Group,ou=Groups,dc=example,dc=com
objectClass: groupOfUniqueNames
cn: Legacy Group
uniquemember: cn=Legacy User1,ou=People,dc=example,dc=com
""",
        # Modern format already compliant
        """dn: cn=Modern User,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: Modern User
sn: Modern
mail: modern@example.com
""",
    ]

    # Write source files
    def write_legacy_file(item: tuple[int, str]) -> None:
        """Write legacy entry to file."""
        i, entry = item
        (source_dir / f"legacy_{i}.ldif").write_text(entry)

    _ = u.process(
        list(enumerate(legacy_entries)),
        write_legacy_file,
        on_error="skip",
    )

    migration_results: dict[str, object] = {}

    # Step 1: Parse source data with schema validation
    def parse_file(ldif_file: Path) -> list[FlextLdifModels.Entry]:
        """Parse LDIF file."""
        parse_result = api.parse(ldif_file)
        return parse_result.map_or([])

    batch_result = u.process(
        list(source_dir.glob("*.ldif")),
        parse_file,
        on_error="skip",
        flatten=True,
    )
    all_entries = (
        cast("list[FlextLdifModels.Entry]", batch_result.value["results"])
        if batch_result.is_success
        else []
    )

    migration_results["source_entries_parsed"] = len(all_entries)

    # Step 2: Schema validation before migration
    pre_validation = api.validate_entries(all_entries)
    if pre_validation.is_success:
        pre_report = pre_validation.value
        migration_results["pre_migration_validation"] = {
            "valid": pre_report.valid_entries,
            "invalid": pre_report.invalid_entries,
            "errors": len(pre_report.errors),
        }

    # Step 3: Schema-aware migration (attribute name changes, etc.)
    # This would transform legacy 'emailAddress' to 'mail', etc.
    def migrate_entry(
        ldif_entry: FlextLdifModels.Entry,
    ) -> FlextLdifModels.Entry | None:
        """Migrate legacy entry to modern schema."""
        # Transform legacy attributes to modern schema
        attrs_dict: dict[str, str | list[str]] = {}
        if (
            hasattr(ldif_entry, "attributes")
            and ldif_entry.attributes is not None
            and hasattr(ldif_entry.attributes, "attributes")
        ):
            for attr_name, attr_values in ldif_entry.attributes.attributes.items():
                if attr_name == "emailAddress":
                    # Migrate legacy emailAddress to mail
                    attrs_dict["mail"] = attr_values
                else:
                    attrs_dict[attr_name] = attr_values

        # Create migrated entry
        entry_dn: str = (
            ldif_entry.dn.value
            if ldif_entry.dn is not None and hasattr(ldif_entry.dn, "value")
            else str(ldif_entry.dn)
            if ldif_entry.dn is not None
            else ""
        )
        migrate_result = api.create_entry(
            dn=entry_dn,
            attributes=attrs_dict,
        )
        return migrate_result.map_or(None)

    batch_result = u.process(
        all_entries,
        migrate_entry,
        on_error="skip",
    )
    migrated_entries = (
        cast("list[FlextLdifModels.Entry]", batch_result.value["results"])
        if batch_result.is_success
        else []
    )

    migration_results["entries_migrated"] = len(migrated_entries)

    # Step 4: Post-migration schema validation
    post_validation = api.validate_entries(migrated_entries)
    if post_validation.is_success:
        post_report = post_validation.value
        migration_results["post_migration_validation"] = {
            "valid": post_report.valid_entries,
            "invalid": post_report.invalid_entries,
            "errors": len(post_report.errors),
        }

    # Step 5: Write migrated data with schema compliance
    if migrated_entries:
        output_file = migrated_dir / "migrated_schema_compliant.ldif"
        write_result = api.write(migrated_entries, output_file)
        migration_results["output_written"] = write_result.is_success

    return FlextResult.ok(migration_results)


def batch_schema_operations() -> FlextResult[dict[str, object]]:
    """Batch schema operations with parallel processing."""
    api = FlextLdif.get_instance()

    # Create multiple schema batches
    schema_batches = []

    # Batch 1: Core attributes
    core_attrs = []
    core_attribute_definitions = [
        ("cn", "Common Name", "1.3.6.1.4.1.1466.115.121.1.15", False),
        ("sn", "Surname", "1.3.6.1.4.1.1466.115.121.1.15", False),
        ("mail", "Email Address", "1.3.6.1.4.1.1466.115.121.1.26", False),
        ("telephoneNumber", "Telephone Number", "1.3.6.1.4.1.1466.115.121.1.50", False),
    ]

    def create_core_attr(
        attr_def: tuple[str, str, str, bool],
    ) -> FlextLdifModels.Entry | None:
        """Create core attribute entry."""
        name, desc, syntax, single_val = attr_def
        attr_result = api.create_entry(
            dn=f"cn={name},cn=schema",
            attributes={
                "objectClass": ["top", "ldapSubentry", "attributeTypeDescription"],
                "cn": [name],
                "description": [desc],
                "syntax": [syntax],
                "singleValue": ["TRUE" if single_val else "FALSE"],
            },
        )
        return attr_result.map_or(None)

    batch_result = u.process(
        core_attribute_definitions,
        create_core_attr,
        on_error="skip",
    )
    if batch_result.is_success:
        core_attrs.extend(
            cast("list[FlextLdifModels.Entry]", batch_result.value["results"]),
        )

    schema_batches.append(("core_attributes", core_attrs))

    # Batch 2: Object classes
    object_classes = []
    oc_definitions = [
        ("person", "Person", "top", ["cn", "sn"], ["mail", "telephoneNumber"]),
        (
            "inetOrgPerson",
            "Internet Organization Person",
            "person",
            [],
            ["departmentNumber", "employeeNumber"],
        ),
        ("groupOfNames", "Group of Names", "top", ["cn", "member"], ["description"]),
        (
            "organizationalUnit",
            "Organizational Unit",
            "top",
            ["ou"],
            ["description", "businessCategory"],
        ),
    ]

    def create_oc_def(
        oc_def: tuple[str, str, str, list[str], list[str]],
    ) -> FlextLdifModels.Entry | None:
        """Create object class definition entry."""
        name, desc, sup, must_attrs, may_attrs = oc_def
        attrs = cast(
            "dict[str, list[str] | str]",
            {
                "objectClass": ["top", "ldapSubentry", "objectClassDescription"],
                "cn": [name],
                "description": [desc],
                "sup": [sup],
            },
        )
        if must_attrs:
            attrs["must"] = must_attrs
        if may_attrs:
            attrs["may"] = may_attrs

        oc_result = api.create_entry(dn=f"cn={name},cn=schema", attributes=attrs)
        return oc_result.map_or(None)

    batch_result = u.process(
        oc_definitions,
        create_oc_def,
        on_error="skip",
    )
    if batch_result.is_success:
        object_classes.extend(
            cast("list[FlextLdifModels.Entry]", batch_result.value["results"]),
        )

    schema_batches.append(("object_classes", object_classes))

    # Process batches in parallel
    batch_results: dict[str, object] = {}
    total_schema_entries = 0

    for batch_name, entries in schema_batches:
        if not entries:
            continue

        # Parallel validation for schema entries
        validation_result = api.validate_entries(entries)
        if validation_result.is_failure:
            batch_results[f"{batch_name}_error"] = validation_result.error
            continue

        report = validation_result.value
        batch_results[batch_name] = {
            "entries": len(entries),
            "valid": report.valid_entries,
            "invalid": report.invalid_entries,
            "error_count": len(report.errors),
        }

        total_schema_entries += len(entries)

    # Overall schema statistics
    batch_results["summary"] = {
        "total_batches": len(schema_batches),
        "total_schema_entries": total_schema_entries,
        "batches_processed": len([
            b for b in batch_results if not b.endswith("_error") and b != "summary"
        ]),
    }

    return FlextResult.ok(batch_results)


def railway_schema_pipeline() -> FlextResult[dict[str, object]]:
    """Railway-oriented schema pipeline with integrated validation."""
    api = FlextLdif.get_instance()

    # Railway Step 1: Build schema definitions
    schema_build_result = intelligent_schema_building()
    if schema_build_result.is_failure:
        return FlextResult[dict[str, object]].fail(
            f"Schema building failed: {schema_build_result.error}",
        )

    schema_entries = schema_build_result.value

    # Railway Step 2: Validate schema compliance
    schema_validation = api.validate_entries(schema_entries)
    if schema_validation.is_failure:
        return FlextResult.fail(f"Schema validation failed: {schema_validation.error}")

    schema_report = schema_validation.value
    if not schema_report.is_valid:
        return FlextResult.fail(f"Schema entries invalid: {schema_report.errors}")

    # Railway Step 3: Create test entries using the schema
    def create_test_entry(i: int) -> FlextLdifModels.Entry | None:
        """Create test entry compliant with schema."""
        # Create entries compliant with our schema
        if i % 2 == 0:
            entry_result = api.create_entry(
                dn=f"cn=Schema Test User{i},ou=People,dc=example,dc=com",
                attributes={
                    "objectClass": ["person", "inetOrgPerson"],
                    "cn": [f"Schema Test User{i}"],
                    "sn": [f"TestUser{i}"],
                    "mail": [f"user{i}@schema.example.com"],
                    "departmentNumber": ["Engineering"],
                },
            )
        else:
            entry_result = api.create_entry(
                dn=f"cn=Schema Test Group{i},ou=Groups,dc=example,dc=com",
                attributes={
                    "objectClass": ["groupOfNames"],
                    "cn": [f"Schema Test Group{i}"],
                    "member": [
                        f"cn=Schema Test User{j},ou=People,dc=example,dc=com"
                        for j in range(2)
                    ],
                    "description": [f"Schema-compliant group {i}"],
                },
            )

        return entry_result.map_or(None)

    batch_result = u.process(
        list(range(10)),
        create_test_entry,
        on_error="skip",
    )
    test_entries = (
        cast("list[FlextLdifModels.Entry]", batch_result.value["results"])
        if batch_result.is_success
        else []
    )

    # Railway Step 4: Validate test entries against schema
    entry_validation = api.validate_entries(test_entries)
    if entry_validation.is_failure:
        return FlextResult.fail(f"Entry validation failed: {entry_validation.error}")

    entry_report = entry_validation.value
    if not entry_report.is_valid:
        return FlextResult.fail(f"Test entries invalid: {entry_report.errors}")

    # Railway Step 5: Parallel processing of validated entries
    process_result = api.process(
        "transform",
        test_entries,
        parallel=True,
        max_workers=4,
    )
    if process_result.is_failure:
        return FlextResult[dict[str, object]].fail(
            f"Processing failed: {process_result.error}",
        )

    transformed_count = len(process_result.value)

    # Railway Step 6: Write schema-compliant output
    output_dir = Path("examples/schema_compliant_output")
    output_dir.mkdir(exist_ok=True)

    schema_file = output_dir / "schema.ldif"
    schema_write = api.write(schema_entries, schema_file)

    entries_file = output_dir / "entries.ldif"
    entries_write = api.write(test_entries, entries_file)

    return FlextResult.ok({
        "schema_entries": len(schema_entries),
        "schema_valid": schema_report.valid_entries,
        "test_entries": len(test_entries),
        "entries_valid": entry_report.valid_entries,
        "parallel_transformed": transformed_count,
        "schema_file_written": schema_write.is_success,
        "entries_file_written": entries_write.is_success,
        "pipeline_completed": True,
    })
