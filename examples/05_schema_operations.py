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

from collections.abc import Mapping, MutableMapping, MutableSequence
from pathlib import Path
from typing import TypedDict

from flext_core import r

from flext_ldif import FlextLdif, FlextLdifModels, m, t, u


class _InvalidScenario(TypedDict):
    dn: str
    attributes: Mapping[str, t.StrSequence]


def intelligent_schema_building() -> r[MutableSequence[m.Ldif.Entry]]:
    """Intelligent schema building with automatic type detection and validation."""
    api = FlextLdif.get_instance()
    schema_entries: list[FlextLdifModels.Ldif.Entry] = []
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
    attribute_types: list[Mapping[str, str | bool | t.StrSequence]] = [
        {
            "name": "cn",
            "description": "Common Name",
            "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
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
            "syntax": "1.3.6.1.4.1.1466.115.121.1.26",
            "single_value": False,
            "usage": "userApplications",
        },
        {
            "name": "member",
            "description": "Group member",
            "syntax": "1.3.6.1.4.1.1466.115.121.1.12",
            "single_value": False,
            "usage": "userApplications",
        },
    ]

    def create_attr_entry(
        attr_def: Mapping[str, str | bool | t.StrSequence],
    ) -> m.Ldif.Entry | None:
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

    for attr_def in attribute_types:
        created_entry = create_attr_entry(attr_def)
        if created_entry is not None:
            schema_entries.append(created_entry)
    object_classes = [
        {
            "name": "person",
            "description": "Person t.NormalizedValue class",
            "sup": "top",
            "must": ["cn", "sn"],
            "may": ["mail", "telephoneNumber"],
        },
        {
            "name": "inetOrgPerson",
            "description": "Internet Organization Person",
            "sup": "person",
            "must": ["cn"],
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
        oc_def: Mapping[str, str | t.StrSequence],
    ) -> m.Ldif.Entry | None:
        """Create t.NormalizedValue class entry."""
        oc_dn = f"cn={oc_def['name']},cn=schema"
        attrs: MutableMapping[str, MutableSequence[str] | str] = {
            "objectClass": ["top", "ldapSubentry", "objectClassDescription"],
            "cn": [str(oc_def["name"])],
            "description": [str(oc_def["description"])],
            "sup": [str(oc_def["sup"])],
        }
        must_raw = oc_def.get("must")
        if isinstance(must_raw, list):
            attrs["must"] = must_raw
        may_raw = oc_def.get("may")
        if isinstance(may_raw, list):
            attrs["may"] = may_raw
        oc_result = api.create_entry(dn=oc_dn, attributes=attrs)
        return oc_result.map_or(None)

    for oc_def in object_classes:
        created_entry = create_oc_entry(oc_def)
        if created_entry is not None:
            schema_entries.append(created_entry)
    return r[MutableSequence[m.Ldif.Entry]].ok(schema_entries)


def parallel_schema_validation() -> r[t.ContainerMapping]:
    """Parallel schema validation with comprehensive error analysis."""
    api = FlextLdif.get_instance()
    test_entries: list[m.Ldif.Entry] = []
    for i in range(30):
        if i % 3 == 0:
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
    invalid_scenarios: list[_InvalidScenario] = [
        {
            "dn": "cn=Invalid Person,ou=People,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["Invalid Person"]},
        },
        {
            "dn": "cn=Invalid Group,ou=Groups,dc=example,dc=com",
            "attributes": {
                "objectClass": ["groupOfNames"],
                "cn": ["Invalid Group"],
                "sn": ["Should not exist for groupOfNames"],
            },
        },
        {
            "dn": "cn=Wrong Syntax,ou=People,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person", "inetOrgPerson"],
                "cn": ["Wrong Syntax"],
                "sn": ["Test"],
                "employeeNumber": ["not-a-number"],
            },
        },
    ]
    for invalid in invalid_scenarios:
        dn = invalid["dn"]
        attributes = invalid["attributes"]
        attrs_mutable: MutableMapping[str, MutableSequence[str] | str] = {
            k: list(v) for k, v in attributes.items()
        }
        entry_result = api.create_entry(dn=dn, attributes=attrs_mutable)
        if entry_result.is_success:
            test_entries.append(entry_result.value)
    validation_result = api.validate_entries(test_entries)
    if validation_result.is_failure:
        return r[t.ContainerMapping].fail(
            f"Schema validation failed: {validation_result.error}",
        )
    validation_report = validation_result.value
    error_analysis: dict[str, int] = {}
    analysis: dict[str, int | float | dict[str, int]] = {
        "total_entries": len(test_entries),
        "valid_entries": validation_report.valid_entries,
        "invalid_entries": validation_report.invalid_entries,
        "schema_errors": len(validation_report.errors),
        "error_analysis": error_analysis,
    }
    for error in validation_report.errors:
        if "schema" in error.lower():
            error_type = "schema"
        elif "attribute" in error.lower():
            error_type = "attribute"
        else:
            error_type = "other"
        error_analysis[error_type] = error_analysis.get(error_type, 0) + 1
    analysis["compliance_rate"] = (
        validation_report.valid_entries / len(test_entries) if test_entries else 0
    )
    return r[t.ContainerMapping].ok(analysis)


def schema_migration_pipeline() -> r[t.ContainerMapping]:
    """Schema-aware migration pipeline with validation."""
    api = FlextLdif.get_instance()
    migration_dir = Path("examples/schema_migration")
    source_dir = migration_dir / "source"
    migrated_dir = migration_dir / "migrated"
    schema_dir = migration_dir / "schema"
    for dir_path in [source_dir, migrated_dir, schema_dir]:
        dir_path.mkdir(exist_ok=True, parents=True)
    legacy_entries = [
        "dn: cn=Legacy User1,ou=People,dc=example,dc=com\nobjectClass: person\ncn: Legacy User1\nsn: User1\nemailAddress: legacy1@example.com\n",
        "dn: cn=Legacy Group,ou=Groups,dc=example,dc=com\nobjectClass: groupOfUniqueNames\ncn: Legacy Group\nuniquemember: cn=Legacy User1,ou=People,dc=example,dc=com\n",
        "dn: cn=Modern User,ou=People,dc=example,dc=com\nobjectClass: person\nobjectClass: inetOrgPerson\ncn: Modern User\nsn: Modern\nmail: modern@example.com\n",
    ]

    def write_legacy_file(item: tuple[int, str]) -> None:
        """Write legacy entry to file."""
        i, entry = item
        (source_dir / f"legacy_{i}.ldif").write_text(entry)

    _ = u.process(list(enumerate(legacy_entries)), write_legacy_file, on_error="skip")
    migration_results: dict[str, int | bool | dict[str, int]] = {}

    def parse_file(ldif_file: Path) -> MutableSequence[m.Ldif.Entry]:
        """Parse LDIF file."""
        parse_result = api.parse_ldif(ldif_file)
        return parse_result.map_or([])

    batch_result = u.process(
        list(source_dir.glob("*.ldif")),
        parse_file,
        on_error="skip",
    )
    all_entries: list[m.Ldif.Entry]
    if batch_result.is_success:
        all_entries = [e for sub in batch_result.value for e in sub]
    else:
        all_entries = []
    migration_results["source_entries_parsed"] = len(all_entries)
    pre_validation = api.validate_entries(all_entries)
    if pre_validation.is_success:
        pre_report = pre_validation.value
        migration_results["pre_migration_validation"] = {
            "valid": pre_report.valid_entries,
            "invalid": pre_report.invalid_entries,
            "errors": len(pre_report.errors),
        }

    def migrate_entry(ldif_entry: m.Ldif.Entry) -> MutableSequence[m.Ldif.Entry]:
        """Migrate legacy entry to modern schema."""
        attrs_dict: MutableMapping[str, str | MutableSequence[str]] = {}
        if (
            hasattr(ldif_entry, "attributes")
            and ldif_entry.attributes is not None
            and hasattr(ldif_entry.attributes, "attributes")
        ):
            for attr_name, attr_values in ldif_entry.attributes.attributes.items():
                if attr_name == "emailAddress":
                    attrs_dict["mail"] = attr_values
                else:
                    attrs_dict[attr_name] = attr_values
        entry_dn: str = (
            ldif_entry.dn.value
            if ldif_entry.dn is not None and hasattr(ldif_entry.dn, "value")
            else str(ldif_entry.dn)
            if ldif_entry.dn is not None
            else ""
        )
        migrate_result = api.create_entry(dn=entry_dn, attributes=attrs_dict)
        if migrate_result.is_success:
            return [migrate_result.value]
        return []

    batch_result = u.process(all_entries, migrate_entry, on_error="skip")
    migrated_entries: list[m.Ldif.Entry]
    if batch_result.is_success:
        migrated_entries = [x for batch in batch_result.value for x in batch]
    else:
        migrated_entries = []
    migration_results["entries_migrated"] = len(migrated_entries)
    post_validation = api.validate_entries(migrated_entries)
    if post_validation.is_success:
        post_report = post_validation.value
        migration_results["post_migration_validation"] = {
            "valid": post_report.valid_entries,
            "invalid": post_report.invalid_entries,
            "errors": len(post_report.errors),
        }
    if migrated_entries:
        output_file = migrated_dir / "migrated_schema_compliant.ldif"
        write_result = api.write_ldif_file(migrated_entries, output_file)
        migration_results["output_written"] = write_result.is_success
    return r[t.ContainerMapping].ok(migration_results)


def batch_schema_operations() -> r[t.ContainerMapping]:
    """Batch schema operations with parallel processing."""
    api = FlextLdif.get_instance()
    schema_batches: list[tuple[str, list[FlextLdifModels.Ldif.Entry]]] = []
    core_attrs: list[FlextLdifModels.Ldif.Entry] = []
    core_attribute_definitions = [
        ("cn", "Common Name", "1.3.6.1.4.1.1466.115.121.1.15", False),
        ("sn", "Surname", "1.3.6.1.4.1.1466.115.121.1.15", False),
        ("mail", "Email Address", "1.3.6.1.4.1.1466.115.121.1.26", False),
        ("telephoneNumber", "Telephone Number", "1.3.6.1.4.1.1466.115.121.1.50", False),
    ]

    def create_core_attr(attr_def: tuple[str, str, str, bool]) -> m.Ldif.Entry | None:
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
        core_attrs.extend([x for x in batch_result.value if x is not None])
    schema_batches.append(("core_attributes", core_attrs))
    object_classes: list[FlextLdifModels.Ldif.Entry] = []
    oc_definitions = [
        ("person", "Person", "top", ["cn", "sn"], ["mail", "telephoneNumber"]),
        (
            "inetOrgPerson",
            "Internet Organization Person",
            "person",
            ["cn"],
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
        oc_def: tuple[str, str, str, t.StrSequence, t.StrSequence],
    ) -> m.Ldif.Entry | None:
        """Create t.NormalizedValue class definition entry."""
        name, desc, sup, must_attrs, may_attrs = oc_def
        attrs: MutableMapping[str, MutableSequence[str] | str] = {
            "objectClass": ["top", "ldapSubentry", "objectClassDescription"],
            "cn": [name],
            "description": [desc],
            "sup": [sup],
        }
        if must_attrs:
            attrs["must"] = list(must_attrs)
        if may_attrs:
            attrs["may"] = list(may_attrs)
        oc_result = api.create_entry(dn=f"cn={name},cn=schema", attributes=attrs)
        return oc_result.map_or(None)

    batch_result = u.process(oc_definitions, create_oc_def, on_error="skip")
    if batch_result.is_success:
        object_classes.extend([x for x in batch_result.value if x is not None])
    schema_batches.append(("object_classes", object_classes))
    batch_results: dict[str, dict[str, int] | str | None] = {}
    total_schema_entries = 0
    for batch_name, entries in schema_batches:
        if not entries:
            continue
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
    batch_results["summary"] = {
        "total_batches": len(schema_batches),
        "total_schema_entries": total_schema_entries,
        "batches_processed": len([
            b for b in batch_results if not b.endswith("_error") and b != "summary"
        ]),
    }
    return r[t.ContainerMapping].ok(batch_results)


def railway_schema_pipeline() -> r[t.ContainerMapping]:
    """Railway-oriented schema pipeline with integrated validation."""
    api = FlextLdif.get_instance()
    schema_build_result = intelligent_schema_building()
    if schema_build_result.is_failure:
        return r[t.ContainerMapping].fail(
            f"Schema building failed: {schema_build_result.error}",
        )
    schema_entries = schema_build_result.value
    schema_validation = api.validate_entries(schema_entries)
    if schema_validation.is_failure:
        return r[t.ContainerMapping].fail(
            f"Schema validation failed: {schema_validation.error}",
        )
    schema_report = schema_validation.value
    if not schema_report.is_valid:
        return r[t.ContainerMapping].fail(
            f"Schema entries invalid: {schema_report.errors}",
        )

    def create_test_entry(i: int) -> m.Ldif.Entry | None:
        """Create test entry compliant with schema."""
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

    batch_result = u.process(list(range(10)), create_test_entry, on_error="skip")
    test_entries: list[m.Ldif.Entry] = (
        [x for x in batch_result.value if x is not None]
        if batch_result.is_success
        else []
    )
    entry_validation = api.validate_entries(test_entries)
    if entry_validation.is_failure:
        return r[t.ContainerMapping].fail(
            f"Entry validation failed: {entry_validation.error}",
        )
    entry_report = entry_validation.value
    if not entry_report.is_valid:
        return r[t.ContainerMapping].fail(
            f"Test entries invalid: {entry_report.errors}",
        )
    process_result = api.process_ldif(
        "transform",
        test_entries,
        parallel=True,
        max_workers=4,
    )
    if process_result.is_failure:
        return r[t.ContainerMapping].fail(f"Processing failed: {process_result.error}")
    transformed_count = len(process_result.value)
    output_dir = Path("examples/schema_compliant_output")
    output_dir.mkdir(exist_ok=True)
    schema_file = output_dir / "schema.ldif"
    schema_write = api.write_ldif_file(list(schema_entries), schema_file)
    entries_file = output_dir / "entries.ldif"
    entries_write = api.write_ldif_file(test_entries, entries_file)
    return r[t.ContainerMapping].ok({
        "schema_entries": len(schema_entries),
        "schema_valid": schema_report.valid_entries,
        "test_entries": len(test_entries),
        "entries_valid": entry_report.valid_entries,
        "parallel_transformed": transformed_count,
        "schema_file_written": schema_write.is_success,
        "entries_file_written": entries_write.is_success,
        "pipeline_completed": True,
    })
