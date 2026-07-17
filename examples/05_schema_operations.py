"""Example 5: Advanced Schema Operations - Parallel Processing and Validation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import (
    MutableSequence,
)
from pathlib import Path

from flext_ldif import ldif, m, p, r, t


def _create_entry_or_none(
    dn: str,
    attributes: t.MutableAttributeMapping,
) -> m.Ldif.Entry | None:
    """Create an entry, returning None on failure."""
    result = m.Ldif.Entry.create(dn=dn, attributes=attributes)
    return result.unwrap() if result.success else None


def intelligent_schema_building() -> p.Result[MutableSequence[m.Ldif.Entry]]:
    """Intelligent schema building with automatic type detection and validation."""
    schema_entries: list[m.Ldif.Entry] = []
    schema_root = _create_entry_or_none(
        dn="cn=schema",
        attributes={
            "objectClass": ["top", "ldapSubentry", "subschema"],
            "cn": ["schema"],
            "description": ["Schema container for LDAP directory"],
        },
    )
    if schema_root is not None:
        schema_entries.append(schema_root)
    attribute_types: t.SequenceOf[tuple[str, str, str, bool]] = [
        ("cn", "Common Name", "1.3.6.1.4.1.1466.115.121.1.15", False),
        ("sn", "Surname", "1.3.6.1.4.1.1466.115.121.1.15", False),
        ("mail", "Email Address", "1.3.6.1.4.1.1466.115.121.1.26", False),
        ("member", "Group member", "1.3.6.1.4.1.1466.115.121.1.12", False),
    ]
    for name, desc, syntax, single_val in attribute_types:
        entry = _create_entry_or_none(
            dn=f"cn={name},cn=schema",
            attributes={
                "objectClass": ["top", "ldapSubentry", "attributeTypeDescription"],
                "cn": [name],
                "description": [desc],
                "syntax": [syntax],
                "singleValue": ["TRUE" if single_val else "FALSE"],
                "usage": ["userApplications"],
            },
        )
        if entry is not None:
            schema_entries.append(entry)
    object_classes: t.SequenceOf[tuple[str, str, str, list[str], list[str]]] = [
        (
            "person",
            "Person object class",
            "top",
            ["cn", "sn"],
            ["mail", "telephoneNumber"],
        ),
        (
            "inetOrgPerson",
            "Internet Organization Person",
            "person",
            ["cn"],
            ["departmentNumber"],
        ),
        ("groupOfNames", "Group of names", "top", ["cn", "member"], ["description"]),
    ]
    for name, desc, sup, must_attrs, may_attrs in object_classes:
        attrs: t.MutableAttributeMapping = {
            "objectClass": ["top", "ldapSubentry", "objectClassDescription"],
            "cn": [name],
            "description": [desc],
            "sup": [sup],
        }
        if must_attrs:
            attrs["must"] = must_attrs
        if may_attrs:
            attrs["may"] = may_attrs
        entry = _create_entry_or_none(dn=f"cn={name},cn=schema", attributes=attrs)
        if entry is not None:
            schema_entries.append(entry)
    return r[MutableSequence[m.Ldif.Entry]].ok(schema_entries)


def parallel_schema_validation() -> p.Result[t.JsonMapping]:
    """Validate schema with comprehensive error analysis."""
    api = ldif()
    test_entries: list[m.Ldif.Entry] = []
    for i in range(30):
        if i % 3 == 0:
            attrs: t.MutableAttributeMapping = {
                "objectClass": ["person", "inetOrgPerson"],
                "cn": [f"Person{i}"],
                "sn": [f"LastName{i}"],
                "mail": [f"person{i}@example.com"],
            }
            dn = f"cn=Person{i},ou=People,dc=example,dc=com"
        elif i % 3 == 1:
            attrs = {
                "objectClass": ["groupOfNames"],
                "cn": [f"Group{i}"],
                "member": [
                    f"cn=Person{j},ou=People,dc=example,dc=com" for j in range(3)
                ],
                "description": [f"Test group {i}"],
            }
            dn = f"cn=Group{i},ou=Groups,dc=example,dc=com"
        else:
            attrs = {
                "objectClass": ["organizationalUnit"],
                "ou": [f"Container{i}"],
                "description": [f"Container {i}"],
            }
            dn = f"ou=Container{i},dc=example,dc=com"
        entry_result = m.Ldif.Entry.create(dn=dn, attributes=attrs)
        if entry_result.success:
            test_entries.append(entry_result.unwrap())
    invalid_scenarios: t.SequenceOf[tuple[str, t.MutableAttributeMapping]] = [
        (
            "cn=Invalid Person,ou=People,dc=example,dc=com",
            {"objectClass": ["person"], "cn": ["Invalid Person"]},
        ),
        (
            "cn=Invalid Group,ou=Groups,dc=example,dc=com",
            {
                "objectClass": ["groupOfNames"],
                "cn": ["Invalid Group"],
                "sn": ["Should not exist"],
            },
        ),
        (
            "cn=Wrong Syntax,ou=People,dc=example,dc=com",
            {
                "objectClass": ["person", "inetOrgPerson"],
                "cn": ["Wrong Syntax"],
                "sn": ["Test"],
                "employeeNumber": ["not-a-number"],
            },
        ),
    ]
    for inv_dn, inv_attrs in invalid_scenarios:
        entry_result = m.Ldif.Entry.create(dn=inv_dn, attributes=inv_attrs)
        if entry_result.success:
            test_entries.append(entry_result.unwrap())
    validation_result = api.validate_entries(test_entries)
    if validation_result.failure:
        return r[t.JsonMapping].fail(
            f"Schema validation failed: {validation_result.error}",
        )
    validation_report = validation_result.unwrap()
    error_analysis: dict[str, int] = {}
    analysis: dict[str, t.Numeric | dict[str, int]] = {
        "total_entries": len(test_entries),
        "valid_entries": validation_report.valid_entries,
        "invalid_entries": validation_report.invalid_entries,
        "schema_errors": len(validation_report.errors),
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
    analysis["error_analysis"] = error_analysis
    return r[t.JsonMapping].ok(t.json_mapping_adapter().validate_python(analysis))


def schema_migration_pipeline() -> p.Result[t.JsonMapping]:
    """Schema-aware migration pipeline with validation."""
    api = ldif()
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
    for i, entry_text in enumerate(legacy_entries):
        (source_dir / f"legacy_{i}.ldif").write_text(entry_text)
    migration_results: dict[str, int | bool | dict[str, int]] = {}
    all_entries: list[m.Ldif.Entry] = []
    for ldif_file in source_dir.glob("*.ldif"):
        parse_result = api.parse_ldif(ldif_file)
        if parse_result.success:
            parse_response = parse_result.unwrap()
            all_entries.extend(parse_response.entries)
    migration_results["source_entries_parsed"] = len(all_entries)
    pre_validation = api.validate_entries(all_entries)
    if pre_validation.success:
        pre_report = pre_validation.unwrap()
        migration_results["pre_migration_validation"] = {
            "valid": pre_report.valid_entries,
            "invalid": pre_report.invalid_entries,
            "errors": len(pre_report.errors),
        }
    migrated_entries: list[m.Ldif.Entry] = []
    for ldif_entry in all_entries:
        attrs_dict: t.MutableAttributeMapping = {}
        if ldif_entry.attributes is not None:
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
        migrate_result = m.Ldif.Entry.create(dn=entry_dn, attributes=attrs_dict)
        if migrate_result.success:
            migrated_entries.append(migrate_result.unwrap())
    migration_results["entries_migrated"] = len(migrated_entries)
    post_validation = api.validate_entries(migrated_entries)
    if post_validation.success:
        post_report = post_validation.unwrap()
        migration_results["post_migration_validation"] = {
            "valid": post_report.valid_entries,
            "invalid": post_report.invalid_entries,
            "errors": len(post_report.errors),
        }
    if migrated_entries:
        output_file = migrated_dir / "migrated_schema_compliant.ldif"
        write_result = api.write_ldif_file(migrated_entries, output_file)
        migration_results["output_written"] = write_result.success
    return r[t.JsonMapping].ok(
        t.json_mapping_adapter().validate_python(migration_results),
    )


def batch_schema_operations() -> p.Result[t.JsonMapping]:
    """Batch schema operations with validation."""
    api = ldif()
    schema_batches: list[tuple[str, list[m.Ldif.Entry]]] = []
    core_attrs: list[m.Ldif.Entry] = []
    core_attribute_definitions: t.SequenceOf[tuple[str, str, str, bool]] = [
        ("cn", "Common Name", "1.3.6.1.4.1.1466.115.121.1.15", False),
        ("sn", "Surname", "1.3.6.1.4.1.1466.115.121.1.15", False),
        ("mail", "Email Address", "1.3.6.1.4.1.1466.115.121.1.26", False),
        ("telephoneNumber", "Telephone Number", "1.3.6.1.4.1.1466.115.121.1.50", False),
    ]
    for name, desc, syntax, single_val in core_attribute_definitions:
        attr_result = m.Ldif.Entry.create(
            dn=f"cn={name},cn=schema",
            attributes={
                "objectClass": ["top", "ldapSubentry", "attributeTypeDescription"],
                "cn": [name],
                "description": [desc],
                "syntax": [syntax],
                "singleValue": ["TRUE" if single_val else "FALSE"],
            },
        )
        if attr_result.success:
            core_attrs.append(attr_result.unwrap())
    schema_batches.append(("core_attributes", core_attrs))
    object_classes: list[m.Ldif.Entry] = []
    oc_definitions: t.SequenceOf[tuple[str, str, str, list[str], list[str]]] = [
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
    for name, desc, sup, must_attrs, may_attrs in oc_definitions:
        attrs: t.MutableAttributeMapping = {
            "objectClass": ["top", "ldapSubentry", "objectClassDescription"],
            "cn": [name],
            "description": [desc],
            "sup": [sup],
        }
        if must_attrs:
            attrs["must"] = must_attrs
        if may_attrs:
            attrs["may"] = may_attrs
        oc_result = m.Ldif.Entry.create(dn=f"cn={name},cn=schema", attributes=attrs)
        if oc_result.success:
            object_classes.append(oc_result.unwrap())
    schema_batches.append(("object_classes", object_classes))
    batch_results: dict[str, dict[str, int] | str | None] = {}
    total_schema_entries = 0
    for batch_name, entries in schema_batches:
        if not entries:
            continue
        validation_result = api.validate_entries(entries)
        if validation_result.failure:
            batch_results[f"{batch_name}_error"] = validation_result.error
            continue
        report = validation_result.unwrap()
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
    return r[t.JsonMapping].ok(t.json_mapping_adapter().validate_python(batch_results))


def railway_schema_pipeline() -> p.Result[t.JsonMapping]:
    """Railway-oriented schema pipeline with integrated validation."""
    api = ldif()
    test_entries = [
        entry
        for i in range(10)
        if (
            entry := _create_entry_or_none(
                dn=(
                    f"cn=Schema Test User{i},ou=People,dc=example,dc=com"
                    if i % 2 == 0
                    else f"cn=Schema Test Group{i},ou=Groups,dc=example,dc=com"
                ),
                attributes=(
                    {
                        "objectClass": ["person", "inetOrgPerson"],
                        "cn": [f"Schema Test User{i}"],
                        "sn": [f"TestUser{i}"],
                        "mail": [f"user{i}@schema.example.com"],
                        "departmentNumber": ["Engineering"],
                    }
                    if i % 2 == 0
                    else {
                        "objectClass": ["groupOfNames"],
                        "cn": [f"Schema Test Group{i}"],
                        "member": [
                            f"cn=Schema Test User{j},ou=People,dc=example,dc=com"
                            for j in range(2)
                        ],
                        "description": [f"Schema-compliant group {i}"],
                    }
                ),
            )
        )
        is not None
    ]
    validated_pipeline = (
        intelligent_schema_building()
        .map_error(
            lambda error: f"Schema building failed: {error}",
        )
        .flat_map(
            lambda schema_entries: (
                api
                .validate_entries(schema_entries)
                .map_error(lambda error: f"Schema validation failed: {error}")
                .flat_map(
                    lambda schema_report: (
                        r[tuple[list[m.Ldif.Entry], int]].fail(
                            f"Schema entries invalid: {schema_report.errors}",
                        )
                        if not schema_report.valid
                        else r[tuple[list[m.Ldif.Entry], int]].ok(
                            (list(schema_entries), schema_report.valid_entries),
                        )
                    ),
                )
            ),
        )
        .flat_map(
            lambda schema_data: (
                api
                .validate_entries(test_entries)
                .map_error(lambda error: f"Entry validation failed: {error}")
                .flat_map(
                    lambda entry_report: (
                        r[tuple[list[m.Ldif.Entry], int, int]].fail(
                            f"Test entries invalid: {entry_report.errors}",
                        )
                        if not entry_report.valid
                        else r[tuple[list[m.Ldif.Entry], int, int]].ok(
                            (
                                schema_data[0],
                                schema_data[1],
                                entry_report.valid_entries,
                            ),
                        )
                    ),
                )
            ),
        )
    )
    if validated_pipeline.failure:
        return r[t.JsonMapping].fail(
            validated_pipeline.error or "Schema pipeline failed",
        )

    schema_entries, schema_valid_entries, entry_valid_entries = (
        validated_pipeline.unwrap()
    )

    output_dir = Path("examples/schema_compliant_output")
    output_dir.mkdir(exist_ok=True)
    schema_file = output_dir / "schema.ldif"
    schema_write = api.write_ldif_file(list(schema_entries), schema_file)
    entries_file = output_dir / "entries.ldif"
    entries_write = api.write_ldif_file(test_entries, entries_file)
    return r[t.JsonMapping].ok(
        t.json_mapping_adapter().validate_python({
            "schema_entries": len(schema_entries),
            "schema_valid": schema_valid_entries,
            "test_entries": len(test_entries),
            "entries_valid": entry_valid_entries,
            "schema_file_written": schema_write.success,
            "entries_file_written": entries_write.success,
            "pipeline_completed": True,
        }),
    )
