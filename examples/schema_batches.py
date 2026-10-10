"""Batched schema operation example with per-batch validation.

Part of Example 5 (Advanced Schema Operations); see
``examples/schema_operations.py`` for the combined facade.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from examples.schema_building import object_class_entries
from flext_ldif import FlextLdif, ldif
from examples import m, p, r, t


def _core_attribute_entries() -> list[m.Ldif.Entry]:
    """Build the core attribute-type schema entries.

    Returns:
        The resulting ``list[m.Ldif.Entry]``.
    """
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
    return core_attrs


def _object_class_entries() -> list[m.Ldif.Entry]:
    """Build the object-class schema entries.

    Returns:
        The resulting ``list[m.Ldif.Entry]``.
    """
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
    return object_class_entries(oc_definitions)


def _validated_batch_results(
    api: FlextLdif,
    schema_batches: list[tuple[str, list[m.Ldif.Entry]]],
) -> tuple[dict[str, dict[str, int] | str | None], int]:
    """Validate each non-empty batch and collect per-batch results.

    Returns:
        The resulting ``tuple[dict[str, dict[str, int] | str | None], int]``.
    """
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
    return batch_results, total_schema_entries


def batch_schema_operations() -> p.Result[t.JsonMapping]:
    """Batch schema operations with validation.

    Returns:
        The resulting ``p.Result[t.JsonMapping]``.
    """
    api = ldif()
    schema_batches: list[tuple[str, list[m.Ldif.Entry]]] = [
        ("core_attributes", _core_attribute_entries()),
        ("object_classes", _object_class_entries()),
    ]
    batch_results, total_schema_entries = _validated_batch_results(api, schema_batches)
    batch_results["summary"] = {
        "total_batches": len(schema_batches),
        "total_schema_entries": total_schema_entries,
        "batches_processed": len([
            b for b in batch_results if not b.endswith("_error") and b != "summary"
        ]),
    }
    return r[t.JsonMapping].ok(t.json_mapping_adapter().validate_python(batch_results))
