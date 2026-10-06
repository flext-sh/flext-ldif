"""Railway-oriented schema pipeline example with integrated validation.

Part of Example 5 (Advanced Schema Operations); see
``examples/schema_operations.py`` for the combined facade.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path

from examples.schema_building import (
    create_entry_or_none,
    intelligent_schema_building,
)
from flext_ldif import ldif, m, p, r, t


def _pipeline_test_entries() -> list[m.Ldif.Entry]:
    """Build the user and group test entries driven through the pipeline.

    Returns:
        The resulting ``list[m.Ldif.Entry]``.
    """
    return [
        entry
        for i in range(10)
        if (
            entry := create_entry_or_none(
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


def railway_schema_pipeline() -> p.Result[t.JsonMapping]:
    """Railway-oriented schema pipeline with integrated validation.

    Returns:
        The resulting ``p.Result[t.JsonMapping]``.
    """
    api = ldif()
    test_entries = _pipeline_test_entries()
    validated_pipeline = (
        intelligent_schema_building()
        .map_error(lambda error: f"Schema building failed: {error}")
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
                        else r[tuple[list[m.Ldif.Entry], int]].ok((
                            list(schema_entries),
                            schema_report.valid_entries,
                        ))
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
                        else r[tuple[list[m.Ldif.Entry], int, int]].ok((
                            schema_data[0],
                            schema_data[1],
                            entry_report.valid_entries,
                        ))
                    ),
                )
            ),
        )
    )
    if validated_pipeline.failure:
        return r[t.JsonMapping].from_failure(validated_pipeline)

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
