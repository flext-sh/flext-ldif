"""Schema validation example with comprehensive error analysis.

Part of Example 5 (Advanced Schema Operations); see
``examples/schema_operations.py`` for the combined facade.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldif import ldif, m, p, r, t


def _append_created_entry(
    entries: list[m.Ldif.Entry],
    dn: str,
    attributes: t.MutableAttributeMapping,
) -> None:
    """Create an entry and append it to ``entries`` when creation succeeds."""
    entry_result = m.Ldif.Entry.create(dn=dn, attributes=attributes)
    if entry_result.success:
        entries.append(entry_result.unwrap())


def _generate_test_entries() -> list[m.Ldif.Entry]:
    """Generate the valid and invalid test entries for validation.

    Returns:
        The resulting ``list[m.Ldif.Entry]``.
    """
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
        _append_created_entry(test_entries, dn, attrs)
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
        _append_created_entry(test_entries, inv_dn, inv_attrs)
    return test_entries


def _classify_error(error: str) -> str:
    """Classify a validation error message by category.

    Returns:
        The resulting ``str``.
    """
    if "schema" in error.lower():
        return "schema"
    if "attribute" in error.lower():
        return "attribute"
    return "other"


def _error_analysis(errors: t.SequenceOf[str]) -> dict[str, int]:
    """Count validation errors per category.

    Returns:
        The resulting ``dict[str, int]``.
    """
    error_analysis: dict[str, int] = {}
    for error in errors:
        error_type = _classify_error(error)
        error_analysis[error_type] = error_analysis.get(error_type, 0) + 1
    return error_analysis


def parallel_schema_validation() -> p.Result[t.JsonMapping]:
    """Validate schema with comprehensive error analysis.

    Returns:
        The resulting ``p.Result[t.JsonMapping]``.
    """
    api = ldif()
    test_entries = _generate_test_entries()
    validation_result = api.validate_entries(test_entries)
    if validation_result.failure:
        return r[t.JsonMapping].fail(
            f"Schema validation failed: {validation_result.error}",
        )
    validation_report = validation_result.unwrap()
    analysis: dict[str, t.Numeric | dict[str, int]] = {
        "total_entries": len(test_entries),
        "valid_entries": validation_report.valid_entries,
        "invalid_entries": validation_report.invalid_entries,
        "schema_errors": len(validation_report.errors),
    }
    analysis["compliance_rate"] = (
        validation_report.valid_entries / len(test_entries) if test_entries else 0
    )
    analysis["error_analysis"] = _error_analysis(validation_report.errors)
    return r[t.JsonMapping].ok(t.json_mapping_adapter().validate_python(analysis))
