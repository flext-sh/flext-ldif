"""Schema validation example with comprehensive error analysis.

Part of Example 5 (Advanced Schema Operations); see
``examples/schema_operations.py`` for the combined facade.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from examples import m, p, r, t
from flext_ldif import ldif


class ExamplesFlextLdifSchemaValidation:
    """Schema validation example namespace with error analysis."""

    @staticmethod
    def _append_created_entry(
        entries: list[m.Ldif.Entry],
        dn: str,
        attributes: t.MutableAttributeMapping,
    ) -> None:
        """Create an entry and append it to ``entries`` when creation succeeds."""
        entry_result = m.Ldif.Entry.create(dn=dn, attributes=attributes)
        if entry_result.success:
            entries.append(entry_result.unwrap())

    @staticmethod
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
            ExamplesFlextLdifSchemaValidation._append_created_entry(
                test_entries,
                dn,
                attrs,
            )
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
            ExamplesFlextLdifSchemaValidation._append_created_entry(
                test_entries,
                inv_dn,
                inv_attrs,
            )
        return test_entries

    @staticmethod
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

    @staticmethod
    def _error_analysis(errors: t.SequenceOf[str]) -> t.MutableMappingKV[str, int]:
        """Count validation errors per category.

        Returns:
            The resulting ``t.MutableMappingKV[str, int]``.
        """
        error_analysis: t.MutableMappingKV[str, int] = {}
        for error in errors:
            error_type = ExamplesFlextLdifSchemaValidation._classify_error(error)
            error_analysis[error_type] = error_analysis.get(error_type, 0) + 1
        return error_analysis

    @staticmethod
    def parallel_schema_validation() -> p.Result[t.JsonMapping]:
        """Validate schema with comprehensive error analysis.

        Returns:
            The resulting ``p.Result[t.JsonMapping]``.
        """
        api = ldif()
        test_entries = ExamplesFlextLdifSchemaValidation._generate_test_entries()
        validation_result = api.validate_entries(test_entries)
        if validation_result.failure:
            return r[t.JsonMapping].fail(
                f"Schema validation failed: {validation_result.error}",
            )
        validation_report = validation_result.unwrap()
        analysis: t.MutableMappingKV[str, t.Numeric | t.MappingKV[str, t.Numeric]] = {
            "total_entries": len(test_entries),
            "valid_entries": validation_report.valid_entries,
            "invalid_entries": validation_report.invalid_entries,
            "schema_errors": len(validation_report.errors),
        }
        analysis["compliance_rate"] = (
            validation_report.valid_entries / len(test_entries) if test_entries else 0
        )
        analysis["error_analysis"] = ExamplesFlextLdifSchemaValidation._error_analysis(
            validation_report.errors,
        )
        return r[t.JsonMapping].ok(t.json_mapping_adapter().validate_python(analysis))


# Module-level rebinding of the namespace surface: the lazy package export and
# the schema_operations aggregator import this name as a module attribute.
parallel_schema_validation = (
    ExamplesFlextLdifSchemaValidation.parallel_schema_validation
)

__all__: list[str] = [
    "ExamplesFlextLdifSchemaValidation",
    "parallel_schema_validation",
]
