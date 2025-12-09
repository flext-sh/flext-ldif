"""Integration tests for categorization with real migration data.

Tests categorization and base DN filtering with real-world scenarios including:
- Base DN substring matching edge cases (e.g., "dc=example" vs "dc=example2")
- ACL filtering edge cases
- Entries that should be rejected vs categorized

Note: These tests use generic examples (dc=example) to validate behavior.
Real-world scenarios (like CTBC) are tested in client-a-oud-mig project.

All test outputs use pytest tmp_path fixture for proper cleanup.
"""

from __future__ import annotations

from pathlib import Path
from typing import TextIO

from flext_ldif import FlextLdif
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.utilities import FlextLdifUtilities


def _write_entry_to_file(
    entry: m.Ldif.Entry,
    f: TextIO,
    output_content_lines: list[str],
    *,
    include_attributes: bool = False,
) -> None:
    """Write single entry to file."""
    dn = entry.dn.value if entry.dn else "N/A"
    entry_line = f"dn: {dn}\n"
    f.write(entry_line)
    output_content_lines.append(entry_line)

    if include_attributes and entry.attributes and entry.attributes.attributes:
        for attr_name, attr_values in entry.attributes.attributes.items():
            if isinstance(attr_values, list):
                for val in attr_values:
                    attr_line = f"{attr_name}: {val}\n"
                    f.write(attr_line)
                    output_content_lines.append(attr_line)

    if entry.metadata and entry.metadata.processing_stats:
        stats = entry.metadata.processing_stats
        if stats.rejected:
            rejected_line = f"# Rejected: {stats.rejected}\n"
            f.write(rejected_line)
            output_content_lines.append(rejected_line)
        if stats.filtered:
            filtered_line = f"# Filtered: {stats.filtered}\n"
            f.write(filtered_line)
            output_content_lines.append(filtered_line)

    f.write("\n")
    output_content_lines.append("\n")


def _write_categories_to_file(
    filtered: m.FlexibleCategories,
    f: TextIO,
    output_content_lines: list[str],
    *,
    include_attributes: bool = False,
) -> None:
    """Write categories to file."""
    categories = [
        c.Ldif.Categories.SCHEMA,
        c.Ldif.Categories.HIERARCHY,
        c.Ldif.Categories.USERS,
        c.Ldif.Categories.GROUPS,
        c.Ldif.Categories.ACL,
        c.Ldif.Categories.REJECTED,
    ]

    for category in categories:
        cat_entries = filtered.get_entries(category)
        if not cat_entries:
            continue

        _write_category_header(
            category,
            len(cat_entries),
            include_attributes,
            f,
            output_content_lines,
        )

        for entry in cat_entries:
            _write_entry_to_file(entry, f, output_content_lines, include_attributes)


def _write_category_header(
    category: str,
    entry_count: int,
    include_attributes: bool,
    f: TextIO,
    output_content_lines: list[str],
) -> None:
    """Write category header to file."""
    category_header = (
        f"\n# ========================================\n# Category: {category} ({entry_count} entries)\n# ========================================\n\n"
        if include_attributes
        else f"# Category: {category}\n"
    )
    f.write(category_header)
    output_content_lines.append(category_header)


class TestCategorizationRealData:
    """Test categorization with real-world data scenarios."""

    def test_base_dn_substring_matching_edge_cases(self, tmp_path: Path) -> None:
        """Test categorization with base DN that could cause substring matching false positives.

        Business Rule: Entries under base DN should be categorized correctly using
        hierarchical DN check (is_under_base), not substring matching.
        This prevents false positives like "dc=example2" matching "dc=example".

        Uses generic examples (dc=example) to validate behavior without knowing
        about specific projects like client-a-oud-mig or CTBC.
        """
        base_dn = "dc=example"

        # Create entries that could cause false positives with substring matching
        entries = [
            m.Ldif.Entry(
                dn=m.Ldif.DistinguishedName(value="dc=example"),
                attributes=m.Ldif.LdifAttributes.(attributes={"objectClass": ["domain"]}),
            ),
            m.Ldif.Entry(
                dn=m.Ldif.DistinguishedName(value="ou=users,dc=example"),
                attributes=m.Ldif.LdifAttributes.(
                    attributes={"objectClass": ["organizationalUnit"]},
                ),
            ),
            m.Ldif.Entry(
                dn=m.Ldif.DistinguishedName(value="cn=user1,ou=users,dc=example"),
                attributes=m.Ldif.LdifAttributes.(attributes={"objectClass": ["person"]}),
            ),
            # This should NOT match base DN (false positive with substring matching)
            m.Ldif.Entry(
                dn=m.Ldif.DistinguishedName(value="dc=example2"),
                attributes=m.Ldif.LdifAttributes.(attributes={"objectClass": ["domain"]}),
            ),
            # This should NOT match base DN (false positive with substring matching)
            m.Ldif.Entry(
                dn=m.Ldif.DistinguishedName(value="ou=test,dc=example2"),
                attributes=m.Ldif.LdifAttributes.(
                    attributes={"objectClass": ["organizationalUnit"]},
                ),
            ),
        ]

        categorization = FlextLdif.categorization(base_dn=base_dn, server_type="oud")

        # Validate DNs
        validate_result = categorization.validate_dns(entries)
        assert validate_result.is_success, (
            f"DN validation failed: {validate_result.error}"
        )

        # Categorize entries
        categories_result = categorization.categorize_entries(validate_result.unwrap())
        assert categories_result.is_success, (
            f"Categorization failed: {categories_result.error}"
        )

        categories = categories_result.unwrap()

        # Filter by base DN
        filtered = categorization.filter_by_base_dn(categories)

        # Write results to temporary file for validation (not inspection)
        output_file = tmp_path / "test_base_dn_substring_edge_cases.ldif"
        output_content_lines: list[str] = []
        with output_file.open("w", encoding="utf-8") as f:
            header = f"# Base DN Substring Matching Edge Cases Test\n# Base DN: {base_dn}\n# Tests: dc=example vs dc=example2 (should not match)\n\n"
            f.write(header)
            output_content_lines.append(header)

            _write_categories_to_file(
                filtered,
                f,
                output_content_lines,
                include_attributes=False,
            )

        # Validate output file was created and has content
        assert output_file.exists(), "Output file should be created"
        output_content = output_file.read_text(encoding="utf-8")
        assert len(output_content) > 0, "Output file should not be empty"
        assert base_dn in output_content, f"Output should contain base DN: {base_dn}"

        # Validate: Entries under base DN should be in correct categories
        hierarchy = filtered.get_entries(c.Ldif.Categories.HIERARCHY)
        users = filtered.get_entries(c.Ldif.Categories.USERS)
        rejected = filtered.get_entries(c.Ldif.Categories.REJECTED)

        # dc=example should be in hierarchy (not rejected)
        example_dns = [
            e.dn.value for e in hierarchy if e.dn and e.dn.value == "dc=example"
        ]
        assert len(example_dns) == 1, "dc=example should be in hierarchy category"

        # ou=users,dc=example should be in hierarchy (not rejected)
        users_ou_dns = [
            e.dn.value
            for e in hierarchy
            if e.dn and e.dn.value == "ou=users,dc=example"
        ]
        assert len(users_ou_dns) == 1, (
            "ou=users,dc=example should be in hierarchy category"
        )

        # cn=user1,ou=users,dc=example should be in users (not rejected)
        user1_dns = [
            e.dn.value
            for e in users
            if e.dn and e.dn.value == "cn=user1,ou=users,dc=example"
        ]
        assert len(user1_dns) == 1, (
            "cn=user1,ou=users,dc=example should be in users category"
        )

        # dc=example2 should be in rejected (not matching base DN - substring false positive prevention)
        example2_rejected = [
            e.dn.value for e in rejected if e.dn and e.dn.value == "dc=example2"
        ]
        assert len(example2_rejected) == 1, (
            "dc=example2 should be rejected (not under base DN, prevents substring false positive)"
        )

        # ou=test,dc=example2 should be in rejected (not matching base DN)
        test_ou_rejected = [
            e.dn.value for e in rejected if e.dn and e.dn.value == "ou=test,dc=example2"
        ]
        assert len(test_ou_rejected) == 1, (
            "ou=test,dc=example2 should be rejected (not under base DN)"
        )

    def test_acl_filtering_substring_matching_edge_cases(self, tmp_path: Path) -> None:
        """Test ACL filtering with base DN that could cause substring matching false positives.

        Business Rule: ACLs should be classified correctly using hierarchical DN check
        (is_under_base), not substring matching. Prevents false positives like
        "dc=example2" matching "dc=example".

        Uses generic examples to validate behavior without knowing about specific projects.
        """
        base_dn = "dc=example"

        # Create ACL entries that could cause false positives
        acl_entries = [
            m.Ldif.Entry(
                dn=m.Ldif.DistinguishedName(value="dc=example"),
                attributes=m.Ldif.LdifAttributes.(
                    attributes={"aci": ['(targetattr="*")(version 3.0;acl "test";)']},
                ),
            ),
            m.Ldif.Entry(
                dn=m.Ldif.DistinguishedName(value="ou=users,dc=example"),
                attributes=m.Ldif.LdifAttributes.(
                    attributes={"aci": ['(targetattr="*")(version 3.0;acl "test";)']},
                ),
            ),
            # This should NOT match base DN (false positive with substring matching)
            m.Ldif.Entry(
                dn=m.Ldif.DistinguishedName(value="dc=example2"),
                attributes=m.Ldif.LdifAttributes.(
                    attributes={"aci": ['(targetattr="*")(version 3.0;acl "test";)']},
                ),
            ),
            # System ACL (no base DN)
            m.Ldif.Entry(
                dn=m.Ldif.DistinguishedName(value="cn=config"),
                attributes=m.Ldif.LdifAttributes.(
                    attributes={"aci": ['(targetattr="*")(version 3.0;acl "test";)']},
                ),
            ),
        ]

        categorization = FlextLdif.categorization(base_dn=base_dn, server_type="oud")

        # Categorize entries (ACLs should be categorized as ACL category)
        validate_result = categorization.validate_dns(acl_entries)
        assert validate_result.is_success

        categories_result = categorization.categorize_entries(validate_result.unwrap())
        assert categories_result.is_success

        categories = categories_result.unwrap()
        acl_category = categories.get_entries(c.Ldif.Categories.ACL)

        # Filter ACLs by base DN (simulating client-a-oud-mig logic)
        acls_with_basedn: list[m.Ldif.Entry] = []
        acls_without_basedn: list[m.Ldif.Entry] = []

        for entry in acl_category:
            dn_str = entry.dn.value if entry.dn else None
            # Use is_under_base for correct hierarchical check
            if dn_str and FlextLdifUtilities.Ldif.DN.is_under_base(dn_str, base_dn):
                acls_with_basedn.append(entry)
            else:
                acls_without_basedn.append(entry)

        # Write results to temporary file for validation
        output_file = tmp_path / "test_acl_substring_edge_cases.ldif"
        output_content_lines: list[str] = []
        with output_file.open("w", encoding="utf-8") as f:
            header = f"# ACL Substring Matching Edge Cases Test\n# Base DN: {base_dn}\n# Tests: dc=example vs dc=example2 (should not match)\n\n"
            f.write(header)
            output_content_lines.append(header)

            f.write("# ACLs WITH BaseDN (should be filtered):\n")
            output_content_lines.append("# ACLs WITH BaseDN (should be filtered):\n")
            for entry in acls_with_basedn:
                dn = entry.dn.value if entry.dn else "N/A"
                entry_line = f"dn: {dn}\n\n"
                f.write(entry_line)
                output_content_lines.append(entry_line)

            f.write("\n# ACLs WITHOUT BaseDN (system ACLs, kept):\n")
            output_content_lines.append(
                "\n# ACLs WITHOUT BaseDN (system ACLs, kept):\n",
            )
            for entry in acls_without_basedn:
                dn = entry.dn.value if entry.dn else "N/A"
                entry_line = f"dn: {dn}\n\n"
                f.write(entry_line)
                output_content_lines.append(entry_line)

        # Validate output file was created and has content
        assert output_file.exists(), "Output file should be created"
        output_content = output_file.read_text(encoding="utf-8")
        assert len(output_content) > 0, "Output file should not be empty"
        assert base_dn in output_content, f"Output should contain base DN: {base_dn}"
        assert "dc=example" in output_content, "Output should contain matching entries"
        assert "dc=example2" in output_content, (
            "Output should contain non-matching entries"
        )

        # Validate: dc=example and ou=users,dc=example should be in acls_with_basedn
        basedn_dns = [e.dn.value for e in acls_with_basedn if e.dn]
        assert "dc=example" in basedn_dns, "dc=example should be in acls_with_basedn"
        assert "ou=users,dc=example" in basedn_dns, (
            "ou=users,dc=example should be in acls_with_basedn"
        )

        # Validate: dc=example2 should NOT be in acls_with_basedn (false positive prevention)
        assert "dc=example2" not in basedn_dns, (
            "dc=example2 should NOT be in acls_with_basedn (false positive prevention)"
        )

        # Validate: cn=config should be in acls_without_basedn (system ACL)
        without_basedn_dns = [e.dn.value for e in acls_without_basedn if e.dn]
        assert "cn=config" in without_basedn_dns, (
            "cn=config should be in acls_without_basedn"
        )
        assert "dc=example2" in without_basedn_dns, (
            "dc=example2 should be in acls_without_basedn (not matching base DN)"
        )

    def test_complete_migration_with_real_data(self, tmp_path: Path) -> None:
        """Test complete migration pipeline with real-world data.

        Creates a complete migration scenario using temporary files.
        Uses generic examples (dc=example) to validate behavior.
        """
        # Create realistic LDIF content with generic examples
        ldif_content = """dn: dc=example
objectClass: domain
dc: example

dn: ou=users,dc=example
objectClass: organizationalUnit
ou: users

dn: cn=REDACTED_LDAP_BIND_PASSWORD,ou=users,dc=example
objectClass: person
cn: REDACTED_LDAP_BIND_PASSWORD
sn: Admin

dn: cn=user1,ou=users,dc=example
objectClass: person
cn: user1
sn: User1

dn: dc=example2
objectClass: domain
dc: example2

dn: ou=test,dc=example2
objectClass: organizationalUnit
ou: test
"""

        # Write input file to temporary directory
        input_file = tmp_path / "input_real_migration.ldif"
        input_file.write_text(ldif_content, encoding="utf-8")

        # Validate input file was created
        assert input_file.exists(), "Input file should be created"
        assert input_file.read_text(encoding="utf-8") == ldif_content, (
            "Input file content should match"
        )

        # Parse entries from file content (parse accepts string content directly)
        ldif = FlextLdif()
        parse_result = ldif.parse(
            source=ldif_content,  # Parse from content string, not file path
            server_type="rfc",
        )
        assert parse_result.is_success, f"Parsing failed: {parse_result.error}"

        entries = parse_result.unwrap()
        assert len(entries) == 6, f"Should parse 6 entries, got {len(entries)}"

        # Categorize with base DN filtering
        base_dn = "dc=example"
        categorization = FlextLdif.categorization(base_dn=base_dn, server_type="oud")

        validate_result = categorization.validate_dns(entries)
        assert validate_result.is_success

        categories_result = categorization.categorize_entries(validate_result.unwrap())
        assert categories_result.is_success

        categories = categories_result.unwrap()
        filtered = categorization.filter_by_base_dn(categories)

        # Write categorized output to temporary file
        output_file = tmp_path / "output_real_migration_categorized.ldif"
        output_content_lines: list[str] = []
        with output_file.open("w", encoding="utf-8") as f:
            header = f"# Complete Migration Test Output\n# Base DN: {base_dn}\n# Total entries processed: {len(entries)}\n\n"
            f.write(header)
            output_content_lines.append(header)

            _write_categories_to_file(
                filtered,
                f,
                output_content_lines,
                include_attributes=True,
            )

        # Validate output file was created and has expected content
        assert output_file.exists(), "Output file should be created"
        output_content = output_file.read_text(encoding="utf-8")
        assert len(output_content) > 0, "Output file should not be empty"
        assert base_dn in output_content, f"Output should contain base DN: {base_dn}"
        assert str(len(entries)) in output_content, "Output should contain entry count"
        # Validate that entries under base DN are in correct categories
        assert "dc=example" in output_content, (
            "Output should contain entries under base DN"
        )

        # Validate results
        hierarchy = filtered.get_entries(c.Ldif.Categories.HIERARCHY)
        users = filtered.get_entries(c.Ldif.Categories.USERS)
        rejected = filtered.get_entries(c.Ldif.Categories.REJECTED)

        # Entries under base DN should be categorized correctly
        assert len(hierarchy) >= 2, "Should have hierarchy entries under base DN"
        assert len(users) >= 2, "Should have user entries under base DN"

        # Entries outside base DN should be rejected
        assert len(rejected) >= 2, "Should have rejected entries outside base DN"
