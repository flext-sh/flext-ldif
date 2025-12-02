"""Integration tests for categorization with real migration data.

Tests categorization and base DN filtering with real-world scenarios including:
- Base DN substring matching edge cases (e.g., "dc=example" vs "dc=example2")
- ACL filtering edge cases
- Entries that should be rejected vs categorized

All test outputs are written to tests/data/output for inspection.

Note: These tests use generic examples (dc=example) to validate behavior.
Real-world scenarios (like CTBC) are tested in client-a-oud-mig project.
"""

from __future__ import annotations

from pathlib import Path

from flext_ldif import FlextLdif, FlextLdifConstants, FlextLdifModels
from flext_ldif.utilities import FlextLdifUtilities

# Output directory for real migration data
OUTPUT_DIR = Path(__file__).parent.parent / "data" / "output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


class TestCategorizationRealData:
    """Test categorization with real-world data scenarios."""

    def test_base_dn_substring_matching_edge_cases(self) -> None:
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
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value="dc=example"),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={"objectClass": ["domain"]}
                ),
            ),
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value="ou=users,dc=example"),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={"objectClass": ["organizationalUnit"]}
                ),
            ),
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value="cn=user1,ou=users,dc=example"
                ),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={"objectClass": ["person"]}
                ),
            ),
            # This should NOT match base DN (false positive with substring matching)
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value="dc=example2"),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={"objectClass": ["domain"]}
                ),
            ),
            # This should NOT match base DN (false positive with substring matching)
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value="ou=test,dc=example2"),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={"objectClass": ["organizationalUnit"]}
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

        # Write results to file for inspection
        output_file = OUTPUT_DIR / "test_base_dn_substring_edge_cases.ldif"
        with output_file.open("w", encoding="utf-8") as f:
            f.write("# Base DN Substring Matching Edge Cases Test\n")
            f.write(f"# Base DN: {base_dn}\n")
            f.write("# Tests: dc=example vs dc=example2 (should not match)\n\n")

            for category in [
                FlextLdifConstants.Categories.SCHEMA,
                FlextLdifConstants.Categories.HIERARCHY,
                FlextLdifConstants.Categories.USERS,
                FlextLdifConstants.Categories.GROUPS,
                FlextLdifConstants.Categories.ACL,
                FlextLdifConstants.Categories.REJECTED,
            ]:
                cat_entries = filtered.get_entries(category)
                if cat_entries:
                    f.write(f"# Category: {category}\n")
                    for entry in cat_entries:
                        dn = entry.dn.value if entry.dn else "N/A"
                        f.write(f"dn: {dn}\n")
                        if entry.metadata and entry.metadata.processing_stats:
                            stats = entry.metadata.processing_stats
                            if stats.rejected:
                                f.write(f"# Rejected: {stats.rejected}\n")
                            if stats.filtered:
                                f.write(f"# Filtered: {stats.filtered}\n")
                        f.write("\n")

        # Validate: Entries under base DN should be in correct categories
        hierarchy = filtered.get_entries(FlextLdifConstants.Categories.HIERARCHY)
        users = filtered.get_entries(FlextLdifConstants.Categories.USERS)
        rejected = filtered.get_entries(FlextLdifConstants.Categories.REJECTED)

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

    def test_acl_filtering_substring_matching_edge_cases(self) -> None:
        """Test ACL filtering with base DN that could cause substring matching false positives.

        Business Rule: ACLs should be classified correctly using hierarchical DN check
        (is_under_base), not substring matching. Prevents false positives like
        "dc=example2" matching "dc=example".

        Uses generic examples to validate behavior without knowing about specific projects.
        """
        base_dn = "dc=example"

        # Create ACL entries that could cause false positives
        acl_entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value="dc=example"),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={"aci": ['(targetattr="*")(version 3.0;acl "test";)']}
                ),
            ),
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value="ou=users,dc=example"),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={"aci": ['(targetattr="*")(version 3.0;acl "test";)']}
                ),
            ),
            # This should NOT match base DN (false positive with substring matching)
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value="dc=example2"),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={"aci": ['(targetattr="*")(version 3.0;acl "test";)']}
                ),
            ),
            # System ACL (no base DN)
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value="cn=config"),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={"aci": ['(targetattr="*")(version 3.0;acl "test";)']}
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
        acl_category = categories.get_entries(FlextLdifConstants.Categories.ACL)

        # Filter ACLs by base DN (simulating client-a-oud-mig logic)
        acls_with_basedn: list[FlextLdifModels.Entry] = []
        acls_without_basedn: list[FlextLdifModels.Entry] = []

        for entry in acl_category:
            dn_str = entry.dn.value if entry.dn else None
            # Use is_under_base for correct hierarchical check
            if dn_str and FlextLdifUtilities.DN.is_under_base(dn_str, base_dn):
                acls_with_basedn.append(entry)
            else:
                acls_without_basedn.append(entry)

        # Write results to file for inspection
        output_file = OUTPUT_DIR / "test_acl_substring_edge_cases.ldif"
        with output_file.open("w", encoding="utf-8") as f:
            f.write("# ACL Substring Matching Edge Cases Test\n")
            f.write(f"# Base DN: {base_dn}\n")
            f.write("# Tests: dc=example vs dc=example2 (should not match)\n\n")

            f.write("# ACLs WITH BaseDN (should be filtered):\n")
            for entry in acls_with_basedn:
                dn = entry.dn.value if entry.dn else "N/A"
                f.write(f"dn: {dn}\n")
                f.write("\n")

            f.write("\n# ACLs WITHOUT BaseDN (system ACLs, kept):\n")
            for entry in acls_without_basedn:
                dn = entry.dn.value if entry.dn else "N/A"
                f.write(f"dn: {dn}\n")
                f.write("\n")

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

    def test_complete_migration_with_real_data(self) -> None:
        """Test complete migration pipeline with real-world data.

        Creates a complete migration scenario and writes all outputs to tests/data/output.
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

        # Write input file for reference
        input_file = OUTPUT_DIR / "input_real_migration.ldif"
        input_file.write_text(ldif_content, encoding="utf-8")

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

        # Write categorized output
        output_file = OUTPUT_DIR / "output_real_migration_categorized.ldif"
        with output_file.open("w", encoding="utf-8") as f:
            f.write("# Complete Migration Test Output\n")
            f.write(f"# Base DN: {base_dn}\n")
            f.write(f"# Total entries processed: {len(entries)}\n\n")

            for category in [
                FlextLdifConstants.Categories.SCHEMA,
                FlextLdifConstants.Categories.HIERARCHY,
                FlextLdifConstants.Categories.USERS,
                FlextLdifConstants.Categories.GROUPS,
                FlextLdifConstants.Categories.ACL,
                FlextLdifConstants.Categories.REJECTED,
            ]:
                cat_entries = filtered.get_entries(category)
                if cat_entries:
                    f.write("\n# ========================================\n")
                    f.write(f"# Category: {category} ({len(cat_entries)} entries)\n")
                    f.write("# ========================================\n\n")

                    for entry in cat_entries:
                        dn = entry.dn.value if entry.dn else "N/A"
                        f.write(f"dn: {dn}\n")

                        if entry.attributes and entry.attributes.attributes:
                            for (
                                attr_name,
                                attr_values,
                            ) in entry.attributes.attributes.items():
                                if isinstance(attr_values, list):
                                    for val in attr_values:
                                        f.write(f"{attr_name}: {val}\n")

                        if entry.metadata and entry.metadata.processing_stats:
                            stats = entry.metadata.processing_stats
                            if stats.rejected:
                                f.write(f"# Rejected: {stats.rejected}\n")
                            if stats.filtered:
                                f.write(f"# Filtered: {stats.filtered}\n")

                        f.write("\n")

        # Validate results
        hierarchy = filtered.get_entries(FlextLdifConstants.Categories.HIERARCHY)
        users = filtered.get_entries(FlextLdifConstants.Categories.USERS)
        rejected = filtered.get_entries(FlextLdifConstants.Categories.REJECTED)

        # Entries under base DN should be categorized correctly
        assert len(hierarchy) >= 2, "Should have hierarchy entries under base DN"
        assert len(users) >= 2, "Should have user entries under base DN"

        # Entries outside base DN should be rejected
        assert len(rejected) >= 2, "Should have rejected entries outside base DN"
