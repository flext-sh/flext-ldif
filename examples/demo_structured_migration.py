#!/usr/bin/env python3
"""Demo: Structured Migration with 6-File Output.

This example demonstrates the new structured migration feature that produces
6 organized LDIF files (00-schema through 06-rejected) with:
- Automatic categorization (schema, hierarchy, users, groups, ACLs, data)
- Removed attribute tracking and commenting
- Jinja2 header templates
- Unlimited line width (no line folding)
"""

import tempfile
from pathlib import Path

from flext_ldif import FlextLdif, FlextLdifModels


def main() -> None:
    """Run structured migration demo."""
    # Sample LDIF data
    test_ldif = """dn: cn=schema
objectClass: subschema
cn: schema
attributeTypes: ( 1.2.3.4 NAME 'customAttr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )

dn: dc=example,dc=com
objectClass: organization
dc: example
o: Example Organization

dn: ou=People,dc=example,dc=com
objectClass: organizationalUnit
ou: People

dn: ou=Groups,dc=example,dc=com
objectClass: organizationalUnit
ou: Groups

dn: cn=john,ou=People,dc=example,dc=com
objectClass: inetOrgPerson
cn: john
sn: Doe
uid: john
mail: john@example.com
userPassword: {SSHA}...
pwdChangedTime: 20230101000000Z
modifiersName: cn=REDACTED_LDAP_BIND_PASSWORD

dn: cn=jane,ou=People,dc=example,dc=com
objectClass: inetOrgPerson
cn: jane
sn: Smith
uid: jane
mail: jane@example.com
pwdChangedTime: 20230115000000Z

dn: cn=REDACTED_LDAP_BIND_PASSWORDs,ou=Groups,dc=example,dc=com
objectClass: groupOfNames
cn: REDACTED_LDAP_BIND_PASSWORDs
member: cn=john,ou=People,dc=example,dc=com
member: cn=jane,ou=People,dc=example,dc=com

dn: cn=app-data,dc=example,dc=com
objectClass: applicationProcess
cn: app-data
description: Application data entry
"""

    api = FlextLdif.get_instance()

    with tempfile.TemporaryDirectory() as tmpdir:
        # Setup directories
        input_dir = Path(tmpdir) / "input"
        output_dir = Path(tmpdir) / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        # Write test LDIF
        (input_dir / "source.ldif").write_text(test_ldif)

        # Configure structured migration
        config = FlextLdifModels.MigrationConfig(
            # Categorization rules
            hierarchy_objectclasses=["organization", "organizationalUnit"],
            user_objectclasses=["inetOrgPerson", "person"],
            group_objectclasses=["groupOfNames", "groupOfUniqueNames"],
            # Filtering rules
            attribute_blacklist=["pwdChangedTime", "modifiersName"],
            # Removed attribute tracking
            track_removed_attributes=True,
            write_removed_as_comments=True,
            # Header template
            header_template="""#
# Migration: {{source_system}} → {{target_system}}
# Date: {{migration_date}}
# Category: {{category}}
# Description: {{description}}
#
""",
            header_data={
                "source_system": "Oracle Internet Directory (OID)",
                "target_system": "Oracle Unified Directory (OUD)",
                "migration_date": "2025-10-30",
                "description": "Automated LDAP directory migration",
            },
        )

        # Configure write options
        write_options = FlextLdifModels.WriteFormatOptions(
            disable_line_folding=True,  # No line breaks
            write_removed_attributes_as_comments=True,  # Comment removed attrs
        )

        # Execute migration
        print("🚀 Starting structured migration...")
        result = api.migrate(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server="rfc",
            target_server="rfc",
            migration_config=config,
            write_options=write_options,
        )

        if result.is_failure:
            print(f"❌ Migration failed: {result.error}")
            return

        # Display results
        pipeline_result = result.unwrap()
        print("\n✅ Migration completed successfully!")
        print("\n📊 Statistics:")
        print(f"  Total entries: {pipeline_result.statistics.total_entries}")
        print(f"  Schema entries: {pipeline_result.statistics.schema_entries}")
        print(f"  Hierarchy entries: {pipeline_result.statistics.hierarchy_entries}")
        print(f"  User entries: {pipeline_result.statistics.user_entries}")
        print(f"  Group entries: {pipeline_result.statistics.group_entries}")
        print(f"  ACL entries: {pipeline_result.statistics.acl_entries}")
        print(f"  Rejected entries: {pipeline_result.statistics.rejected_entries}")

        print(f"\n📁 Output files ({len(pipeline_result.file_paths)}):")
        for category, path in sorted(pipeline_result.file_paths.items()):
            file_path = Path(path)
            if file_path.exists():
                size = file_path.stat().st_size
                lines = len(file_path.read_text(encoding="utf-8").splitlines())
                print(
                    f"  {category:12} → {file_path.name:20} ({size:5} bytes, {lines:3} lines)",
                )

        # Show sample output
        user_file = output_dir / "02-users.ldif"
        if user_file.exists():
            print(f"\n📄 Sample: {user_file.name}")
            print("─" * 80)
            content = user_file.read_text()
            # Show first 30 lines
            lines = content.splitlines()[:30]
            print("\n".join(lines))
            if len(content.splitlines()) > 30:
                print("...")
            print("─" * 80)

        print("\n✨ Key features demonstrated:")
        print("  ✓ Automatic 6-file categorization (00-schema to 06-rejected)")
        print("  ✓ Removed attributes tracked in metadata")
        print("  ✓ Removed attributes commented in output")
        print("  ✓ Jinja2 header templates rendered")
        print("  ✓ No line folding (unlimited line width)")
        print("  ✓ RFC 2849 compliant LDIF output")


if __name__ == "__main__":
    main()
