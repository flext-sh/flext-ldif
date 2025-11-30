#!/usr/bin/env python3
"""Demo: Structured Migration with 6-File Output.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

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
modifiersName: cn=admin

dn: cn=jane,ou=People,dc=example,dc=com
objectClass: inetOrgPerson
cn: jane
sn: Smith
uid: jane
mail: jane@example.com
pwdChangedTime: 20230115000000Z

dn: cn=admins,ou=Groups,dc=example,dc=com
objectClass: groupOfNames
cn: admins
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

        # Configure write options
        write_options = FlextLdifModels.WriteFormatOptions(
            line_width=100,  # Set line width for folding
            respect_attribute_order=True,  # Respect attribute order
        )

        # Create migration options combining config and write options
        migrate_options = FlextLdifModels.MigrateOptions(
            migration_config=write_options.model_dump(),
            write_options=write_options.model_dump(),
        )

        # Execute migration
        result = api.migrate(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server="rfc",
            target_server="rfc",
            options=migrate_options,
        )

        if result.is_failure:
            return

        # Display results
        pipeline_result = result.unwrap()

        for _category, path in sorted(pipeline_result.file_paths.items()):
            file_path = Path(path)
            if file_path.exists():
                _size = file_path.stat().st_size
                _lines = len(file_path.read_text(encoding="utf-8").splitlines())

        # Show sample output
        user_file = output_dir / "02-users.ldif"
        if user_file.exists():
            content = user_file.read_text()
            # Show first 30 lines
            content.splitlines()[:30]
            if len(content.splitlines()) > 30:
                pass


if __name__ == "__main__":
    main()
