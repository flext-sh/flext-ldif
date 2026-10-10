"""Demo: Structured Migration with 6-File Output.

This example demonstrates the new structured migration feature that produces
6 organized LDIF files (00-schema through 06-rejected) with:
- Automatic categorization (schema, hierarchy, users, groups, ACLs, data)
- Removed attribute tracking and commenting
- Jinja2 header templates
- Unlimited line width (no line folding)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from flext_ldif import ldif
from examples import p


def main() -> None:
    """Run structured migration demo."""
    test_ldif = (
        "dn: cn=schema\nobjectClass: subschema\ncn: schema\nattributeTypes: ( "
        "1.2.3.4 NAME 'customAttr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )\n\n"
        "dn: dc=example,dc=com\nobjectClass: organization\ndc: example\n"
        "o: Example Organization\n\n"
        "dn: ou=People,dc=example,dc=com\nobjectClass: organizationalUnit\n"
        "ou: People\n\n"
        "dn: ou=Groups,dc=example,dc=com\nobjectClass: organizationalUnit\n"
        "ou: Groups\n\n"
        "dn: cn=john,ou=People,dc=example,dc=com\nobjectClass: inetOrgPerson\n"
        "cn: john\nsn: Doe\nuid: john\nmail: john@example.com\n"
        "userPassword: {SSHA}...\npwdChangedTime: 20230101000000Z\n"
        "modifiersName: cn=REDACTED_LDAP_BIND_PASSWORD\n\n"
        "dn: cn=jane,ou=People,dc=example,dc=com\nobjectClass: inetOrgPerson\n"
        "cn: jane\nsn: Smith\nuid: jane\nmail: jane@example.com\n"
        "pwdChangedTime: 20230115000000Z\n\n"
        "dn: cn=REDACTED_LDAP_BIND_PASSWORDs,ou=Groups,dc=example,dc=com\n"
        "objectClass: groupOfNames\ncn: REDACTED_LDAP_BIND_PASSWORDs\n"
        "member: cn=john,ou=People,dc=example,dc=com\n"
        "member: cn=jane,ou=People,dc=example,dc=com\n\n"
        "dn: cn=app-data,dc=example,dc=com\nobjectClass: applicationProcess\n"
        "cn: app-data\ndescription: Application data entry\n"
    )
    api: p.Ldif.LdifClient = ldif()
    with tempfile.TemporaryDirectory() as tmpdir:
        input_dir = Path(tmpdir) / "input"
        output_dir = Path(tmpdir) / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        (input_dir / "source.ldif").write_text(test_ldif)
        result = api.migrate(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server="rfc",
            target_server="rfc",
        )
        pipeline_result = result.unwrap()
        for path in pipeline_result.output_files:
            file_path = Path(path)
            if file_path.exists():
                _lines = len(file_path.read_text(encoding="utf-8").splitlines())
        user_file = output_dir / "02-users.ldif"
        if user_file.exists():
            _content = user_file.read_text(encoding="utf-8")


if __name__ == "__main__":
    main()
