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

from __future__ import annotations

import tempfile
from pathlib import Path

from flext_ldif import ldif


def main() -> None:
    """Run structured migration demo."""
    test_ldif = "dn: cn=schema\nobjectClass: subschema\ncn: schema\nattributeTypes: ( 1.2.3.4 NAME 'customAttr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )\n\ndn: dc=example,dc=com\nobjectClass: organization\ndc: example\no: Example Organization\n\ndn: ou=People,dc=example,dc=com\nobjectClass: organizationalUnit\nou: People\n\ndn: ou=Groups,dc=example,dc=com\nobjectClass: organizationalUnit\nou: Groups\n\ndn: cn=john,ou=People,dc=example,dc=com\nobjectClass: inetOrgPerson\ncn: john\nsn: Doe\nuid: john\nmail: john@example.com\nuserPassword: {SSHA}...\npwdChangedTime: 20230101000000Z\nmodifiersName: cn=REDACTED_LDAP_BIND_PASSWORD\n\ndn: cn=jane,ou=People,dc=example,dc=com\nobjectClass: inetOrgPerson\ncn: jane\nsn: Smith\nuid: jane\nmail: jane@example.com\npwdChangedTime: 20230115000000Z\n\ndn: cn=REDACTED_LDAP_BIND_PASSWORDs,ou=Groups,dc=example,dc=com\nobjectClass: groupOfNames\ncn: REDACTED_LDAP_BIND_PASSWORDs\nmember: cn=john,ou=People,dc=example,dc=com\nmember: cn=jane,ou=People,dc=example,dc=com\n\ndn: cn=app-data,dc=example,dc=com\nobjectClass: applicationProcess\ncn: app-data\ndescription: Application data entry\n"
    api = ldif.get_instance()
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
        if result.is_failure:
            return
        pipeline_result = result.value
        for path in pipeline_result.output_files:
            file_path = Path(path)
            if file_path.exists():
                _lines = len(file_path.read_text(encoding="utf-8").splitlines())
        user_file = output_dir / "02-users.ldif"
        if user_file.exists():
            _content = user_file.read_text(encoding="utf-8")


if __name__ == "__main__":
    main()
