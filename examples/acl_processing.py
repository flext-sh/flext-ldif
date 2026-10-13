"""Example 6: ACL (Access Control List) Processing.

Demonstrates ldif ACL-related functionality:
- Extracting ACLs from LDIF entries
- Parsing ACL attributes
- Evaluating ACLs against context
- Working with ACL components

All functionality accessed through ldif facade and FlextLdifAcl service.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from examples import m, t
from flext_ldif import ldif


class ExamplesFlextLdifAclProcessing:
    """ACL processing example namespace."""

    @staticmethod
    def _parse_first_entry_with_acls(
        ldif_content: str,
    ) -> tuple[m.Ldif.Entry, m.Ldif.AclResponse] | None:
        """Parse LDIF text and extract ACLs from its first entry.

        Returns:
            The resulting ``tuple[m.Ldif.Entry, m.Ldif.AclResponse] | None``.
        """
        api = ldif()
        entries = api.parse_ldif(ldif_content).unwrap().entries
        if not entries:
            return None
        entry = entries[0]
        acl_result = api.extract_acls_from_entry(entry, server_type="openldap")
        return entry, acl_result.unwrap()

    @staticmethod
    def extract_acls_from_entry() -> None:
        """Extract ACL information from an LDIF entry."""
        parsed = ExamplesFlextLdifAclProcessing._parse_first_entry_with_acls(
            (
                "dn: cn=test,ou=People,dc=example,dc=com\nobjectClass: person\ncn: "
                "test\nsn: user\n"
                'aci: (target="ldap:///ou=People,dc=example,dc=com")'
                '(targetattr="*")'
                '(version 3.0; acl "Allow read"; '
                'allow (read,search) userdn="ldap:///anyone";)\n'
            ),
        )
        if parsed is not None:
            _, acl_response = parsed
            _ = len(acl_response.acls)

    @staticmethod
    def parse_and_evaluate_acls() -> None:
        """Parse ACL attributes and evaluate against context."""
        parsed = ExamplesFlextLdifAclProcessing._parse_first_entry_with_acls(
            (
                "dn: ou=People,dc=example,dc=com\nobjectClass: "
                "organizationalUnit\nou: People\n"
                'aci: (target="ldap:///ou=People,dc=example,dc=com")'
                '(targetattr="cn || sn")'
                '(version 3.0; acl "Allow self write"; '
                'allow (write) userdn="ldap:///self";)\n'
                'aci: (target="ldap:///ou=People,dc=example,dc=com")'
                '(targetattr="*")'
                '(version 3.0; acl "Allow admin all"; '
                'allow (all) userdn="ldap:///cn=admin,dc=example,dc=com";)\n'
            ),
        )
        if parsed is None:
            return
        _, acl_response = parsed
        required_perms: t.MutableBoolMapping = {"read": True, "write": True}
        evaluation_result = ldif().evaluate_acl_context(
            acl_response.acls,
            required_perms,
        )
        if evaluation_result.success:
            _ = evaluation_result.unwrap()

    @staticmethod
    def process_entries_with_acls() -> None:
        """Process entries that contain ACL information."""
        api = ldif()
        ldif_content = (
            "dn: ou=People,dc=example,dc=com\nobjectClass: "
            "organizationalUnit\nou: People\n"
            'aci: (target="ldap:///ou=People,dc=example,dc=com")'
            '(targetattr="*")'
            '(version 3.0; acl "Read access"; '
            'allow (read) userdn="ldap:///anyone";)\n'
            "\ndn: ou=Groups,dc=example,dc=com\n"
            "objectClass: organizationalUnit\n"
            "ou: Groups\n"
            'aci: (target="ldap:///ou=Groups,dc=example,dc=com")'
            '(targetattr="*")'
            '(version 3.0; acl "Admin access"; '
            'allow (all) userdn="ldap:///cn=admin,dc=example,dc=com";)\n'
            "\ndn: cn=user,ou=People,dc=example,dc=com\n"
            "objectClass: person\n"
            "cn: user\n"
            "sn: test\n"
        )
        parse_result = api.parse_ldif(ldif_content)

        parse_response = parse_result.unwrap()
        entries = parse_response.entries
        acl_service = ldif()
        for entry in entries:
            acl_result = acl_service.extract_acls_from_entry(
                entry, server_type="openldap"
            )
            if acl_result.success:
                acl_response = acl_result.unwrap()
                acls = acl_response.acls
                if acls:
                    _ = (str(entry.dn), len(acls))

    @staticmethod
    def execute_acl_service() -> None:
        """Execute ACL service with entry data."""
        m.Ldif.Entry.create(
            dn="ou=Test,dc=example,dc=com",
            attributes={
                "objectClass": ["organizationalUnit"],
                "ou": ["Test"],
                "aci": [
                    (
                        '(target="ldap:///ou=Test,dc=example,dc=com")'
                        '(targetattr="*")'
                        '(version 3.0; acl "Test ACL"; allow (read) '
                        'userdn="ldap:///anyone";)'
                    ),
                ],
            },
        )

        acl_service = ldif()
        exec_result = acl_service.service_check()
        if exec_result.success:
            _ = exec_result.unwrap()

    @staticmethod
    def acl_pipeline() -> None:
        """Complete ACL processing pipeline."""
        parsed = ExamplesFlextLdifAclProcessing._parse_first_entry_with_acls(
            (
                "dn: ou=Pipeline,dc=example,dc=com\nobjectClass: "
                "organizationalUnit\nou: Pipeline\n"
                'aci: (target="ldap:///ou=Pipeline,dc=example,dc=com")'
                '(targetattr="*")'
                '(version 3.0; acl "Pipeline ACL"; '
                'allow (read,search) userdn="ldap:///anyone";)\n'
            ),
        )
        if parsed is None:
            return
        entry, acl_response = parsed
        required_perms: t.MutableBoolMapping = {"read": True}
        eval_result = ldif().evaluate_acl_context(
            acl_response.acls,
            required_perms,
        )
        if eval_result.success:
            ldif().validate_entries([entry])

    @staticmethod
    def main() -> None:
        """Run all ACL processing examples."""
        ExamplesFlextLdifAclProcessing.extract_acls_from_entry()
        ExamplesFlextLdifAclProcessing.parse_and_evaluate_acls()
        ExamplesFlextLdifAclProcessing.process_entries_with_acls()
        ExamplesFlextLdifAclProcessing.execute_acl_service()
        ExamplesFlextLdifAclProcessing.acl_pipeline()


# Module-level rebinding of the namespace surface: the ``__main__`` entry
# point resolves the runner as a module attribute.
main = ExamplesFlextLdifAclProcessing.main

__all__: list[str] = ["ExamplesFlextLdifAclProcessing", "main"]
