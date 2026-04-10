"""Example 6: ACL (Access Control List) Processing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Demonstrates ldif ACL-related functionality:
- Extracting ACLs from LDIF entries
- Parsing ACL attributes
- Evaluating ACLs against context
- Working with ACL components

All functionality accessed through ldif facade and FlextLdifAcl service.
"""

from __future__ import annotations

from flext_ldif import FlextLdifAcl, ldif, m, t


def _get_acl_service() -> FlextLdifAcl:
    """Create an ACL service instance."""
    return FlextLdifAcl()


def extract_acls_from_entry() -> None:
    """Extract ACL information from an LDIF entry."""
    api = ldif.get_instance()
    ldif_content = 'dn: cn=test,ou=People,dc=example,dc=com\nobjectClass: person\ncn: test\nsn: user\naci: (target="ldap:///ou=People,dc=example,dc=com")(targetattr="*")(version 3.0; acl "Allow read"; allow (read,search) userdn="ldap:///anyone";)\n'
    parse_result = api.parse_ldif(ldif_content)
    if parse_result.is_failure:
        return
    parse_response = parse_result.unwrap()
    entries = parse_response.entries
    if not entries:
        return
    entry = entries[0]
    acl_service = _get_acl_service()
    acl_result = acl_service.extract_acls_from_entry(entry, server_type="openldap")
    if acl_result.is_success:
        acl_response = acl_result.unwrap()
        acls = acl_response.acls
        _ = len(acls)


def parse_and_evaluate_acls() -> None:
    """Parse ACL attributes and evaluate against context."""
    api = ldif.get_instance()
    ldif_content = 'dn: ou=People,dc=example,dc=com\nobjectClass: organizationalUnit\nou: People\naci: (target="ldap:///ou=People,dc=example,dc=com")(targetattr="cn || sn")(version 3.0; acl "Allow self write"; allow (write) userdn="ldap:///self";)\naci: (target="ldap:///ou=People,dc=example,dc=com")(targetattr="*")(version 3.0; acl "Allow admin all"; allow (all) userdn="ldap:///cn=admin,dc=example,dc=com";)\n'
    parse_result = api.parse_ldif(ldif_content)
    if parse_result.is_failure:
        return
    parse_response = parse_result.unwrap()
    entries = parse_response.entries
    if not entries:
        return
    entry = entries[0]
    acl_service = _get_acl_service()
    acl_result = acl_service.extract_acls_from_entry(entry, server_type="openldap")
    if acl_result.is_failure:
        return
    acl_response = acl_result.unwrap()
    acls = acl_response.acls
    required_perms: t.MutableBoolMapping = {"read": True, "write": True}
    evaluation_result = acl_service.evaluate_acl_context(acls, required_perms)
    if evaluation_result.is_success:
        _ = evaluation_result.unwrap()


def process_entries_with_acls() -> None:
    """Process entries that contain ACL information."""
    api = ldif.get_instance()
    ldif_content = 'dn: ou=People,dc=example,dc=com\nobjectClass: organizationalUnit\nou: People\naci: (target="ldap:///ou=People,dc=example,dc=com")(targetattr="*")(version 3.0; acl "Read access"; allow (read) userdn="ldap:///anyone";)\n\ndn: ou=Groups,dc=example,dc=com\nobjectClass: organizationalUnit\nou: Groups\naci: (target="ldap:///ou=Groups,dc=example,dc=com")(targetattr="*")(version 3.0; acl "Admin access"; allow (all) userdn="ldap:///cn=admin,dc=example,dc=com";)\n\ndn: cn=user,ou=People,dc=example,dc=com\nobjectClass: person\ncn: user\nsn: test\n'
    parse_result = api.parse_ldif(ldif_content)
    if parse_result.is_failure:
        return
    parse_response = parse_result.unwrap()
    entries = parse_response.entries
    acl_service = _get_acl_service()
    for entry in entries:
        acl_result = acl_service.extract_acls_from_entry(entry, server_type="openldap")
        if acl_result.is_success:
            acl_response = acl_result.unwrap()
            acls = acl_response.acls
            if acls:
                _ = (str(entry.dn), len(acls))


def execute_acl_service() -> None:
    """Execute ACL service with entry data."""
    entry_result = m.Ldif.Entry.create(
        dn="ou=Test,dc=example,dc=com",
        attributes={
            "objectClass": ["organizationalUnit"],
            "ou": ["Test"],
            "aci": [
                '(target="ldap:///ou=Test,dc=example,dc=com")(targetattr="*")(version 3.0; acl "Test ACL"; allow (read) userdn="ldap:///anyone";)',
            ],
        },
    )
    if entry_result.is_failure:
        return
    acl_service = _get_acl_service()
    exec_result = acl_service.execute()
    if exec_result.is_success:
        _ = exec_result.unwrap()


def acl_pipeline() -> None:
    """Complete ACL processing pipeline."""
    api = ldif.get_instance()
    ldif_content = 'dn: ou=Pipeline,dc=example,dc=com\nobjectClass: organizationalUnit\nou: Pipeline\naci: (target="ldap:///ou=Pipeline,dc=example,dc=com")(targetattr="*")(version 3.0; acl "Pipeline ACL"; allow (read,search) userdn="ldap:///anyone";)\n'
    parse_result = api.parse_ldif(ldif_content)
    if parse_result.is_failure:
        return
    parse_response = parse_result.unwrap()
    entries = parse_response.entries
    if not entries:
        return
    entry = entries[0]
    acl_service = _get_acl_service()
    acl_result = acl_service.extract_acls_from_entry(entry, server_type="openldap")
    if acl_result.is_failure:
        return
    acl_response = acl_result.unwrap()
    acls = acl_response.acls
    required_perms: t.MutableBoolMapping = {"read": True}
    eval_result = acl_service.evaluate_acl_context(acls, required_perms)
    if eval_result.is_success:
        api.validate_entries([entry])


def main() -> None:
    """Run all ACL processing examples."""
    extract_acls_from_entry()
    parse_and_evaluate_acls()
    process_entries_with_acls()
    execute_acl_service()
    acl_pipeline()
