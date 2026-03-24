"""Example 6: ACL (Access Control List) Processing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Demonstrates FlextLdif ACL-related functionality:
- Extracting ACLs from LDIF entries
- Parsing ACL attributes
- Evaluating ACLs against context
- Working with ACL components

All functionality accessed through FlextLdif facade.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from flext_ldif import FlextLdif, FlextLdifModels, m, t, u


def extract_acls_from_entry() -> None:
    """Extract ACL information from an LDIF entry."""
    api = FlextLdif.get_instance()
    ldif_content = 'dn: cn=test,ou=People,dc=example,dc=com\nobjectClass: person\ncn: test\nsn: user\naci: (target="ldap:///ou=People,dc=example,dc=com")(targetattr="*")(version 3.0; acl "Allow read"; allow (read,search) userdn="ldap:///anyone";)\n'
    parse_result = api.parse(ldif_content)
    if parse_result.is_failure:
        return
    entries = parse_result.value
    if not entries:
        return
    entry = entries[0]
    acl_service = api.acl_service
    acl_result = acl_service.extract_acls_from_entry(entry, server_type="openldap")
    if acl_result.is_success:
        acl_response = acl_result.value
        acls = acl_response.acls
        _ = len(acls)


def parse_and_evaluate_acls() -> None:
    """Parse ACL attributes and evaluate against context."""
    api = FlextLdif.get_instance()
    ldif_content = 'dn: ou=People,dc=example,dc=com\nobjectClass: organizationalUnit\nou: People\naci: (target="ldap:///ou=People,dc=example,dc=com")(targetattr="cn || sn")(version 3.0; acl "Allow self write"; allow (write) userdn="ldap:///self";)\naci: (target="ldap:///ou=People,dc=example,dc=com")(targetattr="*")(version 3.0; acl "Allow REDACTED_LDAP_BIND_PASSWORD all"; allow (all) userdn="ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com";)\n'
    parse_result = api.parse(ldif_content)
    if parse_result.is_failure:
        return
    entries = parse_result.value
    if not entries:
        return
    entry = entries[0]
    acl_service = api.acl_service
    acl_result = acl_service.extract_acls_from_entry(entry, server_type="openldap")
    if acl_result.is_failure:
        return
    acl_response = acl_result.value
    acls = acl_response.acls
    eval_context: t.ContainerMapping = {
        "subject_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        "target_dn": "ou=People,dc=example,dc=com",
        "permissions": {"read": True, "write": True},
    }
    required_perms: Mapping[str, bool] = {}
    if "permissions" in eval_context and isinstance(eval_context["permissions"], dict):
        required_perms = cast("Mapping[str, bool]", eval_context["permissions"])
    acls_for_eval = [m.Ldif.Acl.model_validate(acl) for acl in acls]
    evaluation_result = api.acl_service.evaluate_acl_context(
        acls_for_eval, required_perms
    )
    if evaluation_result.is_success:
        allowed = evaluation_result.value
        _ = allowed


def process_entries_with_acls() -> None:
    """Process entries that contain ACL information."""
    api = FlextLdif.get_instance()
    ldif_content = 'dn: ou=People,dc=example,dc=com\nobjectClass: organizationalUnit\nou: People\naci: (target="ldap:///ou=People,dc=example,dc=com")(targetattr="*")(version 3.0; acl "Read access"; allow (read) userdn="ldap:///anyone";)\n\ndn: ou=Groups,dc=example,dc=com\nobjectClass: organizationalUnit\nou: Groups\naci: (target="ldap:///ou=Groups,dc=example,dc=com")(targetattr="*")(version 3.0; acl "Admin access"; allow (all) userdn="ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com";)\n\ndn: cn=user,ou=People,dc=example,dc=com\nobjectClass: person\ncn: user\nsn: test\n'
    parse_result = api.parse(ldif_content)
    if parse_result.is_failure:
        return
    entries = parse_result.value
    acl_service = api.acl_service

    def process_entry_acls(entry: FlextLdifModels.Ldif.Entry) -> tuple[str, int] | None:
        """Extract ACLs from entry."""
        acl_result = acl_service.extract_acls_from_entry(entry, server_type="openldap")
        if acl_result.is_success:
            acl_response = acl_result.value
            acls = acl_response.acls
            if acls:
                return (str(entry.dn), len(acls))
        return None

    _ = u.process(entries, process_entry_acls, on_error="skip")


def execute_acl_service() -> None:
    """Execute ACL service with entry data."""
    api = FlextLdif.get_instance()
    entry_result = api.models.Ldif.Entry.create(
        dn="ou=Test,dc=example,dc=com",
        attributes={
            "objectClass": ["organizationalUnit"],
            "ou": ["Test"],
            "aci": [
                '(target="ldap:///ou=Test,dc=example,dc=com")(targetattr="*")(version 3.0; acl "Test ACL"; allow (read) userdn="ldap:///anyone";)'
            ],
        },
    )
    if entry_result.is_failure:
        return
    acl_service = api.acl_service
    exec_result = acl_service.execute()
    if exec_result.is_success:
        acl_data = exec_result.value
        _ = acl_data


def acl_pipeline() -> None:
    """Complete ACL processing pipeline."""
    api = FlextLdif.get_instance()
    ldif_content = 'dn: ou=Pipeline,dc=example,dc=com\nobjectClass: organizationalUnit\nou: Pipeline\naci: (target="ldap:///ou=Pipeline,dc=example,dc=com")(targetattr="*")(version 3.0; acl "Pipeline ACL"; allow (read,search) userdn="ldap:///anyone";)\n'
    parse_result = api.parse(ldif_content)
    if parse_result.is_failure:
        return
    entries = parse_result.value
    if not entries:
        return
    entry = entries[0]
    acl_service = api.acl_service
    acl_result = acl_service.extract_acls_from_entry(entry, server_type="openldap")
    if acl_result.is_failure:
        return
    acl_response = acl_result.value
    acls = acl_response.acls
    eval_context: t.ContainerMapping = {
        "subject_dn": "cn=anonymous",
        "permissions": {"read": True},
    }
    acls_typed = [m.Ldif.Acl.model_validate(acl) for acl in acls]
    required_perms: Mapping[str, bool] = {}
    if "permissions" in eval_context and isinstance(eval_context["permissions"], dict):
        required_perms = cast("Mapping[str, bool]", eval_context["permissions"])
    eval_result = api.acl_service.evaluate_acl_context(acls_typed, required_perms)
    if eval_result.is_success:
        validation_result = api.validate_entries([entry])
        if validation_result.is_success:
            pass


def main() -> None:
    """Run all ACL processing examples."""
    extract_acls_from_entry()
    parse_and_evaluate_acls()
    process_entries_with_acls()
    execute_acl_service()
    acl_pipeline()
