"""Example 6: ACL (Access Control List) Processing.

Demonstrates FlextLdif ACL-related functionality:
- Extracting ACLs from LDIF entries
- Parsing ACL attributes
- Evaluating ACLs against context
- Working with ACL components

All functionality accessed through FlextLdif facade.
"""

from __future__ import annotations

from typing import cast

from flext_ldif import FlextLdif, FlextLdifModels


def extract_acls_from_entry() -> None:
    """Extract ACL information from an LDIF entry."""
    api = FlextLdif.get_instance()

    # Entry with ACL attributes
    ldif_content = """dn: cn=test,ou=People,dc=example,dc=com
objectClass: person
cn: test
sn: user
aci: (target="ldap:///ou=People,dc=example,dc=com")(targetattr="*")(version 3.0; acl "Allow read"; allow (read,search) userdn="ldap:///anyone";)
"""

    parse_result = api.parse(ldif_content)

    if parse_result.is_failure:
        return

    entries = parse_result.unwrap()

    if not entries:
        return

    entry = entries[0]

    # Access AclService through API
    acl_service = api.acl_service

    # Extract ACLs from entry
    acl_result = acl_service.extract_acls_from_entry(entry, server_type="openldap")

    if acl_result.is_success:
        acl_response = acl_result.unwrap()
        # Access ACLs from response
        acls = acl_response.acls
        _ = len(acls)


def parse_and_evaluate_acls() -> None:
    """Parse ACL attributes and evaluate against context."""
    api = FlextLdif.get_instance()

    # Entry with multiple ACL rules
    ldif_content = """dn: ou=People,dc=example,dc=com
objectClass: organizationalUnit
ou: People
aci: (target="ldap:///ou=People,dc=example,dc=com")(targetattr="cn || sn")(version 3.0; acl "Allow self write"; allow (write) userdn="ldap:///self";)
aci: (target="ldap:///ou=People,dc=example,dc=com")(targetattr="*")(version 3.0; acl "Allow REDACTED_LDAP_BIND_PASSWORD all"; allow (all) userdn="ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com";)
"""

    parse_result = api.parse(ldif_content)

    if parse_result.is_failure:
        return

    entries = parse_result.unwrap()

    if not entries:
        return

    entry = entries[0]

    acl_service = api.acl_service

    # Extract and parse ACLs
    acl_result = acl_service.extract_acls_from_entry(entry, server_type="openldap")

    if acl_result.is_failure:
        return

    acl_response = acl_result.unwrap()
    acls = acl_response.acls

    # Evaluate ACLs directly against a context
    eval_context: dict[str, object] = {
        "subject_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        "target_dn": "ou=People,dc=example,dc=com",
        "permissions": {"read": True, "write": True},
    }

    # Cast acls to FlextLdifModels.Acl for API compatibility
    acls_typed = [cast("FlextLdifModels.Acl", acl) for acl in acls]
    evaluation_result = acl_service.evaluate_acl_context(acls_typed, eval_context)

    if evaluation_result.is_success:
        allowed = evaluation_result.unwrap()
        # allowed is True if all ACL constraints are met, False otherwise
        _ = allowed


def process_entries_with_acls() -> None:
    """Process entries that contain ACL information."""
    api = FlextLdif.get_instance()

    # Multiple entries with different ACLs
    ldif_content = """dn: ou=People,dc=example,dc=com
objectClass: organizationalUnit
ou: People
aci: (target="ldap:///ou=People,dc=example,dc=com")(targetattr="*")(version 3.0; acl "Read access"; allow (read) userdn="ldap:///anyone";)

dn: ou=Groups,dc=example,dc=com
objectClass: organizationalUnit
ou: Groups
aci: (target="ldap:///ou=Groups,dc=example,dc=com")(targetattr="*")(version 3.0; acl "Admin access"; allow (all) userdn="ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com";)

dn: cn=user,ou=People,dc=example,dc=com
objectClass: person
cn: user
sn: test
"""

    parse_result = api.parse(ldif_content)

    if parse_result.is_failure:
        return

    entries = parse_result.unwrap()

    acl_service = api.acl_service

    # Process each entry for ACLs
    for entry in entries:
        acl_result = acl_service.extract_acls_from_entry(entry, server_type="openldap")

        if acl_result.is_success:
            acl_response = acl_result.unwrap()
            acls = acl_response.acls

            if acls:
                # Entry has ACLs
                _ = (entry.dn, len(acls))


def execute_acl_service() -> None:
    """Execute ACL service with entry data."""
    api = FlextLdif.get_instance()

    # Entry with ACL
    entry_result = api.models.Entry.create(
        dn="ou=Test,dc=example,dc=com",
        attributes={
            "objectClass": ["organizationalUnit"],
            "ou": ["Test"],
            "aci": [
                (
                    '(target="ldap:///ou=Test,dc=example,dc=com")'
                    '(targetattr="*")'
                    '(version 3.0; acl "Test ACL"; allow (read) userdn="ldap:///anyone";)'
                ),
            ],
        },
    )
    if entry_result.is_failure:
        return
    entry_result.unwrap()

    acl_service = api.acl_service

    # Execute service (no parameters needed)
    exec_result = acl_service.execute()

    if exec_result.is_success:
        acl_data = exec_result.unwrap()
        # Result contains service status
        _ = acl_data


def acl_pipeline() -> None:
    """Complete ACL processing pipeline."""
    api = FlextLdif.get_instance()

    # Parse entry with ACLs
    ldif_content = """dn: ou=Pipeline,dc=example,dc=com
objectClass: organizationalUnit
ou: Pipeline
aci: (target="ldap:///ou=Pipeline,dc=example,dc=com")(targetattr="*")(version 3.0; acl "Pipeline ACL"; allow (read,search) userdn="ldap:///anyone";)
"""

    parse_result = api.parse(ldif_content)

    if parse_result.is_failure:
        return

    entries = parse_result.unwrap()

    if not entries:
        return

    entry = entries[0]

    # Extract ACLs
    acl_service = api.acl_service
    acl_result = acl_service.extract_acls_from_entry(entry, server_type="openldap")

    if acl_result.is_failure:
        return

    acl_response = acl_result.unwrap()
    acls = acl_response.acls

    # Evaluate ACLs against an anonymous user context
    eval_context: dict[str, object] = {
        "subject_dn": "cn=anonymous",
        "permissions": {"read": True},
    }

    # Cast acls to FlextLdifModels.Acl for API compatibility
    acls_typed = [cast("FlextLdifModels.Acl", acl) for acl in acls]
    eval_result = acl_service.evaluate_acl_context(acls_typed, eval_context)

    if eval_result.is_success:
        # Validate entry
        validation_result = api.validate_entries([entry])

        if validation_result.is_success:
            # ACL validation successful
            pass


def main() -> None:
    """Run all ACL processing examples."""
    extract_acls_from_entry()
    parse_and_evaluate_acls()
    process_entries_with_acls()
    execute_acl_service()
    acl_pipeline()
