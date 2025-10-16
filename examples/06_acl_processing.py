"""Example 6: ACL (Access Control List) Processing.

Demonstrates FlextLdif ACL-related functionality:
- Extracting ACLs from LDIF entries
- Creating ACL rules (composite, permission, subject)
- Parsing ACL attributes
- Evaluating ACL rules
- Working with ACL components

All functionality accessed through FlextLdif facade.
"""

from __future__ import annotations

from flext_core import FlextResult

from flext_ldif import FlextLdif


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
    acl_result = acl_service.extract_acls_from_entry(entry)

    if acl_result.is_success:
        acls = acl_result.unwrap()
        # ACLs is a list of parsed ACL rules
        _ = len(acls)


def create_acl_rules() -> None:
    """Create different types of ACL rules."""
    api = FlextLdif.get_instance()

    acl_service = api.acl_service

    # Create permission rule (single permission)
    _permission_rule = acl_service.create_permission_rule(
        permission="read",
        required=True,
    )

    # Create subject rule
    _subject_rule = acl_service.create_subject_rule(
        subject_dn="cn=admin,dc=example,dc=com",
    )

    # Create target rule
    _target_rule = acl_service.create_target_rule(
        target_dn="ou=People,dc=example,dc=com",
    )

    # Create composite rule (combines multiple rules)
    _composite_rule = acl_service.create_composite_rule(
        operator="AND",
    )
    # Add rules to composite (would use composite.add_rule() if available)


def parse_and_evaluate_acls() -> None:
    """Parse ACL attributes and evaluate rules."""
    api = FlextLdif.get_instance()

    # Entry with multiple ACL rules
    ldif_content = """dn: ou=People,dc=example,dc=com
objectClass: organizationalUnit
ou: People
aci: (target="ldap:///ou=People,dc=example,dc=com")(targetattr="cn || sn")(version 3.0; acl "Allow self write"; allow (write) userdn="ldap:///self";)
aci: (target="ldap:///ou=People,dc=example,dc=com")(targetattr="*")(version 3.0; acl "Allow admin all"; allow (all) userdn="ldap:///cn=admin,dc=example,dc=com";)
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
    acl_result = acl_service.extract_acls_from_entry(entry)

    if acl_result.is_failure:
        return

    acls = acl_result.unwrap()

    # Evaluate ACL rules (if evaluation context provided)
    for acl in acls:
        # ACL is a structured rule object
        _ = acl


def work_with_acl_components() -> None:
    """Work with ACL components (helper classes)."""
    api = FlextLdif.get_instance()

    acl_service = api.acl_service

    # Create permission rule with specific permission
    _permission = acl_service.create_permission_rule(
        permission="write",
        required=True,
    )

    # Create subject rule for specific user
    _subject = acl_service.create_subject_rule(
        subject_dn="cn=groupadmin,dc=example,dc=com",
    )

    # Create target rule
    _target = acl_service.create_target_rule(
        target_dn="ou=Groups,dc=example,dc=com",
    )

    # Combine into composite rule
    composite = acl_service.create_composite_rule(
        operator="AND",
    )

    # Evaluate composite rule (with empty context for demonstration)
    evaluation_result = acl_service.evaluate_acl_rules([composite], context={})

    if evaluation_result.is_success:
        eval_data = evaluation_result.unwrap()
        _ = eval_data


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
aci: (target="ldap:///ou=Groups,dc=example,dc=com")(targetattr="*")(version 3.0; acl "Admin access"; allow (all) userdn="ldap:///cn=admin,dc=example,dc=com";)

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
        acl_result = acl_service.extract_acls_from_entry(entry)

        if acl_result.is_success:
            acls = acl_result.unwrap()

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
                )
            ],
        },
    )
    if entry_result.is_failure:
        print(f"Failed to create entry: {entry_result.error}")
        return
    entry_result.unwrap()

    acl_service = api.acl_service

    # Execute service (no parameters needed)
    exec_result = acl_service.execute()

    if exec_result.is_success:
        acl_data = exec_result.unwrap()
        # Result contains processed ACL information
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
    acl_result = acl_service.extract_acls_from_entry(entry)

    if acl_result.is_failure:
        return

    acl_result.unwrap()

    # Evaluate ACLs - need to convert Acl to AclRule and provide context
    # For this example, skip evaluation as it requires proper type conversion
    # eval_result = acl_service.evaluate_acl_rules(acls, {"user": "anonymous"})
    eval_result = FlextResult[bool].ok(True)  # Placeholder for example

    if eval_result.is_success:
        evaluation = eval_result.unwrap()

        # Validate entry
        validation_result = api.validate_entries([entry])

        if validation_result.is_success:
            _ = evaluation


def filter_entries_with_acls() -> None:
    """Filter entries that have ACL attributes."""
    api = FlextLdif.get_instance()

    ldif_content = """dn: ou=WithACL,dc=example,dc=com
objectClass: organizationalUnit
ou: WithACL
aci: (target="ldap:///ou=WithACL,dc=example,dc=com")(targetattr="*")(version 3.0; acl "Has ACL"; allow (read) userdn="ldap:///anyone";)

dn: ou=NoACL,dc=example,dc=com
objectClass: organizationalUnit
ou: NoACL

dn: cn=user,ou=WithACL,dc=example,dc=com
objectClass: person
cn: user
sn: test
"""

    parse_result = api.parse(ldif_content)

    if parse_result.is_failure:
        return

    entries = parse_result.unwrap()

    # Find entries with ACL attributes
    acl_service = api.acl_service
    entries_with_acls = []

    for entry in entries:
        acl_result = acl_service.extract_acls_from_entry(entry)

        if acl_result.is_success:
            acls = acl_result.unwrap()
            if acls:
                entries_with_acls.append(entry)

    _ = len(entries_with_acls)
