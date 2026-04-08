"""Complete LDIF processing workflow examples.

Copyright (c) 2025 FLEXT Team. All rights reserved.
"""

from __future__ import annotations

from collections.abc import MutableSequence
from datetime import UTC, datetime
from pathlib import Path

from flext_ldif import c, ldif, m


def complete_ldif_processing_workflow() -> None:
    """Run a complete LDIF processing workflow."""
    api = ldif.get_instance()
    content = "dn: cn=Workflow User,dc=example,dc=com\nobjectClass: person\ncn: Workflow User\nsn: User\n"
    parse_result = api.parse_ldif(content, server_type="rfc")
    if parse_result.is_failure:
        return
    entries = parse_result.value.entries
    validation_result = api.validate_entries(entries)
    if validation_result.is_failure:
        return
    _ = validation_result.value.total_entries
    _ = api.write_ldif_file(entries, Path("examples/workflow_output.ldif"))


def server_migration_workflow() -> None:
    """Run a server migration workflow."""
    api = ldif.get_instance()
    source_dir = Path("examples/workflow_source")
    target_dir = Path("examples/workflow_target")
    source_dir.mkdir(exist_ok=True)
    target_dir.mkdir(exist_ok=True)
    source_file = source_dir / "source.ldif"
    source_file.write_text(
        "dn: cn=Migration User,dc=example,dc=com\nobjectClass: person\ncn: Migration User\nsn: User\n",
        encoding="utf-8",
    )
    migration_result = api.migrate(
        input_dir=source_dir,
        output_dir=target_dir,
        source_server="rfc",
        target_server="rfc",
    )
    if migration_result.is_failure:
        return
    for entry in migration_result.value.entries:
        _ = entry.dn


def entry_building_and_processing_workflow() -> None:
    """Run an entry building and processing workflow."""
    api = ldif.get_instance()
    created: list[m.Ldif.Entry] = []
    for idx in range(2):
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=f"cn=User{idx},ou=People,dc=example,dc=com"),
            attributes=m.Ldif.Attributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": [f"User{idx}"],
                    "sn": ["User"],
                },
                attribute_metadata={},
            ),
        )
        created.append(entry)
    if not created:
        return
    if api.validate_entries(created).is_failure:
        return
    persons: MutableSequence[m.Ldif.Entry] = [
        e
        for e in created
        if e.attributes is not None and "person" in e.attributes["objectClass"]
    ]
    _ = api.write(persons)


def schema_driven_workflow() -> None:
    """Run a schema driven workflow."""
    entries: list[m.Ldif.Entry] = []
    for idx in range(5):
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=f"cn=Schema User {idx},ou=People,dc=example,dc=com"),
            attributes=m.Ldif.Attributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": [f"Schema User {idx}"],
                    "sn": ["User"],
                },
                attribute_metadata={},
            ),
        )
        entries.append(entry)
    _ = entries


def acl_processing_workflow() -> None:
    """Run an ACL processing workflow."""
    api = ldif.get_instance()
    ldif_content = 'dn: ou=Secure,dc=example,dc=com\nobjectClass: organizationalUnit\nou: Secure\naci: (targetattr="*")(version 3.0; acl "a"; allow (read) userdn="ldap:///anyone";)\n'
    parse_result = api.parse_ldif(ldif_content)
    if parse_result.is_failure:
        return
    for entry in parse_result.value.entries:
        if entry.attributes is not None and "aci" in entry.attributes.attributes:
            _ = entry.attributes["aci"]


def batch_processing_workflow() -> None:
    """Run a batch processing workflow."""
    api = ldif.get_instance()
    entries: list[m.Ldif.Entry] = []
    for idx in range(10):
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=f"cn=BatchUser{idx},ou=People,dc=example,dc=com"),
            attributes=m.Ldif.Attributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": [f"BatchUser{idx}"],
                    "sn": ["User"],
                },
                attribute_metadata={},
            ),
        )
        entries.append(entry)
    validation_result = api.validate_entries(entries)
    if validation_result.is_success:
        _ = validation_result.value.total_entries


def access_all_namespace_classes() -> None:
    """Access all namespace classes."""
    entry = m.Ldif.Entry(
        dn=m.Ldif.DN(value="cn=test,dc=example,dc=com"),
        attributes=m.Ldif.Attributes(
            attributes={"objectClass": ["person"], "cn": ["test"], "sn": ["user"]},
            attribute_metadata={},
        ),
    )
    _ = entry
    _ = c.Ldif.DEFAULT_LINE_WIDTH
    _ = c.Ldif.Encoding.UTF8
    _ = datetime.now(UTC).timestamp()


def error_handling_and_recovery() -> None:
    """Run an error handling and recovery workflow."""
    api = ldif.get_instance()
    parse_result = api.parse_ldif(
        "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n",
    )
    if parse_result.is_failure:
        return
    entries = parse_result.value.entries
    validation_result = api.validate_entries(entries)
    if validation_result.is_failure:
        return
    report = validation_result.value
    if not report.is_valid:
        _ = api.validate_entries(entries)


def main() -> None:
    """Run all workflows."""
    complete_ldif_processing_workflow()
    server_migration_workflow()
    entry_building_and_processing_workflow()
    schema_driven_workflow()
    acl_processing_workflow()
    batch_processing_workflow()
    access_all_namespace_classes()
    error_handling_and_recovery()


if __name__ == "__main__":
    main()
