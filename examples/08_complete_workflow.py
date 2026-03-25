"""Complete LDIF processing workflow examples.

Copyright (c) 2025 FLEXT Team. All rights reserved.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from flext_ldif import FlextLdif, c, m


def complete_ldif_processing_workflow() -> None:
    """Run a complete LDIF processing workflow."""
    api = FlextLdif.get_instance()
    content = "dn: cn=Workflow User,dc=example,dc=com\nobjectClass: person\ncn: Workflow User\nsn: User\n"
    parse_result = api.parse_ldif(content, server_type="rfc")
    if parse_result.is_failure:
        return
    entries = parse_result.value
    validation_result = api.validate_entries(entries)
    if validation_result.is_failure:
        return
    stats_result = api.get_entry_statistics(entries)
    if stats_result.is_failure:
        return
    _ = stats_result.value.total_entries
    _ = api.write_ldif_file(entries, Path("examples/workflow_output.ldif"))


def server_migration_workflow() -> None:
    """Run a server migration workflow."""
    api = FlextLdif.get_instance()
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
    for path in migration_result.value.output_files:
        _ = api.parse_ldif(Path(path), server_type="rfc")


def entry_building_and_processing_workflow() -> None:
    """Run an entry building and processing workflow."""
    api = FlextLdif.get_instance()
    created: list[m.Ldif.Entry] = []
    for idx in range(2):
        create_result = api.create_entry(
            dn=f"cn=User{idx},ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": [f"User{idx}"],
                "sn": ["User"],
            },
        )
        if create_result.is_success:
            created.append(create_result.value)
    if not created:
        return
    if api.validate_entries(created).is_failure:
        return
    persons_result = api.filter_persons(created)
    if persons_result.is_failure:
        return
    _ = api.write(persons_result.value)


def schema_driven_workflow() -> None:
    """Run a schema driven workflow."""
    api = FlextLdif.get_instance()
    entries: list[m.Ldif.Entry] = []
    for idx in range(5):
        created = api.create_entry(
            dn=f"cn=Schema User {idx},ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": [f"Schema User {idx}"],
                "sn": ["User"],
            },
        )
        if created.is_success:
            entries.append(created.value)
    _ = entries


def acl_processing_workflow() -> None:
    """Run an ACL processing workflow."""
    api = FlextLdif.get_instance()
    ldif_content = 'dn: ou=Secure,dc=example,dc=com\nobjectClass: organizationalUnit\nou: Secure\naci: (targetattr="*")(version 3.0; acl "a"; allow (read) userdn="ldap:///anyone";)\n'
    parse_result = api.parse_ldif(ldif_content)
    if parse_result.is_failure:
        return
    for entry in parse_result.value:
        acl_result = api.extract_acls(entry)
        if acl_result.is_success:
            _ = acl_result.value.acls


def batch_processing_workflow() -> None:
    """Run a batch processing workflow."""
    api = FlextLdif.get_instance()
    entries: list[m.Ldif.Entry] = []
    for idx in range(10):
        result = api.create_entry(
            dn=f"cn=BatchUser{idx},ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": [f"BatchUser{idx}"],
                "sn": ["User"],
            },
        )
        if result.is_success:
            entries.append(result.value)
    if api.validate_entries(entries).is_success:
        _ = api.process_ldif("validate", entries, parallel=False)


def access_all_namespace_classes() -> None:
    """Access all namespace classes."""
    api = FlextLdif.get_instance()
    entry_result = api.models.Ldif.Entry.create(
        dn="cn=test,dc=example,dc=com",
        attributes={"objectClass": ["person"], "cn": ["test"], "sn": ["user"]},
    )
    if entry_result.is_failure:
        return
    _ = entry_result.value
    _ = c.Ldif.MAX_LINE_WIDTH
    _ = c.Ldif.Encoding.UTF8
    _ = datetime.now(UTC).timestamp()
    _ = api.ldif_config.ldif_encoding


def error_handling_and_recovery() -> None:
    """Run an error handling and recovery workflow."""
    api = FlextLdif.get_instance()
    parse_result = api.parse_ldif(
        "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n",
    )
    if parse_result.is_failure:
        return
    entries = parse_result.value
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
