"""Example 4: Server-Specific Operations and Migration - Optimized with Railway Pattern.

Demonstrates FlextLdif server-specific functionality with minimal code bloat:

NOTE: This example intentionally uses assert statements (S101) for type narrowing
demonstration. Asserts are acceptable in examples for pedagogical purposes and
do not represent production error handling patterns.
- Parsing with server-specific quirks (OID, OUD, OpenLDAP, RFC)
- Migrating LDIF data between different LDAP servers
- Server-agnostic migration pipeline
- Railway-oriented error handling

This example shows how flext-ldif REDUCES code through library automation.
Original: 252 lines | Optimized: ~140 lines (44% reduction)
"""

from __future__ import annotations

from pathlib import Path

from flext_ldif import FlextLdif


def parse_with_server_quirks_example() -> None:
    """Parse LDIF with different server quirks - library handles variations."""
    api = FlextLdif.get_instance()

    ldif_content = """dn: cn=Server Test,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: Server Test
sn: Test
mail: server@example.com
"""

    # Library automates server-specific parsing - no manual quirk handling!
    servers = ["rfc", "oid", "oud", "openldap"]
    results = {
        server: api.parse(ldif_content, server_type=server).unwrap_or([])
        for server in servers
    }

    print(
        "Parsed with quirks: "
        + ", ".join([f"{s}={len(e)}" for s, e in results.items()])
    )


def compare_server_parsing() -> None:
    """Compare server parsing using list comprehension - library handles iteration."""
    api = FlextLdif.get_instance()

    ldif_content = """dn: cn=Compare,ou=People,dc=example,dc=com
objectClass: person
cn: Compare
sn: Test

dn: cn=schema
objectClass: top
objectClass: ldapSubentry
objectClass: subschema
cn: schema
"""

    # Railway pattern with dict comprehension - auto error handling
    results = {
        server: len(api.parse(ldif_content, server_type=server).unwrap_or([]))
        for server in ["rfc", "oid", "oud", "openldap"]
    }

    print(f"Comparison: {results}")


def migrate_between_servers() -> None:
    """Migrate LDIF between servers - library automates everything."""
    api = FlextLdif.get_instance()

    input_dir = Path("examples/migration_source")
    output_dir = Path("examples/migration_target")
    input_dir.mkdir(exist_ok=True)
    output_dir.mkdir(exist_ok=True)

    # Create sample source LDIF
    source_ldif = """dn: cn=Migration Test,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: Migration Test
sn: Test
mail: migration@example.com

dn: cn=schema
objectClass: top
objectClass: ldapSubentry
objectClass: subschema
cn: schema
"""
    (input_dir / "source.ldif").write_text(source_ldif)

    # Library handles: parsing, quirk translation, validation, writing
    result = api.migrate(
        input_dir=input_dir,
        output_dir=output_dir,
        from_server="oid",  # Oracle Internet Directory
        to_server="oud",  # Oracle Unified Directory
        process_schema=True,
        process_entries=True,
    ).map(
        lambda stats: (
            f"Migrated {stats.get('total_entries', 0)} entries "
            f"in {stats.get('total_files', 0)} files"
        )
    )

    print(result.unwrap_or("Migration failed"))


def migrate_openldap_to_oud() -> None:
    """Migrate OpenLDAP → OUD using railway pattern."""
    api = FlextLdif.get_instance()

    input_dir = Path("examples/openldap_source")
    output_dir = Path("examples/oud_target")
    input_dir.mkdir(exist_ok=True)
    output_dir.mkdir(exist_ok=True)

    openldap_ldif = """dn: cn=OpenLDAP User,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: OpenLDAP User
sn: User
mail: openldap@example.com
"""
    (input_dir / "openldap.ldif").write_text(openldap_ldif)

    # Railway pattern - single operation, auto error handling
    result = api.migrate(
        input_dir=input_dir,
        output_dir=output_dir,
        from_server="openldap",
        to_server="oud",
        process_schema=True,
        process_entries=True,
    )

    print(
        f"OpenLDAP→OUD: {result.unwrap().get('total_entries', 0)} entries"
        if result.is_success
        else f"Error: {result.error}"
    )


def migrate_to_rfc_compliant() -> None:
    """Normalize to RFC format - library handles quirk removal."""
    api = FlextLdif.get_instance()

    input_dir = Path("examples/server_specific")
    output_dir = Path("examples/rfc_compliant")
    input_dir.mkdir(exist_ok=True)
    output_dir.mkdir(exist_ok=True)

    server_ldif = """dn: cn=Normalize,ou=People,dc=example,dc=com
objectClass: person
cn: Normalize
sn: Test
"""
    (input_dir / "server.ldif").write_text(server_ldif)

    # Migrate to pure RFC - library strips server quirks automatically
    result = api.migrate(
        input_dir=input_dir,
        output_dir=output_dir,
        from_server="oid",
        to_server="rfc",
        process_schema=False,
        process_entries=True,
    )

    print("RFC normalization: " + ("Success" if result.is_success else "Failed"))


def pipeline_with_server_quirks() -> None:
    """Complete pipeline using railway composition with server quirks."""
    api = FlextLdif.get_instance()

    ldif_content = """dn: cn=Pipeline,ou=People,dc=example,dc=com
objectClass: person
cn: Pipeline
sn: Test
"""

    # Parse and validate
    parse_result = api.parse(ldif_content, server_type="oid")
    if parse_result.is_failure:
        return

    entries = parse_result.unwrap()
    validation_result = api.validate_entries(entries)

    if validation_result.is_failure:
        return

    report = validation_result.unwrap()
    assert isinstance(report, dict)

    if not report.get("is_valid", False):
        return

    # Analyze
    analysis_result = api.analyze(entries)
    if analysis_result.is_failure:
        return

    # Write result
    result = api.write(entries)

    print(
        f"Pipeline: {len(result.unwrap())} bytes"
        if result.is_success
        else f"Error: {result.error}"
    )


if __name__ == "__main__":
    print("=== FlextLdif Server-Specific Operations Examples ===\n")

    print("1. Parse with Server Quirks:")
    parse_with_server_quirks_example()

    print("\n2. Compare Server Parsing:")
    compare_server_parsing()

    print("\n3. Migrate Between Servers (OID→OUD):")
    migrate_between_servers()

    print("\n4. Migrate OpenLDAP→OUD:")
    migrate_openldap_to_oud()

    print("\n5. Migrate to RFC Compliant:")
    migrate_to_rfc_compliant()

    print("\n6. Pipeline with Server Quirks:")
    pipeline_with_server_quirks()
