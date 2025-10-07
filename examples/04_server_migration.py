"""Example 4: Server-Specific Operations and Migration.

Demonstrates FlextLdif server-specific functionality:
- Parsing with server-specific quirks (OID, OUD, OpenLDAP, RFC)
- Migrating LDIF data between different LDAP servers
- Server-agnostic migration pipeline
- Handling server-specific attributes and schema

All functionality accessed through FlextLdif facade.
"""

from __future__ import annotations

from pathlib import Path

from flext_ldif import FlextLdif


def parse_with_server_quirks() -> None:
    """Parse LDIF with server-specific quirks."""
    api = FlextLdif.get_instance()

    # Sample LDIF content that might have server-specific elements
    ldif_content = """dn: cn=Server Test,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: Server Test
sn: Test
mail: server@example.com
"""

    # Parse as RFC-compliant (default)
    rfc_result = api.parse(ldif_content, server_type="rfc")

    if rfc_result.is_success:
        rfc_entries = rfc_result.unwrap()
        _ = len(rfc_entries)

    # Parse with OID (Oracle Internet Directory) quirks
    oid_result = api.parse(ldif_content, server_type="oid")

    if oid_result.is_success:
        oid_entries = oid_result.unwrap()
        _ = len(oid_entries)

    # Parse with OUD (Oracle Unified Directory) quirks
    oud_result = api.parse(ldif_content, server_type="oud")

    if oud_result.is_success:
        oud_entries = oud_result.unwrap()
        _ = len(oud_entries)

    # Parse with OpenLDAP quirks
    openldap_result = api.parse(ldif_content, server_type="openldap")

    if openldap_result.is_success:
        openldap_entries = openldap_result.unwrap()
        _ = len(openldap_entries)


def compare_server_parsing() -> None:
    """Compare how different servers parse the same LDIF."""
    api = FlextLdif.get_instance()

    # LDIF with potential server-specific variations
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

    server_types = ["rfc", "oid", "oud", "openldap"]
    results = {}

    for server_type in server_types:
        result = api.parse(ldif_content, server_type=server_type)

        if result.is_success:
            entries = result.unwrap()
            results[server_type] = len(entries)

    # Compare results across server types
    _ = results


def migrate_between_servers() -> None:
    """Migrate LDIF files between different LDAP servers."""
    api = FlextLdif.get_instance()

    # Create test directories
    input_dir = Path("examples/migration_source")
    output_dir = Path("examples/migration_target")

    input_dir.mkdir(exist_ok=True)
    output_dir.mkdir(exist_ok=True)

    # Create sample source LDIF (OID format)
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

    # Migrate from OID to OUD
    migration_result = api.migrate(
        input_dir=input_dir,
        output_dir=output_dir,
        from_server="oid",  # Oracle Internet Directory
        to_server="oud",  # Oracle Unified Directory
        process_schema=True,
        process_entries=True,
    )

    if migration_result.is_success:
        stats = migration_result.unwrap()

        # Migration statistics
        total_entries = stats.get("total_entries", 0)
        total_files = stats.get("total_files", 0)
        output_files = stats.get("output_files", [])

        _ = (total_entries, total_files, output_files)
    else:
        _ = migration_result.error


def migrate_openldap_to_oud() -> None:
    """Migrate from OpenLDAP to Oracle Unified Directory."""
    api = FlextLdif.get_instance()

    input_dir = Path("examples/openldap_source")
    output_dir = Path("examples/oud_target")

    input_dir.mkdir(exist_ok=True)
    output_dir.mkdir(exist_ok=True)

    # OpenLDAP LDIF content
    openldap_ldif = """dn: cn=OpenLDAP User,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: OpenLDAP User
sn: User
mail: openldap@example.com
"""

    (input_dir / "openldap.ldif").write_text(openldap_ldif)

    # Migrate OpenLDAP → OUD
    migration_result = api.migrate(
        input_dir=input_dir,
        output_dir=output_dir,
        from_server="openldap",
        to_server="oud",
        process_schema=True,
        process_entries=True,
    )

    if migration_result.is_success:
        stats = migration_result.unwrap()
        _ = stats.get("total_entries", 0)


def migrate_to_rfc_compliant() -> None:
    """Migrate server-specific LDIF to RFC-compliant format."""
    api = FlextLdif.get_instance()

    input_dir = Path("examples/server_specific")
    output_dir = Path("examples/rfc_compliant")

    input_dir.mkdir(exist_ok=True)
    output_dir.mkdir(exist_ok=True)

    # Server-specific LDIF
    server_ldif = """dn: cn=Normalize,ou=People,dc=example,dc=com
objectClass: person
cn: Normalize
sn: Test
"""

    (input_dir / "server.ldif").write_text(server_ldif)

    # Migrate to RFC-compliant
    migration_result = api.migrate(
        input_dir=input_dir,
        output_dir=output_dir,
        from_server="oid",
        to_server="rfc",  # Target pure RFC format
        process_schema=False,  # Only process entries
        process_entries=True,
    )

    if migration_result.is_success:
        stats = migration_result.unwrap()
        _ = stats


def pipeline_with_server_quirks() -> None:
    """Complete pipeline using server-specific parsing."""
    api = FlextLdif.get_instance()

    # Parse with server quirks
    ldif_content = """dn: cn=Pipeline,ou=People,dc=example,dc=com
objectClass: person
cn: Pipeline
sn: Test
"""

    # Parse from source server (OID)
    parse_result = api.parse(ldif_content, server_type="oid")

    if parse_result.is_failure:
        return

    entries = parse_result.unwrap()

    # Validate entries
    validation_result = api.validate_entries(entries)

    if validation_result.is_failure:
        return

    # Analyze entries
    analysis_result = api.analyze(entries)

    if analysis_result.is_failure:
        return

    stats = analysis_result.unwrap()

    # Write entries (RFC-compliant output)
    write_result = api.write(entries)

    if write_result.is_success:
        ldif_output = write_result.unwrap()
        _ = (stats, len(ldif_output))
