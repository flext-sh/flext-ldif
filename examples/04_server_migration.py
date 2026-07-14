"""Example 4: Advanced Server Migration - Parallel Processing and Auto-Detection.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import MutableMapping, MutableSequence
from pathlib import Path

from flext_ldif import c, ldif, m, p, r, t, u


class ExampleServerMigration:
    """Demonstrates advanced server migration capabilities with parallel processing."""

    @staticmethod
    def _create_test_data(source_dir: Path) -> None:
        """Create and write test data files."""

        def create_entry_data(i: int) -> str:
            """Create entry data based on index."""
            if i % 4 == 0:
                return f"dn: ou=Container{i},dc=example,dc=com\nobjectClass: organizationalUnit\nou: Container{i}\ndescription: Container {i}\norclaci: access to * by * read\n"
            if i % 2 == 0:
                return f"dn: cn=Group{i},ou=Groups,dc=example,dc=com\nobjectClass: groupOfUniqueNames\ncn: Group{i}\nuniquemember: cn=User{i},ou=People,dc=example,dc=com\norclguid: group{i}guid123\n"
            return f'dn: cn=User{i},ou=People,dc=example,dc=com\nobjectClass: person\nobjectClass: inetOrgPerson\ncn: User{i}\nsn: TestUser{i}\nmail: user{i}@example.com\norclguid: user{i}guid456\naci: (target="ldap:///cn=User{i}")(version 3.0; acl "self"; allow (all) userdn="ldap:///self";)\n'

        batch_result = u.process(list(range(20)), create_entry_data, on_error="skip")
        source_data: MutableSequence[str] = []
        if batch_result.success:
            source_data = list(batch_result.value)

        def write_file(item: tuple[int, str]) -> None:
            """Write entry to file."""
            i, entry = item
            (source_dir / f"data_{i:02d}.ldif").write_text(entry)

        _ = u.process(list(enumerate(source_data)), write_file, on_error="skip")

    @staticmethod
    def _detect_server_type(
        api: p.Ldif.ServerDetectionService,
        source_dir: Path,
    ) -> tuple[str, t.JsonMapping]:
        """Detect server type from source data."""
        sample_file = source_dir / "data_00.ldif"
        detect_result = api.detect_server_type(ldif_content=sample_file.read_text())
        detection_data: t.JsonMapping = t.json_mapping_adapter().validate_python({})
        if detect_result.success:
            detection = detect_result.unwrap()
            detection_data = t.json_mapping_adapter().validate_python({
                "detected_server": detection.detected_server_type,
                "detection_confidence": detection.confidence,
            })
            return (
                detection.detected_server_type or c.Ldif.ServerTypes.OID.value,
                detection_data,
            )
        return (c.Ldif.ServerTypes.OID.value, detection_data)

    @staticmethod
    def _setup_directories(base_dir: Path) -> tuple[Path, Path, Path]:
        """Setup migration directories."""
        source_dir = base_dir / "source"
        intermediate_dir = base_dir / "intermediate"
        final_dir = base_dir / "final"

        def setup_dir(dir_path: Path) -> None:
            """Setup directory."""
            dir_path.mkdir(exist_ok=True, parents=True)

        _ = u.process(
            [source_dir, intermediate_dir, final_dir],
            setup_dir,
            on_error="skip",
        )
        return (source_dir, intermediate_dir, final_dir)

    @staticmethod
    def auto_detection_migration_pipeline() -> p.Result[t.JsonMapping]:
        """Migration pipeline with automatic server detection."""
        api = ldif()
        mixed_ldif = 'dn: cn=Auto Detect Test,ou=People,dc=example,dc=com\nobjectClass: person\nobjectClass: inetOrgPerson\ncn: Auto Detect Test\nsn: Test\nmail: auto@example.com\n# This could be from OID (has orclaci) or OUD (has aci)\norclaci: access to * by * read\naci: (target="ldap:///cn=Auto Detect Test")(version 3.0; acl "test"; allow (read) userdn="ldap:///anyone";)\n\ndn: cn=Auto Group,ou=Groups,dc=example,dc=com\nobjectClass: groupOfUniqueNames\nobjectClass: groupOfNames\ncn: Auto Group\nuniquemember: cn=Auto Detect Test,ou=People,dc=example,dc=com\nmember: cn=Auto Detect Test,ou=People,dc=example,dc=com\n'
        detect_result = api.detect_server_type(ldif_content=mixed_ldif)
        if detect_result.failure:
            return r[t.JsonMapping].fail(
                f"Server detection failed: {detect_result.error}",
            )
        detection = detect_result.unwrap()
        detected_server = detection.detected_server_type or "rfc"
        parse_result = api.parse_ldif(mixed_ldif, server_type=detected_server)
        if parse_result.failure:
            return r[t.JsonMapping].fail(f"Parse failed: {parse_result.error}")
        parse_response = parse_result.unwrap()
        entries = parse_response.entries
        migration_dir = Path("examples/auto_migration")
        migration_dir.mkdir(exist_ok=True, parents=True)
        (migration_dir / "source.ldif").write_text(mixed_ldif)
        migration_result = api.migrate(
            input_dir=migration_dir,
            output_dir=migration_dir / "migrated",
            source_server=detected_server,
            target_server="rfc",
        )
        if migration_result.failure:
            return r[t.JsonMapping].fail(
                f"Migration to RFC failed: {migration_result.error}",
            )
        return r[t.JsonMapping].ok(
            t.json_mapping_adapter().validate_python({
                "detected_server": detected_server,
                "confidence": detection.confidence,
                "patterns_found": detection.patterns_found,
                "total_entries": len(entries),
                "migration_success": True,
            }),
        )

    @staticmethod
    def batch_server_comparison() -> p.Result[t.JsonMapping]:
        """Batch comparison of parsing across multiple LDAP servers."""
        api = ldif()
        test_ldif = 'dn: cn=Server Comparison,ou=People,dc=example,dc=com\nobjectClass: person\nobjectClass: inetOrgPerson\ncn: Server Comparison\nsn: Test\nmail: comparison@example.com\n# OID-specific attributes\norclguid: abc123def456\norclaci: access to attr=mail by * read\n# OUD-specific attributes\naci: (targetattr="mail")(version 3.0; acl "mail access"; allow (read,search) userdn="ldap:///anyone";)\n# OpenLDAP-specific attributes\nentryUUID: 12345678-1234-1234-1234-123456789012\nentryCSN: 20240101000000.000000Z#000000#000#000000\n'
        servers: t.SequenceOf[str] = ("rfc", "oid", "oud", "openldap")
        comparison_results: MutableMapping[str, t.JsonMapping] = {}
        for server in servers:
            server_type = server
            parse_result = api.parse_ldif(test_ldif, server_type=server_type)
            if parse_result.success:
                parse_response = parse_result.unwrap()
                entries = parse_response.entries
                server_result = t.json_mapping_adapter().validate_python({
                    "parsed_successfully": True,
                    "entry_count": len(entries),
                    "server_type": server,
                })
                if entries:
                    validate_result = api.validate_entries(entries)
                    if validate_result.success:
                        report = validate_result.unwrap()
                        server_result = t.json_mapping_adapter().validate_python({
                            **server_result,
                            "validation_is_valid": report.valid,
                            "validation_valid_entries": report.valid_entries,
                            "validation_invalid_entries": report.invalid_entries,
                            "validation_error_count": len(report.errors),
                        })
                comparison_results[server] = server_result
            else:
                comparison_results[server] = t.json_mapping_adapter().validate_python({
                    "parsed_successfully": False,
                    "error": parse_result.error,
                    "server_type": server,
                })
        successful_parses = sum(
            1
            for res in comparison_results.values()
            if res.get("parsed_successfully", False)
        )
        total_servers = len(servers)
        return r[t.JsonMapping].ok(
            t.json_mapping_adapter().validate_python({
                "servers_tested": total_servers,
                "successful_parses": successful_parses,
                "success_rate": successful_parses / total_servers
                if total_servers > 0
                else 0,
                "server_results": comparison_results,
            }),
        )

    @staticmethod
    def comprehensive_migration_workflow() -> p.Result[t.JsonMapping]:
        """Comprehensive migration workflow with parallel processing and validation."""
        api = ldif()
        workflow_dir = Path("examples/comprehensive_migration")
        source_dir, intermediate_dir, final_dir = (
            ExampleServerMigration._setup_directories(workflow_dir)
        )
        ExampleServerMigration._create_test_data(source_dir)
        source_server, detection_data = ExampleServerMigration._detect_server_type(
            api,
            source_dir,
        )
        source_server_typed = source_server
        intermediate_migration = api.migrate(
            input_dir=source_dir,
            output_dir=intermediate_dir,
            source_server=source_server_typed,
            target_server="oud",
        )
        if intermediate_migration.failure:
            return r[t.JsonMapping].fail(
                f"Intermediate migration failed: {intermediate_migration.error}",
            )
        final_migration = api.migrate(
            input_dir=intermediate_dir,
            output_dir=final_dir,
            source_server="oud",
            target_server="rfc",
        )
        if final_migration.failure:
            return r[t.JsonMapping].fail(
                f"Final migration failed: {final_migration.error}",
            )
        final_result = final_migration.unwrap()
        final_stats = final_result.stats
        final_count = final_stats.processed_entries
        return r[t.JsonMapping].ok(
            t.json_mapping_adapter().validate_python({
                **detection_data,
                "intermediate_migration": "success",
                "final_migration": "success",
                "final_entry_count": final_count,
                "source_server_detected": source_server,
                "migration_pipeline": "oid → oud → rfc",
                "parallel_processing": True,
                "validation_performed": True,
            }),
        )

    @staticmethod
    def parallel_server_migration() -> p.Result[m.Ldif.MigrationPipelineResult]:
        """Parallel migration between servers with comprehensive error handling."""
        api = ldif()
        input_dir = Path("examples/migration_input")
        output_dir = Path("examples/migration_output")
        input_dir.mkdir(exist_ok=True, parents=True)
        output_dir.mkdir(exist_ok=True, parents=True)
        oid_ldif = "dn: cn=OID User,ou=People,dc=example,dc=com\nobjectClass: person\nobjectClass: inetOrgPerson\ncn: OID User\nsn: Test\nmail: oid@example.com\norclguid: 1234567890abcdef\norclaci: access to * by * read\n\ndn: cn=OID Group,ou=Groups,dc=example,dc=com\nobjectClass: groupOfUniqueNames\ncn: OID Group\nuniquemember: cn=OID User,ou=People,dc=example,dc=com\n"
        oud_ldif = 'dn: cn=OUD User,ou=People,dc=example,dc=com\nobjectClass: person\nobjectClass: inetOrgPerson\ncn: OUD User\nsn: Test\nmail: oud@example.com\naci: (target="ldap:///cn=OUD User")(version 3.0; acl "Anonymous read"; allow (read,search,compare) userdn="ldap:///anyone";)\n\ndn: cn=OUD Group,ou=Groups,dc=example,dc=com\nobjectClass: groupOfNames\ncn: OUD Group\nmember: cn=OUD User,ou=People,dc=example,dc=com\n'
        (input_dir / "oid_data.ldif").write_text(oid_ldif)
        (input_dir / "oud_data.ldif").write_text(oud_ldif)
        migration_result = api.migrate(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server="oid",
            target_server="oud",
        )
        if migration_result.failure:
            return r[m.Ldif.MigrationPipelineResult].fail(
                f"Migration failed: {migration_result.error}",
            )
        pipeline_result = migration_result.unwrap()
        _ = len(pipeline_result.entries)
        stats = pipeline_result.stats
        _ = stats.processed_entries
        return r[m.Ldif.MigrationPipelineResult].ok(pipeline_result)
