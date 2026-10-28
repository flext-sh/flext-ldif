"""Schema-aware migration pipeline example with pre/post validation.

Part of Example 5 (Advanced Schema Operations); see
``examples/schema_operations.py`` for the combined facade.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from examples import create_entry_or_none, ldif, m, p, r, t, u

if TYPE_CHECKING:
    from flext_ldif import FlextLdif

_LEGACY_LDIF_FIXTURES: tuple[str, ...] = (
    (
        "dn: cn=Legacy User1,ou=People,dc=example,dc=com\n"
        "objectClass: person\ncn: "
        "Legacy User1\nsn: User1\nemailAddress: legacy1@example.com\n"
    ),
    (
        "dn: cn=Legacy Group,ou=Groups,dc=example,dc=com\nobjectClass: "
        "groupOfUniqueNames\ncn: Legacy Group\n"
        "uniquemember: cn=Legacy User1,ou=People,dc=example,dc=com\n"
    ),
    (
        "dn: cn=Modern User,ou=People,dc=example,dc=com\nobjectClass: "
        "person\nobjectClass: inetOrgPerson\ncn: Modern User\nsn: Modern\n"
        "mail: modern@example.com\n"
    ),
)


class ExamplesFlextLdifSchemaMigration:
    """Schema-aware migration pipeline example namespace."""

    @staticmethod
    def _prepare_migration_dirs() -> tuple[Path, Path]:
        """Create the migration source, migrated, and schema directories.

        Returns:
            The resulting ``tuple[Path, Path]`` of source and migrated paths.

        """
        migration_dir = Path("examples/schema_migration")
        source_dir = migration_dir / "source"
        migrated_dir = migration_dir / "migrated"
        schema_dir = migration_dir / "schema"
        for dir_path in (source_dir, migrated_dir, schema_dir):
            dir_path.mkdir(exist_ok=True, parents=True)
        return source_dir, migrated_dir

    @staticmethod
    def _write_legacy_fixtures(source_dir: Path) -> None:
        """Write the legacy LDIF fixtures consumed by the migration demo."""
        for i, entry_text in enumerate(_LEGACY_LDIF_FIXTURES):
            (source_dir / f"legacy_{i}.ldif").write_text(entry_text)

    @staticmethod
    def _parse_source_entries(api: FlextLdif, source_dir: Path) -> list[m.Ldif.Entry]:
        """Parse every legacy LDIF file in the source directory.

        Returns:
            The resulting ``list[m.Ldif.Entry]``.

        """
        all_entries: list[m.Ldif.Entry] = []
        for ldif_file in source_dir.glob("*.ldif"):
            parse_result = api.parse_ldif(ldif_file)
            if parse_result.success:
                parse_response = parse_result.unwrap()
                all_entries.extend(parse_response.entries)
        return all_entries

    @staticmethod
    def _migrated_dn(ldif_entry: m.Ldif.Entry) -> str:
        """Resolve the DN string of a parsed entry.

        Returns:
            The resulting ``str``.

        """
        entry_dn = ldif_entry.dn
        if entry_dn is None:
            return ""
        return entry_dn.value if hasattr(entry_dn, "value") else str(entry_dn)

    @staticmethod
    def _migrate_entry(ldif_entry: m.Ldif.Entry) -> m.Ldif.Entry | None:
        """Migrate one entry, renaming ``emailAddress`` to the modern ``mail``.

        Returns:
            The resulting ``m.Ldif.Entry | None``.

        """
        attrs_dict: t.MutableAttributeMapping = {}
        if ldif_entry.attributes is not None:
            for attr_name, attr_values in ldif_entry.attributes.attributes.items():
                if attr_name == "emailAddress":
                    attrs_dict["mail"] = attr_values
                else:
                    attrs_dict[attr_name] = attr_values
        return create_entry_or_none(
            dn=ExamplesFlextLdifSchemaMigration._migrated_dn(ldif_entry),
            attributes=attrs_dict,
        )

    @staticmethod
    def _validation_summary(
        api: FlextLdif,
        entries: list[m.Ldif.Entry],
    ) -> p.Result[t.JsonMapping]:
        """Validate entries and summarize the report through the declared path.

        Returns:
            The resulting ``p.Result[t.JsonMapping]``: the per-report counters,
            or the typed failure carrying the validation error.

        """
        validation_result = api.validate_entries(entries)
        if not validation_result.success:
            return r[t.JsonMapping].fail(validation_result.error)
        report = validation_result.unwrap()
        return r[t.JsonMapping].ok({
            "valid": report.valid_entries,
            "invalid": report.invalid_entries,
            "errors": len(report.errors),
        })

    @staticmethod
    def schema_migration_pipeline() -> p.Result[t.JsonMapping]:
        """Schema-aware migration pipeline with validation.

        Returns:
            The resulting ``p.Result[t.JsonMapping]``.

        """
        api = ldif()
        source_dir, migrated_dir = (
            ExamplesFlextLdifSchemaMigration._prepare_migration_dirs()
        )
        ExamplesFlextLdifSchemaMigration._write_legacy_fixtures(source_dir)
        migration_results: t.MutableMappingKV[str, t.JsonValue] = {}
        all_entries = ExamplesFlextLdifSchemaMigration._parse_source_entries(
            api,
            source_dir,
        )
        migration_results["source_entries_parsed"] = len(all_entries)
        pre_summary = ExamplesFlextLdifSchemaMigration._validation_summary(
            api,
            all_entries,
        )
        if pre_summary.success:
            migration_results["pre_migration_validation"] = dict(pre_summary.unwrap())
        migrated_entries: list[m.Ldif.Entry] = []
        for ldif_entry in all_entries:
            migrated = ExamplesFlextLdifSchemaMigration._migrate_entry(ldif_entry)
            if migrated is not None:
                migrated_entries.append(migrated)
        migration_results["entries_migrated"] = len(migrated_entries)
        post_summary = ExamplesFlextLdifSchemaMigration._validation_summary(
            api,
            migrated_entries,
        )
        if post_summary.success:
            migration_results["post_migration_validation"] = dict(post_summary.unwrap())
        if migrated_entries:
            output_file = migrated_dir / "migrated_schema_compliant.ldif"
            write_result = api.write_ldif_file(migrated_entries, output_file)
            migration_results["output_written"] = write_result.success
        return r[t.JsonMapping].ok(
            u.json_mapping_adapter().validate_python(migration_results),
        )


# Module-level rebinding of the namespace surface: the lazy package export and
# the schema_operations aggregator import this name as a module attribute.
schema_migration_pipeline = ExamplesFlextLdifSchemaMigration.schema_migration_pipeline

__all__: list[str] = [
    "ExamplesFlextLdifSchemaMigration",
    "schema_migration_pipeline",
]
