# from flext-ldif/docs/guides/integration.md:89
from __future__ import annotations

from pathlib import Path
from flext_ldif import ldif, FlextLdifSettings, m, p, r, t, u


class FLEXTOUDMigrationService:
    """FLEXT Oracle Unified Directory LDIF processing."""

    def __init__(self) -> None:
        self.logger = u.fetch_logger(__name__)

        # Configure for enterprise migration with legacy data accommodation
        migration_config = FlextLdifSettings(
            ldif_max_entries=None,  # No entry limits for enterprise data
            ldif_strict_validation=False,  # Accommodate legacy LDIF variations
            ldif_ignore_unknown_attributes=True,  # Handle custom schema attributes
            ldif_encoding="utf-8",
        )

        self._ldif_api = ldif(settings=migration_config)

    def process_oud_export(self, export_file: Path) -> p.Result[m.Dict]:
        """Process Oracle Unified Directory LDIF export."""
        self.logger.info(
            "Starting OUD LDIF processing",
            extra={
                "export_file": str(export_file),
                "migration_phase": "ldif_processing",
            },
        )

        return (
            # Parse enterprise LDIF export
            self._ldif_api
            .parse_file(export_file)
            # Categorize entries for migration-specific processing
            .flat_map(self._categorize_ldif_entries)
            # Apply FLEXT-specific directory transformations
            .flat_map(self._apply_migration_transformations)
            # Generate migration-specific report
            .map(self._generate_migration_report)
            # Log LDIF processing completion
            .map(self._log_ldif_completion)
        )

    def _categorize_ldif_entries(self, entries) -> p.Result[m.Dict]:
        """Categorize LDIF entries for migration processing."""
        try:
            users = []
            groups = []
            organizational_units = []
            other = []

            for entry in entries:
                if entry.is_person():
                    users.append(entry)
                elif entry.is_group():
                    groups.append(entry)
                elif entry.has_object_class("organizationalUnit"):
                    organizational_units.append(entry)
                else:
                    other.append(entry)

            return r[m.Dict].ok({
                "users": users,
                "groups": groups,
                "organizational_units": organizational_units,
                "other": other,
                "total": len(entries),
            })
        except Exception as e:
            return r[m.Dict].fail(f"LDIF entry categorization failed: {e}")

    def _apply_migration_transformations(self, categorized: dict) -> p.Result[m.Dict]:
        """Apply FLEXT-specific LDIF entry transformations."""
        # LDIF-specific transformations for OUD migration

        self.logger.info(
            "Applying LDIF migration transformations",
            extra={
                "user_count": len(categorized["users"]),
                "group_count": len(categorized["groups"]),
                "ou_count": len(categorized["organizational_units"]),
                "other_count": len(categorized["other"]),
            },
        )

        # Apply FLEXT business rules to LDIF entries
        transformed_users = self._transform_user_entries(categorized["users"])
        transformed_groups = self._transform_group_entries(categorized["groups"])

        return r[m.Dict].ok({
            "users": transformed_users,
            "groups": transformed_groups,
            "organizational_units": categorized["organizational_units"],
            "other": categorized["other"],
            "total": categorized["total"],
        })

    def _transform_user_entries(self, user_entries):
        """Transform user LDIF entries for FLEXT migration."""
        # LDIF-specific user entry transformations
        return user_entries

    def _transform_group_entries(self, group_entries):
        """Transform group LDIF entries for FLEXT migration."""
        # LDIF-specific group entry transformations
        return group_entries

    def _generate_migration_report(self, processed_data: dict) -> t.JsonMapping:
        """Generate LDIF migration processing report."""
        return {
            "ldif_migration_summary": {
                "total_entries_processed": processed_data["total"],
                "users_processed": len(processed_data["users"]),
                "groups_processed": len(processed_data["groups"]),
                "organizational_units": len(processed_data["organizational_units"]),
                "other_entries": len(processed_data["other"]),
            },
            "ldif_processing_status": "completed",
            "processed_data": processed_data,
        }

    def _log_ldif_completion(self, report: dict) -> t.JsonMapping:
        """Log LDIF migration processing completion."""
        self.logger.info(
            "OUD LDIF processing completed",
            extra={
                "ldif_summary": report["ldif_migration_summary"],
                "migration_phase": "ldif_processing_complete",
            },
        )
        return report```
## LDIF-Specific Service Integration

### LDIF API Service Integration

