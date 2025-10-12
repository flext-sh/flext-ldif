"""Filter DTO models."""

from __future__ import annotations

from flext_core import FlextCore
from pydantic import Field

from flext_ldif.models.domain import Entry


class FilterCriteria(FlextCore.Models.Value):
    """Criteria for filtering LDIF entries.

    Supports multiple filter types:
    - dn_pattern: Wildcard DN pattern matching (e.g., "*,dc=example,dc=com")
    - oid_pattern: OID pattern matching with wildcard support
    - objectclass: Filter by objectClass with optional attribute validation
    - attribute: Filter by attribute presence/absence

    Example:
        criteria = FilterCriteria(
            filter_type="dn_pattern",
            pattern="*,ou=users,dc=ctbc,dc=com",
            mode="include"
        )

    """

    filter_type: str = Field(
        ...,
        description="Type of filter: dn_pattern, oid_pattern, objectclass, or attribute",
    )
    pattern: str | None = Field(
        default=None,
        description="Pattern for matching (supports wildcards with fnmatch)",
    )
    whitelist: FlextCore.Types.StringList | None = Field(
        default=None,
        description="Whitelist of patterns to include (for OID filtering)",
    )
    blacklist: FlextCore.Types.StringList | None = Field(
        default=None, description="Blacklist of patterns to exclude"
    )
    required_attributes: FlextCore.Types.StringList | None = Field(
        default=None, description="Required attributes for objectClass filtering"
    )
    mode: str = Field(
        default="include",
        description="Filter mode: 'include' to keep matches, 'exclude' to remove matches",
    )


class ExclusionInfo(FlextCore.Models.Value):
    """Metadata for excluded entries/schema items.

    Stored in QuirkMetadata.extensions['exclusion_info'] to track why
    an entry was excluded during filtering operations.

    Example:
        exclusion = ExclusionInfo(
            excluded=True,
            exclusion_reason="DN outside base context",
            filter_criteria=FilterCriteria(filter_type="dn_pattern", pattern="*,dc=old,dc=com"),
            timestamp="2025-10-09T12:34:56Z"
        )

    """

    excluded: bool = Field(default=False, description="Whether the item is excluded")
    exclusion_reason: str | None = Field(
        default=None, description="Human-readable reason for exclusion"
    )
    filter_criteria: FilterCriteria | None = Field(
        default=None, description="Filter criteria that caused the exclusion"
    )
    timestamp: str = Field(
        ..., description="ISO 8601 timestamp when exclusion was marked"
    )


class CategorizedEntries(FlextCore.Models.Value):
    """Result of entry categorization by objectClass.

    Categorizes LDIF entries into users, groups, containers, and uncategorized
    based on configurable objectClass sets.

    Example:
        categorized = CategorizedEntries(
            users=[user_entry1, user_entry2],
            groups=[group_entry1],
            containers=[ou_entry1, ou_entry2],
            uncategorized=[],
            summary={"users": 2, "groups": 1, "containers": 2, "uncategorized": 0}
        )

    """

    model_config = {"frozen": False}  # Allow mutation for summary updates

    users: list[Entry] = Field(
        default_factory=list,
        description="Entries categorized as users (inetOrgPerson, person, etc.)",
    )
    groups: list[Entry] = Field(
        default_factory=list,
        description="Entries categorized as groups (groupOfNames, etc.)",
    )
    containers: list[Entry] = Field(
        default_factory=list,
        description="Entries categorized as containers (organizationalUnit, etc.)",
    )
    uncategorized: list[Entry] = Field(
        default_factory=list, description="Entries that don't match any category"
    )
    summary: dict[str, int] = Field(
        default_factory=dict, description="Summary counts for each category"
    )

    @classmethod
    def create_empty(cls) -> CategorizedEntries:
        """Create empty categorization result."""
        return cls(
            users=[],
            groups=[],
            containers=[],
            uncategorized=[],
            summary={"users": 0, "groups": 0, "containers": 0, "uncategorized": 0},
        )

    def update_summary(self) -> None:
        """Update summary counts based on current entries."""
        self.summary = {
            "users": len(self.users),
            "groups": len(self.groups),
            "containers": len(self.containers),
            "uncategorized": len(self.uncategorized),
            "total": len(self.users)
            + len(self.groups)
            + len(self.containers)
            + len(self.uncategorized),
        }
