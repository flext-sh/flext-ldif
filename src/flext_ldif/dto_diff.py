"""Diff DTO models."""

from flext_core import FlextCore
from pydantic import Field


class DiffResult(FlextCore.Models.Value):
    """Result of a diff operation showing changes between two datasets.

    Value object for diff comparison results across LDAP data types:
    attributes, objectClasses, ACLs, and directory entries.

    Attributes:
        added: Items present in target but not in source
        removed: Items present in source but not in target
        modified: Items present in both but with different values
        unchanged: Items that are identical in both datasets

    """

    model_config = {"frozen": True}

    added: list[FlextCore.Types.Dict] = Field(
        default_factory=list, description="Items present in target but not in source"
    )
    removed: list[FlextCore.Types.Dict] = Field(
        default_factory=list, description="Items present in source but not in target"
    )
    modified: list[FlextCore.Types.Dict] = Field(
        default_factory=list,
        description="Items present in both but with different values",
    )
    unchanged: list[FlextCore.Types.Dict] = Field(
        default_factory=list, description="Items that are identical in both datasets"
    )

    def has_changes(self) -> bool:
        """Check if there are any differences."""
        return bool(self.added or self.removed or self.modified)

    def total_changes(self) -> int:
        """Total number of changes (added + removed + modified)."""
        return len(self.added) + len(self.removed) + len(self.modified)

    def get_summary(self) -> str:
        """Get human-readable summary of changes."""
        if not self.has_changes():
            return "No differences found"

        parts = []
        if self.added:
            parts.append(f"{len(self.added)} added")
        if self.removed:
            parts.append(f"{len(self.removed)} removed")
        if self.modified:
            parts.append(f"{len(self.modified)} modified")
        if self.unchanged:
            parts.append(f"{len(self.unchanged)} unchanged")

        return ", ".join(parts)
