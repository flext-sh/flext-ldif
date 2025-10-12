"""Analytics DTO models."""

from flext_core import FlextCore
from pydantic import Field


class LdifValidationResult(FlextCore.Models.Value):
    """Result of LDIF validation operations."""

    is_valid: bool = Field(default=False, description="Whether validation passed")
    errors: FlextCore.Types.StringList = Field(
        default_factory=list, description="List of validation errors"
    )
    warnings: FlextCore.Types.StringList = Field(
        default_factory=list, description="List of validation warnings"
    )


class AnalyticsResult(FlextCore.Models.Value):
    """Result of LDIF analytics operations."""

    total_entries: int = Field(
        default=0, description="Total number of entries analyzed"
    )
    object_class_distribution: dict[str, int] = Field(
        default_factory=dict, description="Distribution of object classes"
    )
    patterns_detected: FlextCore.Types.StringList = Field(
        default_factory=list, description="Detected patterns in the data"
    )


class SearchConfig(FlextCore.Models.Value):
    """Configuration for LDAP search operations."""

    base_dn: str = Field(..., description="Base DN for the search")
    search_filter: str = Field(
        default="(objectClass=*)", description="LDAP search filter"
    )
    attributes: FlextCore.Types.StringList = Field(
        default_factory=list, description="Attributes to retrieve"
    )
    scope: str = Field(default="sub", description="Search scope (base, one, sub)")
    time_limit: int = Field(default=30, description="Time limit for search in seconds")
    size_limit: int = Field(
        default=0, description="Size limit for search results (0 = no limit)"
    )

    def validate_base_dn(self, v: str) -> str:
        """Validate base DN is not empty.

        Args:
            v: Base DN to validate

        Returns:
            Validated base DN

        Raises:
            ValueError: If base DN is empty

        """
        if not v or not v.strip():
            msg = "Base DN cannot be empty"
            raise ValueError(msg)
        return v.strip()
