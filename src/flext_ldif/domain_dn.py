"""Distinguished Name domain model."""

from __future__ import annotations

from flext_core import FlextCore
from ldap3.utils.dn import safe_dn
from pydantic import Field, field_validator


class DistinguishedName(FlextCore.Models.Value):
    """Distinguished Name value object."""

    value: str = Field(..., description="DN string value")
    metadata: dict[str, str] | None = Field(
        default=None,
        description="Quirk-specific metadata for preserving original format",
    )

    @field_validator("value", mode="before")
    @classmethod
    def normalize_dn(cls, v: str) -> str:
        """Normalize DN value using RFC 4514 compliant normalization.

        Uses ldap3.utils.dn.safe_dn for proper DN normalization:
        - Lowercases attribute names (cn, dc, ou, etc.)
        - Preserves case in attribute values (user names, etc.)
        - Normalizes spaces and escaping per RFC 4514

        Args:
            v: DN string to normalize

        Returns:
            Normalized DN string

        Raises:
            ValueError: If DN format is invalid

        """
        try:
            return safe_dn(v)
        except Exception as e:
            msg = f"Invalid DN format: {e}"
            raise ValueError(msg) from e

    @classmethod
    def create(cls, value: str | dict[str, str]) -> FlextCore.Result[DistinguishedName]:
        """Create DistinguishedName instance with validation, returns FlextCore.Result.

        Args:
            value: DN string or dict with 'value' key

        Returns:
            FlextCore.Result containing DistinguishedName instance

        """
        try:
            if isinstance(value, str):
                instance = cls(value=value)
            elif isinstance(value, dict):
                instance = cls.model_validate(value)
            else:
                return FlextCore.Result[DistinguishedName].fail(
                    f"Expected string or dict, got {type(value)}"
                )
            return FlextCore.Result[DistinguishedName].ok(instance)
        except Exception as e:
            return FlextCore.Result[DistinguishedName].fail(
                f"Failed to create DistinguishedName: {e}"
            )

    def get_components(self) -> FlextCore.Types.StringList:
        """Get DN components as list of strings."""
        return [comp.strip() for comp in self.value.split(",") if comp.strip()]

    def __str__(self) -> str:
        """Return DN string value for ldap3 compatibility."""
        return self.value

    def __repr__(self) -> str:
        """Return DN representation."""
        return f"DistinguishedName(value={self.value!r})"
