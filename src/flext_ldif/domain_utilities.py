"""Domain utility models."""

from __future__ import annotations

from flext_core import FlextCore
from pydantic import Field, field_validator

from flext_ldif.constants import FlextLdifConstants


class AttributeName(FlextCore.Models.Value):
    """LDIF attribute name value object."""

    name: str = Field(..., description="Attribute name")

    @field_validator("name", mode="before")
    @classmethod
    def validate_attribute_name(cls, v: str) -> str:
        """Validate attribute name format per LDAP standards.

        Args:
            v: Attribute name to validate

        Returns:
            Validated attribute name

        Raises:
            ValueError: If attribute name is invalid

        """
        if not v or not v.strip():
            msg = "Attribute name cannot be empty"
            raise ValueError(msg)

        v = v.strip()

        # LDAP attribute names must start with a letter
        if not v[0].isalpha():
            msg = "Attribute name must start with a letter"
            raise ValueError(msg)

        # LDAP attribute names can only contain letters, digits, and hyphens
        if not all(c.isalnum() or c == "-" for c in v):
            msg = "Attribute name can only contain letters, digits, and hyphens"
            raise ValueError(msg)

        return v


class LdifUrl(FlextCore.Models.Value):
    """LDIF URL value object."""

    url: str = Field(..., description="LDIF URL")

    @field_validator("url", mode="before")
    @classmethod
    def validate_url(cls, v: str) -> str:
        """Validate URL format.

        Args:
            v: URL to validate

        Returns:
            Validated URL

        Raises:
            ValueError: If URL is invalid

        """
        if not v or not v.strip():
            msg = "URL cannot be empty"
            raise ValueError(msg)

        v = v.strip()

        # Basic URL validation - must have protocol
        if "://" not in v:
            msg = "URL must contain a protocol (e.g., http://, https://, ldap://)"
            raise ValueError(msg)

        return v


class Encoding(FlextCore.Models.Value):
    """LDIF encoding value object."""

    encoding: str = Field(..., description="Character encoding")

    @field_validator("encoding", mode="before")
    @classmethod
    def validate_encoding(cls, v: str) -> str:
        """Validate encoding is supported.

        Args:
            v: Encoding name to validate

        Returns:
            Validated encoding name

        Raises:
            ValueError: If encoding is not supported

        """
        if not v or not v.strip():
            msg = "Encoding cannot be empty"
            raise ValueError(msg)

        v_lower = v.strip().lower()

        if v_lower not in FlextLdifConstants.ValidationRules.VALID_ENCODINGS_RULE:
            supported = ", ".join(
                FlextLdifConstants.ValidationRules.VALID_ENCODINGS_RULE
            )
            msg = f"Invalid encoding: {v}. Supported encodings: {supported}"
            raise ValueError(msg)

        return v_lower
