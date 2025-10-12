"""Entry domain model."""

from __future__ import annotations

from typing import cast

from flext_core import FlextCore
from pydantic import Field, field_validator

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.exceptions import FlextLdifExceptions
from flext_ldif.models.domain import DistinguishedName, LdifAttributes


class Entry(FlextCore.Models.Entity):
    """LDIF entry domain model."""

    dn: DistinguishedName = Field(..., description="Distinguished Name of the entry")
    attributes: LdifAttributes = Field(..., description="Entry attributes container")
    metadata: dict[str, str] | None = Field(
        default=None,
        description="Quirk-specific metadata for preserving original entry format",
    )

    @field_validator("dn", mode="before")
    @classmethod
    def validate_dn(cls, v: DistinguishedName | str) -> DistinguishedName:
        """Convert string DN to DistinguishedName object."""
        if isinstance(v, str):
            return DistinguishedName(value=v)
        return v

    @field_validator("attributes", mode="before")
    @classmethod
    def validate_attributes(
        cls, v: LdifAttributes | dict[str, FlextCore.Types.StringList]
    ) -> LdifAttributes:
        """Convert dict attributes to LdifAttributes object."""
        if isinstance(v, dict):
            # Convert raw attributes dict to LdifAttributes
            raw_attrs = cast("dict[str, FlextCore.Types.StringList]", v)
            return LdifAttributes(
                attributes={
                    name: AttributeValues(values=values)
                    for name, values in raw_attrs.items()
                }
            )
        return v

    @classmethod
    def create(
        cls, data: FlextCore.Types.Dict | None = None, **kwargs: object
    ) -> FlextCore.Result[Entry]:
        """Create Entry instance with validation, returns FlextCore.Result."""
        try:
            if data is None:
                data = {}
            data.update(kwargs)

            # Handle DN conversion if needed
            if FlextLdifConstants.DictKeys.DN in data and isinstance(
                data[FlextLdifConstants.DictKeys.DN], str
            ):
                data[FlextLdifConstants.DictKeys.DN] = DistinguishedName(
                    value=data[FlextLdifConstants.DictKeys.DN]
                )

            # Handle attributes conversion if needed
            if FlextLdifConstants.DictKeys.ATTRIBUTES in data and isinstance(
                data[FlextLdifConstants.DictKeys.ATTRIBUTES], dict
            ):
                # Raw attributes mapping from keys to list of values
                raw_attrs = cast(
                    "dict[str, FlextCore.Types.StringList]",
                    data[FlextLdifConstants.DictKeys.ATTRIBUTES],
                )
                ldif_attrs = LdifAttributes(
                    attributes={
                        name: AttributeValues(values=values)
                        for name, values in raw_attrs.items()
                    }
                )
                data[FlextLdifConstants.DictKeys.ATTRIBUTES] = ldif_attrs
            else:
                # Handle raw LDIF format where attributes are at top level
                raw_attrs_else: dict[str, FlextCore.Types.StringList] = {}
                keys_to_remove: FlextCore.Types.StringList = []
                for key, value in data.items():
                    if key != FlextLdifConstants.DictKeys.DN:
                        if isinstance(value, list):
                            existing_values = cast("FlextCore.Types.StringList", value)
                            raw_attrs_else[key] = existing_values
                        else:
                            raw_attrs_else[key] = [str(value)]
                        keys_to_remove.append(key)
                for key in keys_to_remove:
                    del data[key]
                if raw_attrs_else:
                    ldif_attrs = LdifAttributes(
                        attributes={
                            name: AttributeValues(values=values)
                            for name, values in raw_attrs_else.items()
                        }
                    )
                    data[FlextLdifConstants.DictKeys.ATTRIBUTES] = ldif_attrs

            # Use model_validate for proper Pydantic validation with type coercion
            instance = cls.model_validate(data)
            return FlextCore.Result[Entry].ok(instance)
        except Exception as e:
            return FlextCore.Result[Entry].fail(f"Failed to create Entry: {e}")

    @classmethod
    def from_ldif_string(cls, ldif_string: str) -> FlextCore.Result[Entry]:
        """Create Entry from LDIF string.

        Args:
            ldif_string: LDIF formatted string

        Returns:
            FlextCore.Result with Entry instance

        """
        try:
            # Import here to avoid circular import
            from flext_ldif.client import FlextLdifClient

            # Use client to parse the LDIF string
            client = FlextLdifClient()
            result = client.parse_ldif(ldif_string)
            if result.is_failure:
                return FlextCore.Result[Entry].fail(result.error)

            entries = result.unwrap()
            if not entries:
                return FlextCore.Result[Entry].fail("No entries found in LDIF string")

            if len(entries) > 1:
                return FlextCore.Result[Entry].fail(
                    "Multiple entries found, expected single entry"
                )

            return FlextCore.Result[Entry].ok(entries[0])

        except Exception as e:
            return FlextCore.Result[Entry].fail(f"Failed to parse LDIF string: {e}")

    def to_ldif_string(self, indent: int = 0) -> str:
        """Convert Entry to LDIF string.

        Args:
            indent: Number of spaces to indent each line

        Returns:
            LDIF formatted string

        """
        try:
            # Import here to avoid circular import
            from flext_ldif.client import FlextLdifClient

            # Use client to write the entry to string
            client = FlextLdifClient()
            result = client.write_ldif([self])
            if result.is_failure:
                error_msg = f"Failed to write entry: {result.error}"
                raise FlextLdifExceptions.LdifProcessingError(
                    error_msg,
                    operation="write_entry_to_ldif",
                    entry_dn=self.dn.value,
                    context={"entry_attributes": list(self.attributes.keys())},
                )

            ldif_content = result.unwrap()

            # Apply indentation if requested
            if indent > 0:
                indent_str = " " * indent
                lines = ldif_content.splitlines()
                indented_lines = [
                    indent_str + line if line.strip() else line for line in lines
                ]
                return "\n".join(indented_lines)

            return ldif_content

        except Exception as e:
            error_msg = f"Failed to convert entry to LDIF string: {e}"
            raise ValueError(error_msg) from e
