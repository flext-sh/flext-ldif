"""RFC validation services."""

from __future__ import annotations

import struct
from collections.abc import (
    MutableSequence,
)
from typing import Annotated

from flext_core import r

from flext_ldif import (
    FlextLdifServiceBase,
    u,
)


class FlextLdifValidation(
    FlextLdifServiceBase,
):
    """FlextLdifValidation class."""

    attribute_names: Annotated[
        MutableSequence[str],
        u.Field(
            default_factory=list,
            description="Attribute names to validate against RFC 4512",
        ),
    ] = u.Field(default_factory=list)
    objectclass_names: Annotated[
        MutableSequence[str],
        u.Field(
            default_factory=list,
            description="Object class names to validate against RFC 4512",
        ),
    ] = u.Field(default_factory=list)
    max_attr_value_length: Annotated[
        int | None,
        u.Field(description="Maximum allowed attribute value length for validation"),
    ] = None

    def validate_attribute_name(self, name: str) -> r[bool]:
        """Validate_attribute_name method."""
        return r[bool].from_result(
            u.try_(
                lambda: u.Ldif.Rfc.is_valid_rfc4512_descriptor(name),
                catch=(
                    ValueError,
                    KeyError,
                    AttributeError,
                    UnicodeDecodeError,
                    struct.error,
                ),
            ).map_error(lambda e: f"Failed to validate attribute name: {e}"),
        )

    def validate_objectclass_name(self, name: str) -> r[bool]:
        """Validate_objectclass_name method."""
        return self.validate_attribute_name(name)


__all__: list[str] = ["FlextLdifValidation"]
