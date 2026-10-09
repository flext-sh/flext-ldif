"""RFC validation services.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import struct
from typing import Annotated

from flext_ldif import c, p, r, s, t, u


class FlextLdifValidation(s):
    """FlextLdifValidation class."""

    attribute_names: Annotated[
        t.MutableSequenceOf[str],
        u.Field(
            default_factory=list,
            description="Attribute names to validate against RFC 4512",
        ),
    ] = u.Field(default_factory=list[str])
    objectclass_names: Annotated[
        t.MutableSequenceOf[str],
        u.Field(
            default_factory=list,
            description="Object class names to validate against RFC 4512",
        ),
    ] = u.Field(default_factory=list[str])
    max_attr_value_length: Annotated[
        int | None,
        u.Field(description="Maximum allowed attribute value length for validation"),
    ] = None

    @staticmethod
    def validate_attribute_name(name: str) -> p.Result[bool]:
        """Validate_attribute_name method.

        Returns:
            The resulting ``p.Result[bool]``.
        """
        return r[bool].from_result(
            u.try_(
                lambda: u.Ldif.Rfc.is_valid_rfc4512_descriptor(name),
                catch=(
                    c.ValidationError,
                    ValueError,
                    KeyError,
                    AttributeError,
                    UnicodeDecodeError,
                    struct.error,
                ),
            ).map_error(lambda e: f"Failed to validate attribute name: {e}"),
        )

    def validate_objectclass_name(self, name: str) -> p.Result[bool]:
        """Validate_objectclass_name method.

        Returns:
            The resulting ``p.Result[bool]``.
        """
        return self.validate_attribute_name(name)


__all__: list[str] = ["FlextLdifValidation"]
