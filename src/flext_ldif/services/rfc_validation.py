"""RFC validation services."""

from __future__ import annotations

import struct
from collections.abc import MutableSequence
from typing import Annotated, override

from pydantic import Field

from flext_core import d, r
from flext_ldif.base import s
from flext_ldif.models import m
from flext_ldif.utilities import u


class FlextLdifValidation(
    s[m.Ldif.ValidationServiceStatus],
):
    """FlextLdifValidation class."""

    attribute_names: Annotated[
        MutableSequence[str],
        Field(
            default_factory=list,
            description="Attribute names to validate against RFC 4512",
        ),
    ] = Field(default_factory=list)
    objectclass_names: Annotated[
        MutableSequence[str],
        Field(
            default_factory=list,
            description="Object class names to validate against RFC 4512",
        ),
    ] = Field(default_factory=list)
    max_attr_value_length: Annotated[
        int | None,
        Field(description="Maximum allowed attribute value length for validation"),
    ] = None

    @override
    @d.log_operation("validation_service_check", track_perf=True)
    def execute(self) -> r[m.Ldif.ValidationServiceStatus]:
        return r[m.Ldif.ValidationServiceStatus].ok(
            m.Ldif.ValidationServiceStatus(
                service="ValidationService",
                status="operational",
                rfc_compliance="RFC 2849, RFC 4512",
                validation_types=[
                    "attribute_name",
                    "objectclass_name",
                    "attribute_value",
                ],
            ),
        )

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
