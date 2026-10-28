"""RFC validation helpers for LDIF.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

from flext_core import u

from flext_ldif import t


class FlextLdifUtilitiesValidationRfc:
    """RFC validation helpers."""

    class Rfc:
        """RFC validation adapter helpers."""

        RFC2849_ATTRIBUTE_VALUE_ADAPTER: u.type_adapter[
            t.Ldif.Rfc2849AttributeValue
        ] = u.type_adapter(
            cast("type[t.Ldif.Rfc2849AttributeValue]", t.Ldif.Rfc2849AttributeValue)
        )
        RFC4512_DESCRIPTOR_ADAPTER: u.type_adapter[t.Ldif.Rfc4512Descriptor] = (
            u.type_adapter(
                cast("type[t.Ldif.Rfc4512Descriptor]", t.Ldif.Rfc4512Descriptor)
            )
        )
        RFC4514_DN_COMPONENT_ADAPTER: u.type_adapter[t.Ldif.Rfc4514DnComponent] = (
            u.type_adapter(
                cast("type[t.Ldif.Rfc4514DnComponent]", t.Ldif.Rfc4514DnComponent)
            )
        )

        @classmethod
        def is_valid_rfc2849_attribute_value(cls, value: str) -> bool:
            return u.validate_value(cls.RFC2849_ATTRIBUTE_VALUE_ADAPTER, value).success

        @classmethod
        def is_valid_rfc4512_descriptor(cls, value: str) -> bool:
            return u.validate_value(cls.RFC4512_DESCRIPTOR_ADAPTER, value).success

        @classmethod
        def is_valid_rfc4514_dn_component(cls, attribute_name: str, value: str) -> bool:
            return u.validate_value(
                cls.RFC4514_DN_COMPONENT_ADAPTER,
                f"{attribute_name}={value}",
            ).success


__all__: list[str] = ["FlextLdifUtilitiesValidationRfc"]
