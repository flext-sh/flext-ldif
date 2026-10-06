"""Examples flext ldif utilities module.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_utilities/examples_flext_ldif_utilities
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import FlextLdifUtilities, m


class ExamplesFlextLdifUtilities(FlextLdifUtilities):
    """Utility functions for flextldif."""

    @staticmethod
    def create_user_entry(index: int, *, sn: str | None = None) -> m.Ldif.Entry:
        """Create a person entry for example workflows.

        Returns:
            The resulting ``m.Ldif.Entry``.
        """
        return m.Ldif.Entry(
            dn=m.Ldif.DN(value=f"cn=User{index},ou=People,dc=example,dc=com"),
            attributes=m.Ldif.Attributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": [f"User{index}"],
                    "sn": [sn if sn is not None else f"User{index}"],
                },
                attribute_metadata={},
            ),
        )
