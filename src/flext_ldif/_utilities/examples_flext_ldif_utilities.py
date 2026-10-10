from __future__ import annotations

from examples import m

from flext_ldif import FlextLdifUtilities


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
