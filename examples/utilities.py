"""Utility functions for flextldif."""

from __future__ import annotations

from flext_ldif import FlextLdifUtilities, m


class ExamplesFlextLdifUtilities(FlextLdifUtilities):
    """Utility functions for flextldif."""

    @staticmethod
    def create_user_entry(index: int, *, sn: str | None = None) -> m.Ldif.Entry:
        """Create a person entry for example workflows."""
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


__all__: list[str] = ["ExamplesFlextLdifUtilities"]
