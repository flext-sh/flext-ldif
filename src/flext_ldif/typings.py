"""LDIF type facade."""

from __future__ import annotations

from flext_core import FlextTypes
from flext_ldif import FlextLdifTypesBase, FlextLdifTypesDomain


class FlextLdifTypes(FlextTypes):
    """LDIF domain types extending flext-core FlextTypes."""

    class Ldif(FlextLdifTypesDomain, FlextLdifTypesBase):
        """LDIF-specific type namespace."""


t = FlextLdifTypes

__all__: list[str] = ["FlextLdifTypes", "t"]
