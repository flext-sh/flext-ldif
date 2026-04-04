"""LDIF type facade."""

from __future__ import annotations

from flext_core import FlextTypes
from flext_ldif._typings.base import FlextLdifTypesBase
from flext_ldif._typings.domain import FlextLdifTypesDomain


class FlextLdifTypes(FlextTypes):
    """LDIF domain types extending flext-core FlextTypes."""

    class Ldif(FlextLdifTypesDomain, FlextLdifTypesBase):
        """LDIF-specific type namespace."""


t = FlextLdifTypes

__all__ = ["FlextLdifTypes", "t"]
