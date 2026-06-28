"""LDIF type facade."""

from __future__ import annotations

from flext_cli import FlextCliTypes
from flext_ldif._typings.base import FlextLdifTypesBase
from flext_ldif._typings.domain import FlextLdifTypesDomain


class FlextLdifTypes(FlextCliTypes):
    """LDIF domain types extending flext-core FlextTypes."""

    class Ldif(FlextLdifTypesDomain, FlextLdifTypesBase):
        """LDIF-specific type namespace."""


t = FlextLdifTypes

__all__: list[str] = ["FlextLdifTypes", "t"]
