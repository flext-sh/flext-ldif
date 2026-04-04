"""Detection and Identification Mixins for LDIF Server Quirks."""

from __future__ import annotations

from typing import TypeIs

from flext_ldif.protocols import FlextLdifProtocols as p


class FlextLdifUtilitiesDetection:
    """Detection utilities for LDIF server quirks."""

    @staticmethod
    def _is_server_constants_class(
        value: type,
        required_attr: str | None = None,
    ) -> TypeIs[type[p.Ldif.ServerConstants]]:
        if required_attr is not None:
            return getattr(value, required_attr, None) is not None
        return all(
            getattr(value, attr, None) is not None
            for attr in (
                "DETECTION_OID_PATTERN",
                "DETECTION_ATTRIBUTE_PREFIXES",
                "DETECTION_OBJECTCLASS_NAMES",
                "DETECTION_DN_MARKERS",
                "ACL_ATTRIBUTE_NAME",
            )
        )


__all__ = ["FlextLdifUtilitiesDetection"]
