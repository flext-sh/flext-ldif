"""FlextLdifConstantsServers - Server-family constants (SSOT).

ENFORCE-079 owner for the ``servers/*`` family runtime constants: the
server constants classes (``FlextLdifServers*Constants``) compose these
parts through inheritance so every constant declaration lives inside the
``_constants`` package while consumer attribute paths stay stable via MRO.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar

from .base import FlextLdifConstantsBase
from .enums import FlextLdifConstantsEnums

if TYPE_CHECKING:
    from flext_core import t


class FlextLdifConstantsServers:
    """Server-family constants composed into the server constants classes."""

    class Base:
        """Baseline identity constants shared by every server family."""

        CANONICAL_NAME: ClassVar[str] = ""
        ALIASES: ClassVar[frozenset[str]] = frozenset()
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset()

    class Rfc:
        """RFC 4512 baseline server constants."""

        SERVER_TYPE: ClassVar[str] = FlextLdifConstantsEnums.ServerTypes.RFC.value
        PRIORITY: ClassVar[int] = 100
        DEFAULT_PORT: ClassVar[int] = 389

    class Oid:
        """Oracle Internet Directory (OID) server constants."""

        SERVER_TYPE: ClassVar[str] = FlextLdifConstantsEnums.ServerTypes.OID
        PRIORITY: ClassVar[int] = 10
        MAX_LOG_LINE_LENGTH: ClassVar[int] = 200
        OID_ACL_ATTRIBUTES: ClassVar[t.StrSequence] = (
            "orclaci",
            "orclentrylevelaci",
            "orclContainerLevelACL",
        )

    class Oud:
        """Oracle Unified Directory (OUD) server constants."""

        SERVER_TYPE: ClassVar[str] = FlextLdifConstantsEnums.ServerTypes.OUD
        PRIORITY: ClassVar[int] = 10
        DEFAULT_PORT: ClassVar[int] = 1389
        OUD_ACL_ATTRIBUTES: ClassVar[t.StrSequence] = ("ds-privilege-name",)
        PARSED_ACL_KEY_MAP: ClassVar[t.MappingKV[str, str]] = MappingProxyType({
            "targattrfilters": FlextLdifConstantsBase.ACL_TARGETATTR_FILTERS,
            "targetcontrol": FlextLdifConstantsBase.ACL_TARGET_CONTROL,
            "extop": FlextLdifConstantsBase.ACL_EXTOP,
            "ip": FlextLdifConstantsBase.ACL_BIND_IP_FILTER,
            "dns": FlextLdifConstantsBase.ACL_TARGETSCOPE,
            "dayofweek": FlextLdifConstantsBase.ACL_NUMBERING,
            "timeofday": FlextLdifConstantsBase.ACL_BINDMODE,
            "authmethod": FlextLdifConstantsBase.ACL_SOURCE_PERMISSIONS,
            "ssf": FlextLdifConstantsBase.ACL_SSFS,
        })
        ACL_KEY_MAP: ClassVar[t.MappingKV[str, str]] = MappingProxyType({
            "extop": FlextLdifConstantsBase.ACL_EXTOP,
            "ip": FlextLdifConstantsBase.ACL_BIND_IP_FILTER,
            "bind_ip": FlextLdifConstantsBase.ACL_BIND_IP_FILTER,
            "dns": FlextLdifConstantsBase.ACL_BIND_DNS,
            "bind_dns": FlextLdifConstantsBase.ACL_BIND_DNS,
            "dayofweek": FlextLdifConstantsBase.ACL_BIND_DAYOFWEEK,
            "bind_dayofweek": FlextLdifConstantsBase.ACL_BIND_DAYOFWEEK,
            "timeofday": FlextLdifConstantsBase.ACL_BIND_TIMEOFDAY,
            "bind_timeofday": FlextLdifConstantsBase.ACL_BIND_TIMEOFDAY,
            "authmethod": FlextLdifConstantsBase.ACL_AUTHMETHOD,
            "ssf": FlextLdifConstantsBase.ACL_SSF,
            "targetcontrol": "targetcontrol",
            "targetscope": "targetscope",
            "targattrfilters": FlextLdifConstantsBase.ACL_TARGETATTR_FILTERS,
        })


__all__: list[str] = ["FlextLdifConstantsServers"]
