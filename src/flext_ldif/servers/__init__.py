# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif.servers package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.servers.ad import FlextLdifServersAd
    from flext_ldif.servers.apache import FlextLdifServersApache
    from flext_ldif.servers.base import FlextLdifServersBase
    from flext_ldif.servers.ds389 import FlextLdifServersDs389
    from flext_ldif.servers.novell import FlextLdifServersNovell
    from flext_ldif.servers.oid import (
        FlextLdifConstantsServersOid,
        FlextLdifServersOid,
        FlextLdifServersOidAclAssemble,
        FlextLdifServersOidAclConvert,
        FlextLdifServersOidAclPipeline,
        FlextLdifServersOidAclRender,
        FlextLdifServersOidAclToOud,
        FlextLdifServersOidEntry,
        FlextLdifServersOidSchema,
    )
    from flext_ldif.servers.openldap import FlextLdifServersOpenldap
    from flext_ldif.servers.openldap1 import FlextLdifServersOpenldap1
    from flext_ldif.servers.openldap1_entry import FlextLdifServersOpenldap1Entry
    from flext_ldif.servers.oud import FlextLdifServersOud
    from flext_ldif.servers.relaxed import FlextLdifServersRelaxed
    from flext_ldif.servers.relaxed_entry import FlextLdifServersRelaxedEntry
    from flext_ldif.servers.relaxed_entry_parse import FlextLdifServersRelaxedEntryParse
    from flext_ldif.servers.relaxed_entry_write import FlextLdifServersRelaxedEntryWrite
    from flext_ldif.servers.relaxed_schema import FlextLdifServersRelaxedSchema
    from flext_ldif.servers.rfc import FlextLdifServersRfc
    from flext_ldif.servers.tivoli import FlextLdifServersTivoli


__all__: tuple[str, ...] = (
    "FlextLdifConstantsServersOid",
    "FlextLdifServersAd",
    "FlextLdifServersApache",
    "FlextLdifServersBase",
    "FlextLdifServersDs389",
    "FlextLdifServersNovell",
    "FlextLdifServersOid",
    "FlextLdifServersOidAclAssemble",
    "FlextLdifServersOidAclConvert",
    "FlextLdifServersOidAclPipeline",
    "FlextLdifServersOidAclRender",
    "FlextLdifServersOidAclToOud",
    "FlextLdifServersOidEntry",
    "FlextLdifServersOidSchema",
    "FlextLdifServersOpenldap",
    "FlextLdifServersOpenldap1",
    "FlextLdifServersOpenldap1Entry",
    "FlextLdifServersOud",
    "FlextLdifServersRelaxed",
    "FlextLdifServersRelaxedEntry",
    "FlextLdifServersRelaxedEntryParse",
    "FlextLdifServersRelaxedEntryWrite",
    "FlextLdifServersRelaxedSchema",
    "FlextLdifServersRfc",
    "FlextLdifServersTivoli",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdifServersAd": ".ad",
        "FlextLdifServersApache": ".apache",
        "FlextLdifServersBase": ".base",
        "FlextLdifServersDs389": ".ds389",
        "FlextLdifServersNovell": ".novell",
        "FlextLdifServersOid": ".oid",
        "FlextLdifServersOidAclAssemble": ".oid",
        "FlextLdifServersOidAclConvert": ".oid",
        "FlextLdifServersOidAclPipeline": ".oid",
        "FlextLdifServersOidAclRender": ".oid",
        "FlextLdifServersOidAclToOud": ".oid",
        "FlextLdifConstantsServersOid": ".oid",
        "FlextLdifServersOidEntry": ".oid",
        "FlextLdifServersOidSchema": ".oid",
        "FlextLdifServersOpenldap": ".openldap",
        "FlextLdifServersOpenldap1": ".openldap1",
        "FlextLdifServersOpenldap1Entry": ".openldap1_entry",
        "FlextLdifServersOud": ".oud",
        "FlextLdifServersRelaxed": ".relaxed",
        "FlextLdifServersRelaxedEntry": ".relaxed_entry",
        "FlextLdifServersRelaxedEntryParse": ".relaxed_entry_parse",
        "FlextLdifServersRelaxedEntryWrite": ".relaxed_entry_write",
        "FlextLdifServersRelaxedSchema": ".relaxed_schema",
        "FlextLdifServersRfc": ".rfc",
        "FlextLdifServersTivoli": ".tivoli",
    }),
    public_exports=__all__,
)
