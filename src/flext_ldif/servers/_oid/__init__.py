# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif.servers. Oid package.

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
    from flext_ldif.servers._oid.acl import FlextLdifServersOidAcl
    from flext_ldif.servers._oid.acl_assemble import FlextLdifServersOidAclAssemble
    from flext_ldif.servers._oid.acl_convert import FlextLdifServersOidAclConvert
    from flext_ldif.servers._oid.acl_convert_oud import FlextLdifServersOidAclToOud
    from flext_ldif.servers._oid.acl_format import FlextLdifServersOidAclFormat
    from flext_ldif.servers._oid.acl_parse import FlextLdifServersOidAclParse
    from flext_ldif.servers._oid.acl_pipeline import FlextLdifServersOidAclPipeline
    from flext_ldif.servers._oid.acl_render import FlextLdifServersOidAclRender
    from flext_ldif.servers._oid.acl_subjects import FlextLdifServersOidAclSubject
    from flext_ldif.servers._oid.acl_write import FlextLdifServersOidAclWrite
    from flext_ldif.servers._oid.entry import FlextLdifServersOidEntry
    from flext_ldif.servers._oid.entry_boolean import FlextLdifServersOidEntryBoolean
    from flext_ldif.servers._oid.entry_metadata import FlextLdifServersOidEntryMetadata
    from flext_ldif.servers._oid.entry_normalize import (
        FlextLdifServersOidEntryNormalize,
    )
    from flext_ldif.servers._oid.entry_parse import FlextLdifServersOidEntryParse
    from flext_ldif.servers._oid.entry_restore import FlextLdifServersOidEntryRestore
    from flext_ldif.servers._oid.schema import FlextLdifServersOidSchema
    from flext_ldif.servers._oid.schema_normalize import (
        FlextLdifServersOidSchemaNormalize,
    )
    from flext_ldif.servers._oid.server_constants import FlextLdifConstantsServersOid


__all__: tuple[str, ...] = (
    "FlextLdifConstantsServersOid",
    "FlextLdifServersOidAcl",
    "FlextLdifServersOidAclAssemble",
    "FlextLdifServersOidAclConvert",
    "FlextLdifServersOidAclFormat",
    "FlextLdifServersOidAclParse",
    "FlextLdifServersOidAclPipeline",
    "FlextLdifServersOidAclRender",
    "FlextLdifServersOidAclSubject",
    "FlextLdifServersOidAclToOud",
    "FlextLdifServersOidAclWrite",
    "FlextLdifServersOidEntry",
    "FlextLdifServersOidEntryBoolean",
    "FlextLdifServersOidEntryMetadata",
    "FlextLdifServersOidEntryNormalize",
    "FlextLdifServersOidEntryParse",
    "FlextLdifServersOidEntryRestore",
    "FlextLdifServersOidSchema",
    "FlextLdifServersOidSchemaNormalize",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdifServersOidAcl": ".acl",
        "FlextLdifServersOidAclAssemble": ".acl_assemble",
        "FlextLdifServersOidAclConvert": ".acl_convert",
        "FlextLdifServersOidAclFormat": ".acl_format",
        "FlextLdifServersOidAclParse": ".acl_parse",
        "FlextLdifServersOidAclPipeline": ".acl_pipeline",
        "FlextLdifServersOidAclRender": ".acl_render",
        "FlextLdifServersOidAclSubject": ".acl_subjects",
        "FlextLdifServersOidAclToOud": ".acl_convert_oud",
        "FlextLdifServersOidAclWrite": ".acl_write",
        "FlextLdifConstantsServersOid": ".server_constants",
        "FlextLdifServersOidEntry": ".entry",
        "FlextLdifServersOidEntryBoolean": ".entry_boolean",
        "FlextLdifServersOidEntryMetadata": ".entry_metadata",
        "FlextLdifServersOidEntryNormalize": ".entry_normalize",
        "FlextLdifServersOidEntryParse": ".entry_parse",
        "FlextLdifServersOidEntryRestore": ".entry_restore",
        "FlextLdifServersOidSchema": ".schema",
        "FlextLdifServersOidSchemaNormalize": ".schema_normalize",
    }),
    public_exports=__all__,
)
