# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif.servers. Oid package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.servers._oid.acl import FlextLdifServersOidAcl
    from flext_ldif.servers._oid.acl_assemble import FlextLdifServersOidAclAssemble
    from flext_ldif.servers._oid.acl_convert import FlextLdifServersOidAclConvert
    from flext_ldif.servers._oid.acl_convert_oud import FlextLdifServersOidAclToOud
    from flext_ldif.servers._oid.acl_format import FlextLdifServersOidAclFormatMixin
    from flext_ldif.servers._oid.acl_parse import FlextLdifServersOidAclParseMixin
    from flext_ldif.servers._oid.acl_pipeline import FlextLdifServersOidAclPipeline
    from flext_ldif.servers._oid.acl_render import FlextLdifServersOidAclRender
    from flext_ldif.servers._oid.acl_subjects import FlextLdifServersOidAclSubjectMixin
    from flext_ldif.servers._oid.acl_write import FlextLdifServersOidAclWriteMixin
    from flext_ldif.servers._oid.entry import FlextLdifServersOidEntry
    from flext_ldif.servers._oid.entry_boolean import (
        FlextLdifServersOidEntryBooleanMixin,
    )
    from flext_ldif.servers._oid.entry_metadata import (
        FlextLdifServersOidEntryMetadataMixin,
    )
    from flext_ldif.servers._oid.entry_normalize import (
        FlextLdifServersOidEntryNormalizeMixin,
    )
    from flext_ldif.servers._oid.entry_parse import FlextLdifServersOidEntryParseMixin
    from flext_ldif.servers._oid.entry_restore import (
        FlextLdifServersOidEntryRestoreMixin,
    )
    from flext_ldif.servers._oid.schema import FlextLdifServersOidSchema
    from flext_ldif.servers._oid.schema_normalize import (
        FlextLdifServersOidSchemaNormalizeMixin,
    )
    from flext_ldif.servers._oid.server_constants import FlextLdifServersOidConstants


__all__: tuple[str, ...] = (
    "FlextLdifServersOidAcl",
    "FlextLdifServersOidAclAssemble",
    "FlextLdifServersOidAclConvert",
    "FlextLdifServersOidAclFormatMixin",
    "FlextLdifServersOidAclParseMixin",
    "FlextLdifServersOidAclPipeline",
    "FlextLdifServersOidAclRender",
    "FlextLdifServersOidAclSubjectMixin",
    "FlextLdifServersOidAclToOud",
    "FlextLdifServersOidAclWriteMixin",
    "FlextLdifServersOidConstants",
    "FlextLdifServersOidEntry",
    "FlextLdifServersOidEntryBooleanMixin",
    "FlextLdifServersOidEntryMetadataMixin",
    "FlextLdifServersOidEntryNormalizeMixin",
    "FlextLdifServersOidEntryParseMixin",
    "FlextLdifServersOidEntryRestoreMixin",
    "FlextLdifServersOidSchema",
    "FlextLdifServersOidSchemaNormalizeMixin",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdifServersOidAcl": ".acl",
        "FlextLdifServersOidAclAssemble": ".acl_assemble",
        "FlextLdifServersOidAclConvert": ".acl_convert",
        "FlextLdifServersOidAclFormatMixin": ".acl_format",
        "FlextLdifServersOidAclParseMixin": ".acl_parse",
        "FlextLdifServersOidAclPipeline": ".acl_pipeline",
        "FlextLdifServersOidAclRender": ".acl_render",
        "FlextLdifServersOidAclSubjectMixin": ".acl_subjects",
        "FlextLdifServersOidAclToOud": ".acl_convert_oud",
        "FlextLdifServersOidAclWriteMixin": ".acl_write",
        "FlextLdifServersOidConstants": ".server_constants",
        "FlextLdifServersOidEntry": ".entry",
        "FlextLdifServersOidEntryBooleanMixin": ".entry_boolean",
        "FlextLdifServersOidEntryMetadataMixin": ".entry_metadata",
        "FlextLdifServersOidEntryNormalizeMixin": ".entry_normalize",
        "FlextLdifServersOidEntryParseMixin": ".entry_parse",
        "FlextLdifServersOidEntryRestoreMixin": ".entry_restore",
        "FlextLdifServersOidSchema": ".schema",
        "FlextLdifServersOidSchemaNormalizeMixin": ".schema_normalize",
    }),
    public_exports=__all__,
)
