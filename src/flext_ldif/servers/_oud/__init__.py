# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif.servers. Oud package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.servers._oud.aci import FlextLdifServersOudAciMixin
    from flext_ldif.servers._oud.acl import FlextLdifServersOudAcl
    from flext_ldif.servers._oud.acl_extract import FlextLdifServersOudAclExtractMixin
    from flext_ldif.servers._oud.acl_metadata import FlextLdifServersOudAclMetadataMixin
    from flext_ldif.servers._oud.comments import FlextLdifServersOudCommentsMixin
    from flext_ldif.servers._oud.entry import FlextLdifServersOudEntry
    from flext_ldif.servers._oud.helpers import FlextLdifServersOudHelpersMixin
    from flext_ldif.servers._oud.schema import FlextLdifServersOudSchema
    from flext_ldif.servers._oud.schema_write import FlextLdifServersOudSchemaWriteMixin
    from flext_ldif.servers._oud.server_constants import FlextLdifServersOudConstants
    from flext_ldif.servers._oud.server_utilities import FlextLdifServersOudUtilities
    from flext_ldif.servers._oud.transform import FlextLdifServersOudTransformMixin


__all__: tuple[str, ...] = (
    "FlextLdifServersOudAciMixin",
    "FlextLdifServersOudAcl",
    "FlextLdifServersOudAclExtractMixin",
    "FlextLdifServersOudAclMetadataMixin",
    "FlextLdifServersOudCommentsMixin",
    "FlextLdifServersOudConstants",
    "FlextLdifServersOudEntry",
    "FlextLdifServersOudHelpersMixin",
    "FlextLdifServersOudSchema",
    "FlextLdifServersOudSchemaWriteMixin",
    "FlextLdifServersOudTransformMixin",
    "FlextLdifServersOudUtilities",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".aci": ("FlextLdifServersOudAciMixin",),
            ".acl": ("FlextLdifServersOudAcl",),
            ".acl_extract": ("FlextLdifServersOudAclExtractMixin",),
            ".acl_metadata": ("FlextLdifServersOudAclMetadataMixin",),
            ".comments": ("FlextLdifServersOudCommentsMixin",),
            ".entry": ("FlextLdifServersOudEntry",),
            ".helpers": ("FlextLdifServersOudHelpersMixin",),
            ".schema": ("FlextLdifServersOudSchema",),
            ".schema_write": ("FlextLdifServersOudSchemaWriteMixin",),
            ".server_constants": ("FlextLdifServersOudConstants",),
            ".server_utilities": ("FlextLdifServersOudUtilities",),
            ".transform": ("FlextLdifServersOudTransformMixin",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    ),
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
