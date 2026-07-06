# AUTO-GENERATED FILE — Regenerate with: make gen
"""Oud package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.servers._oud.aci import FlextLdifServersOudAciMixin
    from flext_ldif.servers._oud.acl import FlextLdifServersOudAcl
    from flext_ldif.servers._oud.acl_extract import FlextLdifServersOudAclExtractMixin
    from flext_ldif.servers._oud.acl_metadata import FlextLdifServersOudAclMetadataMixin
    from flext_ldif.servers._oud.comments import FlextLdifServersOudCommentsMixin
    from flext_ldif.servers._oud.constants import FlextLdifServersOudConstants
    from flext_ldif.servers._oud.entry import FlextLdifServersOudEntry
    from flext_ldif.servers._oud.helpers import FlextLdifServersOudHelpersMixin
    from flext_ldif.servers._oud.schema import FlextLdifServersOudSchema
    from flext_ldif.servers._oud.transform import FlextLdifServersOudTransformMixin
    from flext_ldif.servers._oud.utilities import FlextLdifServersOudUtilities
_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".aci": ("FlextLdifServersOudAciMixin",),
        ".acl": ("FlextLdifServersOudAcl",),
        ".acl_extract": ("FlextLdifServersOudAclExtractMixin",),
        ".acl_metadata": ("FlextLdifServersOudAclMetadataMixin",),
        ".comments": ("FlextLdifServersOudCommentsMixin",),
        ".constants": ("FlextLdifServersOudConstants",),
        ".entry": ("FlextLdifServersOudEntry",),
        ".helpers": ("FlextLdifServersOudHelpersMixin",),
        ".schema": ("FlextLdifServersOudSchema",),
        ".transform": ("FlextLdifServersOudTransformMixin",),
        ".utilities": ("FlextLdifServersOudUtilities",),
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
