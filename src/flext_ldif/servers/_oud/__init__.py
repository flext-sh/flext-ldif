# AUTO-GENERATED FILE — Regenerate with: make gen
"""Oud package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif.servers._oud.aci import (
        FlextLdifServersOudAciMixin as FlextLdifServersOudAciMixin,
    )
    from flext_ldif.servers._oud.acl import (
        FlextLdifServersOudAcl as FlextLdifServersOudAcl,
    )
    from flext_ldif.servers._oud.acl_extract import (
        FlextLdifServersOudAclExtractMixin as FlextLdifServersOudAclExtractMixin,
    )
    from flext_ldif.servers._oud.acl_metadata import (
        FlextLdifServersOudAclMetadataMixin as FlextLdifServersOudAclMetadataMixin,
    )
    from flext_ldif.servers._oud.comments import (
        FlextLdifServersOudCommentsMixin as FlextLdifServersOudCommentsMixin,
    )
    from flext_ldif.servers._oud.constants import (
        FlextLdifServersOudConstants as FlextLdifServersOudConstants,
    )
    from flext_ldif.servers._oud.entry import (
        FlextLdifServersOudEntry as FlextLdifServersOudEntry,
    )
    from flext_ldif.servers._oud.helpers import (
        FlextLdifServersOudHelpersMixin as FlextLdifServersOudHelpersMixin,
    )
    from flext_ldif.servers._oud.schema import (
        FlextLdifServersOudSchema as FlextLdifServersOudSchema,
    )
    from flext_ldif.servers._oud.transform import (
        FlextLdifServersOudTransformMixin as FlextLdifServersOudTransformMixin,
    )
    from flext_ldif.servers._oud.utilities import (
        FlextLdifServersOudUtilities as FlextLdifServersOudUtilities,
    )
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
