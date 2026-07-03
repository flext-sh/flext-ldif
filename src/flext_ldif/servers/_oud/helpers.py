"""OUD entry helpers — composed facade.

Per AGENTS.md §2.3 (MRO Composition): single Mixin facade composing all
domain-specific OUD helpers. Consumed by ``FlextLdifServersOudEntry``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.servers._oud.aci import FlextLdifServersOudAciMixin
from flext_ldif.servers._oud.acl_extract import FlextLdifServersOudAclExtractMixin
from flext_ldif.servers._oud.acl_metadata import FlextLdifServersOudAclMetadataMixin
from flext_ldif.servers._oud.comments import FlextLdifServersOudCommentsMixin
from flext_ldif.servers._oud.transform import FlextLdifServersOudTransformMixin


class FlextLdifServersOudHelpersMixin(
    FlextLdifServersOudAciMixin,
    FlextLdifServersOudAclExtractMixin,
    FlextLdifServersOudAclMetadataMixin,
    FlextLdifServersOudCommentsMixin,
    FlextLdifServersOudTransformMixin,
):
    """Composed Mixin facade for OUD entry helpers."""


__all__: list[str] = ["FlextLdifServersOudHelpersMixin"]
