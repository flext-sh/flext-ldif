# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif.servers. Oud package.

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
    from flext_ldif.servers._oud.aci import FlextLdifServersOudAci
    from flext_ldif.servers._oud.aci_process import FlextLdifServersOudAciProcess
    from flext_ldif.servers._oud.acl import FlextLdifServersOudAcl
    from flext_ldif.servers._oud.acl_extract import FlextLdifServersOudAclExtract
    from flext_ldif.servers._oud.acl_metadata import FlextLdifServersOudAclMetadata
    from flext_ldif.servers._oud.acl_subject import FlextLdifServersOudAclSubject
    from flext_ldif.servers._oud.acl_write import FlextLdifServersOudAclWrite
    from flext_ldif.servers._oud.comments import FlextLdifServersOudComments
    from flext_ldif.servers._oud.comments_acl import FlextLdifServersOudCommentsAcl
    from flext_ldif.servers._oud.entry import FlextLdifServersOudEntry
    from flext_ldif.servers._oud.entry_parse import FlextLdifServersOudEntryParse
    from flext_ldif.servers._oud.helpers import FlextLdifServersOudHelpers
    from flext_ldif.servers._oud.schema import FlextLdifServersOudSchema
    from flext_ldif.servers._oud.schema_write import FlextLdifServersOudSchemaWrite
    from flext_ldif.servers._oud.server_constants import FlextLdifConstantsServersOud
    from flext_ldif.servers._oud.server_utilities import FlextLdifUtilitiesServersOud
    from flext_ldif.servers._oud.transform import FlextLdifServersOudTransform


__all__: tuple[str, ...] = (
    "FlextLdifConstantsServersOud",
    "FlextLdifServersOudAci",
    "FlextLdifServersOudAciProcess",
    "FlextLdifServersOudAcl",
    "FlextLdifServersOudAclExtract",
    "FlextLdifServersOudAclMetadata",
    "FlextLdifServersOudAclSubject",
    "FlextLdifServersOudAclWrite",
    "FlextLdifServersOudComments",
    "FlextLdifServersOudCommentsAcl",
    "FlextLdifServersOudEntry",
    "FlextLdifServersOudEntryParse",
    "FlextLdifServersOudHelpers",
    "FlextLdifServersOudSchema",
    "FlextLdifServersOudSchemaWrite",
    "FlextLdifServersOudTransform",
    "FlextLdifUtilitiesServersOud",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdifServersOudAci": ".aci",
        "FlextLdifServersOudAciProcess": ".aci_process",
        "FlextLdifServersOudAcl": ".acl",
        "FlextLdifServersOudAclExtract": ".acl_extract",
        "FlextLdifServersOudAclMetadata": ".acl_metadata",
        "FlextLdifServersOudAclSubject": ".acl_subject",
        "FlextLdifServersOudAclWrite": ".acl_write",
        "FlextLdifServersOudCommentsAcl": ".comments_acl",
        "FlextLdifServersOudComments": ".comments",
        "FlextLdifConstantsServersOud": ".server_constants",
        "FlextLdifServersOudEntry": ".entry",
        "FlextLdifServersOudEntryParse": ".entry_parse",
        "FlextLdifServersOudHelpers": ".helpers",
        "FlextLdifServersOudSchema": ".schema",
        "FlextLdifServersOudSchemaWrite": ".schema_write",
        "FlextLdifServersOudTransform": ".transform",
        "FlextLdifUtilitiesServersOud": ".server_utilities",
    }),
    public_exports=__all__,
)
