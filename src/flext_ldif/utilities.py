# AUTO-GENERATED FILE — Regenerate with: make gen
"""FLEXT LDIF Utilities - Reusable helpers for LDIF operations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_cli import u as flext_cli_u

from flext_ldif._utilities import (
    FlextLdifUtilitiesACL,
    FlextLdifUtilitiesAttribute,
    FlextLdifUtilitiesCollectionLdif,
    FlextLdifUtilitiesDispatch,
    FlextLdifUtilitiesDN,
    FlextLdifUtilitiesEntry,
    FlextLdifUtilitiesEvents,
    FlextLdifUtilitiesLazy,
    FlextLdifUtilitiesLazyMeta,
    FlextLdifUtilitiesMetadata,
    FlextLdifUtilitiesObjectClass,
    FlextLdifUtilitiesOID,
    FlextLdifUtilitiesParser,
    FlextLdifUtilitiesPipeline,
    FlextLdifUtilitiesSchema,
    FlextLdifUtilitiesServer,
    FlextLdifUtilitiesTransformers,
    FlextLdifUtilitiesValidation,
    FlextLdifUtilitiesWriter,
)
from flext_ldif._utilities.flext_ldif_servers_oud_utilities import (
    FlextLdifUtilitiesServersOud,
)


class FlextLdifUtilities(
    FlextLdifUtilitiesLazy,
    FlextLdifUtilitiesACL,
    FlextLdifUtilitiesAttribute,
    FlextLdifUtilitiesCollectionLdif,
    FlextLdifUtilitiesDispatch,
    FlextLdifUtilitiesDN,
    FlextLdifUtilitiesEntry,
    FlextLdifUtilitiesEvents,
    FlextLdifUtilitiesServersOud,
    FlextLdifUtilitiesMetadata,
    FlextLdifUtilitiesObjectClass,
    FlextLdifUtilitiesOID,
    FlextLdifUtilitiesParser,
    FlextLdifUtilitiesSchema,
    FlextLdifUtilitiesServer,
    FlextLdifUtilitiesTransformers,
    FlextLdifUtilitiesValidation,
    FlextLdifUtilitiesWriter,
    FlextLdifUtilitiesPipeline,
    flext_cli_u,
    metaclass=FlextLdifUtilitiesLazyMeta,
):
    """Centralized helpers with domain collection behavior under ``Ldif``.

    The root inherits the core ``find`` Result contract. LDIF's optional-item
    ``find`` belongs only to ``Ldif`` and must not enter the root MRO.
    """


u = FlextLdifUtilities
__all__: list[str] = ["FlextLdifUtilities", "u"]
