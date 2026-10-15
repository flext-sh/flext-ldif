"""FLEXT LDIF Utilities - Reusable helpers for LDIF operations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_cli import FlextCliUtilities

from flext_ldif._utilities import (
    FlextLdifEntryAnalysis,
    FlextLdifEntryAttributeValidation,
    FlextLdifEntryServerRules,
    FlextLdifEntryValidation,
    FlextLdifUtilitiesACL,
    FlextLdifUtilitiesAttribute,
    FlextLdifUtilitiesCollectionLdif,
    FlextLdifUtilitiesDispatch,
    FlextLdifUtilitiesDN,
    FlextLdifUtilitiesEntry,
    FlextLdifUtilitiesEvents,
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


class FlextLdifUtilities(
    FlextCliUtilities,
    FlextLdifUtilitiesCollectionLdif,
    FlextLdifEntryServerRules,
    FlextLdifEntryAnalysis,
    FlextLdifEntryAttributeValidation,
    FlextLdifEntryValidation,
):
    """Centralized helpers with domain collection behavior under ``Ldif``.

    The root inherits the core ``find`` Result contract. LDIF's optional-item
    ``find`` belongs only to ``Ldif`` and must not enter the root MRO.
    """

    class Ldif(
        FlextLdifUtilitiesCollectionLdif.Search,
        FlextLdifUtilitiesCollectionLdif,
        FlextLdifUtilitiesACL,
        FlextLdifUtilitiesAttribute,
        FlextLdifUtilitiesDispatch,
        FlextLdifUtilitiesDN,
        FlextLdifUtilitiesEntry,
        FlextLdifUtilitiesEvents,
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
    ):
        """LDIF utility namespace shared by runtime and static consumers."""


u = FlextLdifUtilities

__all__: list[str] = ["FlextLdifUtilities", "u"]
