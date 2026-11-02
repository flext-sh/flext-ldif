# AUTO-GENERATED FILE — Regenerate with: make gen
"""FLEXT LDIF Utilities - Reusable helpers for LDIF operations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TypeAlias

from flext_cli import u as flext_cli_u

from flext_ldif._utilities._lazy import FlextLdifUtilitiesLazyMeta
from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
from flext_ldif._utilities.attribute import FlextLdifUtilitiesAttribute
from flext_ldif._utilities.collection_ldif import FlextLdifUtilitiesCollectionLdif
from flext_ldif._utilities.dispatch import FlextLdifUtilitiesDispatch
from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
from flext_ldif._utilities.events import FlextLdifUtilitiesEvents
from flext_ldif._utilities.flext_ldif_servers_oud_utilities import (
    FlextLdifUtilitiesServersOud,
)
from flext_ldif._utilities.lazy import FlextLdifUtilitiesLazy
from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
from flext_ldif._utilities.object_class import FlextLdifUtilitiesObjectClass
from flext_ldif._utilities.oid import FlextLdifUtilitiesOID
from flext_ldif._utilities.parser import FlextLdifUtilitiesParser
from flext_ldif._utilities.pipeline import FlextLdifUtilitiesPipeline
from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema
from flext_ldif._utilities.server import FlextLdifUtilitiesServer
from flext_ldif._utilities.transformers import FlextLdifUtilitiesTransformers
from flext_ldif._utilities.validation import FlextLdifUtilitiesValidation
from flext_ldif._utilities.writer import FlextLdifUtilitiesWriter


class FlextLdifUtilities(
    flext_cli_u,
    FlextLdifUtilitiesACL,
    FlextLdifUtilitiesAttribute,
    FlextLdifUtilitiesCollectionLdif,
    FlextLdifUtilitiesDispatch,
    FlextLdifUtilitiesDN,
    FlextLdifUtilitiesEntry,
    FlextLdifUtilitiesEvents,
    FlextLdifUtilitiesServersOud,
    FlextLdifUtilitiesLazy,
    FlextLdifUtilitiesMetadata,
    FlextLdifUtilitiesObjectClass,
    FlextLdifUtilitiesOID,
    FlextLdifUtilitiesParser,
    FlextLdifUtilitiesSchema,
    FlextLdifUtilitiesServer,
    FlextLdifUtilitiesTransformers,
    FlextLdifUtilitiesValidation,
    FlextLdifUtilitiesWriter,
    metaclass=FlextLdifUtilitiesLazyMeta,
):
    """Centralized helpers with domain collection behavior under ``Ldif``.

    The root inherits the core ``find`` Result contract. LDIF's optional-item
    ``find`` belongs only to ``Ldif`` and must not enter the root MRO.
    """

    FlextLdifUtilitiesPipeline: TypeAlias = FlextLdifUtilitiesPipeline


u = FlextLdifUtilities
__all__: list[str] = ["FlextLdifUtilities", "u"]
