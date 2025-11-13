"""LDIF Utilities - Pure Helper Functions for LDIF Processing.

RFC 4514 DN operations, string manipulation, LDIF formatting.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import logging

from flext_ldif._utilities import (
    FlextLdifUtilitiesACL,
    FlextLdifUtilitiesAttribute,
    FlextLdifUtilitiesDecorators,
    FlextLdifUtilitiesDetection,
    FlextLdifUtilitiesDN,
    FlextLdifUtilitiesEntry,
    FlextLdifUtilitiesEvents,
    FlextLdifUtilitiesMetadata,
    FlextLdifUtilitiesObjectClass,
    FlextLdifUtilitiesOID,
    FlextLdifUtilitiesParser,
    FlextLdifUtilitiesSchema,
    FlextLdifUtilitiesValidation,
    FlextLdifUtilitiesWriter,
)

logger = logging.getLogger(__name__)


class FlextLdifUtilities:
    """Pure LDIF Utilities - RFC 4514 DN operations, string manipulation."""

    ACL = FlextLdifUtilitiesACL
    Attribute = FlextLdifUtilitiesAttribute
    Decorators = FlextLdifUtilitiesDecorators
    Detection = FlextLdifUtilitiesDetection
    DN = FlextLdifUtilitiesDN
    Entry = FlextLdifUtilitiesEntry
    Events = FlextLdifUtilitiesEvents
    Metadata = FlextLdifUtilitiesMetadata
    ObjectClass = FlextLdifUtilitiesObjectClass
    OID = FlextLdifUtilitiesOID
    Parser = FlextLdifUtilitiesParser
    Schema = FlextLdifUtilitiesSchema
    Validation = FlextLdifUtilitiesValidation
    Writer = FlextLdifUtilitiesWriter


__all__ = [
    "FlextLdifUtilities",
]
