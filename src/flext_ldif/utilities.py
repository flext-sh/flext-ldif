"""FLEXT LDIF Utilities - Reusable helpers for LDIF operations."""

from __future__ import annotations

from flext_cli import FlextCliUtilities
from flext_ldif import (
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


class FlextLdifUtilities(FlextCliUtilities):
    """FLEXT LDIF Utilities - Centralized helpers for LDIF operations."""

    class Ldif(
        FlextLdifUtilitiesDispatch,
        FlextLdifUtilitiesCollectionLdif,
        FlextLdifUtilitiesACL,
        FlextLdifUtilitiesAttribute,
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
        """LDIF-specific utility namespace."""


u = FlextLdifUtilities

__all__: list[str] = ["FlextLdifUtilities", "u"]
