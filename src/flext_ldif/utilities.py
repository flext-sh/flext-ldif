"""FLEXT LDIF Utilities - Reusable helpers for LDIF operations."""

from __future__ import annotations

from flext_cli import u

from ._utilities.acl import FlextLdifUtilitiesACL
from ._utilities.attribute import FlextLdifUtilitiesAttribute
from ._utilities.collection_ldif import FlextLdifUtilitiesCollectionLdif
from ._utilities.dispatch import FlextLdifUtilitiesDispatch
from ._utilities.dn import FlextLdifUtilitiesDN
from ._utilities.entry import FlextLdifUtilitiesEntry
from ._utilities.events import FlextLdifUtilitiesEvents
from ._utilities.metadata import FlextLdifUtilitiesMetadata
from ._utilities.object_class import FlextLdifUtilitiesObjectClass
from ._utilities.oid import FlextLdifUtilitiesOID
from ._utilities.parser import FlextLdifUtilitiesParser
from ._utilities.pipeline import FlextLdifUtilitiesPipeline
from ._utilities.schema import FlextLdifUtilitiesSchema
from ._utilities.server import FlextLdifUtilitiesServer
from ._utilities.transformers import FlextLdifUtilitiesTransformers
from ._utilities.validation import FlextLdifUtilitiesValidation
from ._utilities.writer import FlextLdifUtilitiesWriter


class FlextLdifUtilities(u):
    """FLEXT LDIF Utilities - Centralized helpers for LDIF operations."""

    class Ldif(
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
    ):
        """LDIF-specific utility namespace."""


u = FlextLdifUtilities

__all__: list[str] = ["FlextLdifUtilities", "u"]
