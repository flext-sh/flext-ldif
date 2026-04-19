"""FLEXT LDIF Utilities - Reusable helpers for LDIF operations."""

from __future__ import annotations

from flext_cli import u
from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
from flext_ldif._utilities.attribute import FlextLdifUtilitiesAttribute
from flext_ldif._utilities.collection_ldif import FlextLdifUtilitiesCollectionLdif
from flext_ldif._utilities.dispatch import FlextLdifUtilitiesDispatch
from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
from flext_ldif._utilities.events import FlextLdifUtilitiesEvents
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


class FlextLdifUtilities(u):
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
