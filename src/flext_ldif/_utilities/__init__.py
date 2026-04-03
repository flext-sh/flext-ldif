# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Utilities package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_ldif import (
        acl,
        attribute,
        collection_ldif,
        detection,
        dispatch,
        dn,
        entry,
        events,
        metadata,
        object_class,
        oid,
        parser,
        parsers,
        pipeline,
        result,
        schema,
        server,
        transformers,
        validation,
        writer,
        writers,
    )
    from flext_ldif.acl import FlextLdifUtilitiesACL
    from flext_ldif.attribute import FlextLdifUtilitiesAttribute
    from flext_ldif.collection_ldif import FlextLdifUtilitiesCollectionLdif
    from flext_ldif.detection import FlextLdifUtilitiesDetection
    from flext_ldif.dispatch import FlextLdifUtilitiesDispatch
    from flext_ldif.dn import FlextLdifUtilitiesDN
    from flext_ldif.entry import FlextLdifUtilitiesEntry
    from flext_ldif.events import FlextLdifUtilitiesEvents
    from flext_ldif.metadata import FlextLdifUtilitiesMetadata
    from flext_ldif.object_class import FlextLdifUtilitiesObjectClass
    from flext_ldif.oid import FlextLdifUtilitiesOID
    from flext_ldif.parser import FlextLdifUtilitiesParser
    from flext_ldif.parsers import FlextLdifUtilitiesParsers
    from flext_ldif.pipeline import FlextLdifUtilitiesPipeline
    from flext_ldif.result import FlextLdifUtilitiesResult
    from flext_ldif.schema import FlextLdifUtilitiesSchema
    from flext_ldif.server import FlextLdifUtilitiesServer
    from flext_ldif.transformers import FlextLdifUtilitiesTransformer
    from flext_ldif.validation import FlextLdifUtilitiesValidation
    from flext_ldif.writer import FlextLdifUtilitiesWriter
    from flext_ldif.writers import FlextLdifUtilitiesWriters, logger

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "FlextLdifUtilitiesACL": "flext_ldif.acl",
    "FlextLdifUtilitiesAttribute": "flext_ldif.attribute",
    "FlextLdifUtilitiesCollectionLdif": "flext_ldif.collection_ldif",
    "FlextLdifUtilitiesDN": "flext_ldif.dn",
    "FlextLdifUtilitiesDetection": "flext_ldif.detection",
    "FlextLdifUtilitiesDispatch": "flext_ldif.dispatch",
    "FlextLdifUtilitiesEntry": "flext_ldif.entry",
    "FlextLdifUtilitiesEvents": "flext_ldif.events",
    "FlextLdifUtilitiesMetadata": "flext_ldif.metadata",
    "FlextLdifUtilitiesOID": "flext_ldif.oid",
    "FlextLdifUtilitiesObjectClass": "flext_ldif.object_class",
    "FlextLdifUtilitiesParser": "flext_ldif.parser",
    "FlextLdifUtilitiesParsers": "flext_ldif.parsers",
    "FlextLdifUtilitiesPipeline": "flext_ldif.pipeline",
    "FlextLdifUtilitiesResult": "flext_ldif.result",
    "FlextLdifUtilitiesSchema": "flext_ldif.schema",
    "FlextLdifUtilitiesServer": "flext_ldif.server",
    "FlextLdifUtilitiesTransformer": "flext_ldif.transformers",
    "FlextLdifUtilitiesValidation": "flext_ldif.validation",
    "FlextLdifUtilitiesWriter": "flext_ldif.writer",
    "FlextLdifUtilitiesWriters": "flext_ldif.writers",
    "acl": "flext_ldif.acl",
    "attribute": "flext_ldif.attribute",
    "collection_ldif": "flext_ldif.collection_ldif",
    "detection": "flext_ldif.detection",
    "dispatch": "flext_ldif.dispatch",
    "dn": "flext_ldif.dn",
    "entry": "flext_ldif.entry",
    "events": "flext_ldif.events",
    "logger": "flext_ldif.writers",
    "metadata": "flext_ldif.metadata",
    "object_class": "flext_ldif.object_class",
    "oid": "flext_ldif.oid",
    "parser": "flext_ldif.parser",
    "parsers": "flext_ldif.parsers",
    "pipeline": "flext_ldif.pipeline",
    "result": "flext_ldif.result",
    "schema": "flext_ldif.schema",
    "server": "flext_ldif.server",
    "transformers": "flext_ldif.transformers",
    "validation": "flext_ldif.validation",
    "writer": "flext_ldif.writer",
    "writers": "flext_ldif.writers",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
