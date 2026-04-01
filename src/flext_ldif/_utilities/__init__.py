# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""FLEXT LDIF Utilities - Internal package exports."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes

    from flext_ldif._utilities import (
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
    from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
    from flext_ldif._utilities.attribute import FlextLdifUtilitiesAttribute
    from flext_ldif._utilities.collection_ldif import FlextLdifUtilitiesCollectionLdif
    from flext_ldif._utilities.detection import FlextLdifUtilitiesDetection
    from flext_ldif._utilities.dispatch import FlextLdifUtilitiesDispatch
    from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
    from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
    from flext_ldif._utilities.events import FlextLdifUtilitiesEvents
    from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
    from flext_ldif._utilities.object_class import FlextLdifUtilitiesObjectClass
    from flext_ldif._utilities.oid import FlextLdifUtilitiesOID
    from flext_ldif._utilities.parser import FlextLdifUtilitiesParser
    from flext_ldif._utilities.parsers import FlextLdifUtilitiesParsers
    from flext_ldif._utilities.pipeline import FlextLdifUtilitiesPipeline
    from flext_ldif._utilities.result import FlextLdifUtilitiesResult
    from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema
    from flext_ldif._utilities.server import FlextLdifUtilitiesServer
    from flext_ldif._utilities.transformers import (
        FlextLdifUtilitiesTransformer,
        FlextLdifUtilitiesTransformers,
    )
    from flext_ldif._utilities.validation import FlextLdifUtilitiesValidation
    from flext_ldif._utilities.writer import FlextLdifUtilitiesWriter
    from flext_ldif._utilities.writers import FlextLdifUtilitiesWriters, logger

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "FlextLdifUtilitiesACL": "flext_ldif._utilities.acl",
    "FlextLdifUtilitiesAttribute": "flext_ldif._utilities.attribute",
    "FlextLdifUtilitiesCollectionLdif": "flext_ldif._utilities.collection_ldif",
    "FlextLdifUtilitiesDN": "flext_ldif._utilities.dn",
    "FlextLdifUtilitiesDetection": "flext_ldif._utilities.detection",
    "FlextLdifUtilitiesDispatch": "flext_ldif._utilities.dispatch",
    "FlextLdifUtilitiesEntry": "flext_ldif._utilities.entry",
    "FlextLdifUtilitiesEvents": "flext_ldif._utilities.events",
    "FlextLdifUtilitiesMetadata": "flext_ldif._utilities.metadata",
    "FlextLdifUtilitiesOID": "flext_ldif._utilities.oid",
    "FlextLdifUtilitiesObjectClass": "flext_ldif._utilities.object_class",
    "FlextLdifUtilitiesParser": "flext_ldif._utilities.parser",
    "FlextLdifUtilitiesParsers": "flext_ldif._utilities.parsers",
    "FlextLdifUtilitiesPipeline": "flext_ldif._utilities.pipeline",
    "FlextLdifUtilitiesResult": "flext_ldif._utilities.result",
    "FlextLdifUtilitiesSchema": "flext_ldif._utilities.schema",
    "FlextLdifUtilitiesServer": "flext_ldif._utilities.server",
    "FlextLdifUtilitiesTransformer": "flext_ldif._utilities.transformers",
    "FlextLdifUtilitiesTransformers": "flext_ldif._utilities.transformers",
    "FlextLdifUtilitiesValidation": "flext_ldif._utilities.validation",
    "FlextLdifUtilitiesWriter": "flext_ldif._utilities.writer",
    "FlextLdifUtilitiesWriters": "flext_ldif._utilities.writers",
    "acl": "flext_ldif._utilities.acl",
    "attribute": "flext_ldif._utilities.attribute",
    "collection_ldif": "flext_ldif._utilities.collection_ldif",
    "detection": "flext_ldif._utilities.detection",
    "dispatch": "flext_ldif._utilities.dispatch",
    "dn": "flext_ldif._utilities.dn",
    "entry": "flext_ldif._utilities.entry",
    "events": "flext_ldif._utilities.events",
    "logger": "flext_ldif._utilities.writers",
    "metadata": "flext_ldif._utilities.metadata",
    "object_class": "flext_ldif._utilities.object_class",
    "oid": "flext_ldif._utilities.oid",
    "parser": "flext_ldif._utilities.parser",
    "parsers": "flext_ldif._utilities.parsers",
    "pipeline": "flext_ldif._utilities.pipeline",
    "result": "flext_ldif._utilities.result",
    "schema": "flext_ldif._utilities.schema",
    "server": "flext_ldif._utilities.server",
    "transformers": "flext_ldif._utilities.transformers",
    "validation": "flext_ldif._utilities.validation",
    "writer": "flext_ldif._utilities.writer",
    "writers": "flext_ldif._utilities.writers",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
