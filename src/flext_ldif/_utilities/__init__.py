# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""FLEXT LDIF Utilities - Internal package exports."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._utilities import (
        acl as acl,
        attribute as attribute,
        collection_ldif as collection_ldif,
        detection as detection,
        dispatch as dispatch,
        dn as dn,
        entry as entry,
        events as events,
        metadata as metadata,
        object_class as object_class,
        oid as oid,
        parser as parser,
        parsers as parsers,
        pipeline as pipeline,
        result as result,
        schema as schema,
        server as server,
        transformers as transformers,
        validation as validation,
        writer as writer,
        writers as writers,
    )
    from flext_ldif._utilities.acl import FlextLdifUtilitiesACL as FlextLdifUtilitiesACL
    from flext_ldif._utilities.attribute import (
        FlextLdifUtilitiesAttribute as FlextLdifUtilitiesAttribute,
    )
    from flext_ldif._utilities.collection_ldif import (
        FlextLdifUtilitiesCollectionLdif as FlextLdifUtilitiesCollectionLdif,
    )
    from flext_ldif._utilities.detection import (
        FlextLdifUtilitiesDetection as FlextLdifUtilitiesDetection,
    )
    from flext_ldif._utilities.dispatch import (
        FlextLdifUtilitiesDispatch as FlextLdifUtilitiesDispatch,
    )
    from flext_ldif._utilities.dn import FlextLdifUtilitiesDN as FlextLdifUtilitiesDN
    from flext_ldif._utilities.entry import (
        FlextLdifUtilitiesEntry as FlextLdifUtilitiesEntry,
    )
    from flext_ldif._utilities.events import (
        FlextLdifUtilitiesEvents as FlextLdifUtilitiesEvents,
    )
    from flext_ldif._utilities.metadata import (
        FlextLdifUtilitiesMetadata as FlextLdifUtilitiesMetadata,
    )
    from flext_ldif._utilities.object_class import (
        FlextLdifUtilitiesObjectClass as FlextLdifUtilitiesObjectClass,
    )
    from flext_ldif._utilities.oid import FlextLdifUtilitiesOID as FlextLdifUtilitiesOID
    from flext_ldif._utilities.parser import (
        FlextLdifUtilitiesParser as FlextLdifUtilitiesParser,
    )
    from flext_ldif._utilities.parsers import (
        FlextLdifUtilitiesParsers as FlextLdifUtilitiesParsers,
    )
    from flext_ldif._utilities.pipeline import (
        FlextLdifUtilitiesPipeline as FlextLdifUtilitiesPipeline,
    )
    from flext_ldif._utilities.result import (
        FlextLdifUtilitiesResult as FlextLdifUtilitiesResult,
    )
    from flext_ldif._utilities.schema import (
        FlextLdifUtilitiesSchema as FlextLdifUtilitiesSchema,
    )
    from flext_ldif._utilities.server import (
        FlextLdifUtilitiesServer as FlextLdifUtilitiesServer,
    )
    from flext_ldif._utilities.transformers import (
        FlextLdifUtilitiesTransformer as FlextLdifUtilitiesTransformer,
        FlextLdifUtilitiesTransformers as FlextLdifUtilitiesTransformers,
    )
    from flext_ldif._utilities.validation import (
        FlextLdifUtilitiesValidation as FlextLdifUtilitiesValidation,
    )
    from flext_ldif._utilities.writer import (
        FlextLdifUtilitiesWriter as FlextLdifUtilitiesWriter,
    )
    from flext_ldif._utilities.writers import (
        FlextLdifUtilitiesWriters as FlextLdifUtilitiesWriters,
        logger as logger,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "FlextLdifUtilitiesACL": ["flext_ldif._utilities.acl", "FlextLdifUtilitiesACL"],
    "FlextLdifUtilitiesAttribute": [
        "flext_ldif._utilities.attribute",
        "FlextLdifUtilitiesAttribute",
    ],
    "FlextLdifUtilitiesCollectionLdif": [
        "flext_ldif._utilities.collection_ldif",
        "FlextLdifUtilitiesCollectionLdif",
    ],
    "FlextLdifUtilitiesDN": ["flext_ldif._utilities.dn", "FlextLdifUtilitiesDN"],
    "FlextLdifUtilitiesDetection": [
        "flext_ldif._utilities.detection",
        "FlextLdifUtilitiesDetection",
    ],
    "FlextLdifUtilitiesDispatch": [
        "flext_ldif._utilities.dispatch",
        "FlextLdifUtilitiesDispatch",
    ],
    "FlextLdifUtilitiesEntry": [
        "flext_ldif._utilities.entry",
        "FlextLdifUtilitiesEntry",
    ],
    "FlextLdifUtilitiesEvents": [
        "flext_ldif._utilities.events",
        "FlextLdifUtilitiesEvents",
    ],
    "FlextLdifUtilitiesMetadata": [
        "flext_ldif._utilities.metadata",
        "FlextLdifUtilitiesMetadata",
    ],
    "FlextLdifUtilitiesOID": ["flext_ldif._utilities.oid", "FlextLdifUtilitiesOID"],
    "FlextLdifUtilitiesObjectClass": [
        "flext_ldif._utilities.object_class",
        "FlextLdifUtilitiesObjectClass",
    ],
    "FlextLdifUtilitiesParser": [
        "flext_ldif._utilities.parser",
        "FlextLdifUtilitiesParser",
    ],
    "FlextLdifUtilitiesParsers": [
        "flext_ldif._utilities.parsers",
        "FlextLdifUtilitiesParsers",
    ],
    "FlextLdifUtilitiesPipeline": [
        "flext_ldif._utilities.pipeline",
        "FlextLdifUtilitiesPipeline",
    ],
    "FlextLdifUtilitiesResult": [
        "flext_ldif._utilities.result",
        "FlextLdifUtilitiesResult",
    ],
    "FlextLdifUtilitiesSchema": [
        "flext_ldif._utilities.schema",
        "FlextLdifUtilitiesSchema",
    ],
    "FlextLdifUtilitiesServer": [
        "flext_ldif._utilities.server",
        "FlextLdifUtilitiesServer",
    ],
    "FlextLdifUtilitiesTransformer": [
        "flext_ldif._utilities.transformers",
        "FlextLdifUtilitiesTransformer",
    ],
    "FlextLdifUtilitiesTransformers": [
        "flext_ldif._utilities.transformers",
        "FlextLdifUtilitiesTransformers",
    ],
    "FlextLdifUtilitiesValidation": [
        "flext_ldif._utilities.validation",
        "FlextLdifUtilitiesValidation",
    ],
    "FlextLdifUtilitiesWriter": [
        "flext_ldif._utilities.writer",
        "FlextLdifUtilitiesWriter",
    ],
    "FlextLdifUtilitiesWriters": [
        "flext_ldif._utilities.writers",
        "FlextLdifUtilitiesWriters",
    ],
    "acl": ["flext_ldif._utilities.acl", ""],
    "attribute": ["flext_ldif._utilities.attribute", ""],
    "collection_ldif": ["flext_ldif._utilities.collection_ldif", ""],
    "detection": ["flext_ldif._utilities.detection", ""],
    "dispatch": ["flext_ldif._utilities.dispatch", ""],
    "dn": ["flext_ldif._utilities.dn", ""],
    "entry": ["flext_ldif._utilities.entry", ""],
    "events": ["flext_ldif._utilities.events", ""],
    "logger": ["flext_ldif._utilities.writers", "logger"],
    "metadata": ["flext_ldif._utilities.metadata", ""],
    "object_class": ["flext_ldif._utilities.object_class", ""],
    "oid": ["flext_ldif._utilities.oid", ""],
    "parser": ["flext_ldif._utilities.parser", ""],
    "parsers": ["flext_ldif._utilities.parsers", ""],
    "pipeline": ["flext_ldif._utilities.pipeline", ""],
    "result": ["flext_ldif._utilities.result", ""],
    "schema": ["flext_ldif._utilities.schema", ""],
    "server": ["flext_ldif._utilities.server", ""],
    "transformers": ["flext_ldif._utilities.transformers", ""],
    "validation": ["flext_ldif._utilities.validation", ""],
    "writer": ["flext_ldif._utilities.writer", ""],
    "writers": ["flext_ldif._utilities.writers", ""],
}

_EXPORTS: Sequence[str] = [
    "FlextLdifUtilitiesACL",
    "FlextLdifUtilitiesAttribute",
    "FlextLdifUtilitiesCollectionLdif",
    "FlextLdifUtilitiesDN",
    "FlextLdifUtilitiesDetection",
    "FlextLdifUtilitiesDispatch",
    "FlextLdifUtilitiesEntry",
    "FlextLdifUtilitiesEvents",
    "FlextLdifUtilitiesMetadata",
    "FlextLdifUtilitiesOID",
    "FlextLdifUtilitiesObjectClass",
    "FlextLdifUtilitiesParser",
    "FlextLdifUtilitiesParsers",
    "FlextLdifUtilitiesPipeline",
    "FlextLdifUtilitiesResult",
    "FlextLdifUtilitiesSchema",
    "FlextLdifUtilitiesServer",
    "FlextLdifUtilitiesTransformer",
    "FlextLdifUtilitiesTransformers",
    "FlextLdifUtilitiesValidation",
    "FlextLdifUtilitiesWriter",
    "FlextLdifUtilitiesWriters",
    "acl",
    "attribute",
    "collection_ldif",
    "detection",
    "dispatch",
    "dn",
    "entry",
    "events",
    "logger",
    "metadata",
    "object_class",
    "oid",
    "parser",
    "parsers",
    "pipeline",
    "result",
    "schema",
    "server",
    "transformers",
    "validation",
    "writer",
    "writers",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
