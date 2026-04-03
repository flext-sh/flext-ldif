# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Utilities package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    import flext_ldif._utilities.acl as _flext_ldif__utilities_acl

    acl = _flext_ldif__utilities_acl
    import flext_ldif._utilities.attribute as _flext_ldif__utilities_attribute
    from flext_ldif._utilities.acl import FlextLdifUtilitiesACL

    attribute = _flext_ldif__utilities_attribute
    import flext_ldif._utilities.collection_ldif as _flext_ldif__utilities_collection_ldif
    from flext_ldif._utilities.attribute import FlextLdifUtilitiesAttribute

    collection_ldif = _flext_ldif__utilities_collection_ldif
    import flext_ldif._utilities.detection as _flext_ldif__utilities_detection
    from flext_ldif._utilities.collection_ldif import FlextLdifUtilitiesCollectionLdif

    detection = _flext_ldif__utilities_detection
    import flext_ldif._utilities.dispatch as _flext_ldif__utilities_dispatch
    from flext_ldif._utilities.detection import FlextLdifUtilitiesDetection

    dispatch = _flext_ldif__utilities_dispatch
    import flext_ldif._utilities.dn as _flext_ldif__utilities_dn
    from flext_ldif._utilities.dispatch import FlextLdifUtilitiesDispatch

    dn = _flext_ldif__utilities_dn
    import flext_ldif._utilities.entry as _flext_ldif__utilities_entry
    from flext_ldif._utilities.dn import FlextLdifUtilitiesDN

    entry = _flext_ldif__utilities_entry
    import flext_ldif._utilities.events as _flext_ldif__utilities_events
    from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry

    events = _flext_ldif__utilities_events
    import flext_ldif._utilities.metadata as _flext_ldif__utilities_metadata
    from flext_ldif._utilities.events import FlextLdifUtilitiesEvents

    metadata = _flext_ldif__utilities_metadata
    import flext_ldif._utilities.object_class as _flext_ldif__utilities_object_class
    from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata

    object_class = _flext_ldif__utilities_object_class
    import flext_ldif._utilities.oid as _flext_ldif__utilities_oid
    from flext_ldif._utilities.object_class import FlextLdifUtilitiesObjectClass

    oid = _flext_ldif__utilities_oid
    import flext_ldif._utilities.parser as _flext_ldif__utilities_parser
    from flext_ldif._utilities.oid import FlextLdifUtilitiesOID

    parser = _flext_ldif__utilities_parser
    import flext_ldif._utilities.parsers as _flext_ldif__utilities_parsers
    from flext_ldif._utilities.parser import FlextLdifUtilitiesParser

    parsers = _flext_ldif__utilities_parsers
    import flext_ldif._utilities.pipeline as _flext_ldif__utilities_pipeline
    from flext_ldif._utilities.parsers import FlextLdifUtilitiesParsers

    pipeline = _flext_ldif__utilities_pipeline
    import flext_ldif._utilities.result as _flext_ldif__utilities_result
    from flext_ldif._utilities.pipeline import FlextLdifUtilitiesPipeline

    result = _flext_ldif__utilities_result
    import flext_ldif._utilities.schema as _flext_ldif__utilities_schema
    from flext_ldif._utilities.result import FlextLdifUtilitiesResult

    schema = _flext_ldif__utilities_schema
    import flext_ldif._utilities.server as _flext_ldif__utilities_server
    from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema

    server = _flext_ldif__utilities_server
    import flext_ldif._utilities.transformers as _flext_ldif__utilities_transformers
    from flext_ldif._utilities.server import FlextLdifUtilitiesServer

    transformers = _flext_ldif__utilities_transformers
    import flext_ldif._utilities.validation as _flext_ldif__utilities_validation
    from flext_ldif._utilities.transformers import (
        FlextLdifUtilitiesTransformer,
        FlextLdifUtilitiesTransformers,
    )

    validation = _flext_ldif__utilities_validation
    import flext_ldif._utilities.writer as _flext_ldif__utilities_writer
    from flext_ldif._utilities.validation import FlextLdifUtilitiesValidation

    writer = _flext_ldif__utilities_writer
    import flext_ldif._utilities.writers as _flext_ldif__utilities_writers
    from flext_ldif._utilities.writer import FlextLdifUtilitiesWriter

    writers = _flext_ldif__utilities_writers
    from flext_ldif._utilities.writers import FlextLdifUtilitiesWriters, logger
_LAZY_IMPORTS = {
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

__all__ = [
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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
