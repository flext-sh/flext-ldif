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
    from flext_ldif._utilities.acl import *
    from flext_ldif._utilities.attribute import *
    from flext_ldif._utilities.collection_ldif import *
    from flext_ldif._utilities.detection import *
    from flext_ldif._utilities.dispatch import *
    from flext_ldif._utilities.dn import *
    from flext_ldif._utilities.entry import *
    from flext_ldif._utilities.events import *
    from flext_ldif._utilities.metadata import *
    from flext_ldif._utilities.object_class import *
    from flext_ldif._utilities.oid import *
    from flext_ldif._utilities.parser import *
    from flext_ldif._utilities.parsers import *
    from flext_ldif._utilities.pipeline import *
    from flext_ldif._utilities.result import *
    from flext_ldif._utilities.schema import *
    from flext_ldif._utilities.server import *
    from flext_ldif._utilities.transformers import *
    from flext_ldif._utilities.validation import *
    from flext_ldif._utilities.writer import *
    from flext_ldif._utilities.writers import *

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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, sorted(_LAZY_IMPORTS))
