"""FLEXT LDIF Utilities - Reusable helpers for LDIF operations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import importlib
from functools import lru_cache
from typing import TYPE_CHECKING

from flext_cli import FlextCliUtilities

from flext_ldif._utilities.collection_ldif import FlextLdifUtilitiesCollectionLdif

if TYPE_CHECKING:
    from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
    from flext_ldif._utilities.attribute import FlextLdifUtilitiesAttribute
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

# NOTE (import discipline): models.py binds the ``u`` namespace while
# flext_ldif.models is still mid-init (``u.Field`` runs at class-definition
# time). Building the full ``Ldif`` mixin tree here would re-enter the partial
# models module — the ``_utilities`` family evaluates ``FlextLdifModels`` at
# class level (dispatch.py type adapters) and imports ``m`` from the package
# root. The tree is therefore assembled lazily on first ``Ldif`` access, when
# the package is fully initialized, making both import orders
# (models-first and utilities-first) safe.

_LAZY_UTILITIES: tuple[tuple[str, str], ...] = (
    ("acl", "FlextLdifUtilitiesACL"),
    ("attribute", "FlextLdifUtilitiesAttribute"),
    ("dispatch", "FlextLdifUtilitiesDispatch"),
    ("dn", "FlextLdifUtilitiesDN"),
    ("entry", "FlextLdifUtilitiesEntry"),
    ("events", "FlextLdifUtilitiesEvents"),
    ("metadata", "FlextLdifUtilitiesMetadata"),
    ("object_class", "FlextLdifUtilitiesObjectClass"),
    ("oid", "FlextLdifUtilitiesOID"),
    ("parser", "FlextLdifUtilitiesParser"),
    ("pipeline", "FlextLdifUtilitiesPipeline"),
    ("schema", "FlextLdifUtilitiesSchema"),
    ("server", "FlextLdifUtilitiesServer"),
    ("transformers", "FlextLdifUtilitiesTransformers"),
    ("validation", "FlextLdifUtilitiesValidation"),
    ("writer", "FlextLdifUtilitiesWriter"),
)


@lru_cache(maxsize=1)
def _build_ldif_tree() -> type:
    """Assemble the ``Ldif`` mixin tree on first access.

    The lazy, cached assembly keeps both import orders (models-first and
    utilities-first) safe: the ``_utilities`` family evaluates
    ``FlextLdifModels`` at class level, so the tree may only be built once
    the package is fully initialized.

    Returns:
        The assembled ``Ldif`` utility namespace class.
    """
    bases: list[type] = [
        FlextLdifUtilitiesCollectionLdif.Search,
        FlextLdifUtilitiesCollectionLdif,
    ]
    for module_name, class_name in _LAZY_UTILITIES:
        module = importlib.import_module(f"flext_ldif._utilities.{module_name}")
        bases.append(getattr(module, class_name))
    return type("Ldif", tuple(bases), {"__doc__": "LDIF-specific utility namespace."})


def _lazy_ldif_meta() -> type:
    """Build the lazy-assembly metaclass.

    The codegen facade scanner requires exactly ONE module-level class in a
    utilities module, so the metaclass is assembled inside this factory
    (a FunctionDef in the AST) instead of a module-level ClassDef.

    Returns:
        The resulting ``type`` metaclass.

    """

    class _Meta(type):
        """Assemble ``Ldif`` on first class-level access."""

        def __getattr__(cls, name: str) -> type:
            if name == "Ldif":
                tree = _build_ldif_tree()
                cls.Ldif = tree
                return tree
            msg = f"type object {cls.__name__!r} has no attribute {name!r}"
            raise AttributeError(
                msg,
            )

    return _Meta


class FlextLdifUtilities(
    FlextCliUtilities,
    FlextLdifUtilitiesCollectionLdif,
    metaclass=_lazy_ldif_meta(),
):
    """Centralized helpers with domain collection behavior under ``Ldif``.

    The root inherits the core ``find`` Result contract. LDIF's optional-item
    ``find`` belongs only to ``Ldif`` and must not enter the root MRO.
    """

    if TYPE_CHECKING:
        # Static view of the lazily assembled ``Ldif`` namespace: runtime
        # assembly stays inside the metaclass (import-order safety), while
        # this nested class makes ``Ldif.*`` statically resolvable for
        # consumers fleet-wide. It reuses the real ``_utilities`` mixin
        # classes, so signatures have a single owner.
        class Ldif(
            FlextLdifUtilitiesACL,
            FlextLdifUtilitiesAttribute,
            FlextLdifUtilitiesCollectionLdif.Search,
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
            """Static view of the LDIF-specific utility namespace."""


u = FlextLdifUtilities

__all__: list[str] = ["FlextLdifUtilities", "u"]
