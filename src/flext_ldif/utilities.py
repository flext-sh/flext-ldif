"""FLEXT LDIF Utilities - Reusable helpers for LDIF operations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_cli import FlextCliUtilities

from flext_ldif._utilities.collection_ldif import FlextLdifUtilitiesCollectionLdif

if TYPE_CHECKING:
    from typing import Any

# NOTE (import discipline): models.py binds the ``u`` namespace while
# flext_ldif.models is still mid-init (``u.Field`` runs at class-definition
# time). Building the full ``Ldif`` mixin tree here would re-enter the partial
# models module — the ``_utilities`` family evaluates ``FlextLdifModels`` at
# class level (dispatch.py type adapters) and imports ``m`` from the package
# root. The tree is therefore assembled lazily on first ``Ldif`` access, when
# the package is fully initialized, making both import orders
# (models-first and utilities-first) safe.

_Ldif_tree: type | None = None


def _build_ldif_tree() -> type:
    """Assemble the ``Ldif`` mixin tree on first access.

    Returns:
        The assembled ``Ldif`` utility namespace class.

    """
    global _Ldif_tree
    if _Ldif_tree is not None:
        return _Ldif_tree
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

    _Ldif_tree = Ldif
    return _Ldif_tree


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

        def __getattr__(cls, name: str) -> Any:
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
    """FLEXT LDIF Utilities - Centralized helpers for LDIF operations."""


u = FlextLdifUtilities

__all__: list[str] = ["FlextLdifUtilities", "u"]
