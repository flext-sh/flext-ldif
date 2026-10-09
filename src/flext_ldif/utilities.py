"""FLEXT LDIF Utilities - Reusable helpers for LDIF operations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import importlib
from functools import lru_cache
from typing import TYPE_CHECKING, ClassVar, Final

from flext_cli import FlextCliUtilities

from flext_ldif._utilities import FlextLdifUtilitiesCollectionLdif

if TYPE_CHECKING:
    from flext_ldif._utilities import (
        FlextLdifUtilitiesACL,
        FlextLdifUtilitiesAttribute,
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


def _meta_getattr(cls: type, name: str) -> type:
    """Assemble and return the ``Ldif`` tree on first class-level access.

    Returns:
        The resulting ``type``.

    Raises:
        AttributeError: If type object.
    """
    if name == "Ldif":
        return FlextLdifUtilities._build_ldif_tree()
    msg = f"type object {cls.__name__!r} has no attribute {name!r}"
    raise AttributeError(
        msg,
    )


if TYPE_CHECKING:
    # Static metaclass contract: static analysis needs a real class symbol for
    # the ``metaclass=`` expression, while the codegen facade scanner requires
    # exactly ONE runtime module-level class in a utilities module. The runtime
    # branch below assembles the structurally identical metaclass dynamically.
    class _LazyLdifMeta(type):
        """Assemble ``Ldif`` on first class-level access."""

        __getattr__ = _meta_getattr

else:
    _LazyLdifMeta: Final[type] = type(
        "_LazyLdifMeta",
        (type,),
        {
            "__doc__": "Assemble ``Ldif`` on first class-level access.",
            "__getattr__": _meta_getattr,
        },
    )


class FlextLdifUtilities(
    FlextCliUtilities,
    FlextLdifUtilitiesCollectionLdif,
    metaclass=_LazyLdifMeta,
):
    """FLEXT LDIF Utilities - Centralized helpers for LDIF operations."""

    # NOTE (import discipline): models.py binds the ``u`` namespace while
    # flext_ldif.models is still mid-init (``u.Field`` runs at class-definition
    # time). Building the full ``Ldif`` mixin tree here would re-enter the partial
    # models module — the ``_utilities`` family evaluates ``FlextLdifModels`` at
    # class level (dispatch.py type adapters) and imports ``m`` from the package
    # root. The tree is therefore assembled lazily on first ``Ldif`` access, when
    # the package is fully initialized, making both import orders
    # (models-first and utilities-first) safe.
    _LAZY_UTILITIES: ClassVar[tuple[tuple[str, str], ...]] = (
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

    @staticmethod
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
        bases: list[type] = [FlextLdifUtilitiesCollectionLdif]
        for module_name, class_name in FlextLdifUtilities._LAZY_UTILITIES:
            module = importlib.import_module(f"flext_ldif._utilities.{module_name}")
            bases.append(getattr(module, class_name))
        return type(
            "Ldif", tuple(bases), {"__doc__": "LDIF-specific utility namespace."}
        )

    if TYPE_CHECKING:
        # Static view of the lazily assembled ``Ldif`` namespace: runtime
        # assembly stays inside the metaclass (import-order safety), while
        # this nested class makes ``Ldif.*`` statically resolvable for
        # consumers fleet-wide. It reuses the real ``_utilities`` mixin
        # classes, so signatures have a single owner.
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
            """Static view of the LDIF-specific utility namespace."""


u = FlextLdifUtilities

__all__: list[str] = ["FlextLdifUtilities", "u"]
