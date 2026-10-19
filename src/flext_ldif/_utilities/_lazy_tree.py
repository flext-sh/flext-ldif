"""Lazy ``Ldif`` namespace assembly for the LDIF utilities facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING, ClassVar

from flext_ldif import _utilities
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


class FlextLdifUtilitiesLazyTree:
    """Own the lazy ``Ldif`` mixin tree of the LDIF utilities facade."""

    # NOTE (import discipline): models.py binds the ``u`` namespace while
    # flext_ldif.models is still mid-init (``m.Field`` runs at class-definition
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
    def build_ldif_tree() -> type:
        """Assemble the ``Ldif`` mixin tree on first access.

        The lazy, cached assembly keeps both import orders (models-first and
        utilities-first) safe: the ``_utilities`` family evaluates
        ``FlextLdifModels`` at class level, so the tree may only be built once
        the package is fully initialized. The assembled ``Ldif`` utility
        namespace class is cached on the builder function.

        Returns:
            The assembled ``Ldif`` utility namespace class.

        """
        bases: list[type] = [
            FlextLdifUtilitiesCollectionLdif.Search,
            FlextLdifUtilitiesCollectionLdif,
        ]
        family = _utilities
        for _, class_name in FlextLdifUtilitiesLazyTree.lazy_utilities_table():
            bases.append(getattr(family, class_name))
        return type(
            "Ldif", tuple(bases), {"__doc__": "LDIF-specific utility namespace."}
        )

    @classmethod
    def lazy_utilities_table(cls) -> tuple[tuple[str, str], ...]:
        """Expose the lazy utilities registration table.

        Returns:
            The resulting ``tuple[tuple[str, str], ...]``.

        """
        return cls._LAZY_UTILITIES

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


__all__: list[str] = ["FlextLdifUtilitiesLazyTree"]
