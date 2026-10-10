"""FLEXT LDIF Utilities - Reusable helpers for LDIF operations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING, ClassVar

from flext_cli import FlextCliUtilities

from flext_ldif import _utilities as _utilities_family
from flext_ldif._utilities import FlextLdifUtilitiesCollectionLdif
from flext_ldif._utilities._lazy_meta import FlextLdifUtilitiesLazyMeta

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


class FlextLdifUtilities(
    FlextCliUtilities,
    FlextLdifUtilitiesCollectionLdif,
    metaclass=FlextLdifUtilitiesLazyMeta,
):
    """Centralized helpers with domain collection behavior under ``Ldif``.

    The root inherits the core ``find`` Result contract. LDIF's optional-item
    ``find`` belongs only to ``Ldif`` and must not enter the root MRO.
    """

    # NOTE (import discipline): models.py binds the ``u`` namespace while
    # flext_ldif.models is still mid-init (``u.Field`` runs at class-definition
    # time). Building the full ``Ldif`` mixin tree here would re-enter the partial
    # models module — the ``_utilities`` family evaluates ``FlextLdifModels`` at
    # class level (dispatch.py type adapters) and imports ``m`` from the package
    # root. The tree is therefore assembled lazily on first ``Ldif`` access, when
    # the package is fully initialized, making both import orders
    # (models-first and utilities-first) safe.
    LAZY_UTILITIES: ClassVar[tuple[tuple[str, str], ...]] = (
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
        the package is fully initialized.

        Returns:
            The assembled ``Ldif`` utility namespace class.
        """
        bases: list[type] = [
            FlextLdifUtilitiesCollectionLdif.Search,
            FlextLdifUtilitiesCollectionLdif,
        ]
        family = _utilities_family
        for _, class_name in FlextLdifUtilities.LAZY_UTILITIES:
            bases.append(getattr(family, class_name))
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
