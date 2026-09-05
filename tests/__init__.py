# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from enum import StrEnum, unique
    from pathlib import Path
    from typing import TYPE_CHECKING, Final, Literal

    from flext_tests import FlextTestsConstants, d, e, h, r, td, tf, tk, tm, tv, x

    from . import integration as integration, unit as unit
    from .base import TestsFlextLdifServiceBase, TestsFlextLdifServiceBase as s
    from .constants import TestsFlextLdifConstants, TestsFlextLdifConstants as c
    from .models import TestsFlextLdifModels, TestsFlextLdifModels as m
    from .protocols import TestsFlextLdifProtocols, TestsFlextLdifProtocols as p
    from .settings import TestsFlextLdifSettings
    from .typings import TestsFlextLdifTypes, TestsFlextLdifTypes as t
    from .utilities import TestsFlextLdifUtilities, TestsFlextLdifUtilities as u
__all__: tuple[str, ...] = (
    "TYPE_CHECKING",
    "Final",
    "FlextTestsConstants",
    "Literal",
    "MappingProxyType",
    "Path",
    "StrEnum",
    "TestsFlextLdifConstants",
    "TestsFlextLdifModels",
    "TestsFlextLdifProtocols",
    "TestsFlextLdifServiceBase",
    "TestsFlextLdifSettings",
    "TestsFlextLdifTypes",
    "TestsFlextLdifUtilities",
    "c",
    "d",
    "e",
    "h",
    "integration",
    "m",
    "p",
    "r",
    "s",
    "t",
    "td",
    "tf",
    "tk",
    "tm",
    "tv",
    "u",
    "unique",
    "unit",
    "x",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".base": ("TestsFlextLdifServiceBase", "s"),
            ".constants": ("TestsFlextLdifConstants", "c"),
            ".integration": ("integration",),
            ".models": ("TestsFlextLdifModels", "m"),
            ".protocols": ("TestsFlextLdifProtocols", "p"),
            ".settings": ("TestsFlextLdifSettings",),
            ".typings": ("TestsFlextLdifTypes", "t"),
            ".unit": ("unit",),
            ".utilities": ("TestsFlextLdifUtilities", "u"),
            "enum": ("StrEnum", "unique"),
            "flext_tests": (
                "FlextTestsConstants",
                "d",
                "e",
                "h",
                "r",
                "td",
                "tf",
                "tk",
                "tm",
                "tv",
                "x",
            ),
            "pathlib": ("Path",),
            "types": ("MappingProxyType",),
            "typing": ("Final", "Literal", "TYPE_CHECKING"),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
