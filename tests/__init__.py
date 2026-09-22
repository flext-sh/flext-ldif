# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_cli import cli
    from flext_infra import docs_main, infra, main
    from flext_tests import (
        active_rules,
        api,
        config,
        discover_repository_root,
        install_local_packages,
        load_infra_report,
        settings,
        split_csv,
        td,
        tf,
        tk,
        tm,
        tv,
    )
    from pydantic_core import from_json, to_json, to_jsonable_python

    from flext_core import core, d, e, h, lazy_attribute, r, x
    from flext_ldif import ldif

    from . import integration, unit
    from .base import TestsFlextLdifServiceBase, TestsFlextLdifServiceBase as s
    from .constants import TestsFlextLdifConstants, c
    from .models import TestsFlextLdifModels, m
    from .protocols import TestsFlextLdifProtocols, TestsFlextLdifProtocols as p
    from .settings import TestsFlextLdifSettings
    from .typings import TestsFlextLdifTypes, t
    from .utilities import TestsFlextLdifUtilities, u
__all__: tuple[str, ...] = (
    "TestsFlextLdifConstants",
    "TestsFlextLdifModels",
    "TestsFlextLdifProtocols",
    "TestsFlextLdifServiceBase",
    "TestsFlextLdifSettings",
    "TestsFlextLdifTypes",
    "TestsFlextLdifUtilities",
    "active_rules",
    "api",
    "c",
    "cli",
    "config",
    "core",
    "d",
    "discover_repository_root",
    "docs_main",
    "e",
    "from_json",
    "h",
    "infra",
    "install_local_packages",
    "integration",
    "lazy_attribute",
    "ldif",
    "load_infra_report",
    "m",
    "main",
    "p",
    "r",
    "s",
    "settings",
    "split_csv",
    "t",
    "td",
    "tf",
    "tk",
    "tm",
    "to_json",
    "to_jsonable_python",
    "tv",
    "u",
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
            "flext_cli": ("cli",),
            "flext_core": ("core", "d", "e", "h", "lazy_attribute", "r", "x"),
            "flext_infra": ("docs_main", "infra", "main"),
            "flext_ldif": ("ldif",),
            "flext_tests": (
                "active_rules",
                "api",
                "config",
                "discover_repository_root",
                "install_local_packages",
                "load_infra_report",
                "settings",
                "split_csv",
                "td",
                "tf",
                "tk",
                "tm",
                "tv",
            ),
            "pydantic_core": ("from_json", "to_json", "to_jsonable_python"),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)
