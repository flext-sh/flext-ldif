# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from types import MappingProxyType

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from . import integration as integration
    from . import unit as unit
    from enum import StrEnum, unique
    from flext_tests import FlextTestsConstants, d, e, h, r, td, tf, tk, tm, tv, x
    from pathlib import Path
    from typing import Final, Literal, TYPE_CHECKING

    from .base import TestsFlextLdifServiceBase, TestsFlextLdifServiceBase as s
    from .constants import TestsFlextLdifConstants, TestsFlextLdifConstants as c
    from .integration.fixtures import (
        clean_test_ou,
        ldap_connection,
        ldap_container,
        make_test_base_dn,
        make_test_username,
        unique_dn_suffix,
    )
    from .models import TestsFlextLdifModels, TestsFlextLdifModels as m
    from .protocols import TestsFlextLdifProtocols, TestsFlextLdifProtocols as p
    from .settings import TestsFlextLdifSettings
    from .typings import TestsFlextLdifTypes, TestsFlextLdifTypes as t
    from .unit.fixtures import (
        api,
        conversion_matrix,
        fixtures_dir,
        migration_dirs,
        migration_pipeline_factory,
        oid_acl_fixture,
        oid_acl_server,
        oid_entries,
        oid_entries_fixture,
        oid_integration_fixture,
        oid_schema_fixture,
        oid_schema_server,
        oid_server,
        oud_acl_fixture,
        oud_acl_server,
        oud_entries,
        oud_entries_fixture,
        oud_integration_fixture,
        oud_schema_fixture,
        oud_schema_server,
        oud_server,
        parser,
        server,
        writer,
    )
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
    "api",
    "c",
    "clean_test_ou",
    "conversion_matrix",
    "d",
    "e",
    "fixtures_dir",
    "h",
    "integration",
    "ldap_connection",
    "ldap_container",
    "m",
    "make_test_base_dn",
    "make_test_username",
    "migration_dirs",
    "migration_pipeline_factory",
    "oid_acl_fixture",
    "oid_acl_server",
    "oid_entries",
    "oid_entries_fixture",
    "oid_integration_fixture",
    "oid_schema_fixture",
    "oid_schema_server",
    "oid_server",
    "oud_acl_fixture",
    "oud_acl_server",
    "oud_entries",
    "oud_entries_fixture",
    "oud_integration_fixture",
    "oud_schema_fixture",
    "oud_schema_server",
    "oud_server",
    "p",
    "parser",
    "r",
    "s",
    "server",
    "t",
    "td",
    "tf",
    "tk",
    "tm",
    "tv",
    "u",
    "unique",
    "unique_dn_suffix",
    "unit",
    "writer",
    "x",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".base": ("TestsFlextLdifServiceBase", "s"),
            ".constants": ("TestsFlextLdifConstants", "c"),
            ".integration": ("integration",),
            ".integration.fixtures": (
                "clean_test_ou",
                "ldap_connection",
                "ldap_container",
                "make_test_base_dn",
                "make_test_username",
                "unique_dn_suffix",
            ),
            ".models": ("TestsFlextLdifModels", "m"),
            ".protocols": ("TestsFlextLdifProtocols", "p"),
            ".settings": ("TestsFlextLdifSettings",),
            ".typings": ("TestsFlextLdifTypes", "t"),
            ".unit": ("unit",),
            ".unit.fixtures": (
                "api",
                "conversion_matrix",
                "fixtures_dir",
                "migration_dirs",
                "migration_pipeline_factory",
                "oid_acl_fixture",
                "oid_acl_server",
                "oid_entries",
                "oid_entries_fixture",
                "oid_integration_fixture",
                "oid_schema_fixture",
                "oid_schema_server",
                "oid_server",
                "oud_acl_fixture",
                "oud_acl_server",
                "oud_entries",
                "oud_entries_fixture",
                "oud_integration_fixture",
                "oud_schema_fixture",
                "oud_schema_server",
                "oud_server",
                "parser",
                "server",
                "writer",
            ),
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
