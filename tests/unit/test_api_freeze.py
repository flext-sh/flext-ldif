"""Behavioral contract tests for the flext_ldif root package public surface.

These tests exercise the *observable* import contract that downstream consumers
rely on: which names resolve, that lazy resolution is stable, that facade
aliases point at their canonical owners, and that private implementation
classes stay encapsulated. Nothing here reaches into private attributes of the
unit under test -- every assertion goes through the public package namespace.
"""

from __future__ import annotations

import inspect

import pytest
from flext_tests import tm

import flext_ldif

type PublicSymbol = str

PUBLIC_API: tuple[PublicSymbol, ...] = (
    "FlextLdif",
    "FlextLdifAcl",
    "FlextLdifAnalysis",
    "FlextLdifCategorization",
    "FlextLdifConstants",
    "FlextLdifConversion",
    "FlextLdifConversionAclMixin",
    "FlextLdifConversionAclPreserveMixin",
    "FlextLdifConversionEntryMixin",
    "FlextLdifConversionMetadataMixin",
    "FlextLdifConversionSchemaEntryMixin",
    "FlextLdifConversionSchemaMixin",
    "FlextLdifConversionSupportMixin",
    "FlextLdifDetector",
    "FlextLdifEntries",
    "FlextLdifFilters",
    "FlextLdifMigrationPipeline",
    "FlextLdifModels",
    "FlextLdifParser",
    "FlextLdifProcessing",
    "FlextLdifProcessingPipeline",
    "FlextLdifProtocols",
    "FlextLdifServer",
    "FlextLdifServersAd",
    "FlextLdifServersApache",
    "FlextLdifServersBase",
    "FlextLdifServersDs389",
    "FlextLdifServersNovell",
    "FlextLdifServersOid",
    "FlextLdifServersOpenldap",
    "FlextLdifServersOpenldap1",
    "FlextLdifServersOud",
    "FlextLdifServersRelaxed",
    "FlextLdifServersRfc",
    "FlextLdifServersTivoli",
    "FlextLdifServiceBase",
    "FlextLdifSettings",
    "FlextLdifShared",
    "FlextLdifStatistics",
    "FlextLdifTransformer",
    "FlextLdifTypes",
    "FlextLdifUtilities",
    "FlextLdifValidation",
    "FlextLdifWriter",
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__title__",
    "__url__",
    "__version__",
    "__version_info__",
    "c",
    "d",
    "e",
    "h",
    "ldif",
    "m",
    "p",
    "r",
    "s",
    "t",
    "u",
    "x",
)

# Public symbols that consumers use as types (subclass / instantiate / isinstance).
CLASS_SYMBOLS: tuple[PublicSymbol, ...] = tuple(
    name for name in PUBLIC_API if name.startswith("FlextLdif")
)

# Metadata strings exposed at the package root.
METADATA_STRING_SYMBOLS: tuple[PublicSymbol, ...] = (
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__title__",
    "__url__",
    "__version__",
)

# Facade alias -> canonical owner name. Aliases MUST be the *same object* so that
# `isinstance(x, flext_ldif.m.Entry)` and `flext_ldif.FlextLdifModels.Entry`
# agree for every consumer.
FACADE_ALIAS_OWNERS: tuple[tuple[PublicSymbol, PublicSymbol], ...] = (
    ("c", "FlextLdifConstants"),
    ("m", "FlextLdifModels"),
    ("p", "FlextLdifProtocols"),
    ("s", "FlextLdifServiceBase"),
    ("t", "FlextLdifTypes"),
    ("u", "FlextLdifUtilities"),
)

# Implementation classes that live behind their canonical owner modules and must
# never leak onto the package root.
PRIVATE_ROOT_SYMBOLS: tuple[PublicSymbol, ...] = (
    "FlextLdifConstantsBase",
    "FlextLdifConstantsEnums",
    "FlextLdifModelsBases",
    "FlextLdifModelsDomainEntry",
    "FlextLdifProtocolsBase",
    "FlextLdifTypesBase",
    "FlextLdifUtilitiesDN",
    "FlextLdifServersBaseSchema",
    "FlextLdifServersOidAcl",
    "FlextLdifServersOudAcl",
    "FlextLdifServersRfcAcl",
)


class TestsFlextLdifApiFreeze:
    """Validate the observable public import contract of ``flext_ldif``."""

    def test_all_declares_the_frozen_public_api(self) -> None:
        """``__all__`` is the exact backward-compatible public surface."""
        tm.that(tuple(flext_ldif.__all__), eq=PUBLIC_API)

    def test_all_entries_are_unique(self) -> None:
        """The advertised surface never lists a name twice."""
        tm.that(list(flext_ldif.__all__), unique=True)

    def test_public_surface_and_private_symbols_are_disjoint(self) -> None:
        """No private implementation class is advertised as public."""
        tm.that(set(PUBLIC_API) & set(PRIVATE_ROOT_SYMBOLS), eq=set())

    @pytest.mark.parametrize("symbol", PUBLIC_API)
    def test_public_symbol_resolves_to_a_real_object(
        self,
        symbol: PublicSymbol,
    ) -> None:
        """Accessing any advertised name yields a bound, non-None object."""
        tm.that(getattr(flext_ldif, symbol), ne=None)

    @pytest.mark.parametrize("symbol", PUBLIC_API)
    def test_lazy_resolution_is_idempotent(
        self,
        symbol: PublicSymbol,
    ) -> None:
        """Repeated access returns the identical object (stable identity)."""
        first = getattr(flext_ldif, symbol)
        second = getattr(flext_ldif, symbol)
        assert first is second

    @pytest.mark.parametrize("symbol", PUBLIC_API)
    def test_public_symbol_is_discoverable_via_dir(
        self,
        symbol: PublicSymbol,
    ) -> None:
        """Every public name shows up in ``dir()`` for interactive discovery."""
        tm.that(symbol in dir(flext_ldif), eq=True)

    @pytest.mark.parametrize("symbol", CLASS_SYMBOLS)
    def test_flext_symbols_resolve_to_classes(
        self,
        symbol: PublicSymbol,
    ) -> None:
        """Every ``FlextLdif*`` public name is a class consumers can use."""
        tm.that(inspect.isclass(getattr(flext_ldif, symbol)), eq=True)

    @pytest.mark.parametrize(("alias", "owner"), FACADE_ALIAS_OWNERS)
    def test_facade_alias_is_its_canonical_owner(
        self,
        alias: PublicSymbol,
        owner: PublicSymbol,
    ) -> None:
        """Short facade aliases are the same object as their named owner."""
        assert getattr(flext_ldif, alias) is getattr(flext_ldif, owner)

    def test_ldif_singleton_is_a_flext_ldif_instance(self) -> None:
        """The ``ldif`` convenience handle is an instance of ``FlextLdif``."""
        tm.that(isinstance(flext_ldif.ldif, flext_ldif.FlextLdif), eq=True)

    @pytest.mark.parametrize("symbol", METADATA_STRING_SYMBOLS)
    def test_metadata_strings_are_non_empty_strings(
        self,
        symbol: PublicSymbol,
    ) -> None:
        """Package metadata is exposed as populated strings."""
        value = getattr(flext_ldif, symbol)
        assert isinstance(value, str)
        tm.that(value, ne="")

    def test_version_info_is_a_tuple(self) -> None:
        """``__version_info__`` is exposed as a tuple for structured checks."""
        tm.that(isinstance(flext_ldif.__version_info__, tuple), eq=True)

    @pytest.mark.parametrize("symbol", PRIVATE_ROOT_SYMBOLS)
    def test_private_symbol_is_not_advertised(
        self,
        symbol: PublicSymbol,
    ) -> None:
        """Implementation classes never appear in the advertised surface."""
        tm.that(symbol in flext_ldif.__all__, eq=False)

    @pytest.mark.parametrize("symbol", PRIVATE_ROOT_SYMBOLS)
    def test_private_symbol_is_not_accessible_from_root(
        self,
        symbol: PublicSymbol,
    ) -> None:
        """Accessing a private implementation class raises ``AttributeError``."""
        with pytest.raises(AttributeError):
            getattr(flext_ldif, symbol)

    def test_unknown_attribute_raises_attribute_error(self) -> None:
        """The lazy ``__getattr__`` rejects names outside the public surface."""
        with pytest.raises(AttributeError):
            getattr(flext_ldif, "FlextLdifDoesNotExist")
