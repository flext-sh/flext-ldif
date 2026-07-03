"""Public API freeze tests for the flext_ldif root package."""

from __future__ import annotations

import pytest
from flext_tests import tm

import flext_ldif

PUBLIC_API: tuple[str, ...] = (
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

PRIVATE_ROOT_SYMBOLS: tuple[str, ...] = (
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
    """Validate the canonical root package public surface."""

    def test_root_all_matches_frozen_public_api(self) -> None:
        """Root __all__ exposes only the frozen public API."""
        tm.that(tuple(flext_ldif.__all__), eq=PUBLIC_API)

    def test_root_lazy_exports_are_public_api_symbols(self) -> None:
        """The root package cannot expose private implementation symbols."""
        exported_symbols = set(flext_ldif.__all__)
        public_symbols = set(PUBLIC_API)

        tm.that(exported_symbols - public_symbols, eq=set())

    @pytest.mark.parametrize("symbol", PUBLIC_API)
    def test_root_public_symbols_resolve(self, symbol: str) -> None:
        """Every frozen public root symbol resolves."""
        tm.that(hasattr(flext_ldif, symbol), eq=True)

    @pytest.mark.parametrize("symbol", PRIVATE_ROOT_SYMBOLS)
    def test_private_implementation_symbols_are_not_root_exports(
        self,
        symbol: str,
    ) -> None:
        """Implementation classes stay behind their canonical owner modules."""
        tm.that(symbol not in flext_ldif.__all__, eq=True)
        with pytest.raises(AttributeError):
            getattr(flext_ldif, symbol)
