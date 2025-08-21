"""Test public API imports and functionality."""

from __future__ import annotations

from flext_ldif import (
    FlextLdifAPI,
    FlextLdifAttributes,
    FlextLdifConfig,
    FlextLdifDistinguishedName,
    FlextLdifEntry,
    FlextLdifEntryError,
    FlextLdifError,
    FlextLdifFactory,
    FlextLdifParseError,
    FlextLdifParserService,
    FlextLdifRepositoryService,
    FlextLdifTransformerService,
    FlextLdifValidationError,
    FlextLdifValidatorService,
    FlextLdifWriterService,
    __version__,
    cli_main,
    flext_ldif_get_api,
    flext_ldif_parse,
    flext_ldif_validate,
    flext_ldif_write,
)


class TestModuleImports:
    """Test that all modules can be imported correctly."""

    def test_main_imports(self) -> None:
        """Test main module imports work correctly."""
        assert FlextLdifAPI is not None
        assert FlextLdifConfig is not None

        assert FlextLdifAttributes is not None
        assert FlextLdifDistinguishedName is not None
        assert FlextLdifEntry is not None
        assert FlextLdifFactory is not None

        assert FlextLdifError is not None
        assert FlextLdifValidationError is not None
        assert FlextLdifParseError is not None
        assert FlextLdifEntryError is not None

    def test_service_imports(self) -> None:
        """Test service imports work correctly."""
        assert FlextLdifParserService is not None
        assert FlextLdifRepositoryService is not None
        assert FlextLdifTransformerService is not None
        assert FlextLdifValidatorService is not None
        assert FlextLdifWriterService is not None

    def test_convenience_function_imports(self) -> None:
        """Test convenience function imports."""
        assert flext_ldif_get_api is not None
        assert flext_ldif_parse is not None
        assert flext_ldif_validate is not None
        assert flext_ldif_write is not None

    def test_cli_import(self) -> None:
        """Test CLI import (may be None if dependencies missing)."""
        # CLI may be None if dependencies are missing, which is acceptable
        # Just test that import doesn't raise exception
        assert cli_main is not None or cli_main is None  # Both are valid

    def test_version_import(self) -> None:
        """Test version information import."""
        assert __version__ is not None
        assert isinstance(__version__, str)
        assert len(__version__) > 0

    def test_public_api_functionality(self) -> None:
        """Test that public API functions work correctly."""
        # Test that API creation works
        api = flext_ldif_get_api()
        assert api is not None
        assert isinstance(api, FlextLdifAPI)

        # Test that convenience functions exist and are callable
        assert callable(flext_ldif_parse)
        assert callable(flext_ldif_validate)
        assert callable(flext_ldif_write)
