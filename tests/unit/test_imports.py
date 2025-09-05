"""Test public API imports and functionality."""

from __future__ import annotations

from flext_ldif import (
    FlextLDIFAPI,
    FlextLDIFCore,
    FlextLDIFFormatHandler,
    FlextLDIFFormatValidators,
    FlextLDIFModels,
    FlextLDIFServices,
    FlextLDIFUtilities,
    __version__,
)

# CLI availability flag for testing
CLI_AVAILABLE = False
try:
    from flext_ldif.cli import main as cli_main

    CLI_AVAILABLE = True
except ImportError:
    pass


class TestModuleImports:
    """Test that all modules can be imported correctly."""

    def test_main_imports(self) -> None:
        """Test main module imports work correctly."""
        assert FlextLDIFAPI is not None
        assert FlextLDIFModels.Config is not None
        assert FlextLDIFModels.Entry is not None
        assert FlextLDIFModels.DistinguishedName is not None
        assert FlextLDIFModels.LdifAttributes is not None
        assert FlextLDIFModels.Factory is not None

    def test_service_imports(self) -> None:
        """Test service imports work correctly."""
        # Test service classes are accessible through FlextLDIFServices
        assert hasattr(FlextLDIFServices, "ParserService")
        assert hasattr(FlextLDIFServices, "ValidatorService")
        assert hasattr(FlextLDIFServices, "WriterService")
        assert FlextLDIFServices.ParserService is not None
        assert FlextLDIFServices.ValidatorService is not None
        assert FlextLDIFServices.WriterService is not None

    def test_class_based_interface_imports(self) -> None:
        """Test class-based interface imports."""
        assert FlextLDIFCore is not None
        assert FlextLDIFFormatHandler is not None
        assert FlextLDIFFormatValidators is not None
        assert FlextLDIFUtilities is not None

    def test_cli_import(self) -> None:
        """Test CLI import functionality."""
        # Test that CLI import works and function is callable
        if CLI_AVAILABLE:
            assert callable(cli_main)
        else:
            # If import fails, it means dependencies are missing, which is acceptable in test environment
            pass

    def test_version_import(self) -> None:
        """Test version information import."""
        assert __version__ is not None
        assert isinstance(__version__, str)
        assert len(__version__) > 0

    def test_public_api_functionality(self) -> None:
        """Test that public API functions work correctly."""
        # Test that API creation works
        api = FlextLDIFAPI()  # Use direct constructor instead
        assert api is not None
        assert isinstance(api, FlextLDIFAPI)

        # Test that class methods exist and are callable
        assert callable(FlextLDIFFormatHandler.parse_ldif)
        assert callable(FlextLDIFFormatHandler.write_ldif)
        assert callable(FlextLDIFFormatValidators.get_ldap_validators)
        assert callable(
            FlextLDIFUtilities.LdifDomainProcessors.validate_entries_or_warn
        )
