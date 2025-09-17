"""Test public API imports and functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import flext_ldif
from flext_ldif import (
    FlextLdifAPI,
    FlextLdifFormatHandler,
    FlextLdifModels,
    FlextLdifServices,
    FlextLdifUtilities,
    __version__,
)

# CLI components removed - library should not include CLI
# LdifDomainProcessors was removed as it was not implemented


class TestModuleImports:
    """Test that all modules can be imported correctly."""

    def test_main_imports(self) -> None:
        """Test main module imports work correctly."""
        assert FlextLdifAPI is not None
        assert FlextLdifModels.Entry is not None
        assert FlextLdifModels.DistinguishedName is not None
        assert FlextLdifModels.LdifAttributes is not None
        # Factory methods are now available directly on FlextLdifModels class

    def test_service_imports(self) -> None:
        """Test service imports work correctly."""
        # Test service classes are accessible through FlextLdifServices attributes
        services = FlextLdifServices()
        assert services.parser is not None
        assert services.validator is not None
        assert services.writer is not None
        assert services.analytics is not None
        assert services.transformer is not None
        assert services.repository is not None

    def test_class_based_interface_imports(self) -> None:
        """Test class-based interface imports."""
        # FlextLdifCore eliminated - was wrapper violating SOLID
        assert FlextLdifServices is not None
        assert FlextLdifFormatHandler is not None
        assert FlextLdifUtilities is not None

    def test_library_has_no_cli(self) -> None:
        """Test that library correctly excludes CLI components."""
        # Libraries should not include CLI - this ensures clean separation
        assert not hasattr(flext_ldif, "main")
        assert "main" not in flext_ldif.__all__

    def test_version_import(self) -> None:
        """Test version information import."""
        assert __version__ is not None
        assert isinstance(__version__, str)
        assert len(__version__) > 0

    def test_public_api_functionality(self) -> None:
        """Test that public API functions work correctly."""
        # Test that API creation works
        api = FlextLdifAPI()  # Use direct constructor instead
        assert api is not None
        assert isinstance(api, FlextLdifAPI)

        # Test that class methods exist and are callable
        assert callable(FlextLdifFormatHandler.parse_ldif)
        assert callable(FlextLdifFormatHandler.write_ldif)
        # FlextLdifFormatValidators removed - validation now in FlextLdifModels
        # LdifDomainProcessors was removed as it was not implemented
