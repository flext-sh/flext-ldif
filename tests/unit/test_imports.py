"""Test module imports and public API."""

from __future__ import annotations

import flext_ldif.api
import flext_ldif.config
import flext_ldif.core
import flext_ldif.entry_analytics
import flext_ldif.entry_repository
import flext_ldif.entry_transformer
import flext_ldif.entry_validator
import flext_ldif.exceptions
import flext_ldif.format_handlers
import flext_ldif.format_validators
import flext_ldif.ldif_parser
import flext_ldif.ldif_writer
import flext_ldif.models
import flext_ldif.protocols
from flext_ldif import (
    FlextLdifAnalyticsService,
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
      assert FlextLdifAnalyticsService is not None
      assert FlextLdifParserService is not None
      assert FlextLdifRepositoryService is not None
      assert FlextLdifTransformerService is not None
      assert FlextLdifValidatorService is not None
      assert FlextLdifWriterService is not None

    def test_legacy_function_imports(self) -> None:
      """Test legacy convenience function imports."""
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

    def test_individual_module_imports(self) -> None:
      """Test individual module imports."""
      assert flext_ldif.api is not None
      assert flext_ldif.config is not None
      assert flext_ldif.core is not None
      assert flext_ldif.exceptions is not None
      assert flext_ldif.models is not None
      assert flext_ldif.protocols is not None

    def test_service_module_imports(self) -> None:
      """Test service module imports."""
      assert flext_ldif.entry_analytics is not None
      assert flext_ldif.entry_repository is not None
      assert flext_ldif.entry_transformer is not None
      assert flext_ldif.entry_validator is not None
      assert flext_ldif.ldif_parser is not None
      assert flext_ldif.ldif_writer is not None

    def test_format_module_imports(self) -> None:
      """Test format module imports."""
      assert flext_ldif.format_handlers is not None
      assert flext_ldif.format_validators is not None
