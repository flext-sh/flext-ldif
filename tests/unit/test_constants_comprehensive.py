"""Comprehensive unit tests for FlextLdifConstants.

Tests all constant definitions and their usage.
"""

from __future__ import annotations

import pytest

from flext_ldif.constants import FlextLdifConstants


class TestFlextLdifConstantsEncoding:
    """Test suite for encoding constants."""

    def test_default_encoding(self) -> None:
        """Test default encoding constant."""
        assert FlextLdifConstants.Encoding.DEFAULT_ENCODING == "utf-8"
        assert isinstance(FlextLdifConstants.Encoding.DEFAULT_ENCODING, str)

    def test_supported_encodings(self) -> None:
        """Test supported encodings list."""
        encodings = FlextLdifConstants.Encoding.SUPPORTED_ENCODINGS
        assert isinstance(encodings, list)
        assert "utf-8" in encodings
        assert "utf-16" in encodings

    def test_encoding_constants_exist(self) -> None:
        """Test that all encoding constants exist."""
        assert hasattr(FlextLdifConstants.Encoding, 'DEFAULT_ENCODING')
        assert hasattr(FlextLdifConstants.Encoding, 'SUPPORTED_ENCODINGS')


class TestFlextLdifConstantsFormat:
    """Test suite for format constants."""

    def test_max_line_length(self) -> None:
        """Test maximum line length constant."""
        assert FlextLdifConstants.Format.MAX_LINE_LENGTH == 76
        assert isinstance(FlextLdifConstants.Format.MAX_LINE_LENGTH, int)

    def test_line_continuation_char(self) -> None:
        """Test line continuation character."""
        assert FlextLdifConstants.Format.LINE_CONTINUATION_CHAR == " "
        assert isinstance(FlextLdifConstants.Format.LINE_CONTINUATION_CHAR, str)

    def test_format_constants_exist(self) -> None:
        """Test that all format constants exist."""
        assert hasattr(FlextLdifConstants.Format, 'MAX_LINE_LENGTH')
        assert hasattr(FlextLdifConstants.Format, 'LINE_CONTINUATION_CHAR')
        assert hasattr(FlextLdifConstants.Format, 'DN_SEPARATOR')
        assert hasattr(FlextLdifConstants.Format, 'ATTRIBUTE_SEPARATOR')


class TestFlextLdifConstantsProcessing:
    """Test suite for processing constants."""

    def test_max_workers_limit(self) -> None:
        """Test maximum workers limit."""
        assert FlextLdifConstants.Processing.MAX_WORKERS_LIMIT == 16
        assert isinstance(FlextLdifConstants.Processing.MAX_WORKERS_LIMIT, int)

    def test_debug_max_workers(self) -> None:
        """Test debug maximum workers."""
        assert FlextLdifConstants.Processing.DEBUG_MAX_WORKERS == 2
        assert isinstance(FlextLdifConstants.Processing.DEBUG_MAX_WORKERS, int)

    def test_performance_min_workers(self) -> None:
        """Test performance minimum workers."""
        assert FlextLdifConstants.Processing.PERFORMANCE_MIN_WORKERS == 4
        assert isinstance(FlextLdifConstants.Processing.PERFORMANCE_MIN_WORKERS, int)

    def test_processing_constants_exist(self) -> None:
        """Test that all processing constants exist."""
        assert hasattr(FlextLdifConstants.Processing, 'MAX_WORKERS_LIMIT')
        assert hasattr(FlextLdifConstants.Processing, 'DEBUG_MAX_WORKERS')
        assert hasattr(FlextLdifConstants.Processing, 'PERFORMANCE_MIN_WORKERS')
        assert hasattr(FlextLdifConstants.Processing, 'PERFORMANCE_MEMORY_MB_THRESHOLD')


class TestFlextLdifConstantsValidation:
    """Test suite for validation constants."""

    def test_strict_mode_default(self) -> None:
        """Test strict mode default."""
        assert FlextLdifConstants.Validation.STRICT_MODE_DEFAULT is True
        assert isinstance(FlextLdifConstants.Validation.STRICT_MODE_DEFAULT, bool)

    def test_validation_constants_exist(self) -> None:
        """Test that all validation constants exist."""
        assert hasattr(FlextLdifConstants.Validation, 'STRICT_MODE_DEFAULT')
        assert hasattr(FlextLdifConstants.Validation, 'TIMEOUT_MS_DEFAULT')
        assert hasattr(FlextLdifConstants.Validation, 'NAME_LENGTH_MIN')
        assert hasattr(FlextLdifConstants.Validation, 'NAME_LENGTH_MAX')


class TestFlextLdifConstantsAcl:
    """Test suite for ACL constants."""

    def test_default_acl_version(self) -> None:
        """Test default ACL version."""
        assert FlextLdifConstants.Acl.DEFAULT_ACL_VERSION == "1"
        assert isinstance(FlextLdifConstants.Acl.DEFAULT_ACL_VERSION, str)

    def test_acl_constants_exist(self) -> None:
        """Test that all ACL constants exist."""
        assert hasattr(FlextLdifConstants.Acl, 'DEFAULT_ACL_VERSION')
        assert hasattr(FlextLdifConstants.Acl, 'SUPPORTED_VERSIONS')
        assert hasattr(FlextLdifConstants.Acl, 'PERMISSION_READ')
        assert hasattr(FlextLdifConstants.Acl, 'PERMISSION_WRITE')


class TestFlextLdifConstantsSchema:
    """Test suite for schema constants."""

    def test_default_schema_version(self) -> None:
        """Test default schema version."""
        assert FlextLdifConstants.Schema.DEFAULT_SCHEMA_VERSION == "3"
        assert isinstance(FlextLdifConstants.Schema.DEFAULT_SCHEMA_VERSION, str)

    def test_schema_constants_exist(self) -> None:
        """Test that all schema constants exist."""
        assert hasattr(FlextLdifConstants.Schema, 'DEFAULT_SCHEMA_VERSION')
        assert hasattr(FlextLdifConstants.Schema, 'SUPPORTED_VERSIONS')
        assert hasattr(FlextLdifConstants.Schema, 'OBJECT_CLASS_STRUCTURAL')
        assert hasattr(FlextLdifConstants.Schema, 'OBJECT_CLASS_AUXILIARY')


class TestFlextLdifConstantsNamespace:
    """Test suite for the FlextLdifConstants namespace."""

    def test_constants_namespace_access(self) -> None:
        """Test accessing constants through namespace."""
        # Test that all expected constant groups are available
        assert hasattr(FlextLdifConstants, 'Encoding')
        assert hasattr(FlextLdifConstants, 'Format')
        assert hasattr(FlextLdifConstants, 'Processing')
        assert hasattr(FlextLdifConstants, 'Validation')
        assert hasattr(FlextLdifConstants, 'Acl')
        assert hasattr(FlextLdifConstants, 'Schema')

    def test_constant_groups_are_classes(self) -> None:
        """Test that constant groups are classes."""
        assert isinstance(FlextLdifConstants.Encoding, type)
        assert isinstance(FlextLdifConstants.Format, type)
        assert isinstance(FlextLdifConstants.Processing, type)
        assert isinstance(FlextLdifConstants.Validation, type)
        assert isinstance(FlextLdifConstants.Acl, type)
        assert isinstance(FlextLdifConstants.Schema, type)

    def test_constant_values_are_reasonable(self) -> None:
        """Test that constant values are reasonable."""
        # Encoding
        assert FlextLdifConstants.Encoding.DEFAULT_ENCODING in FlextLdifConstants.Encoding.SUPPORTED_ENCODINGS

        # Format
        assert FlextLdifConstants.Format.MAX_LINE_LENGTH > 40
        assert FlextLdifConstants.Format.MAX_LINE_LENGTH < 200

        # Processing
        assert FlextLdifConstants.Processing.MAX_WORKERS_LIMIT > 0
        assert FlextLdifConstants.Processing.DEBUG_MAX_WORKERS <= FlextLdifConstants.Processing.MAX_WORKERS_LIMIT
        assert FlextLdifConstants.Processing.PERFORMANCE_MIN_WORKERS > 0

        # Validation
        assert FlextLdifConstants.Validation.NAME_LENGTH_MIN >= 0
        assert FlextLdifConstants.Validation.NAME_LENGTH_MAX > FlextLdifConstants.Validation.NAME_LENGTH_MIN