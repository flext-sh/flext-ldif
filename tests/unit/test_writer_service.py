"""Tests for FlextLdifWriterService - comprehensive coverage."""

import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from flext_ldif.constants import DEFAULT_OUTPUT_ENCODING, FlextLdifCoreMessages
from flext_ldif.models import FlextLdifConfig, FlextLdifEntry
from flext_ldif.writer_service import FlextLdifWriterService


class TestFlextLdifWriterService:
    """Test writer service functionality."""

    def test_service_initialization(self) -> None:
        """Test service can be initialized."""
        service = FlextLdifWriterService()
        assert service.config is None

    def test_service_initialization_with_config(self) -> None:
        """Test service can be initialized with custom config."""
        config = FlextLdifConfig(strict_validation=True)
        service = FlextLdifWriterService(config=config)
        assert service.config is not None
        assert service.config.strict_validation is True

    def test_execute_default(self) -> None:
        """Test default execute method returns empty string."""
        service = FlextLdifWriterService()
        result = service.execute()

        assert result.is_success
        assert result.value == ""

    def test_write_empty_entries(self) -> None:
        """Test writing empty list of entries."""
        service = FlextLdifWriterService()
        result = service.write([])

        assert result.is_success
        assert result.value == ""

    def test_write_single_entry(self) -> None:
        """Test writing single entry."""
        service = FlextLdifWriterService()
        entry = FlextLdifEntry.model_validate(
            {
                "dn": "cn=John Doe,ou=people,dc=example,dc=com",
                "attributes": {"cn": ["John Doe"], "objectClass": ["person"]},
            }
        )

        result = service.write([entry])

        assert result.is_success
        assert result.value is not None
        assert "dn: cn=John Doe,ou=people,dc=example,dc=com" in result.value
        assert "cn: John Doe" in result.value
        assert "objectClass: person" in result.value

    def test_write_multiple_entries(self) -> None:
        """Test writing multiple entries."""
        service = FlextLdifWriterService()
        entries = [
            FlextLdifEntry.model_validate(
                {
                    "dn": "cn=John,dc=example,dc=com",
                    "attributes": {"cn": ["John"], "objectClass": ["person"]},
                }
            ),
            FlextLdifEntry.model_validate(
                {
                    "dn": "cn=Jane,dc=example,dc=com",
                    "attributes": {"cn": ["Jane"], "objectClass": ["person"]},
                }
            ),
        ]

        result = service.write(entries)

        assert result.is_success
        assert result.value is not None
        # Should contain both entries separated by newline
        assert "dn: cn=John,dc=example,dc=com" in result.value
        assert "dn: cn=Jane,dc=example,dc=com" in result.value

    def test_write_entry_error_handling(self) -> None:
        """Test write handles entry.to_ldif() errors."""
        service = FlextLdifWriterService()

        # Create a mock entry that raises an exception
        mock_entry = Mock(spec=FlextLdifEntry)
        mock_entry.to_ldif.side_effect = ValueError("Test error")

        result = service.write([mock_entry])

        assert result.is_failure
        assert (
            FlextLdifCoreMessages.WRITE_FAILED.format(error="Test error")
            in result.error
        )

    def test_write_entry_attribute_error(self) -> None:
        """Test write handles AttributeError from entry.to_ldif()."""
        service = FlextLdifWriterService()

        # Create a mock entry that raises AttributeError
        mock_entry = Mock(spec=FlextLdifEntry)
        mock_entry.to_ldif.side_effect = AttributeError("Missing attribute")

        result = service.write([mock_entry])

        assert result.is_failure
        assert (
            FlextLdifCoreMessages.WRITE_FAILED.format(error="Missing attribute")
            in result.error
        )

    def test_write_entry_type_error(self) -> None:
        """Test write handles TypeError from entry.to_ldif()."""
        service = FlextLdifWriterService()

        # Create a mock entry that raises TypeError
        mock_entry = Mock(spec=FlextLdifEntry)
        mock_entry.to_ldif.side_effect = TypeError("Type error")

        result = service.write([mock_entry])

        assert result.is_failure
        assert (
            FlextLdifCoreMessages.WRITE_FAILED.format(error="Type error")
            in result.error
        )

    def test_write_entry_success(self) -> None:
        """Test write_entry with single entry."""
        service = FlextLdifWriterService()
        entry = FlextLdifEntry.model_validate(
            {
                "dn": "cn=Test User,ou=people,dc=example,dc=com",
                "attributes": {
                    "cn": ["Test User"],
                    "mail": ["test@example.com"],
                    "objectClass": ["person", "inetOrgPerson"],
                },
            }
        )

        result = service.write_entry(entry)

        assert result.is_success
        assert result.value is not None
        assert "dn: cn=Test User,ou=people,dc=example,dc=com" in result.value
        assert "cn: Test User" in result.value
        assert "mail: test@example.com" in result.value


    def test_write_entry_attribute_error_handling(self) -> None:
        """Test write_entry handles AttributeError."""
        service = FlextLdifWriterService()

        mock_entry = Mock(spec=FlextLdifEntry)
        mock_entry.to_ldif.side_effect = AttributeError("Attribute missing")

        result = service.write_entry(mock_entry)

        assert result.is_failure
        assert (
            FlextLdifCoreMessages.WRITE_FAILED.format(error="Attribute missing")
            in result.error
        )

    def test_write_entry_type_error_handling(self) -> None:
        """Test write_entry handles TypeError."""
        service = FlextLdifWriterService()

        mock_entry = Mock(spec=FlextLdifEntry)
        mock_entry.to_ldif.side_effect = TypeError("Type mismatch")

        result = service.write_entry(mock_entry)

        assert result.is_failure
        assert (
            FlextLdifCoreMessages.WRITE_FAILED.format(error="Type mismatch")
            in result.error
        )

    def test_write_file_success(self) -> None:
        """Test write_file success with temporary file."""
        service = FlextLdifWriterService()
        entries = [
            FlextLdifEntry.model_validate(
                {
                    "dn": "cn=Test,dc=example,dc=com",
                    "attributes": {"cn": ["Test"], "objectClass": ["person"]},
                }
            )
        ]

        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", delete=False, suffix=".ldif"
        ) as tmp_file:
            tmp_path = tmp_file.name

        try:
            result = service.write_file(entries, tmp_path)

            assert result.is_success
            assert result.value is True

            # Verify file was written
            with Path(tmp_path).open(encoding=DEFAULT_OUTPUT_ENCODING) as f:
                content = f.read()
                assert "dn: cn=Test,dc=example,dc=com" in content
                assert "cn: Test" in content
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_write_file_with_custom_encoding(self) -> None:
        """Test write_file with custom encoding."""
        service = FlextLdifWriterService()
        entries = [
            FlextLdifEntry.model_validate(
                {
                    "dn": "cn=Tëst,dc=example,dc=com",
                    "attributes": {"cn": ["Tëst"], "objectClass": ["person"]},
                }
            )
        ]

        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", delete=False, suffix=".ldif"
        ) as tmp_file:
            tmp_path = tmp_file.name

        try:
            result = service.write_file(entries, tmp_path, encoding="utf-8")

            assert result.is_success
            assert result.value is True

            # Verify file was written with correct encoding
            with Path(tmp_path).open(encoding="utf-8") as f:
                content = f.read()
                assert "cn: Tëst" in content
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_write_file_exception_handling(self) -> None:
        """Test write_file handles general exceptions."""
        service = FlextLdifWriterService()

        # Create mock entries that will cause write to fail
        mock_entry = Mock(spec=FlextLdifEntry)
        mock_entry.to_ldif.side_effect = RuntimeError("Unexpected error")

        with tempfile.NamedTemporaryFile(suffix=".ldif", delete=False) as tmp_file:
            tmp_path = tmp_file.name
        result = service.write_file([mock_entry], tmp_path)

        assert result.is_failure
        assert (
            FlextLdifCoreMessages.FILE_WRITE_FAILED.format(error="Unexpected error")
            in result.error
        )

    def test_write_content_to_file_success(self) -> None:
        """Test _write_content_to_file success."""
        service = FlextLdifWriterService()
        content = "dn: cn=test,dc=example,dc=com\ncn: test\nobjectClass: person\n"

        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", delete=False, suffix=".ldif"
        ) as tmp_file:
            tmp_path = tmp_file.name

        try:
            result = service._write_content_to_file(
                content, tmp_path, DEFAULT_OUTPUT_ENCODING
            )

            assert result.is_success
            assert result.value is True

            # Verify content was written
            with Path(tmp_path).open(encoding=DEFAULT_OUTPUT_ENCODING) as f:
                written_content = f.read()
                assert written_content == content
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_write_content_to_file_permission_error(self) -> None:
        """Test _write_content_to_file handles PermissionError during mkdir."""
        service = FlextLdifWriterService()
        content = "test content"

        with patch("pathlib.Path.mkdir") as mock_mkdir:
            mock_mkdir.side_effect = PermissionError("Permission denied")

            result = service._write_content_to_file(
                content, "/root/test.ldif", DEFAULT_OUTPUT_ENCODING
            )

            assert result.is_failure
            assert (
                FlextLdifCoreMessages.FILE_WRITE_FAILED.format(
                    error="Permission denied"
                )
                in result.error
            )

    def test_write_content_to_file_os_error(self) -> None:
        """Test _write_content_to_file handles OSError."""
        service = FlextLdifWriterService()
        content = "test content"

        with patch("pathlib.Path.write_text") as mock_write_text:
            mock_write_text.side_effect = OSError("Disk full")

            with tempfile.NamedTemporaryFile(suffix=".ldif", delete=False) as tmp_file:
                tmp_path = tmp_file.name
            result = service._write_content_to_file(
                content, tmp_path, DEFAULT_OUTPUT_ENCODING
            )

            assert result.is_failure
            assert (
                FlextLdifCoreMessages.FILE_WRITE_FAILED.format(error="Disk full")
                in result.error
            )

    def test_write_content_to_file_unicode_error(self) -> None:
        """Test _write_content_to_file handles UnicodeError."""
        service = FlextLdifWriterService()
        content = "test content with unicode: ñáéíóú"

        with patch("pathlib.Path.write_text") as mock_write_text:
            mock_write_text.side_effect = UnicodeError("Unicode encoding error")

            with tempfile.NamedTemporaryFile(suffix=".ldif", delete=False) as tmp_file:
                tmp_path = tmp_file.name
            result = service._write_content_to_file(content, tmp_path, "ascii")

            assert result.is_failure
            assert (
                FlextLdifCoreMessages.FILE_WRITE_FAILED.format(
                    error="Unicode encoding error"
                )
                in result.error
            )

    def test_write_file_empty_entries(self) -> None:
        """Test write_file with empty entries list."""
        service = FlextLdifWriterService()

        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", delete=False, suffix=".ldif"
        ) as tmp_file:
            tmp_path = tmp_file.name

        try:
            result = service.write_file([], tmp_path)

            assert result.is_success
            assert result.value is True

            # Verify empty file was created
            with Path(tmp_path).open(encoding=DEFAULT_OUTPUT_ENCODING) as f:
                content = f.read()
                assert content == ""
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_write_file_pathlib_path(self) -> None:
        """Test write_file accepts pathlib.Path objects."""
        service = FlextLdifWriterService()
        entries = [
            FlextLdifEntry.model_validate(
                {
                    "dn": "cn=PathTest,dc=example,dc=com",
                    "attributes": {"cn": ["PathTest"], "objectClass": ["person"]},
                }
            )
        ]

        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", delete=False, suffix=".ldif"
        ) as tmp_file:
            tmp_path = Path(tmp_file.name)

        try:
            result = service.write_file(entries, tmp_path)

            assert result.is_success
            assert result.value is True

            # Verify file was written
            content = tmp_path.read_text(encoding=DEFAULT_OUTPUT_ENCODING)
            assert "dn: cn=PathTest,dc=example,dc=com" in content
        finally:
            tmp_path.unlink(missing_ok=True)
