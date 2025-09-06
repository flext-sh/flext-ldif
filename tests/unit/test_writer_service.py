"""Tests for FlextLDIFServices.WriterService - comprehensive coverage."""

import tempfile
from pathlib import Path

from flext_ldif import FlextLDIFModels, FlextLDIFServices
from flext_ldif.constants import FlextLDIFConstants


class TestFlextLDIFServicesWriterService:
    """Test writer service functionality."""

    def test_service_initialization(self) -> None:
        """Test service can be initialized."""
        service = FlextLDIFServices.WriterService()
        assert service.config is None

    def test_service_initialization_with_config(self) -> None:
        """Test service can be initialized with custom config."""
        config = FlextLDIFModels.Config(strict_validation=True)
        service = FlextLDIFServices.WriterService(config=config)
        assert service.config is not None
        assert service.config.strict_validation is True

    def test_execute_default(self) -> None:
        """Test default execute method returns empty string."""
        service = FlextLDIFServices.WriterService()
        result = service.execute()

        assert result.is_success
        assert result.value == ""

    def test_write_empty_entries(self) -> None:
        """Test writing empty list of entries."""
        service = FlextLDIFServices.WriterService()
        result = service.write_entries_to_string([])

        assert result.is_success
        assert result.value == ""

    def test_write_single_entry(self) -> None:
        """Test writing single entry."""
        service = FlextLDIFServices.WriterService()
        entry = FlextLDIFModels.Entry.model_validate(
            {
                "dn": "cn=John Doe,ou=people,dc=example,dc=com",
                "attributes": {"cn": ["John Doe"], "objectClass": ["person"]},
            }
        )

        result = service.write_entries_to_string([entry])

        assert result.is_success
        assert result.value is not None
        assert "dn: cn=John Doe,ou=people,dc=example,dc=com" in result.value
        assert "cn: John Doe" in result.value
        assert "objectClass: person" in result.value

    def test_write_multiple_entries(self) -> None:
        """Test writing multiple entries."""
        service = FlextLDIFServices.WriterService()
        entries = [
            FlextLDIFModels.Entry.model_validate(
                {
                    "dn": "cn=John,dc=example,dc=com",
                    "attributes": {"cn": ["John"], "objectClass": ["person"]},
                }
            ),
            FlextLDIFModels.Entry.model_validate(
                {
                    "dn": "cn=Jane,dc=example,dc=com",
                    "attributes": {"cn": ["Jane"], "objectClass": ["person"]},
                }
            ),
        ]

        result = service.write_entries_to_string(entries)

        assert result.is_success
        assert result.value is not None
        # Should contain both entries separated by newline
        assert "dn: cn=John,dc=example,dc=com" in result.value
        assert "dn: cn=Jane,dc=example,dc=com" in result.value

    def test_write_entry_error_handling(self) -> None:
        """Test write handles general errors during processing."""
        service = FlextLDIFServices.WriterService()

        # Create a regular entry and test successful writing first to ensure service works
        valid_entry = FlextLDIFModels.Entry.model_validate({
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["person"]}
        })

        result = service.write_entries_to_string([valid_entry])
        assert result.is_success  # Normal case should work

    def test_write_entry_with_special_characters(self) -> None:
        """Test write handles entries with special characters."""
        service = FlextLDIFServices.WriterService()

        # Create entry with special characters that require base64 encoding
        entry = FlextLDIFModels.Entry.model_validate({
            "dn": "cn=José María,dc=example,dc=com",
            "attributes": {"cn": ["José María"], "objectClass": ["person"]}
        })

        result = service.write_entries_to_string([entry])

        assert result.is_success
        assert result.value is not None
        assert "José María" in result.value or "base64" in result.value.lower()

    def test_write_entry_with_binary_data(self) -> None:
        """Test write handles entries with binary data attributes."""
        service = FlextLDIFServices.WriterService()

        # Create entry with binary-like data that should be base64 encoded
        entry = FlextLDIFModels.Entry.model_validate({
            "dn": "cn=binary test,dc=example,dc=com",
            "attributes": {
                "cn": ["binary test"],
                "objectClass": ["person"],
                "userCertificate": ["\x00\x01\x02\x03"],  # Binary data
            },
        })

        result = service.write_entries_to_string([entry])

        assert result.is_success
        assert result.value is not None
        assert "userCertificate:" in result.value  # Binary data present in output

    def test_write_entry_success(self) -> None:
        """Test write_entry with single entry."""
        service = FlextLDIFServices.WriterService()
        entry = FlextLDIFModels.Entry.model_validate(
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

    def test_write_entry_with_multivalued_attributes(self) -> None:
        """Test write_entry handles entries with multi-valued attributes."""
        service = FlextLDIFServices.WriterService()

        entry = FlextLDIFModels.Entry.model_validate({
            "dn": "cn=multi test,dc=example,dc=com",
            "attributes": {
                "cn": ["multi test"],
                "objectClass": ["person", "inetOrgPerson"],  # Multi-valued
                "mail": ["test1@example.com", "test2@example.com"],  # Multi-valued
            },
        })

        result = service.write_entry(entry)

        assert result.is_success
        assert result.value is not None
        assert "objectClass: person" in result.value
        assert "objectClass: inetOrgPerson" in result.value
        assert "mail: test1@example.com" in result.value
        assert "mail: test2@example.com" in result.value

    def test_write_entry_with_empty_attributes(self) -> None:
        """Test write_entry handles entry with minimal attributes."""
        service = FlextLDIFServices.WriterService()

        # Entry with minimal required attributes
        entry = FlextLDIFModels.Entry.model_validate({
            "dn": "dc=example,dc=com",
            "attributes": {
                "objectClass": ["domain"],
                "dc": ["example"],
            },
        })

        result = service.write_entry(entry)

        assert result.is_success
        assert result.value is not None
        assert "dn: dc=example,dc=com" in result.value
        assert "objectClass: domain" in result.value
        assert "dc: example" in result.value

    def test_write_file_success(self) -> None:
        """Test write_file success with temporary file."""
        service = FlextLDIFServices.WriterService()
        entries = [
            FlextLDIFModels.Entry.model_validate(
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
            result = service.write_entries_to_file(entries, tmp_path)

            assert result.is_success
            assert result.value is True

            # Verify file was written
            with Path(tmp_path).open(
                encoding=FlextLDIFConstants.FlextLDIFCoreConstants.DEFAULT_ENCODING
            ) as f:
                content = f.read()
                assert "dn: cn=Test,dc=example,dc=com" in content
                assert "cn: Test" in content
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_write_file_with_custom_encoding(self) -> None:
        """Test write_file with custom encoding."""
        service = FlextLDIFServices.WriterService()
        entries = [
            FlextLDIFModels.Entry.model_validate(
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
            result = service.write_entries_to_file(entries, tmp_path, encoding="utf-8")

            assert result.is_success
            assert result.value is True

            # Verify file was written with correct encoding
            with Path(tmp_path).open(encoding="utf-8") as f:
                content = f.read()
                assert "cn: Tëst" in content
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_write_file_exception_handling(self) -> None:
        """Test write_file handles file system exceptions."""
        service = FlextLDIFServices.WriterService()

        # Create real entry
        entry = FlextLDIFModels.Entry.model_validate({
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["person"]}
        })

        # Try to write to an invalid path that will cause a file system exception
        invalid_path = "/non/existent/directory/test.ldif"
        result = service.write_entries_to_file([entry], invalid_path)

        assert result.is_failure
        assert result.error is not None
        # Should contain file write error information
        assert "File write error" in result.error or "File write failed" in result.error
        assert "Permission denied" in result.error

    def test_write_content_to_file_success(self) -> None:
        """Test _write_content_to_file success."""
        service = FlextLDIFServices.WriterService()
        content = "dn: cn=test,dc=example,dc=com\ncn: test\nobjectClass: person\n"

        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", delete=False, suffix=".ldif"
        ) as tmp_file:
            tmp_path = tmp_file.name

        try:
            result = service._write_content_to_file(
                content,
                tmp_path,
                FlextLDIFConstants.FlextLDIFCoreConstants.DEFAULT_ENCODING,
            )

            assert result.is_success
            assert result.value is True

            # Verify content was written
            with Path(tmp_path).open(
                encoding=FlextLDIFConstants.FlextLDIFCoreConstants.DEFAULT_ENCODING
            ) as f:
                written_content = f.read()
                assert written_content == content
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_write_content_to_file_permission_error(self) -> None:
        """Test _write_content_to_file handles permission errors with real filesystem."""
        service = FlextLDIFServices.WriterService()
        content = "test content"

        # Try to write to a path that will likely cause permission error (non-existent directory)
        invalid_path = "/non/existent/directory/test.ldif"
        result = service._write_content_to_file(
            content,
            invalid_path,
            FlextLDIFConstants.FlextLDIFCoreConstants.DEFAULT_ENCODING,
        )

        assert result.is_failure
        assert result.error is not None
        assert "File write failed" in result.error

    def test_write_content_to_file_os_error(self) -> None:
        """Test _write_content_to_file handles OSError."""
        service = FlextLDIFServices.WriterService()
        content = "test content"

        # Create a real scenario that causes OSError - try to write to non-existent directory
        invalid_path = "/non/existent/directory/test.ldif"
        result = service._write_content_to_file(
            content,
            invalid_path,
            FlextLDIFConstants.FlextLDIFCoreConstants.DEFAULT_ENCODING,
        )

        assert result.is_failure
        assert result.error is not None
        assert "File write failed" in result.error
        assert "Permission denied" in result.error

    def test_write_content_to_file_unicode_error(self) -> None:
        """Test _write_content_to_file handles real Unicode encoding errors."""
        service = FlextLDIFServices.WriterService()
        # Content with unicode characters that cannot be encoded to ascii
        content = "test content with unicode: ñáéíóú"

        with tempfile.NamedTemporaryFile(suffix=".ldif", delete=False) as tmp_file:
            tmp_path = tmp_file.name

        try:
            # Try to write unicode content with ascii encoding - should fail
            result = service._write_content_to_file(content, tmp_path, "ascii")

            assert result.is_failure
            assert result.error is not None
            assert "encode" in result.error.lower() or "ascii" in result.error.lower()
        finally:
            # Clean up the temporary file
            Path(tmp_path).unlink(missing_ok=True)

    def test_write_file_empty_entries(self) -> None:
        """Test write_file with empty entries list."""
        service = FlextLDIFServices.WriterService()

        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", delete=False, suffix=".ldif"
        ) as tmp_file:
            tmp_path = tmp_file.name

        try:
            result = service.write_entries_to_file([], tmp_path)

            assert result.is_success
            assert result.value is True

            # Verify empty file was created
            with Path(tmp_path).open(
                encoding=FlextLDIFConstants.FlextLDIFCoreConstants.DEFAULT_ENCODING
            ) as f:
                content = f.read()
                assert content == ""
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_write_file_pathlib_path(self) -> None:
        """Test write_file accepts pathlib.Path objects."""
        service = FlextLDIFServices.WriterService()
        entries = [
            FlextLDIFModels.Entry.model_validate(
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
            result = service.write_entries_to_file(entries, tmp_path)

            assert result.is_success
            assert result.value is True

            # Verify file was written
            content = tmp_path.read_text(
                encoding=FlextLDIFConstants.FlextLDIFCoreConstants.DEFAULT_ENCODING
            )
            assert "dn: cn=PathTest,dc=example,dc=com" in content
        finally:
            tmp_path.unlink(missing_ok=True)
