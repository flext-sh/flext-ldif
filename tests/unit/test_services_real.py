"""Real tests for services module - 100% coverage, zero mocks."""

from __future__ import annotations

import tempfile
from pathlib import Path

from flext_ldif.models import FlextLDIFConfig, FlextLDIFEntry
from flext_ldif.services import FlextLDIFServices


class TestAnalyticsService:
    """Test AnalyticsService with real functionality."""

    def test_init_with_entries_and_config(self) -> None:
        """Test analytics service initialization with entries and config."""
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "uid=test1,ou=people,dc=example,dc=com",
                    "attributes": {
                        "objectClass": ["person"],
                        "cn": ["Test User 1"],
                        "sn": ["User"],
                    },
                }
            )
        ]
        config = FlextLDIFConfig()
        service = FlextLDIFServices.AnalyticsService(entries=entries, config=config)

        assert len(service.entries) == 1
        assert service.config is not None

    def test_init_default(self) -> None:
        """Test analytics service initialization with defaults."""
        service = FlextLDIFServices.AnalyticsService()

        assert len(service.entries) == 0
        assert service.config is not None

    def test_execute_empty_entries(self) -> None:
        """Test execute with empty entries."""
        service = FlextLDIFServices.AnalyticsService()

        result = service.execute()

        assert result.is_success is True
        assert result.value == {"total_entries": 0}

    def test_execute_with_entries(self) -> None:
        """Test execute with real entries."""
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "uid=test1,ou=people,dc=example,dc=com",
                    "attributes": {
                        "objectClass": ["inetOrgPerson", "person"],
                        "uid": ["test1"],
                        "cn": ["Test User 1"],
                        "sn": ["User"],
                        "mail": ["test1@example.com"],
                    },
                }
            ),
            FlextLDIFEntry.model_validate(
                {
                    "dn": "uid=test2,ou=people,dc=example,dc=com",
                    "attributes": {
                        "objectClass": ["person"],
                        "uid": ["test2"],
                        "cn": ["Test User 2"],
                        "sn": ["User"],
                        "telephoneNumber": ["+1-555-0123"],
                    },
                }
            ),
        ]
        service = FlextLDIFServices.AnalyticsService(entries=entries)

        result = service.execute()

        assert result.is_success is True
        metrics = result.value
        assert metrics["total_entries"] == 2
        assert metrics["entries_with_cn"] == 2
        assert metrics["entries_with_mail"] == 1
        assert metrics["entries_with_telephoneNumber"] == 1

    def test_analyze_patterns(self) -> None:
        """Test analyze_patterns method."""
        service = FlextLDIFServices.AnalyticsService()
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "uid=user1,ou=people,dc=example,dc=com",
                    "attributes": {
                        "objectClass": ["inetOrgPerson", "person"],
                        "cn": ["User 1"],
                        "sn": ["User"],
                        "mail": ["user1@example.com"],
                    },
                }
            ),
            FlextLDIFEntry.model_validate(
                {
                    "dn": "cn=group1,ou=groups,dc=example,dc=com",
                    "attributes": {
                        "objectClass": ["groupOfNames"],
                        "cn": ["Group 1"],
                        "member": ["uid=user1,ou=people,dc=example,dc=com"],
                    },
                }
            ),
        ]

        result = service.analyze_patterns(entries)

        assert result.is_success is True
        patterns = result.value
        assert patterns["total_entries"] == 2
        assert patterns["entries_with_cn"] == 2
        assert patterns["entries_with_mail"] == 1
        assert "unique_object_classes" in patterns
        assert "person_entries" in patterns
        assert "group_entries" in patterns

    def test_analyze_attribute_distribution(self) -> None:
        """Test analyze_attribute_distribution method."""
        service = FlextLDIFServices.AnalyticsService()
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "uid=user1,ou=people,dc=example,dc=com",
                    "attributes": {
                        "objectClass": ["person"],
                        "cn": ["User 1"],
                        "sn": ["User"],
                        "mail": ["user1@example.com"],
                    },
                }
            ),
            FlextLDIFEntry.model_validate(
                {
                    "dn": "uid=user2,ou=people,dc=example,dc=com",
                    "attributes": {
                        "objectClass": ["person"],
                        "cn": ["User 2"],
                        "sn": ["User"],
                    },
                }
            ),
        ]

        result = service.analyze_attribute_distribution(entries)

        assert result.is_success is True
        distribution = result.value
        assert distribution["objectClass"] == 2
        assert distribution["cn"] == 2
        assert distribution["sn"] == 2
        assert distribution["mail"] == 1

    def test_analyze_dn_depth(self) -> None:
        """Test analyze_dn_depth method."""
        service = FlextLDIFServices.AnalyticsService()
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "uid=user1,ou=people,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"], "cn": ["User"]},
                }
            ),
            FlextLDIFEntry.model_validate(
                {
                    "dn": "cn=admin,ou=system,ou=config,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"], "cn": ["Admin"]},
                }
            ),
        ]

        result = service.analyze_dn_depth(entries)

        assert result.is_success is True
        depth_analysis = result.value
        assert (
            "depth_4" in depth_analysis
        )  # uid=user1,ou=people,dc=example,dc=com (4 components)
        assert (
            "depth_5" in depth_analysis
        )  # cn=admin,ou=system,ou=config,dc=example,dc=com (5 components)

    def test_get_objectclass_distribution(self) -> None:
        """Test get_objectclass_distribution method."""
        service = FlextLDIFServices.AnalyticsService()
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "uid=user1,ou=people,dc=example,dc=com",
                    "attributes": {
                        "objectClass": ["inetOrgPerson", "person", "top"],
                        "cn": ["User"],
                    },
                }
            ),
            FlextLDIFEntry.model_validate(
                {
                    "dn": "cn=group1,ou=groups,dc=example,dc=com",
                    "attributes": {
                        "objectClass": ["groupOfNames", "top"],
                        "cn": ["Group"],
                    },
                }
            ),
        ]

        result = service.get_objectclass_distribution(entries)

        assert result.is_success is True
        distribution = result.value
        assert distribution["top"] == 2
        assert distribution["person"] == 1
        assert distribution["inetOrgPerson"] == 1
        assert distribution["groupOfNames"] == 1

    def test_get_dn_depth_analysis(self) -> None:
        """Test get_dn_depth_analysis method (alias)."""
        service = FlextLDIFServices.AnalyticsService()
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "uid=user1,ou=people,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"], "cn": ["User"]},
                }
            )
        ]

        result = service.get_dn_depth_analysis(entries)

        assert result.is_success is True
        assert "depth_4" in result.value

    def test_analyze_entry_patterns(self) -> None:
        """Test analyze_entry_patterns method (alias)."""
        service = FlextLDIFServices.AnalyticsService()
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "uid=user1,ou=people,dc=example,dc=com",
                    "attributes": {
                        "objectClass": ["person"],
                        "cn": ["User"],
                        "sn": ["User"],
                    },
                }
            )
        ]

        result = service.analyze_entry_patterns(entries)

        assert result.is_success is True
        patterns = result.value
        assert patterns["total_entries"] == 1


class TestWriterService:
    """Test WriterService with real functionality."""

    def test_init_with_entries_and_config(self) -> None:
        """Test writer service initialization with entries and config."""
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "uid=test,ou=people,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"], "cn": ["Test User"]},
                }
            )
        ]
        config = FlextLDIFConfig()
        service = FlextLDIFServices.WriterService(entries=entries, config=config)

        assert len(service.entries) == 1
        assert service.config is not None

    def test_init_default(self) -> None:
        """Test writer service initialization with defaults."""
        service = FlextLDIFServices.WriterService()

        assert len(service.entries) == 0
        assert service.config is None

    def test_execute_empty_entries(self) -> None:
        """Test execute with empty entries."""
        service = FlextLDIFServices.WriterService()

        result = service.execute()

        assert result.is_success is True
        assert result.value == ""

    def test_execute_with_entries(self) -> None:
        """Test execute with real entries."""
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "uid=test,ou=people,dc=example,dc=com",
                    "attributes": {
                        "objectClass": ["person"],
                        "cn": ["Test User"],
                        "sn": ["User"],
                    },
                }
            )
        ]
        service = FlextLDIFServices.WriterService(entries=entries)

        result = service.execute()

        assert result.is_success is True
        ldif_content = result.value
        assert "dn: uid=test,ou=people,dc=example,dc=com" in ldif_content
        assert "objectClass: person" in ldif_content
        assert "cn: Test User" in ldif_content

    def test_write_entries_to_string_empty(self) -> None:
        """Test write_entries_to_string with empty entries."""
        service = FlextLDIFServices.WriterService()

        result = service.write_entries_to_string([])

        assert result.is_success is True
        assert result.value == ""

    def test_write_entries_to_string_single(self) -> None:
        """Test write_entries_to_string with single entry."""
        service = FlextLDIFServices.WriterService()
        entry = FlextLDIFEntry.model_validate(
            {
                "dn": "uid=single,ou=people,dc=example,dc=com",
                "attributes": {"objectClass": ["person"], "cn": ["Single User"]},
            }
        )

        result = service.write_entries_to_string([entry])

        assert result.is_success is True
        ldif_content = result.value
        assert "dn: uid=single,ou=people,dc=example,dc=com" in ldif_content

    def test_write_entries_to_string_multiple(self) -> None:
        """Test write_entries_to_string with multiple entries."""
        service = FlextLDIFServices.WriterService()
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "uid=user1,ou=people,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"], "cn": ["User 1"]},
                }
            ),
            FlextLDIFEntry.model_validate(
                {
                    "dn": "uid=user2,ou=people,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"], "cn": ["User 2"]},
                }
            ),
        ]

        result = service.write_entries_to_string(entries)

        assert result.is_success is True
        ldif_content = result.value
        assert "uid=user1" in ldif_content
        assert "uid=user2" in ldif_content
        assert "\n\n" in ldif_content  # Entries separated by double newline

    def test_write_entry(self) -> None:
        """Test write_entry method."""
        service = FlextLDIFServices.WriterService()
        entry = FlextLDIFEntry.model_validate(
            {
                "dn": "uid=single,ou=people,dc=example,dc=com",
                "attributes": {"objectClass": ["person"], "cn": ["Single User"]},
            }
        )

        result = service.write_entry(entry)

        assert result.is_success is True
        ldif_content = result.value
        assert "dn: uid=single,ou=people,dc=example,dc=com" in ldif_content

    def test_write_alias(self) -> None:
        """Test write method (alias)."""
        service = FlextLDIFServices.WriterService()
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "uid=alias,ou=people,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"], "cn": ["Alias User"]},
                }
            )
        ]

        result = service.write(entries)

        assert result.is_success is True
        assert "uid=alias" in result.value

    def test_write_entries_to_file_success(self) -> None:
        """Test write_entries_to_file with successful write."""
        service = FlextLDIFServices.WriterService()
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "uid=filetest,ou=people,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"], "cn": ["File Test User"]},
                }
            )
        ]

        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", delete=False, suffix=".ldif"
        ) as tmp_file:
            tmp_path = tmp_file.name

        try:
            result = service.write_entries_to_file(entries, tmp_path)

            assert result.is_success is True
            assert result.value is True

            # Verify file contents
            content = Path(tmp_path).read_text(encoding="utf-8")
            assert "uid=filetest" in content
            assert "cn: File Test User" in content

        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_write_entries_to_file_custom_encoding(self) -> None:
        """Test write_entries_to_file with custom encoding."""
        service = FlextLDIFServices.WriterService()
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "uid=encoding,ou=people,dc=example,dc=com",
                    "attributes": {
                        "objectClass": ["person"],
                        "cn": ["Encoding Test User"],
                    },
                }
            )
        ]

        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", delete=False, suffix=".ldif"
        ) as tmp_file:
            tmp_path = tmp_file.name

        try:
            result = service.write_entries_to_file(entries, tmp_path, encoding="utf-8")

            assert result.is_success is True

        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_write_file_alias(self) -> None:
        """Test write_file method (alias)."""
        service = FlextLDIFServices.WriterService()
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "uid=alias,ou=people,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"], "cn": ["Alias User"]},
                }
            )
        ]

        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", delete=False, suffix=".ldif"
        ) as tmp_file:
            tmp_path = tmp_file.name

        try:
            result = service.write_file(entries, tmp_path)

            assert result.is_success is True

        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_write_content_to_file_success(self) -> None:
        """Test _write_content_to_file internal method."""
        service = FlextLDIFServices.WriterService()
        content = "dn: uid=test,ou=people,dc=example,dc=com\nobjectClass: person\ncn: Test User\n"

        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", delete=False, suffix=".ldif"
        ) as tmp_file:
            tmp_path = tmp_file.name

        try:
            result = service._write_content_to_file(content, tmp_path, "utf-8")

            assert result.is_success is True
            assert result.value is True

            # Verify file was written
            written_content = Path(tmp_path).read_text(encoding="utf-8")
            assert written_content == content

        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_write_content_to_file_permission_error(self) -> None:
        """Test _write_content_to_file with permission error."""
        service = FlextLDIFServices.WriterService()
        content = "test content"
        # Try to write to root directory (should fail with permission error)
        invalid_path = "/root/invalid_file.ldif"

        result = service._write_content_to_file(content, invalid_path, "utf-8")

        assert result.is_success is False
        assert result.error is not None

    def test_write_entries_to_file_directory_creation(self) -> None:
        """Test write_entries_to_file creates parent directories."""
        service = FlextLDIFServices.WriterService()
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "uid=dirtest,ou=people,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"], "cn": ["Dir Test User"]},
                }
            )
        ]

        with tempfile.TemporaryDirectory() as tmp_dir:
            nested_path = Path(tmp_dir) / "nested" / "directory" / "test.ldif"

            result = service.write_entries_to_file(entries, str(nested_path))

            assert result.is_success is True
            assert nested_path.exists()
            assert nested_path.parent.exists()

    def test_format_entry_for_display(self) -> None:
        """Test format_entry_for_display method."""
        service = FlextLDIFServices.WriterService()
        entry = FlextLDIFEntry.model_validate(
            {
                "dn": "uid=display,ou=people,dc=example,dc=com",
                "attributes": {
                    "objectClass": ["inetOrgPerson", "person"],
                    "cn": ["Display User"],
                    "sn": ["User"],
                    "mail": ["display@example.com", "display.alt@example.com"],
                },
            }
        )

        result = service.format_entry_for_display(entry)

        assert result.is_success is True
        display_text = result.value
        assert "DN: uid=display,ou=people,dc=example,dc=com" in display_text
        assert "cn: Display User" in display_text
        assert "mail: display@example.com" in display_text
        assert "mail: display.alt@example.com" in display_text


class TestFieldDefaults:
    """Test FieldDefaults class constants."""

    def test_field_defaults_values(self) -> None:
        """Test that FieldDefaults has expected constant values."""
        defaults = FlextLDIFServices.FieldDefaults

        # DN constants
        assert defaults.DN_MIN_LENGTH == 3
        assert defaults.DN_MAX_LENGTH == 1024

        # Attribute constants
        assert defaults.ATTRIBUTE_NAME_MAX_LENGTH == 255
        assert defaults.ATTRIBUTE_VALUE_MAX_LENGTH == 65536
        assert defaults.OBJECT_CLASS_MAX_LENGTH == 255

        # LDIF format constants
        assert defaults.LINE_MAX_LENGTH == 76
        assert defaults.LDIF_LINE_MAX_LENGTH == 76  # Backward compatibility alias
        assert defaults.ENCODING == "utf-8"
        assert defaults.LINE_SEPARATOR == "\n"

        # Pattern constants
        assert isinstance(defaults.DN_PATTERN, str)
        assert isinstance(defaults.ATTRIBUTE_NAME_PATTERN, str)

        # Processing constants
        assert defaults.DEFAULT_BATCH_SIZE == 1000
        assert defaults.DEFAULT_TIMEOUT == 30
        assert defaults.MAX_ENTRIES_DEFAULT == 10000

    def test_field_defaults_types(self) -> None:
        """Test that FieldDefaults constants have correct types."""
        defaults = FlextLDIFServices.FieldDefaults

        # Integer constants
        assert isinstance(defaults.DN_MIN_LENGTH, int)
        assert isinstance(defaults.DN_MAX_LENGTH, int)
        assert isinstance(defaults.ATTRIBUTE_NAME_MAX_LENGTH, int)
        assert isinstance(defaults.ATTRIBUTE_VALUE_MAX_LENGTH, int)
        assert isinstance(defaults.OBJECT_CLASS_MAX_LENGTH, int)
        assert isinstance(defaults.LINE_MAX_LENGTH, int)
        assert isinstance(defaults.LDIF_LINE_MAX_LENGTH, int)
        assert isinstance(defaults.DEFAULT_BATCH_SIZE, int)
        assert isinstance(defaults.DEFAULT_TIMEOUT, int)
        assert isinstance(defaults.MAX_ENTRIES_DEFAULT, int)

        # String constants
        assert isinstance(defaults.ENCODING, str)
        assert isinstance(defaults.LINE_SEPARATOR, str)
        assert isinstance(defaults.DN_PATTERN, str)
        assert isinstance(defaults.ATTRIBUTE_NAME_PATTERN, str)
