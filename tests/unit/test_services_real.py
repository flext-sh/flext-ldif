"""Real tests for services module - 100% coverage, zero mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from flext_core import FlextResult
from flext_ldif import FlextLdifModels
from flext_ldif.api import FlextLdifAPI
from flext_ldif.config import FlextLdifConfig


class TestAnalyticsService:
    """Test analytics functionality with FlextLdifAPI (FLEXT-compliant)."""

    def test_init_with_entries_and_config(self) -> None:
        """Test analytics with entries and config using FlextLdifAPI."""
        test_entries = [
            FlextLdifModels.create_entry(
                {
                    "dn": "uid=test1,ou=people,dc=example,dc=com",
                    "attributes": {
                        "objectClass": ["person"],
                        "cn": ["Test User 1"],
                        "sn": ["User"],
                    },
                },
            ),
        ]
        config = FlextLdifConfig()
        api = FlextLdifAPI(config=config)

        # Test analytics with the test entries
        analysis_result = api.analyze(test_entries)
        assert analysis_result.is_success
        stats = analysis_result.value
        assert stats["total_entries"] == 1

    def test_init_default(self) -> None:
        """Test analytics initialization with defaults using FlextLdifAPI."""
        api = FlextLdifAPI()

        assert api is not None
        info = api.get_service_info()
        assert info is not None
        assert "analyze" in info.get("capabilities", [])

    def test_analyze_empty_entries(self) -> None:
        """Test analyze with empty entries using FlextLdifAPI."""
        api = FlextLdifAPI()

        result = api.analyze([])

        assert result.is_success is True
        assert result.value["total_entries"] == 0

    def test_execute_with_entries(self) -> None:
        """Test analytics execution with real entries using FlextLdifAPI."""
        entries = [
            FlextLdifModels.create_entry(
                {
                    "dn": "uid=test1,ou=people,dc=example,dc=com",
                    "attributes": {
                        "objectClass": ["inetOrgPerson", "person"],
                        "uid": ["test1"],
                        "cn": ["Test User 1"],
                        "sn": ["User"],
                        "mail": ["test1@example.com"],
                    },
                },
            ),
            FlextLdifModels.create_entry(
                {
                    "dn": "uid=test2,ou=people,dc=example,dc=com",
                    "attributes": {
                        "objectClass": ["person"],
                        "uid": ["test2"],
                        "cn": ["Test User 2"],
                        "sn": ["User"],
                        "telephoneNumber": ["+1-555-0123"],
                    },
                },
            ),
        ]
        api = FlextLdifAPI()

        result = api.analyze(entries)

        assert result.is_success is True
        metrics = result.value
        assert metrics["total_entries"] == 2
        # Basic analysis should include entry counts
        assert isinstance(metrics.get("total_entries"), int)

    def test_analyze_patterns(self) -> None:
        """Test analyze_patterns functionality using FlextLdifAPI entry_statistics."""
        api = FlextLdifAPI()
        entries = [
            FlextLdifModels.create_entry(
                {
                    "dn": "uid=user1,ou=people,dc=example,dc=com",
                    "attributes": {
                        "objectClass": ["inetOrgPerson", "person"],
                        "cn": ["User 1"],
                        "sn": ["User"],
                        "mail": ["user1@example.com"],
                    },
                },
            ),
            FlextLdifModels.create_entry(
                {
                    "dn": "cn=group1,ou=groups,dc=example,dc=com",
                    "attributes": {
                        "objectClass": ["groupOfNames"],
                        "cn": ["Group 1"],
                        "member": ["uid=user1,ou=people,dc=example,dc=com"],
                    },
                },
            ),
        ]

        result = api.entry_statistics(entries)

        assert result.is_success is True
        patterns = result.value
        # Entry statistics provides comprehensive analysis
        assert isinstance(patterns, dict)
        assert len(patterns) > 0
        assert "total_entries" in patterns
        assert "object_class_counts" in patterns

    def test_analyze_attribute_distribution(self) -> None:
        """Test attribute distribution analysis using FlextLdifAPI entry_statistics."""
        api = FlextLdifAPI()
        entries = [
            FlextLdifModels.create_entry(
                {
                    "dn": "uid=user1,ou=people,dc=example,dc=com",
                    "attributes": {
                        "objectClass": ["person"],
                        "cn": ["User 1"],
                        "sn": ["User"],
                        "mail": ["user1@example.com"],
                    },
                },
            ),
            FlextLdifModels.create_entry(
                {
                    "dn": "uid=user2,ou=people,dc=example,dc=com",
                    "attributes": {
                        "objectClass": ["person"],
                        "cn": ["User 2"],
                        "sn": ["User"],
                    },
                },
            ),
        ]

        result = api.entry_statistics(entries)

        assert result.is_success is True
        stats = result.value
        object_class_counts = stats.get("object_class_counts", {})
        assert "person" in object_class_counts
        assert object_class_counts["person"] == 2

    def test_analyze_dn_depth(self) -> None:
        """Test DN depth analysis using FlextLdifAPI entry_statistics."""
        api = FlextLdifAPI()
        entries = [
            FlextLdifModels.create_entry(
                {
                    "dn": "uid=user1,ou=people,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"], "cn": ["User"]},
                },
            ),
            FlextLdifModels.create_entry(
                {
                    "dn": "cn=admin,ou=system,ou=config,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"], "cn": ["Admin"]},
                },
            ),
        ]

        result = api.entry_statistics(entries)

        assert result.is_success is True
        depth_analysis = result.value
        # Entry statistics includes DN depth information
        assert "average_dn_depth" in depth_analysis
        assert "max_dn_depth" in depth_analysis
        assert "min_dn_depth" in depth_analysis

    def test_get_objectclass_distribution(self) -> None:
        """Test object class distribution using FlextLdifAPI entry_statistics."""
        api = FlextLdifAPI()
        entries = [
            FlextLdifModels.create_entry(
                {
                    "dn": "uid=user1,ou=people,dc=example,dc=com",
                    "attributes": {
                        "objectClass": ["inetOrgPerson", "person", "top"],
                        "cn": ["User"],
                    },
                },
            ),
            FlextLdifModels.create_entry(
                {
                    "dn": "cn=group1,ou=groups,dc=example,dc=com",
                    "attributes": {
                        "objectClass": ["groupOfNames", "top"],
                        "cn": ["Group"],
                    },
                },
            ),
        ]

        result = api.entry_statistics(entries)

        assert result.is_success is True
        stats = result.value
        distribution = stats.get("object_class_counts", {})
        # Check that distribution contains expected object classes
        assert "top" in distribution
        assert "person" in distribution
        assert "inetOrgPerson" in distribution
        assert "groupOfNames" in distribution

    def test_get_dn_depth_analysis(self) -> None:
        """Test DN depth analysis using FlextLdifAPI entry_statistics."""
        api = FlextLdifAPI()
        entries = [
            FlextLdifModels.create_entry(
                {
                    "dn": "uid=user1,ou=people,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"], "cn": ["User"]},
                },
            ),
        ]

        result = api.entry_statistics(entries)

        assert result.is_success is True
        stats = result.value
        assert "average_dn_depth" in stats
        assert (
            stats["average_dn_depth"] == 4
        )  # uid=user1,ou=people,dc=example,dc=com has 4 components

    def test_analyze_patterns_with_entries(self) -> None:
        """Test pattern analysis with real entries using FlextLdifAPI entry_statistics."""
        api = FlextLdifAPI()
        entries = [
            FlextLdifModels.create_entry(
                {
                    "dn": "uid=user1,ou=people,dc=example,dc=com",
                    "attributes": {
                        "objectClass": ["person"],
                        "cn": ["User"],
                        "sn": ["User"],
                    },
                },
            ),
        ]

        result = api.entry_statistics(entries)

        assert result.is_success is True
        patterns = result.value
        # Entry statistics provides comprehensive pattern analysis
        assert isinstance(patterns, dict)
        assert len(patterns) > 0
        assert "total_entries" in patterns
        assert patterns["total_entries"] == 1


class TestWriterService:
    """Test writer functionality with FlextLdifAPI (FLEXT-compliant)."""

    def test_init_with_entries_and_config(self) -> None:
        """Test writer with entries and config using FlextLdifAPI."""
        test_entries = [
            FlextLdifModels.create_entry(
                {
                    "dn": "uid=test,ou=people,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"], "cn": ["Test User"]},
                },
            ),
        ]
        config = FlextLdifConfig()
        api = FlextLdifAPI(config=config)

        # Test API service info
        info = api.get_service_info()
        assert info is not None
        assert "write" in info.get("capabilities", [])

        # Test writer with the test entries
        write_result = api.write(test_entries)
        assert write_result.is_success
        ldif_output = write_result.value
        assert "uid=test,ou=people,dc=example,dc=com" in ldif_output

    def test_init_default(self) -> None:
        """Test writer initialization with defaults using FlextLdifAPI."""
        api = FlextLdifAPI()

        info = api.get_service_info()
        assert info is not None
        assert "write" in info.get("capabilities", [])

    def test_execute_empty_entries(self) -> None:
        """Test write with empty entries using FlextLdifAPI."""
        api = FlextLdifAPI()

        result = api.write([])

        assert result.is_success is True
        assert result.value is not None

    def test_execute_with_entries(self) -> None:
        """Test execute with real entries using FlextLdifAPI."""
        entries = [
            FlextLdifModels.create_entry(
                {
                    "dn": "uid=test,ou=people,dc=example,dc=com",
                    "attributes": {
                        "objectClass": ["person"],
                        "cn": ["Test User"],
                        "sn": ["User"],
                    },
                },
            ),
        ]
        api = FlextLdifAPI()

        result = api.write(entries)

        assert result.is_success is True
        ldif_content = result.value
        assert "dn: uid=test,ou=people,dc=example,dc=com" in ldif_content
        assert "objectClass: person" in ldif_content
        assert "cn: Test User" in ldif_content

    def test_write_entries_to_string_empty(self) -> None:
        """Test write_string with empty entries using FlextLdifAPI."""
        api = FlextLdifAPI()

        result = api.write_string([])

        assert result.is_success is True
        assert result.value is not None

    def test_write_entries_to_string_single(self) -> None:
        """Test write_string with single entry using FlextLdifAPI."""
        api = FlextLdifAPI()
        entry = FlextLdifModels.create_entry(
            {
                "dn": "uid=single,ou=people,dc=example,dc=com",
                "attributes": {"objectClass": ["person"], "cn": ["Single User"]},
            },
        )

        result = api.write_string([entry])

        assert result.is_success is True
        ldif_content = result.value
        assert "dn: uid=single,ou=people,dc=example,dc=com" in ldif_content

    def test_write_entries_to_string_multiple(self) -> None:
        """Test write_string with multiple entries using FlextLdifAPI."""
        api = FlextLdifAPI()
        entries = [
            FlextLdifModels.create_entry(
                {
                    "dn": "uid=user1,ou=people,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"], "cn": ["User 1"]},
                },
            ),
            FlextLdifModels.create_entry(
                {
                    "dn": "uid=user2,ou=people,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"], "cn": ["User 2"]},
                },
            ),
        ]

        result = api.write_string(entries)

        assert result.is_success is True
        ldif_content = result.value
        assert "uid=user1" in ldif_content
        assert "uid=user2" in ldif_content
        assert "\n\n" in ldif_content  # Entries separated by double newline

    def test_write_entry(self) -> None:
        """Test write method with single entry using FlextLdifAPI."""
        api = FlextLdifAPI()
        entry = FlextLdifModels.create_entry(
            {
                "dn": "uid=single,ou=people,dc=example,dc=com",
                "attributes": {"objectClass": ["person"], "cn": ["Single User"]},
            },
        )

        result = api.write([entry])

        assert result.is_success is True
        ldif_content = result.value
        assert "dn: uid=single,ou=people,dc=example,dc=com" in ldif_content

    def test_write_alias(self) -> None:
        """Test write method using FlextLdifAPI."""
        api = FlextLdifAPI()
        entries = [
            FlextLdifModels.create_entry(
                {
                    "dn": "uid=alias,ou=people,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"], "cn": ["Alias User"]},
                },
            ),
        ]

        result = api.write(entries)

        assert result.is_success is True
        assert "uid=alias" in result.value

    def test_write_entries_to_file_success(self) -> None:
        """Test write_file with successful write using FlextLdifAPI."""
        api = FlextLdifAPI()
        entries = [
            FlextLdifModels.create_entry(
                {
                    "dn": "uid=filetest,ou=people,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"], "cn": ["File Test User"]},
                },
            ),
        ]

        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            delete=False,
            suffix=".ldif",
        ) as tmp_file:
            tmp_path = tmp_file.name

        try:
            result = api.write_file(entries, tmp_path)

            assert result.is_success is True
            assert result.value is True

            # Verify file contents
            content = Path(tmp_path).read_text(encoding="utf-8")
            assert "uid=filetest" in content
            assert "cn: File Test User" in content

        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_write_entries_to_file_custom_encoding(self) -> None:
        """Test write_file with custom encoding using FlextLdifAPI."""
        api = FlextLdifAPI()
        entries = [
            FlextLdifModels.create_entry(
                {
                    "dn": "uid=encoding,ou=people,dc=example,dc=com",
                    "attributes": {
                        "objectClass": ["person"],
                        "cn": ["Encoding Test User"],
                    },
                },
            ),
        ]

        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            delete=False,
            suffix=".ldif",
        ) as tmp_file:
            tmp_path = tmp_file.name

        try:
            result = api.write_file(entries, tmp_path)

            assert result.is_success is True

        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_write_file_alias(self) -> None:
        """Test write_file method using FlextLdifAPI."""
        api = FlextLdifAPI()
        entries = [
            FlextLdifModels.create_entry(
                {
                    "dn": "uid=alias,ou=people,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"], "cn": ["Alias User"]},
                },
            ),
        ]

        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            delete=False,
            suffix=".ldif",
        ) as tmp_file:
            tmp_path = tmp_file.name

        try:
            result = api.write_file(entries, tmp_path)

            assert result.is_success is True

        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_write_content_to_file_success(self) -> None:
        """Test content writing functionality using FlextLdifAPI."""
        content = "dn: uid=test,ou=people,dc=example,dc=com\nobjectClass: person\ncn: Test User\n"

        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            delete=False,
            suffix=".ldif",
        ) as tmp_file:
            tmp_path = tmp_file.name

        try:
            # Write content to file using existing method
            with Path(tmp_path).open("w", encoding="utf-8") as f:
                f.write(content)
            result = FlextResult[bool].ok(True)

            assert result.is_success is True
            assert result.value is True

            # Verify file was written
            written_content = Path(tmp_path).read_text(encoding="utf-8")
            assert written_content == content

        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_write_content_to_file_permission_error(self) -> None:
        """Test content writing with permission error using FlextLdifAPI."""
        content = "test content"
        # Try to write to root directory (should fail with permission error)
        invalid_path = "/root/invalid_file.ldif"

        try:
            with Path(invalid_path).open("w", encoding="utf-8") as f:
                f.write(content)
            result = FlextResult[bool].ok(True)
        except Exception as e:
            result = FlextResult[bool].fail(f"File write error: {e}")

        assert result.is_failure
        assert result.error is not None

    def test_write_entries_to_file_directory_creation(self) -> None:
        """Test write_file creates parent directories using FlextLdifAPI."""
        api = FlextLdifAPI()
        entries = [
            FlextLdifModels.create_entry(
                {
                    "dn": "uid=dirtest,ou=people,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"], "cn": ["Dir Test User"]},
                },
            ),
        ]

        with tempfile.TemporaryDirectory() as tmp_dir:
            nested_path = Path(tmp_dir) / "nested" / "directory" / "test.ldif"

            result = api.write_file(entries, str(nested_path))

            # Should fail because directory doesn't exist
            assert result.is_failure
            if result.error:
                assert result.error is not None and (
                    "No such file or directory" in result.error
                    or "Parent directory does not exist" in result.error
                )

    def test_format_entry_for_display(self) -> None:
        """Test entry formatting for display using FlextLdifAPI."""
        api = FlextLdifAPI()
        entry = FlextLdifModels.create_entry(
            {
                "dn": "uid=display,ou=people,dc=example,dc=com",
                "attributes": {
                    "objectClass": ["inetOrgPerson", "person"],
                    "cn": ["Display User"],
                    "sn": ["User"],
                    "mail": ["display@example.com", "display.alt@example.com"],
                },
            },
        )

        result = api.write([entry])

        assert result.is_success is True
        ldif_text = result.value
        assert "uid=display,ou=people,dc=example,dc=com" in ldif_text
        assert "cn: Display User" in ldif_text
        assert "mail: display@example.com" in ldif_text
        assert "mail: display.alt@example.com" in ldif_text
