"""Advanced API integration tests with edge cases and error handling.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from flext_core import FlextResult
from flext_ldif import (
    FlextLdifAPI,
    FlextLdifModels,
)
from flext_ldif.config import FlextLdifConfig
from flext_ldif.dispatcher import FlextLdifDispatcher

# Extract nested classes for testing
ParseFileCommand = FlextLdifDispatcher.ParseFileCommand
ParseStringCommand = FlextLdifDispatcher.ParseStringCommand
ValidateEntriesCommand = FlextLdifDispatcher.ValidateEntriesCommand
WriteFileCommand = FlextLdifDispatcher.WriteFileCommand
WriteStringCommand = FlextLdifDispatcher.WriteStringCommand


class TestAdvancedAPIFeatures:
    """Test advanced API features and edge cases."""

    @pytest.fixture
    def api_with_config(self) -> FlextLdifAPI:
        """Create API with custom configuration."""
        config = FlextLdifConfig(
            ldif_max_entries=10000,
            ldif_chunk_size=100,
            ldif_strict_validation=True,
        )
        return FlextLdifAPI(config)

    def test_api_with_large_entries(self, api_with_config: FlextLdifAPI) -> None:
        """Test API with large number of entries."""
        # Generate large LDIF content
        entries: list[FlextLdifModels.Entry] = []
        for i in range(50):
            entry = FlextLdifModels.create_entry(
                {
                    "id": f"user-{i:03d}",
                    "dn": f"cn=user{i:03d},ou=people,dc=example,dc=com",
                    "attributes": {
                        "cn": [f"user{i:03d}"],
                        "objectClass": ["person", "inetOrgPerson"],
                        "mail": [f"user{i:03d}@example.com"],
                    },
                }
            )
            entries.append(entry)

        # Test validation
        validate_result = api_with_config._operations.validate_entries(entries)
        assert validate_result.is_success

        # Test statistics
        stats_result = api_with_config._analytics.entry_statistics(entries)
        assert stats_result.is_success
        assert stats_result.value is not None
        assert stats_result.value["total_entries"] == 50

    def test_api_error_handling_edge_cases(self, api_with_config: FlextLdifAPI) -> None:
        """Test API error handling with various edge cases."""
        # Test with empty content (returns empty list, which is valid)
        result = api_with_config._operations.parse_string("")
        assert result.is_success
        assert result.value == []

        # Test with malformed LDIF
        malformed_ldif = """dn cn=invalid,dc=example,dc=com
objectClass person
cn invalid"""

        result = api_with_config._operations.parse_string(malformed_ldif)
        assert not result.is_success

        # Test with invalid file path
        result = api_with_config._operations.parse_file(
            Path("/totally/invalid/path/file.ldif")
        )
        assert not result.is_success

    def test_api_filtering_capabilities(self, api_with_config: FlextLdifAPI) -> None:
        """Test advanced filtering capabilities."""
        ldif_content = """dn: cn=John Doe,ou=people,dc=example,dc=com
cn: John Doe
objectClass: person
objectClass: inetOrgPerson

dn: cn=Jane Smith,ou=people,dc=example,dc=com
cn: Jane Smith
objectClass: person
objectClass: organizationalPerson

dn: ou=people,dc=example,dc=com
ou: people
objectClass: organizationalUnit

dn: cn=Developers,ou=groups,dc=example,dc=com
cn: Developers
objectClass: groupOfNames
"""

        # Parse entries
        parse_result = api_with_config._operations.parse_string(ldif_content)
        assert parse_result.is_success
        entries = parse_result.value

        # Test filtering by objectClass
        person_result = api_with_config._filters.by_object_class(entries, "person")
        assert person_result.is_success
        assert len(person_result.value) == 2

        inet_result = api_with_config._filters.by_object_class(entries, "inetOrgPerson")
        assert inet_result.is_success
        assert len(inet_result.value) == 1

        ou_result = api_with_config._filters.by_object_class(
            entries, "organizationalUnit"
        )
        assert ou_result.is_success
        assert len(ou_result.value) == 1

    def test_api_file_operations_advanced(self, api_with_config: FlextLdifAPI) -> None:
        """Test advanced file operations."""
        content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
"""

        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write(content)
            temp_file = Path(f.name)

        try:
            # Test parse file
            parse_result = api_with_config._operations.parse_file(temp_file)
            assert parse_result.is_success
            assert len(parse_result.value) == 1

            # Test write file
            output_file = temp_file.with_suffix(".output.ldif")
            write_result = api_with_config._operations.write_file(
                parse_result.value,
                str(output_file),
            )
            assert write_result.is_success
            assert output_file.exists()

            # Verify content
            output_content = output_file.read_text()
            assert "cn=test,dc=example,dc=com" in output_content

            # Clean up
            output_file.unlink()
        finally:
            temp_file.unlink()

    def test_dispatcher_feature_flag_routes_operations(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Ensure dispatcher handles operations when the feature flag is enabled."""
        monkeypatch.setenv("FLEXT_LDIF_ENABLE_DISPATCHER", "1")

        api = FlextLdifAPI()

        sample_entry = FlextLdifModels.create_entry(
            {
                "id": "user-000",
                "dn": "cn=user000,ou=people,dc=example,dc=com",
                "attributes": {
                    "cn": ["user000"],
                    "objectClass": ["person"],
                },
            }
        )

        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file_path = Path(temp_file.name)

        def fake_dispatch(command: object) -> FlextResult[object]:
            if isinstance(command, ParseStringCommand):
                return FlextResult[object](data=[sample_entry])
            if isinstance(command, ParseFileCommand):
                return FlextResult[object](data=[sample_entry])
            if isinstance(command, WriteStringCommand):
                return FlextResult[object](data="ldif-content")
            if isinstance(command, WriteFileCommand):
                return FlextResult[object](data=True)
            if isinstance(command, ValidateEntriesCommand):
                return FlextResult[object](data=True)
            return FlextResult[object].fail("Unsupported command")

        assert api._dispatcher is not None

        monkeypatch.setattr(
            api._dispatcher,
            "dispatch",
            fake_dispatch,
            raising=False,
        )
        monkeypatch.setattr(
            type(api._services.parser),
            "parse_content",
            lambda *_: (_ for _ in ()).throw(AssertionError("fallback parse")),
            raising=False,
        )
        monkeypatch.setattr(
            type(api._services.parser),
            "parse_ldif_file",
            lambda *_: (_ for _ in ()).throw(AssertionError("fallback parse file")),
            raising=False,
        )
        monkeypatch.setattr(
            type(api._services.writer),
            "write_entries_to_string",
            lambda *_: (_ for _ in ()).throw(AssertionError("fallback write string")),
            raising=False,
        )
        monkeypatch.setattr(
            type(api._services.writer),
            "write_entries_to_file",
            lambda *_: (_ for _ in ()).throw(AssertionError("fallback write file")),
            raising=False,
        )
        monkeypatch.setattr(
            type(api._services.validator),
            "validate_entries",
            lambda *_: (_ for _ in ()).throw(AssertionError("fallback validate")),
            raising=False,
        )

        parse_string_result = api._operations.parse_string("dn: cn=user000")
        assert parse_string_result.is_success
        assert parse_string_result.value[0].dn == sample_entry.dn

        parse_file_result = api._operations.parse_file(temp_file_path)
        assert parse_file_result.is_success

        write_string_result = api._operations.write_string([sample_entry])
        assert write_string_result.is_success
        assert write_string_result.value == "ldif-content"

        with tempfile.NamedTemporaryFile(suffix=".ldif", delete=False) as output_file:
            output_path = Path(output_file.name)

        write_file_result = api._operations.write_file(
            [sample_entry],
            output_path,
        )
        assert write_file_result.is_success

        validate_result = api._operations.validate_entries([sample_entry])
        assert validate_result.is_success

        # Cleanup temporary files
        temp_file_path.unlink(missing_ok=True)
        output_path.unlink(missing_ok=True)

    def test_api_performance_monitoring(self, api_with_config: FlextLdifAPI) -> None:
        """Test API performance monitoring capabilities."""
        # Generate moderately large content
        content_parts = [
            f"""dn: cn=user{i:02d},ou=people,dc=example,dc=com
cn: user{i:02d}
objectClass: person
objectClass: inetOrgPerson
mail: user{i:02d}@example.com
"""
            for i in range(20)
        ]

        large_content = "\n".join(content_parts)

        # Test parsing performance
        parse_result = api_with_config._operations.parse_string(large_content)
        assert parse_result.is_success
        assert len(parse_result.value) == 20

        # Test validation performance
        validate_result = api_with_config._operations.validate_entries(
            parse_result.value
        )
        assert validate_result.is_success

        # Test writing performance
        write_result = api_with_config._operations.write_string(parse_result.value)
        assert write_result.is_success
        assert write_result.value is not None
