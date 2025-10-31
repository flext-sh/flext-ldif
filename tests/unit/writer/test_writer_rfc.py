"""Test FlextLdifWriterService with RFC quirks."""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif.config import FlextLdifConfig
from flext_ldif.models import FlextLdifModels

# Import RFC quirks to ensure they are auto-registered
from flext_ldif.services.registry import FlextLdifRegistry
from flext_ldif.services.writer import FlextLdifWriterService


@pytest.fixture
def rfc_config() -> FlextLdifConfig:
    """Create RFC configuration."""
    return FlextLdifConfig(
        quirks_detection_mode="manual",
        quirks_server_type="rfc",
        enable_relaxed_parsing=False,
    )


@pytest.fixture
def registry() -> FlextLdifRegistry:
    """Get global FlextLdifRegistry with all registered quirks."""
    return FlextLdifRegistry.get_global_instance()


@pytest.fixture
def writer(
    rfc_config: FlextLdifConfig, registry: FlextLdifRegistry
) -> FlextLdifWriterService:
    """Create FlextLdifWriterService with RFC server type."""
    return FlextLdifWriterService(
        config=rfc_config,
        quirk_registry=registry,
    )


@pytest.fixture
def simple_entry() -> FlextLdifModels.Entry:
    """Create a simple RFC-compliant entry."""
    return FlextLdifModels.Entry(
        dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
        attributes=FlextLdifModels.LdifAttributes(
            attributes={
                "cn": ["test"],
                "objectClass": ["person", "inetOrgPerson"],
                "sn": ["test-user"],
                "mail": ["test@example.com"],
            }
        ),
    )


def test_write_single_entry_to_string(
    writer: FlextLdifWriterService, simple_entry: FlextLdifModels.Entry
) -> None:
    """Test writing a single entry to string."""
    result = writer.write_to_string([simple_entry])

    assert result.is_success, f"Write failed: {result.error}"
    content = result.unwrap()

    # Check LDIF version line
    assert content.startswith("version: 1\n"), "Missing LDIF version line"

    # Check DN line
    assert "dn: cn=test,dc=example,dc=com" in content, "Missing or incorrect DN"

    # Check attributes
    assert "cn: test" in content, "Missing cn attribute"
    assert "objectClass: person" in content, "Missing objectClass value"
    assert "objectClass: inetOrgPerson" in content, "Missing objectClass value"
    assert "sn: test-user" in content, "Missing sn attribute"
    assert "mail: test@example.com" in content, "Missing mail attribute"


def test_write_multiple_entries_to_string(
    writer: FlextLdifWriterService, simple_entry: FlextLdifModels.Entry
) -> None:
    """Test writing multiple entries to string."""
    entry2 = FlextLdifModels.Entry(
        dn=FlextLdifModels.DistinguishedName(value="cn=test2,dc=example,dc=com"),
        attributes=FlextLdifModels.LdifAttributes(
            attributes={
                "cn": ["test2"],
                "objectClass": ["person"],
            }
        ),
    )

    result = writer.write_to_string([simple_entry, entry2])

    assert result.is_success, f"Write failed: {result.error}"
    content = result.unwrap()

    # Check both entries are present
    assert "dn: cn=test,dc=example,dc=com" in content
    assert "dn: cn=test2,dc=example,dc=com" in content
    assert content.count("dn:") == 2, "Expected 2 entries"


def test_write_to_file(
    tmp_path: Path, writer: FlextLdifWriterService, simple_entry: FlextLdifModels.Entry
) -> None:
    """Test writing entries to file."""
    output_file = tmp_path / "output.ldif"

    result = writer.write_to_file([simple_entry], output_file)

    assert result.is_success, f"Write failed: {result.error}"
    assert output_file.exists(), "Output file not created"

    # Read and verify content
    content = output_file.read_text()
    assert "dn: cn=test,dc=example,dc=com" in content
    assert "cn: test" in content
    assert "objectClass: person" in content


def test_write_entries_counted(
    writer: FlextLdifWriterService, simple_entry: FlextLdifModels.Entry
) -> None:
    """Test that entry count is correct."""
    result = writer.write([simple_entry])

    assert result.is_success
    write_response = result.unwrap()
    assert write_response.statistics.entries_written == 1


def test_effective_server_type(writer: FlextLdifWriterService) -> None:
    """Test that effective server type is set correctly."""
    assert writer.get_effective_server_type() == "rfc"


def test_write_with_multiple_attribute_values(writer: FlextLdifWriterService) -> None:
    """Test writing entry with multiple values for same attribute."""
    entry = FlextLdifModels.Entry(
        dn=FlextLdifModels.DistinguishedName(value="cn=group,dc=example,dc=com"),
        attributes=FlextLdifModels.LdifAttributes(
            attributes={
                "cn": ["group"],
                "objectClass": ["groupOfNames", "top"],
                "member": [
                    "cn=user1,dc=example,dc=com",
                    "cn=user2,dc=example,dc=com",
                    "cn=user3,dc=example,dc=com",
                ],
            }
        ),
    )

    result = writer.write_to_string([entry])

    assert result.is_success
    content = result.unwrap()

    # Check all member values are present
    assert content.count("member: ") == 3, "Not all member values written"
    assert "member: cn=user1,dc=example,dc=com" in content
    assert "member: cn=user2,dc=example,dc=com" in content
    assert "member: cn=user3,dc=example,dc=com" in content


def test_write_empty_entries_list(writer: FlextLdifWriterService) -> None:
    """Test writing empty entries list."""
    result = writer.write_to_string([])

    assert result.is_success
    content = result.unwrap()
    # Should have LDIF version but no entries
    assert content == "version: 1"
    assert content.count("dn:") == 0


def test_error_when_no_quirk_for_entry(
    rfc_config: FlextLdifConfig, registry: FlextLdifRegistry
) -> None:
    """Test that error is raised when no quirk found for entry."""
    # Use non-existent server type
    writer = FlextLdifWriterService(
        config=rfc_config,
        quirk_registry=registry,
        target_server_type="nonexistent-server",
    )

    entry = FlextLdifModels.Entry(
        dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
        attributes=FlextLdifModels.LdifAttributes(
            attributes={"cn": ["test"], "objectClass": ["person"]}
        ),
    )

    result = writer.write_to_string([entry])
    assert result.is_failure
    assert "No quirk found" in result.error
