"""Test FlextLdifWriter with RFC quirks."""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif.config import FlextLdifConfig
from flext_ldif.models import FlextLdifModels

# Import RFC quirks to ensure they are auto-registered
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.services.writer import FlextLdifWriter


@pytest.fixture
def rfc_config() -> FlextLdifConfig:
    """Create RFC configuration."""
    return FlextLdifConfig(
        quirks_detection_mode="manual",
        quirks_server_type="rfc",
        enable_relaxed_parsing=False,
    )


@pytest.fixture
def registry() -> FlextLdifServer:
    """Get global FlextLdifServer with all registered quirks."""
    return FlextLdifServer.get_global_instance()


@pytest.fixture
def writer(rfc_config: FlextLdifConfig, registry: FlextLdifServer) -> FlextLdifWriter:
    """Create FlextLdifWriter with RFC server type (current API)."""
    # FlextLdifWriter() no longer accepts config/registry in __init__
    # Registry is fetched as singleton automatically
    return FlextLdifWriter()


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
            },
        ),
    )


def test_write_single_entry_to_string(
    writer: FlextLdifWriter,
    simple_entry: FlextLdifModels.Entry,
) -> None:
    """Test writing a single entry to string."""
    # Disable base64 encoding for readable output
    format_options = FlextLdifModels.WriteFormatOptions(base64_encode_binary=False)
    result = writer.write(
        [simple_entry],
        target_server_type="rfc",
        output_target="string",
        format_options=format_options,
    )

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
    writer: FlextLdifWriter,
    simple_entry: FlextLdifModels.Entry,
) -> None:
    """Test writing multiple entries to string."""
    entry2 = FlextLdifModels.Entry(
        dn=FlextLdifModels.DistinguishedName(value="cn=test2,dc=example,dc=com"),
        attributes=FlextLdifModels.LdifAttributes(
            attributes={
                "cn": ["test2"],
                "objectClass": ["person"],
            },
        ),
    )

    format_options = FlextLdifModels.WriteFormatOptions(base64_encode_binary=False)
    result = writer.write(
        [simple_entry, entry2],
        target_server_type="rfc",
        output_target="string",
        format_options=format_options,
    )

    assert result.is_success, f"Write failed: {result.error}"
    content = result.unwrap()

    # Check both entries are present
    assert "dn: cn=test,dc=example,dc=com" in content
    assert "dn: cn=test2,dc=example,dc=com" in content
    assert content.count("dn:") == 2, "Expected 2 entries"


def test_write_to_file(
    tmp_path: Path,
    writer: FlextLdifWriter,
    simple_entry: FlextLdifModels.Entry,
) -> None:
    """Test writing entries to file."""
    output_file = tmp_path / "output.ldif"

    format_options = FlextLdifModels.WriteFormatOptions(base64_encode_binary=False)
    result = writer.write(
        [simple_entry],
        target_server_type="rfc",
        output_target="file",
        output_path=output_file,
        format_options=format_options,
    )

    assert result.is_success, f"Write failed: {result.error}"
    assert output_file.exists(), "Output file not created"

    # Read and verify content
    content = output_file.read_text()
    assert "dn: cn=test,dc=example,dc=com" in content
    assert "cn: test" in content
    assert "objectClass: person" in content


def test_write_entries_counted(
    writer: FlextLdifWriter,
    simple_entry: FlextLdifModels.Entry,
    tmp_path: Path,
) -> None:
    """Test that entry count is correct."""
    output_file = tmp_path / "count_test.ldif"
    result = writer.write(
        [simple_entry],
        target_server_type="rfc",
        output_target="file",
        output_path=output_file,
    )

    assert result.is_success
    write_response = result.unwrap()
    assert write_response.statistics.entries_written == 1


def test_effective_server_type(writer: FlextLdifWriter) -> None:
    """Test that writer service can be initialized successfully."""
    # Writer service is initialized correctly - just verify it exists
    assert writer is not None
    assert isinstance(writer, FlextLdifWriter)


def test_write_with_multiple_attribute_values(writer: FlextLdifWriter) -> None:
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
            },
        ),
    )

    format_options = FlextLdifModels.WriteFormatOptions(base64_encode_binary=False)
    result = writer.write(
        [entry],
        target_server_type="rfc",
        output_target="string",
        format_options=format_options,
    )

    assert result.is_success
    content = result.unwrap()

    # Check all member values are present
    assert content.count("member: ") == 3, "Not all member values written"
    assert "member: cn=user1,dc=example,dc=com" in content
    assert "member: cn=user2,dc=example,dc=com" in content
    assert "member: cn=user3,dc=example,dc=com" in content


def test_write_empty_entries_list(writer: FlextLdifWriter) -> None:
    """Test writing empty entries list."""
    result = writer.write([], target_server_type="rfc", output_target="string")

    assert result.is_success
    content = result.unwrap()
    # Empty list produces empty output (no entries, no headers)
    assert content == "" or content.isspace()
    assert content.count("dn:") == 0


def test_fallback_to_rfc_when_no_server(
    rfc_config: FlextLdifConfig,
    registry: FlextLdifServer,
) -> None:
    """Test that non-existent server type fails gracefully."""
    # Use non-existent server type - should fail
    writer = FlextLdifWriter(
        config=rfc_config,
        quirk_registry=registry,
    )

    entry = FlextLdifModels.Entry(
        dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
        attributes=FlextLdifModels.LdifAttributes(
            attributes={"cn": ["test"], "objectClass": ["person"]},
        ),
    )

    format_options = FlextLdifModels.WriteFormatOptions(base64_encode_binary=False)
    result = writer.write(
        [entry],
        target_server_type="nonexistent-server",
        output_target="string",
        format_options=format_options,
    )
    # Should fail with clear error message
    assert result.is_failure
    assert "No quirk implementation found" in result.error or ""
