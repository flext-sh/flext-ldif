"""Test support utilities for flext-ldif.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import contextlib
import os
import tempfile
from collections.abc import Generator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, Self, cast

from flext_core.result import FlextResult

from flext_ldif.api import FlextLdifAPI
from flext_ldif.config import FlextLdifConfig
from flext_ldif.models import FlextLdifModels
from flext_ldif.processor import FlextLdifProcessor


@dataclass
class LdifSample:
    """Represents a sample LDIF content with metadata."""

    content: str
    expected_entries: int


class LdifTestData:
    """Test data factory for LDIF entries and content."""

    @staticmethod
    def get_simple_person_entry() -> FlextLdifModels.Entry:
        """Get a simple person entry for testing."""
        result = FlextLdifModels.Entry.create({
            "dn": "cn=testuser,dc=example,dc=com",
            "attributes": {
                "cn": ["testuser"],
                "sn": ["User"],
                "objectClass": ["person", "organizationalPerson"],
                "userPassword": ["password123"],
            },
        })
        return result.unwrap()

    @staticmethod
    def get_simple_org_entry() -> FlextLdifModels.Entry:
        """Get a simple organizational entry for testing."""
        result = FlextLdifModels.Entry.create({
            "dn": "dc=example,dc=com",
            "attributes": {
                "dc": ["example"],
                "objectClass": ["dcObject", "organization"],
                "o": ["Example Corp"],
            },
        })
        return result.unwrap()

    @staticmethod
    def get_multiple_entries() -> list[FlextLdifModels.Entry]:
        """Get multiple test entries."""
        entry_result = FlextLdifModels.Entry.create({
            "dn": "ou=users,dc=example,dc=com",
            "attributes": {
                "ou": ["users"],
                "objectClass": ["organizationalUnit"],
                "description": ["User accounts"],
            },
        })
        return [
            LdifTestData.get_simple_person_entry(),
            LdifTestData.get_simple_org_entry(),
            entry_result.unwrap(),
        ]

    @staticmethod
    def basic_entries() -> LdifSample:
        """Get basic test entries as LDIF content."""
        content = LdifTestData.get_ldif_content()
        return LdifSample(content=content, expected_entries=2)

    @staticmethod
    def all_samples() -> list[FlextLdifModels.Entry]:
        """Get all sample entries."""
        return LdifTestData.get_multiple_entries()

    @staticmethod
    def large_dataset(count: int) -> list[FlextLdifModels.Entry]:
        """Get a large dataset with specified number of entries."""
        entries = []
        for i in range(count):
            entry_data = {
                "dn": f"cn=user{i},dc=example,dc=com",
                "attributes": {
                    "cn": [f"user{i}"],
                    "sn": ["User"],
                    "objectClass": ["person", "organizationalPerson"],
                    "userPassword": [f"password{i}"],
                },
            }
            entry_result = FlextLdifModels.Entry.create(
                cast("dict[str, object]", entry_data)
            )
            entries.append(entry_result.unwrap())
        return entries

    @staticmethod
    def invalid_data() -> str:
        """Get invalid LDIF data."""
        return LdifTestData.get_invalid_ldif_content()

    @staticmethod
    def special_characters() -> LdifSample:
        """Get LDIF content with special characters."""
        content = """dn: cn=José María Ñuñez,dc=example,dc=com
cn: José María Ñuñez
sn: User
objectClass: person
"""
        return LdifSample(content=content, expected_entries=1)

    @staticmethod
    def multi_valued_attributes() -> LdifSample:
        """Get LDIF content with multi-valued attributes."""
        content = """dn: cn=testuser,dc=example,dc=com
cn: testuser
sn: User
objectClass: person
objectClass: organizationalPerson
mail: multi.user@example.com
mail: multi.user.alt@example.com
userPassword: pass1
userPassword: pass2
"""
        return LdifSample(content=content, expected_entries=1)

    @staticmethod
    def with_changes() -> LdifSample:
        """Get LDIF content with changes."""
        content = """dn: cn=testuser,dc=example,dc=com
changetype: add
cn: testuser
sn: User
objectClass: person
"""
        return LdifSample(content=content, expected_entries=1)

    @staticmethod
    def with_binary_data() -> LdifSample:
        """Get LDIF content with binary data."""
        content = """dn: cn=testuser,dc=example,dc=com
cn: testuser
sn: User
objectClass: person
userCertificate;binary:: MIICiTCCAg+gAwIBAgIJAJ8l4HnPqAICMA0GCSqGSIb3DQEBBQUAMBExDzANBgNVBAMTBk5h
IFRlc3QwHhcNMDYwODI1MDYxODA5WhcNMDYwODI2MDYxODA5WjARMQ8wDQYDVQQDEwZOYSBU
ZXN0MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANAXC4rx8QPJdvtD5xUeWDgzOA2LM2NNL3jB
"""
        return LdifSample(content=content, expected_entries=1)

    @staticmethod
    def empty_and_null_values() -> LdifSample:
        """Get LDIF content with empty and null values."""
        content = """dn: cn=testuser,dc=example,dc=com
cn: testuser
sn:
objectClass: person
description:
"""
        return LdifSample(content=content, expected_entries=1)

    @staticmethod
    def long_lines() -> LdifSample:
        """Get LDIF content with long lines."""
        long_value = "a" * 1000
        content = f"""dn: cn=testuser,dc=example,dc=com
cn: {long_value}
sn: User
objectClass: person
"""
        return LdifSample(content=content, expected_entries=1)

    @staticmethod
    def get_ldif_content() -> str:
        """Get sample LDIF content string."""
        return """dn: cn=testuser,dc=example,dc=com
cn: testuser
sn: User
objectClass: person
objectClass: organizationalPerson
userPassword: password123

dn: dc=example,dc=com
dc: example
objectClass: dcObject
objectClass: organization
o: Example Corp
"""

    @staticmethod
    def get_invalid_ldif_content() -> str:
        """Get invalid LDIF content for testing error handling."""
        return """dn: invalid
invalid line without colon
"""


class FileManager:
    """File management utilities for tests."""

    def __enter__(self) -> Self:
        """Enter context manager."""
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        """Exit context manager."""

    @staticmethod
    def create_temp_ldif_file(content: str) -> Path:
        """Create a temporary LDIF file with given content."""
        fd, path = tempfile.mkstemp(suffix=".ldif")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(content)
            return Path(path)
        except:
            os.close(fd)
            raise

    @staticmethod
    def cleanup_temp_file(file_path: Path) -> None:
        """Clean up temporary file."""
        if file_path.exists():
            file_path.unlink()

    @staticmethod
    @contextlib.contextmanager
    def temporary_directory() -> Generator[Path, object]:
        """Create a temporary directory context manager."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield Path(temp_dir)

    @staticmethod
    def create_all_samples() -> dict[str, Path]:
        """Create all sample LDIF files."""
        samples = {
            "basic_entries": LdifTestData.basic_entries(),
            "with_changes": LdifTestData.with_changes(),
            "with_binary": LdifTestData.with_binary_data(),
        }
        files = {}
        for name, sample in samples.items():
            file_path = FileManager.create_temp_ldif_file(sample.content)
            files[name] = file_path
        return files


class ServiceFactoryProtocol(Protocol):
    """Protocol for service factories."""

    def create_api(self) -> object: ...
    def create_processor(self) -> object: ...


class RealServiceFactory:
    """Factory for creating real services for integration tests."""

    def __init__(self) -> None:
        """Initialize the factory with service classes."""
        self._api_class = FlextLdifAPI
        self._processor_class = FlextLdifProcessor

    def create_api(self) -> FlextLdifAPI:
        """Create a real API instance."""
        return self._api_class()

    def create_processor(self) -> FlextLdifProcessor:
        """Create a real processor instance."""
        return self._processor_class()

    @staticmethod
    def create_test_config(
        *,
        strict_parsing: bool = False,
        max_entries: int | None = None,
        max_line_length: int | None = None,
    ) -> FlextLdifConfig:
        """Create a test configuration."""
        config_kwargs: dict[str, Any] = {"ldif_strict_validation": strict_parsing}
        if max_entries is not None:
            config_kwargs["ldif_max_entries"] = max_entries
        if max_line_length is not None:
            config_kwargs["ldif_max_line_length"] = max_line_length
        return FlextLdifConfig(**config_kwargs)


class TestValidators:
    """Validation utilities for tests."""

    @staticmethod
    def assert_entries_equal(
        entry1: FlextLdifModels.Entry, entry2: FlextLdifModels.Entry
    ) -> None:
        """Assert that two entries are equal."""
        assert entry1.dn == entry2.dn
        assert entry1.attributes.data == entry2.attributes.data

    @staticmethod
    def assert_result_success(result: FlextResult[object]) -> None:
        """Assert that a FlextResult is successful."""
        assert hasattr(result, "is_success"), "Result should have is_success attribute"
        assert result.is_success, f"Result should be successful, got: {result}"

    @staticmethod
    def assert_result_failure(result: FlextResult[object]) -> None:
        """Assert that a FlextResult is a failure."""
        assert hasattr(result, "is_failure"), "Result should have is_failure attribute"
        assert result.is_failure, f"Result should be failure, got: {result}"

    @staticmethod
    def assert_valid_ldif_entry(entry: FlextLdifModels.Entry) -> None:
        """Assert that an LDIF entry is valid."""
        assert hasattr(entry, "dn"), "Entry should have dn"
        assert hasattr(entry, "attributes"), "Entry should have attributes"
        assert entry.dn is not None, "DN should not be None"
        assert entry.attributes is not None, "Attributes should not be None"
