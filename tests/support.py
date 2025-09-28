"""Test support utilities for flext-ldif.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Protocol

from flext_core.result import FlextResult
from flext_ldif.api import FlextLdifAPI
from flext_ldif.models import FlextLdifModels
from flext_ldif.processor import FlextLdifProcessor


class LdifTestData:
    """Test data factory for LDIF entries and content."""

    @staticmethod
    def get_simple_person_entry() -> FlextLdifModels.Entry:
        """Get a simple person entry for testing."""
        return FlextLdifModels.Entry.create({
            "dn": "cn=testuser,dc=example,dc=com",
            "attributes": {
                "cn": ["testuser"],
                "sn": ["User"],
                "objectClass": ["person", "organizationalPerson"],
                "userPassword": ["password123"]
            }
        })

    @staticmethod
    def get_simple_org_entry() -> FlextLdifModels.Entry:
        """Get a simple organizational entry for testing."""
        return FlextLdifModels.Entry.create({
            "dn": "dc=example,dc=com",
            "attributes": {
                "dc": ["example"],
                "objectClass": ["dcObject", "organization"],
                "o": ["Example Corp"]
            }
        })

    @staticmethod
    def get_multiple_entries() -> list[FlextLdifModels.Entry]:
        """Get multiple test entries."""
        return [
            LdifTestData.get_simple_person_entry(),
            LdifTestData.get_simple_org_entry(),
            FlextLdifModels.Entry.create({
                "dn": "ou=users,dc=example,dc=com",
                "attributes": {
                    "ou": ["users"],
                    "objectClass": ["organizationalUnit"],
                    "description": ["User accounts"]
                }
            })
        ]

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

    @staticmethod
    def create_temp_ldif_file(content: str) -> Path:
        """Create a temporary LDIF file with given content."""
        fd, path = tempfile.mkstemp(suffix='.ldif')
        try:
            with os.fdopen(fd, 'w') as f:
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


class TestValidators:
    """Validation utilities for tests."""

    @staticmethod
    def assert_entries_equal(entry1: FlextLdifModels.Entry, entry2: FlextLdifModels.Entry) -> None:
        """Assert that two entries are equal."""
        assert entry1.dn == entry2.dn
        assert entry1.attributes.data == entry2.attributes.data

    @staticmethod
    def assert_result_success(result: FlextResult[object]) -> None:
        """Assert that a FlextResult is successful."""
        assert hasattr(result, 'is_success'), "Result should have is_success attribute"
        assert result.is_success, f"Result should be successful, got: {result}"

    @staticmethod
    def assert_result_failure(result: FlextResult[object]) -> None:
        """Assert that a FlextResult is a failure."""
        assert hasattr(result, 'is_failure'), "Result should have is_failure attribute"
        assert result.is_failure, f"Result should be failure, got: {result}"
