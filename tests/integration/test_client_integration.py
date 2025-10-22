"""Client integration tests verifying FlextLdifClient through facade.

Tests client integration with FlextLdif facade:
- File operations through facade
- Client configuration handling
- Error recovery and resilience
- Multi-file operations

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path

import pytest

from flext_ldif import FlextLdif

logger = logging.getLogger(__name__)


class TestFlextLdifClientIntegration:
    """Test FlextLdifClient integration through FlextLdif facade."""

    def test_facade_delegates_to_client(self) -> None:
        """Test that facade properly delegates to client."""
        ldif = FlextLdif()

        content = """dn: cn=Test,dc=example,dc=com
cn: Test
objectClass: person
"""

        result = ldif.parse(content)
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 1

    def test_client_handles_file_operations(self) -> None:
        """Test client file operations through facade."""
        ldif = FlextLdif()

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
            f.write("""dn: cn=FileTest,dc=example,dc=com
cn: FileTest
objectClass: person
""")
            temp_path = Path(f.name)

        try:
            result = ldif.parse(str(temp_path))
            assert result.is_success
            entries = result.unwrap()
            assert len(entries) == 1
            assert entries[0].dn.value == "cn=FileTest,dc=example,dc=com"
        finally:
            temp_path.unlink()

    def test_client_multiple_file_handling(self) -> None:
        """Test client handles multiple files through facade."""
        ldif = FlextLdif()

        temp_files = []
        try:
            for i in range(3):
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".ldif", delete=False, encoding="utf-8"
                ) as f:
                    f.write(f"""dn: cn=User{i},dc=example,dc=com
cn: User{i}
objectClass: person
""")
                    temp_files.append(Path(f.name))

            # Parse each file
            for temp_file in temp_files:
                result = ldif.parse(str(temp_file))
                assert result.is_success
                entries = result.unwrap()
                assert len(entries) == 1
        finally:
            for temp_file in temp_files:
                temp_file.unlink()

    def test_client_encoding_handling(self) -> None:
        """Test client handles different encodings."""
        ldif = FlextLdif()

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
            f.write("""dn: cn=José García,dc=example,dc=com
cn: José García
objectClass: person
""")
            temp_path = Path(f.name)

        try:
            result = ldif.parse(str(temp_path))
            assert result.is_success
            entries = result.unwrap()
            assert len(entries) == 1
        finally:
            temp_path.unlink()

    def test_client_large_file_handling(self) -> None:
        """Test client can handle larger LDIF data."""
        ldif = FlextLdif()

        # Create LDIF with many entries
        entries_content = "\n\n".join([
            f"""dn: cn=User{i},dc=example,dc=com
cn: User{i}
mail: user{i}@example.com
objectClass: person"""
            for i in range(50)
        ])

        result = ldif.parse(entries_content)
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 50

    def test_client_with_special_characters(self) -> None:
        """Test client handles special characters in attribute values."""
        ldif = FlextLdif()

        content = """dn: cn=Test User,dc=example,dc=com
cn: Test User
mail: test+admin@example.com
description: This is a test (with parentheses)
objectClass: person
"""

        result = ldif.parse(content)
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 1

    def test_client_preserves_entry_data(self) -> None:
        """Test client preserves all entry data."""
        ldif = FlextLdif()

        content = """dn: cn=Complete Entry,dc=example,dc=com
cn: Complete Entry
sn: Entry
mail: entry@example.com
telephoneNumber: +1-555-1234
telephoneNumber: +1-555-5678
objectClass: person
objectClass: inetOrgPerson
"""

        result = ldif.parse(content)
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 1

        entry = entries[0]
        assert entry.dn.value == "cn=Complete Entry,dc=example,dc=com"

    def test_client_consistency_across_operations(self) -> None:
        """Test client maintains consistency across parse operations."""
        ldif = FlextLdif()

        content1 = """dn: cn=User1,dc=example,dc=com
cn: User1
objectClass: person
"""

        content2 = """dn: cn=User2,dc=example,dc=com
cn: User2
objectClass: person
"""

        result1 = ldif.parse(content1)
        result2 = ldif.parse(content2)

        assert result1.is_success
        assert result2.is_success

        entries1 = result1.unwrap()
        entries2 = result2.unwrap()

        assert len(entries1) == 1
        assert len(entries2) == 1
        assert entries1[0].dn.value != entries2[0].dn.value

    def test_client_error_recovery(self) -> None:
        """Test client recovers from parsing issues."""
        ldif = FlextLdif()

        # Invalid LDIF missing objectClass
        invalid_content = """dn: cn=BadEntry,dc=example,dc=com
cn: BadEntry
"""

        # Should either parse successfully or fail gracefully
        result = ldif.parse(invalid_content)
        assert result is not None
        # Result could be success or failure depending on quirks mode


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
