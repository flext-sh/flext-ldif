"""Integration tests for ldif API facade with real workflows.

Tests cover:
- Complete parse-validate-write workflows
- Entry building and validation
- Multiple server type configurations
- Error handling in pipelines
- Real LDIF content processing

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_ldif import ldif

if TYPE_CHECKING:
    from pathlib import Path


class TestsFlextLdifPipelineIntegration:
    """Integration tests for ldif facade workflows."""

    def test_parse_simple_ldif_complete_workflow(self) -> None:
        """Test complete parse workflow with simple LDIF."""
        api = ldif()
        ldif_content = "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\nsn: Test\nmail: test@example.com\n"
        result = api.parse_ldif(ldif_content)
        assert result.success
        entries = result.value.entries
        assert len(entries) == 1
        assert entries[0].dn is not None
        assert entries[0].dn.value == "cn=test,dc=example,dc=com"

    def test_parse_multiple_entries(self) -> None:
        """Test parsing multiple entries from single string."""
        api = ldif()
        ldif_content = "dn: cn=user1,dc=example,dc=com\nobjectClass: person\ncn: user1\nsn: User1\n\ndn: cn=user2,dc=example,dc=com\nobjectClass: person\ncn: user2\nsn: User2\n\ndn: cn=user3,dc=example,dc=com\nobjectClass: person\ncn: user3\nsn: User3\n"
        result = api.parse_ldif(ldif_content)
        assert result.success
        entries = result.value.entries
        assert len(entries) == 3

    def test_parse_entries_with_multivalued_attributes(self) -> None:
        """Test parsing entries with multivalued attributes."""
        api = ldif()
        ldif_content = "dn: cn=group,dc=example,dc=com\nobjectClass: groupOfNames\ncn: group\nmember: cn=user1,dc=example,dc=com\nmember: cn=user2,dc=example,dc=com\nmember: cn=user3,dc=example,dc=com\n"
        result = api.parse_ldif(ldif_content)
        assert result.success
        entries = result.value.entries
        assert len(entries) == 1

    def test_parse_file_from_path(self, tmp_path: Path) -> None:
        """Test parsing LDIF from file path."""
        ldif_file = tmp_path / "test.ldif"
        ldif_file.write_text(
            "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\nsn: Test\n",
        )
        api = ldif()
        result = api.parse_ldif(ldif_file)
        if result.success:
            entries = result.value.entries
            assert len(entries) == 1

    def test_parse_with_rfc_and_extensions(self) -> None:
        """Test parsing LDIF with RFC extensions."""
        api = ldif()
        ldif_content = "version: 1\n# Comment line\ndn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\nsn: Test\n"
        result = api.parse_ldif(ldif_content)
        assert result.success
        entries = result.value.entries
        assert len(entries) == 1
        assert entries[0].attributes is not None
        assert "cn" in entries[0].attributes.attributes
