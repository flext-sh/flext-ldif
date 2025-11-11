"""Comprehensive API integration tests for flext-ldif.

Tests the complete FlextLdif facade with all major operations:
- Parsing LDIF files with different servers
- Filtering entries across multiple criteria
- Building entries with unified API
- Configuration and quirks integration

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_core import FlextLogger

from flext_ldif import FlextLdif, FlextLdifModels

logger = FlextLogger(__name__)


class TestFlextLdifAPIIntegration:
    """Test FlextLdif API complete integration."""

    def test_parse_simple_ldif(self) -> None:
        """Test parsing simple LDIF."""
        ldif = FlextLdif()

        content = """dn: cn=John Doe,ou=People,dc=example,dc=com
cn: John Doe
sn: Doe
objectClass: person
"""

        result = ldif.parse(content)
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 1

    def test_filter_by_objectclass(self) -> None:
        """Test filtering entries by objectClass."""
        ldif = FlextLdif()

        content = """dn: cn=User,ou=People,dc=example,dc=com
cn: User
objectClass: person

dn: cn=Group,dc=example,dc=com
cn: Group
objectClass: groupOfNames
"""

        parse_result = ldif.parse(content)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        # Filter by objectclass
        result = ldif.filter(entries, objectclass="person")
        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 1

    def test_filter_by_dn_pattern(self) -> None:
        """Test filtering entries by DN pattern."""
        ldif = FlextLdif()

        content = """dn: cn=User1,ou=People,dc=example,dc=com
cn: User1
objectClass: person

dn: cn=User2,ou=Admins,dc=example,dc=com
cn: User2
objectClass: person
"""

        parse_result = ldif.parse(content)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        # Filter by DN pattern
        result = ldif.filter(entries, dn_pattern="ou=People")
        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 1

    def test_build_entry(self) -> None:
        """Test building an entry programmatically.

        NOTE: Current API doesn't have a build() method. Entries should be
        created using FlextLdifModels.Entry directly or parsed from LDIF.
        This test validates that entries can be created programmatically.
        """
        from flext_ldif.models import FlextLdifModels

        # Create entry using Entry model directly
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=Test User,dc=example,dc=com",
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["Test User"],
                    "sn": ["User"],
                    "objectClass": ["person"],
                },
            ),
        )
        assert entry.dn.value.startswith("cn=")

    def test_validate_entries(self) -> None:
        """Test validating entries."""
        ldif = FlextLdif()

        content = """dn: cn=User,dc=example,dc=com
cn: User
objectClass: person
"""

        parse_result = ldif.parse(content)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        result = ldif.validate_entries(entries)
        assert result.is_success

    def test_multiple_instances(self) -> None:
        """Test that multiple FlextLdif instances are independent."""
        ldif1 = FlextLdif()
        ldif2 = FlextLdif()

        content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
"""

        result1 = ldif1.parse(content)
        result2 = ldif2.parse(content)

        assert result1.is_success
        assert result2.is_success
        entries1 = result1.unwrap()
        entries2 = result2.unwrap()
        assert len(entries1) == len(entries2) == 1

    def test_filter_with_multiple_criteria(self) -> None:
        """Test filtering with combined criteria."""
        ldif = FlextLdif()

        content = """dn: cn=Admin1,ou=Admins,dc=example,dc=com
cn: Admin1
mail: admin1@example.com
objectClass: person

dn: cn=User1,ou=People,dc=example,dc=com
cn: User1
objectClass: person

dn: cn=Admin2,ou=Admins,dc=example,dc=com
cn: Admin2
mail: admin2@example.com
objectClass: person
"""

        parse_result = ldif.parse(content)
        assert parse_result.is_success
        entries = parse_result.unwrap()
        assert len(entries) == 3

        # Filter by DN and attributes
        result = ldif.filter(entries, dn_pattern="ou=Admins", attributes={"mail": None})
        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 2

    def test_api_facade_properties(self) -> None:
        """Test accessing API properties."""
        ldif = FlextLdif()

        # Verify models are accessible
        models = ldif.models
        assert models is not None

        # Verify config is accessible
        config = ldif.config
        assert config is not None

    def test_end_to_end_workflow(self) -> None:
        """Test complete end-to-end workflow."""
        ldif = FlextLdif()

        # Step 1: Parse LDIF
        parse_content = """dn: cn=TestUser,dc=example,dc=com
cn: TestUser
objectClass: person
"""

        parse_result = ldif.parse(parse_content)
        assert parse_result.is_success
        parsed_entries: list[FlextLdifModels.Entry] = parse_result.unwrap()

        # Step 2: Analyze
        analyze_result = ldif.analyze(parsed_entries)
        assert analyze_result.is_success
        stats = analyze_result.unwrap()
        # AnalysisResult is now a Pydantic model, not a dict
        assert stats.total_entries == 1

        # Step 3: Validate
        validate_result = ldif.validate_entries(parsed_entries)
        assert validate_result.is_success

        # Step 4: Filter
        filter_result = ldif.filter(parsed_entries, objectclass="person")
        assert filter_result.is_success
        filtered = filter_result.unwrap()
        assert len(filtered) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
