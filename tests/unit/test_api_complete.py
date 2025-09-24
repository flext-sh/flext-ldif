"""Comprehensive tests for FlextLdifAPI to achieve 100% coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

from flext_core import FlextResult
from flext_ldif.api import FlextLdifAPI
from flext_ldif.models import FlextLdifModels


class TestFilterValid:
    """Tests for filter_valid to achieve complete coverage."""

    def test_filter_valid_includes_failures(self) -> None:
        """Test filter_valid branch coverage (line 503->501)."""
        api = FlextLdifAPI()

        # Create custom Entry classes that allow method mocking
        class MockableEntry(FlextLdifModels.Entry):
            _validate_result: FlextResult[bool]

            def __init__(
                self,
                dn: FlextLdifModels.DistinguishedName,
                attributes: FlextLdifModels.LdifAttributes,
            ) -> None:
                super().__init__(dn=dn, attributes=attributes)
                self._validate_result = FlextResult[bool].ok(True)

            def validate_business_rules(self) -> FlextResult[bool]:
                return self._validate_result

            def set_validation_result(self, result: FlextResult[bool]) -> None:
                self._validate_result = result

        # Create mockable entries
        entry1_result = MockableEntry.create(
            "cn=valid1,dc=example,dc=com", {"cn": ["valid1"], "objectClass": ["person"]}
        )
        assert entry1_result.is_success
        entry1 = entry1_result.value
        cast("MockableEntry", entry1).set_validation_result(FlextResult[bool].ok(True))

        entry2_result = MockableEntry.create(
            "cn=invalid,dc=example,dc=com",
            {"cn": ["invalid"], "objectClass": ["person"]},
        )
        assert entry2_result.is_success
        entry2 = entry2_result.value
        cast("MockableEntry", entry2).set_validation_result(
            FlextResult[bool].fail("Validation failed")
        )

        entry3_result = MockableEntry.create(
            "cn=valid2,dc=example,dc=com", {"cn": ["valid2"], "objectClass": ["person"]}
        )
        assert entry3_result.is_success
        entry3 = entry3_result.value
        cast("MockableEntry", entry3).set_validation_result(FlextResult[bool].ok(True))

        entries: list[FlextLdifModels.Entry] = [entry1, entry2, entry3]

        result = api.filter_valid(entries)

        assert result.is_success
        valid_entries = result.unwrap()
        assert len(valid_entries) == 2
        assert entry1 in valid_entries
        assert entry2 not in valid_entries
        assert entry3 in valid_entries
