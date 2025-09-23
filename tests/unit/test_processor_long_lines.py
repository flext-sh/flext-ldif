"""Tests for processor.py long line handling to achieve higher coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import FlextLdifAPI, FlextLdifModels


class TestProcessorLongLines:
    """Tests for long line handling in processor."""

    @staticmethod
    def test_write_entry_with_very_long_attribute_value() -> None:
        """Test writing entry with extremely long attribute value that requires wrapping."""
        # Create a very long description value (>76 chars to trigger wrapping)
        long_description = "A" * 200  # 200 character long value

        entry_result = FlextLdifModels.create_entry({
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
                "description": [long_description],
                "objectClass": ["person"],
            },
        })
        assert entry_result.is_success

        api = FlextLdifAPI()
        result = api.write([entry_result.value])
        assert result.is_success

        # Verify the long line was written (may be wrapped)
        ldif_output = result.value
        assert "description:" in ldif_output
        assert "AAA" in ldif_output  # Part of the long value

    @staticmethod
    def test_write_entry_with_multiple_long_values() -> None:
        """Test writing entry with multiple long attribute values."""
        long_value1 = "B" * 150
        long_value2 = "C" * 180

        entry_result = FlextLdifModels.create_entry({
            "dn": "cn=longtest,dc=example,dc=com",
            "attributes": {
                "cn": ["longtest"],
                "description": [long_value1],
                "userCertificate": [long_value2],
                "objectClass": ["person"],
            },
        })
        assert entry_result.is_success

        api = FlextLdifAPI()
        result = api.write([entry_result.value])
        assert result.is_success

    @staticmethod
    def test_parse_and_write_round_trip_with_long_values() -> None:
        """Test round-trip parsing and writing with long values."""
        # Create LDIF with long value
        long_val = "D" * 100
        ldif_content = f"""dn: cn=roundtrip,dc=example,dc=com
cn: roundtrip
description: {long_val}
objectClass: person
"""

        api = FlextLdifAPI()

        # Parse
        parse_result = api.parse(ldif_content)
        assert parse_result.is_success
        entries = parse_result.value

        # Write back
        write_result = api.write(entries)
        assert write_result.is_success

        # Verify description is preserved
        written_ldif = write_result.value
        assert "description:" in written_ldif

    @staticmethod
    def test_entry_with_extremely_long_dn() -> None:
        """Test entry with very long DN."""
        # Create a DN with many components to make it very long
        long_dn = (
            "cn=user,"
            + ",".join([f"ou=dept{i}" for i in range(20)])
            + ",dc=example,dc=com"
        )

        entry_result = FlextLdifModels.create_entry({
            "dn": long_dn,
            "attributes": {
                "cn": ["user"],
                "objectClass": ["person"],
            },
        })
        assert entry_result.is_success

        api = FlextLdifAPI()
        result = api.write([entry_result.value])
        assert result.is_success
        assert long_dn in result.value
