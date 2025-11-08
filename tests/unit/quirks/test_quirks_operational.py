"""Operational tests for quirks using real fixture data.

Tests that use real LDIF fixtures to validate quirk operations with actual data.
Serves as reference implementation for adding operational tests to other test files.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.servers.oud import FlextLdifServersOud
from flext_ldif.services.conversion import FlextLdifConversion
from tests.fixtures import FlextLdifFixtures
from tests.fixtures.helpers import (
    extract_attributes,
    extract_name,
    extract_objectclasses,
    extract_oid,
)


class TestOidQuirksWithRealFixtures:
    """Test OID quirks with real fixture data."""

    @pytest.fixture
    def oid(self) -> FlextLdifServersOid:
        """Create OID quirk instance."""
        return FlextLdifServersOid()

    @pytest.fixture
    def oid_schema_attributes(self, oid_fixtures: FlextLdifFixtures.OID) -> list[str]:
        """Extract OID attributes from schema fixture."""
        try:
            schema = oid_fixtures.schema()
        except AttributeError:
            pytest.skip("OID schema fixture not available")
        return extract_attributes(schema)

    @pytest.fixture
    def oid_schema_objectclasses(
        self,
        oid_fixtures: FlextLdifFixtures.OID,
    ) -> list[str]:
        """Extract OID objectClasses from schema fixture."""
        try:
            schema = oid_fixtures.schema()
        except AttributeError:
            pytest.skip("OID schema fixture not available")
        return extract_objectclasses(schema)

    @pytest.mark.parametrize("attr_index", range(5))
    def test_parse_real_oid_attributes_from_fixtures(
        self,
        oid: FlextLdifServersOid,
        oid_schema_attributes: list[str],
        attr_index: int,
    ) -> None:
        """Test parsing real OID attributes from fixtures.

        Uses parametrization to test multiple attributes.
        """
        if attr_index >= len(oid_schema_attributes):
            pytest.skip(f"Not enough attributes in fixture (need {attr_index + 1})")

        attr_def = oid_schema_attributes[attr_index]
        result = oid.schema_quirk.parse(attr_def)

        assert result.is_success, f"Failed to parse attribute: {result.error}"
        parsed = result.unwrap()
        # Parse attribute returns a Pydantic SchemaAttribute model, not dict
        from flext_ldif import FlextLdifModels

        assert isinstance(parsed, FlextLdifModels.SchemaAttribute)

        # Verify essential elements preserved
        oid = extract_oid(attr_def)
        if oid:
            assert hasattr(parsed, "oid"), f"OID not in parsed attribute: {parsed}"

    @pytest.mark.parametrize("oc_index", range(5))
    def test_parse_real_oid_objectclasses_from_fixtures(
        self,
        oid: FlextLdifServersOid,
        oid_schema_objectclasses: list[str],
        oc_index: int,
    ) -> None:
        """Test parsing real OID objectClasses from fixtures."""
        if oc_index >= len(oid_schema_objectclasses):
            pytest.skip(f"Not enough objectClasses in fixture (need {oc_index + 1})")

        oc_def = oid_schema_objectclasses[oc_index]
        result = oid.schema_quirk.parse(oc_def)

        assert result.is_success, f"Failed to parse objectClass: {result.error}"
        parsed = result.unwrap()
        # Parse objectclass returns a Pydantic SchemaObjectClass model, not dict
        from flext_ldif import FlextLdifModels

        assert isinstance(parsed, FlextLdifModels.SchemaObjectClass)

    def test_parse_all_oid_attributes_success_rate(
        self,
        oid: FlextLdifServersOid,
        oid_schema_attributes: list[str],
    ) -> None:
        """Test that high percentage of real OID attributes parse successfully."""
        if not oid_schema_attributes:
            pytest.skip("No OID attributes in fixture")

        successes = 0
        failures = []

        for attr in oid_schema_attributes:
            result = oid.parse(attr)
            if result.is_success:
                successes += 1
            else:
                failures.append((attr[:50], result.error))

        success_rate = (
            successes / len(oid_schema_attributes) if oid_schema_attributes else 0
        )
        assert success_rate > 0.90, (
            f"Only {success_rate:.1%} of OID attributes parsed successfully "
            f"({successes}/{len(oid_schema_attributes)}). Failures: {failures[:3]}"
        )


class TestConversionMatrixWithRealFixtures:
    """Test conversion matrix using real fixture data."""

    @pytest.fixture
    def matrix(self) -> FlextLdifConversion:
        """Create conversion matrix."""
        return FlextLdifConversion()

    @pytest.fixture
    def oid(self) -> FlextLdifServersOid.Schema:
        """Create OID schema quirk."""
        return FlextLdifServersOid.Schema()

    @pytest.fixture
    def oud(self) -> FlextLdifServersOud.Schema:
        """Create OUD schema quirk."""
        return FlextLdifServersOud.Schema()

    @pytest.fixture
    def oid_conversion_attributes(
        self,
        oid_fixtures: FlextLdifFixtures.OID,
    ) -> list[str]:
        """Extract OID attributes for conversion testing."""
        try:
            schema = oid_fixtures.schema()
        except AttributeError:
            pytest.skip("OID schema fixture not available")
        return extract_attributes(schema)

    def test_oid_to_oud_conversion_with_real_attributes(
        self,
        matrix: FlextLdifConversion,
        oid: FlextLdifServersOid,
        oud: FlextLdifServersOud,
        oid_conversion_attributes: list[str],
    ) -> None:
        """Test OID→OUD conversion with real fixture attributes."""
        if not oid_conversion_attributes:
            pytest.skip("No OID attributes in fixture")

        successes = 0
        failures = []

        # Test first 5 attributes
        for attr in oid_conversion_attributes[:5]:
            result = matrix.convert(oid, oud, "attribute", attr)

            if result.is_success:
                successes += 1
                converted_value = result.unwrap()
                assert isinstance(converted_value, str)
                converted: str = converted_value

                # Validate conversion preserved OID
                orig_oid = extract_oid(attr)
                converted_oid = extract_oid(converted)
                assert orig_oid == converted_oid, (
                    f"OID changed during conversion: {orig_oid} → {converted_oid}"
                )
            else:
                failures.append((attr[:50], result.error))

        assert len(failures) == 0, f"Conversion failures: {failures}"
        assert successes > 0, "No successful conversions"

    def test_roundtrip_oid_oud_oid_with_real_data(
        self,
        matrix: FlextLdifConversion,
        oid: FlextLdifServersOid,
        oud: FlextLdifServersOud,
        oid_conversion_attributes: list[str],
    ) -> None:
        """Test OID→OUD→OID roundtrip preserves essential data."""
        if not oid_conversion_attributes:
            pytest.skip("No OID attributes in fixture")

        # Test first attribute only for roundtrip
        original_attr = oid_conversion_attributes[0]
        orig_oid = extract_oid(original_attr)
        orig_name = extract_name(original_attr)

        # Forward: OID → OUD
        forward_result = matrix.convert(oid, oud, "attribute", original_attr)
        assert forward_result.is_success, (
            f"Forward conversion failed: {forward_result.error}"
        )

        # Backward: OUD → OID
        forward_value = forward_result.unwrap()
        assert isinstance(forward_value, str)
        forward_str: str = forward_value
        backward_result = matrix.convert(oud, oid, "attribute", forward_str)
        assert backward_result.is_success, (
            f"Backward conversion failed: {backward_result.error}"
        )

        final_attr_value = backward_result.unwrap()
        assert isinstance(final_attr_value, str)
        final_attr: str = final_attr_value
        final_oid = extract_oid(final_attr)
        final_name = extract_name(final_attr)

        # Validate semantic equivalence
        assert orig_oid == final_oid, (
            f"OID not preserved in roundtrip: {orig_oid} → {final_oid}"
        )
        assert orig_name == final_name, (
            f"NAME not preserved in roundtrip: {orig_name} → {final_name}"
        )


__all__ = ["TestConversionMatrixWithRealFixtures", "TestOidQuirksWithRealFixtures"]
