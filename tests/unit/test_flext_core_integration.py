"""Test flext-core integration patterns in flext-ldif.

Demonstrates proper usage of flext-core patterns including FlextResult
composition, error handling, and validation using the newer API.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_core import FlextResult
from flext_ldif import FlextLdifModels, FlextLdifProcessor
from tests.test_support import TestValidators


class TestFlextCoreIntegration:
    """Test flext-core integration patterns in flext-ldif."""

    def test_flext_result_composition_patterns(self) -> None:
        """Test FlextResult composition patterns."""
        processor = FlextLdifProcessor()

        # Test successful composition chain
        ldif_content = """dn: cn=test1,dc=example,dc=com
cn: test1
sn: Test1
objectClass: person

dn: cn=test2,dc=example,dc=com
cn: test2
sn: Test2
objectClass: person"""

        # Chain: Parse -> Validate -> Transform -> Write
        parse_result = processor.parse_string(ldif_content)
        assert parse_result.is_success

        entries = parse_result.unwrap()
        validate_result = processor.validate_entries(entries)
        assert validate_result.is_success

        validated_entries = validate_result.unwrap()

        def transform_func(entry: FlextLdifModels.Entry) -> FlextLdifModels.Entry:
            entry.attributes.add_attribute("processed", ["true"])
            return entry

        transform_result = processor.transform_entries(
            validated_entries, transform_func
        )
        assert transform_result.is_success

        transformed_entries = transform_result.unwrap()
        write_result = processor.write_string(transformed_entries)
        assert write_result.is_success

        # Validate composition using flext-core patterns
        results = [parse_result, validate_result, transform_result, write_result]
        TestValidators.assert_flext_result_composition(
            results, expected_success_rate=1.0
        )
        TestValidators.assert_flext_result_chain(results, expect_all_success=True)

    def test_flext_result_error_handling_patterns(self) -> None:
        """Test FlextResult error handling patterns."""
        processor = FlextLdifProcessor()

        # Test various error scenarios
        error_scenarios = [
            ("", "Empty content"),
            ("invalid ldif", "Invalid LDIF format"),
            ("dn: invalid-dn-format\ncn: test", "Invalid DN format"),
        ]

        error_results = []
        for content, _expected_error_type in error_scenarios:
            result = processor.parse_string(content)
            error_results.append(result)

            # Validate error characteristics
            if result.is_failure:
                validation = TestValidators.validate_result_failure(result)
                assert validation["is_failure"]
                assert validation["has_error"]
                assert validation["error_message"] is not None
                assert len(validation["error_message"]) > 0

        # Validate error composition
        TestValidators.assert_flext_result_composition(
            error_results, expected_success_rate=0.0
        )

    def test_flext_result_structured_error_data(self) -> None:
        """Test FlextResult structured error data patterns."""
        processor = FlextLdifProcessor()

        # Test with invalid content that should provide structured error data
        invalid_content = "invalid ldif content without proper dn"
        result = processor.parse_string(invalid_content)

        assert result.is_failure
        validation = TestValidators.validate_result_failure(result)

        # Check for structured error information
        assert validation["has_error"]
        assert validation["error_message"] is not None
        assert len(validation["error_message"]) > 0

        # Error should contain meaningful information
        assert result.error is not None
        assert len(result.error) > 0

    def test_flext_result_monadic_operations(self) -> None:
        """Test FlextResult monadic operations."""
        processor = FlextLdifProcessor()

        # Test map operation
        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
sn: Test
objectClass: person"""

        parse_result = processor.parse_string(ldif_content)
        assert parse_result.is_success

        # Test map operation on successful result
        mapped_result = parse_result.map(len)
        assert mapped_result.is_success
        assert mapped_result.unwrap() == 1

        # Test map operation on failed result
        failed_result = FlextResult[list[FlextLdifModels.Entry]].fail("Test error")
        mapped_failed = failed_result.map(len)
        assert mapped_failed.is_failure
        assert mapped_failed.error == "Test error"

    def test_flext_result_flat_map_operations(self) -> None:
        """Test FlextResult flat_map operations."""
        processor = FlextLdifProcessor()

        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
sn: Test
objectClass: person"""

        parse_result = processor.parse_string(ldif_content)
        assert parse_result.is_success

        # Test flat_map operation
        def validate_and_transform(
            entries: list[FlextLdifModels.Entry],
        ) -> FlextResult[str]:
            validate_result = processor.validate_entries(entries)
            if validate_result.is_failure:
                return FlextResult[str].fail("Validation failed")

            validated_entries = validate_result.unwrap()
            return processor.write_string(validated_entries)

        flat_mapped_result = parse_result.flat_map(validate_and_transform)
        assert flat_mapped_result.is_success
        ldif_output = flat_mapped_result.unwrap()
        assert "cn=test,dc=example,dc=com" in ldif_output

    def test_flext_result_filter_operations(self) -> None:
        """Test FlextResult filter operations."""
        processor = FlextLdifProcessor()

        ldif_content = """dn: cn=test1,dc=example,dc=com
cn: test1
objectClass: person

dn: cn=test2,dc=example,dc=com
cn: test2
objectClass: person"""

        parse_result = processor.parse_string(ldif_content)
        assert parse_result.is_success

        # Test filter operation
        filtered_result = parse_result.filter(
            lambda entries: len(entries) > 1, "Expected more than one entry"
        )
        assert filtered_result.is_success
        assert len(filtered_result.unwrap()) == 2

        # Test filter operation that fails
        filtered_failed = parse_result.filter(
            lambda entries: len(entries) > 10, "Expected more than 10 entries"
        )
        assert filtered_failed.is_failure
        assert "Expected more than 10 entries" in filtered_failed.error

    def test_flext_result_recovery_patterns(self) -> None:
        """Test FlextResult recovery patterns."""
        FlextLdifProcessor()

        # Test recover operation
        failed_result = FlextResult[str].fail("Original error")

        def recovery_func(error: str) -> str:
            return f"Recovered from: {error}"

        recovered_result = failed_result.recover(recovery_func)
        assert recovered_result.is_success
        assert "Recovered from: Original error" in recovered_result.unwrap()

        # Test recover_with operation
        def recovery_with_func(error: str) -> FlextResult[str]:
            return FlextResult[str].ok(f"Recovered with: {error}")

        recovered_with_result = failed_result.recover_with(recovery_with_func)
        assert recovered_with_result.is_success
        assert "Recovered with: Original error" in recovered_with_result.unwrap()

    def test_flext_result_tap_operations(self) -> None:
        """Test FlextResult tap operations."""
        processor = FlextLdifProcessor()

        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person"""

        parse_result = processor.parse_string(ldif_content)
        assert parse_result.is_success

        # Test tap operation (side effects)
        side_effect_called = False

        def side_effect(entries: list[FlextLdifModels.Entry]) -> None:
            nonlocal side_effect_called
            side_effect_called = True
            assert len(entries) == 1

        tapped_result = parse_result.tap(side_effect)
        assert tapped_result.is_success
        assert side_effect_called

        # Test tap_error operation
        failed_result = FlextResult[str].fail("Test error")
        error_side_effect_called = False

        def error_side_effect(error: str) -> None:
            nonlocal error_side_effect_called
            error_side_effect_called = True
            assert error == "Test error"

        tapped_error_result = failed_result.tap_error(error_side_effect)
        assert tapped_error_result.is_failure
        assert error_side_effect_called

    def test_flext_result_zip_operations(self) -> None:
        """Test FlextResult zip operations."""
        FlextLdifProcessor()

        # Create two successful results
        result1 = FlextResult[int].ok(42)
        result2 = FlextResult[str].ok("test")

        # Test zip_with operation
        zipped_result = result1.zip_with(result2, lambda x, y: f"{x}:{y}")
        assert zipped_result.is_success
        assert zipped_result.unwrap() == "42:test"

        # Test zip_with with one failure
        failed_result = FlextResult[str].fail("Error")
        zipped_failed = result1.zip_with(failed_result, lambda x, y: f"{x}:{y}")
        assert zipped_failed.is_failure
        assert zipped_failed.error == "Error"

    def test_flext_result_context_manager(self) -> None:
        """Test FlextResult context manager usage."""
        processor = FlextLdifProcessor()

        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person"""

        parse_result = processor.parse_string(ldif_content)
        assert parse_result.is_success

        # Test context manager with successful result
        with parse_result as entries:
            assert len(entries) == 1
            assert entries[0].dn.value == "cn=test,dc=example,dc=com"

        # Test context manager with failed result
        failed_result = FlextResult[str].fail("Test error")
        with pytest.raises(RuntimeError, match="Test error"), failed_result as _:
            pass

    def test_flext_result_boolean_operations(self) -> None:
        """Test FlextResult boolean operations."""
        FlextLdifProcessor()

        # Test boolean evaluation
        success_result = FlextResult[str].ok("test")
        assert bool(success_result) is True

        failed_result = FlextResult[str].fail("error")
        assert bool(failed_result) is False

        # Test or_else operation
        alternative_result = FlextResult[str].ok("alternative")
        or_else_result = failed_result.or_else(alternative_result)
        assert or_else_result.is_success
        assert or_else_result.unwrap() == "alternative"

        # Test or_else_get operation
        def get_alternative() -> FlextResult[str]:
            return FlextResult[str].ok("alternative from function")

        or_else_get_result = failed_result.or_else_get(get_alternative)
        assert or_else_get_result.is_success
        assert or_else_get_result.unwrap() == "alternative from function"

    def test_flext_result_unwrap_patterns(self) -> None:
        """Test FlextResult unwrap patterns."""
        FlextLdifProcessor()

        # Test unwrap on successful result
        success_result = FlextResult[str].ok("test")
        assert success_result.unwrap() == "test"

        # Test unwrap_or on successful result
        assert success_result.unwrap_or("default") == "test"

        # Test unwrap_or on failed result
        failed_result = FlextResult[str].fail("error")
        assert failed_result.unwrap_or("default") == "default"

        # Test expect on successful result
        assert success_result.expect("Should not fail") == "test"

        # Test expect on failed result
        with pytest.raises(RuntimeError, match="Should not fail: error"):
            failed_result.expect("Should not fail")

    def test_flext_result_static_methods(self) -> None:
        """Test FlextResult static methods."""
        FlextLdifProcessor()

        # Test combine method
        result1 = FlextResult[int].ok(1)
        result2 = FlextResult[int].ok(2)
        result3 = FlextResult[int].ok(3)

        combined_result = FlextResult.combine(result1, result2, result3)
        assert combined_result.is_success
        assert combined_result.unwrap() == [1, 2, 3]

        # Test all_success method
        assert FlextResult.all_success(result1, result2, result3) is True

        failed_result = FlextResult[int].fail("error")
        assert FlextResult.all_success(result1, result2, failed_result) is False

        # Test any_success method
        assert FlextResult.any_success(result1, result2, failed_result) is True
        assert FlextResult.any_success(failed_result, failed_result) is False

        # Test sequence method
        results_list = [result1, result2, result3]
        sequenced_result = FlextResult.sequence(results_list)
        assert sequenced_result.is_success
        assert sequenced_result.unwrap() == [1, 2, 3]

    def test_flext_result_advanced_composition(self) -> None:
        """Test advanced FlextResult composition patterns."""
        processor = FlextLdifProcessor()

        # Test pipeline composition
        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
sn: Test
objectClass: person"""

        def parse_operation(content: str) -> FlextResult[list[FlextLdifModels.Entry]]:
            return processor.parse_string(content)

        def validate_operation(
            entries: list[FlextLdifModels.Entry],
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            return processor.validate_entries(entries)

        def transform_operation(
            entries: list[FlextLdifModels.Entry],
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            def transform_func(entry: FlextLdifModels.Entry) -> FlextLdifModels.Entry:
                entry.attributes.add_attribute("processed", ["true"])
                return entry

            return processor.transform_entries(entries, transform_func)

        def write_operation(entries: list[FlextLdifModels.Entry]) -> FlextResult[str]:
            return processor.write_string(entries)

        # Test pipeline composition
        pipeline_result = FlextResult.pipeline(
            ldif_content,
            parse_operation,
            validate_operation,
            transform_operation,
            write_operation,
        )

        assert pipeline_result.is_success
        ldif_output = pipeline_result.unwrap()
        assert "cn=test,dc=example,dc=com" in ldif_output
        assert "processed: true" in ldif_output

    def test_flext_result_error_accumulation(self) -> None:
        """Test FlextResult error accumulation patterns."""
        FlextLdifProcessor()

        # Create multiple results with some failures
        results = [
            FlextResult[str].ok("success1"),
            FlextResult[str].fail("error1"),
            FlextResult[str].ok("success2"),
            FlextResult[str].fail("error2"),
        ]

        # Test accumulate_errors
        accumulated_result = FlextResult.accumulate_errors(*results)
        assert accumulated_result.is_failure
        assert "Multiple errors occurred" in accumulated_result.error
        assert "error1" in accumulated_result.error
        assert "error2" in accumulated_result.error

        # Test collect_all_errors
        successes, errors = FlextResult.collect_all_errors(*results)
        assert len(successes) == 2
        assert len(errors) == 2
        assert "success1" in successes
        assert "success2" in successes
        assert "error1" in errors
        assert "error2" in errors
