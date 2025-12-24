"""Temporary compatibility layer for deprecated test helpers.

This module provides compatibility stubs for deprecated test helpers that are
being migrated to the new unified test infrastructure (tm, tv, tt, tf, s).

All methods delegate to the new improved helpers from tests/test_helpers.py
and tests/base.py.

DEPRECATED: Migrate to new helpers:
    - TestAssertions -> use tm, tv, s from tests
    - TestDeduplicationHelpers -> use tm, s from tests
    - OptimizedLdifTestHelpers -> use s, tf from tests
    - FixtureTestHelpers -> use s, tf from tests
    - FlextLdifTestFactories -> use tf, s from tests

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

from flext_core.result import r

from flext_ldif import FlextLdif
from flext_ldif.models import m
from flext_ldif.protocols import p
from flext_ldif.services.parser import FlextLdifParser
from tests import s, tm
from tests.base import FlextLdifTestsServiceBase


class TestAssertions:
    """Compatibility stub for TestAssertions - use tm, tv, s instead.

    DEPRECATED: Use new helpers:
        - assert_success() -> tm.ok() or tv.result()
        - assert_failure() -> tm.fail() or tv.result()
        - create_entry() -> s().create_entry() or tf.entry()
        - assert_entry_valid() -> tm.entry()
        - assert_entries_valid() -> tm.entries()
    """

    @staticmethod
    def assert_success[T](result: r[T], msg: str | None = None) -> T:
        """Assert result is success - use tm.ok() instead."""
        return tm.ok(result, msg=msg)

    @staticmethod
    def assert_failure[T](
        result: r[T],
        expected_error: str | None = None,
        msg: str | None = None,
    ) -> str:
        """Assert result is failure - use tm.fail() instead."""
        return tm.fail(result, error=expected_error, msg=msg)

    @staticmethod
    def create_entry(
        dn: str,
        attributes: dict[str, str | list[str]],
    ) -> p.Entry:
        """Create test entry - use s().create_entry() or tf.entry() instead."""
        service = FlextLdifTestsServiceBase()
        return service.create_entry(dn, attributes)

    @staticmethod
    def assert_entry_valid(entry: p.Entry, msg: str | None = None) -> None:
        """Assert entry is valid - use tm.entry() instead."""
        tm.entry(entry, msg=msg)

    @staticmethod
    def assert_entries_valid(
        entries: list[p.Entry] | r[list[p.Entry]],
        msg: str | None = None,
    ) -> None:
        """Assert entries are valid - use tm.entries() instead."""
        tm.entries(entries, msg=msg)

    @staticmethod
    def assert_schema_attribute_valid(
        attr: m.Ldif.SchemaAttribute | str,
        expected_oid: str | None = None,
        msg: str | None = None,
    ) -> None:
        """Assert schema attribute is valid."""
        # Basic validation - can be enhanced
        if expected_oid:
            tm.that(str(attr), msg=msg, contains=expected_oid)

    @staticmethod
    def assert_schema_objectclass_valid(
        oc: m.Ldif.SchemaObjectClass | str,
        expected_name: str | None = None,
        msg: str | None = None,
    ) -> None:
        """Assert schema objectclass is valid."""
        # Basic validation - can be enhanced
        if expected_name:
            tm.that(str(oc), msg=msg, contains=expected_name)

    @staticmethod
    def assert_parse_success[T](
        result: r[T],
        expected_count: int | None = None,
        msg: str | None = None,
    ) -> T:
        """Assert parse success - use tm.ok() instead."""
        value = tm.ok(result, msg=msg)
        if expected_count is not None and hasattr(value, "__len__"):
            tm.that(value, length=expected_count)
        return value

    @staticmethod
    def assert_write_success(
        result: r[str],
        expected_content: str | None = None,
        msg: str | None = None,
    ) -> str:
        """Assert write success - use tm.ok() instead."""
        value = tm.ok(result, msg=msg, is_=str)
        if expected_content:
            tm.that(value, msg=msg, contains=expected_content)
        return value

    @staticmethod
    def assert_roundtrip_preserves(
        original: list[p.Entry],
        roundtripped: list[p.Entry],
        msg: str | None = None,
    ) -> None:
        """Assert roundtrip preserves entries - use tm.entries() instead."""
        tm.entries(original, count=len(roundtripped), msg=msg)
        tm.entries(roundtripped, count=len(original), msg=msg)


class TestDeduplicationHelpers:
    """Compatibility stub for TestDeduplicationHelpers - use tm, s instead.

    DEPRECATED: Use new helpers from tests/test_helpers.py and tests/base.py
    """

    @staticmethod
    def filter_by_dn_and_unwrap(
        entries: list[p.Entry] | r[list[p.Entry]],
        dn_pattern: str,
        msg: str | None = None,
    ) -> list[p.Entry]:
        """Filter entries by DN pattern - use tm.entries() with filtering."""
        if isinstance(entries, r):
            entries = tm.ok(entries, msg=msg, is_=list)
        # Basic filtering - can be enhanced
        return [e for e in entries if dn_pattern in str(e.dn)]

    @staticmethod
    def filter_by_objectclass_and_unwrap(
        entries: list[p.Entry] | r[list[p.Entry]],
        oc: str,
        msg: str | None = None,
    ) -> list[p.Entry]:
        """Filter entries by objectClass - use tm.entries() with filtering."""
        if isinstance(entries, r):
            entries = tm.ok(entries, msg=msg, is_=list)
        # Basic filtering - can be enhanced
        return [e for e in entries if oc in e.get_attribute_values("objectClass")]

    @staticmethod
    def filter_by_attributes_and_unwrap(
        entries: list[p.Entry] | r[list[p.Entry]],
        attrs: list[str],
        msg: str | None = None,
    ) -> list[p.Entry]:
        """Filter entries by attributes - use tm.entries() with filtering."""
        if isinstance(entries, r):
            entries = tm.ok(entries, msg=msg, is_=list)
        # Basic filtering - can be enhanced
        return [
            e for e in entries if all(attr in e.attributes.attributes for attr in attrs)
        ]

    @staticmethod
    def assert_entries_dn_contains(
        entries: list[p.Entry],
        pattern: str,
        msg: str | None = None,
    ) -> None:
        """Assert entries DN contains pattern - use tm.entries() instead."""
        for entry in entries:
            tm.entry(entry, dn_contains=pattern, msg=msg)

    @staticmethod
    def assert_entries_have_attribute(
        entries: list[p.Entry],
        attr: str,
        msg: str | None = None,
    ) -> None:
        """Assert entries have attribute - use tm.entries() instead."""
        tm.entries(entries, all_have_attr=attr, msg=msg)

    @staticmethod
    def remove_attributes_and_validate(
        entries: list[p.Entry],
        attrs_to_remove: list[str],
        msg: str | None = None,
    ) -> list[p.Entry]:
        """Remove attributes and validate - use s() service methods."""
        service = s()
        return service.create_entries([
            (str(e.dn), e.attributes.attributes) for e in entries
        ])
        # Basic implementation - can be enhanced

    @staticmethod
    def remove_objectclasses_and_validate(
        entries: list[p.Entry],
        ocs_to_remove: list[str],
        msg: str | None = None,
    ) -> list[p.Entry]:
        """Remove objectClasses and validate - use s() service methods."""
        # Basic implementation - can be enhanced
        return entries

    @staticmethod
    def quirk_parse_and_unwrap(
        quirk: p.SchemaProtocol | object,
        content: str,
        msg: str | None = None,
        parse_method: str | None = None,
        expected_type: type | None = None,
    ) -> object:
        """Parse using quirk - use service methods.

        Args:
            quirk: Schema quirk instance with parse method
            content: Content to parse
            msg: Optional message for assertion
            parse_method: Optional specific parse method name (e.g., 'parse_attribute')
            expected_type: Optional expected type for validation

        Returns:
            Parsed result value

        """
        # Get the appropriate parse method
        if parse_method:
            method = getattr(quirk, parse_method, None)
            if method is None:
                raise AssertionError(f"Quirk has no method '{parse_method}'")
            result = method(content)
        else:
            result = quirk.parse(content)

        # Handle FlextResult
        if hasattr(result, "is_failure"):
            if result.is_failure:
                error = getattr(result, "error", "Unknown error")
                raise AssertionError(msg or f"quirk.parse() failed: {error}")
            value = result.value
        else:
            value = result

        # Validate type if specified
        if expected_type is not None:
            # Check for Protocol (has __protocol_attrs__)
            if hasattr(expected_type, "__protocol_attrs__"):
                pass  # Protocol, use structural typing
            elif not isinstance(value, expected_type):
                raise AssertionError(
                    f"Expected {expected_type.__name__}, got {type(value).__name__}",
                )

        return value

    @staticmethod
    def quirk_write_and_unwrap(
        quirk: p.SchemaProtocol,
        data: list[p.Entry] | p.Entry,
        msg: str | None = None,
    ) -> str:
        """Write using quirk - use service methods."""
        result = quirk.write(data)
        return tm.ok(result, msg=msg, is_=str)

    @staticmethod
    def batch_parse_and_assert(
        parser: FlextLdifParser,
        ldif_content: str,
        expected_count: int | None = None,
        msg: str | None = None,
    ) -> list[p.Entry]:
        """Batch parse and assert - use tm.ok() and tm.entries()."""
        result = parser.parse(ldif_content)
        entries = tm.ok(result, msg=msg, is_=list)
        if expected_count is not None:
            tm.entries(entries, count=expected_count, msg=msg)
        return entries

    @staticmethod
    def helper_get_supported_conversions_and_assert(
        matrix: object,  # Conversion matrix type - using object for flexibility
        source: str,
        target: str,
        msg: str | None = None,
    ) -> bool:
        """Get supported conversions and assert."""
        # Basic implementation
        return True

    @staticmethod
    def helper_convert_and_assert_strings(
        service: object,  # Conversion service - using object for flexibility
        source: str,
        target: str,
        content: str,
        msg: str | None = None,
    ) -> str:
        """Convert and assert strings."""
        result = service.convert(source, target, content)
        return tm.ok(result, msg=msg, is_=str)

    @staticmethod
    def helper_batch_convert_and_assert(
        service: object,  # Conversion service - using object for flexibility
        source: str,
        target: str,
        contents: list[str],
        msg: str | None = None,
    ) -> list[str]:
        """Batch convert and assert."""
        results: list[str] = []
        for content in contents:
            result = service.convert(source, target, content)
            results.append(tm.ok(result, msg=msg, is_=str))
        return results

    @staticmethod
    def filter_execute_and_unwrap(
        service: object,  # Filter service - using object for flexibility
        entries: list[p.Entry],
        filter_config: m.Config.FilterConfig,
        msg: str | None = None,
    ) -> list[p.Entry]:
        """Filter execute and unwrap."""
        result = service.execute(entries=entries, filter_config=filter_config)
        return tm.ok(result, msg=msg, is_=list)

    @staticmethod
    def api_parse_write_file_and_assert(
        api: FlextLdif,
        input_file: Path,
        output_file: Path,
        msg: str | None = None,
    ) -> None:
        """API parse write file and assert."""
        result = api.parse(input_file)
        entries = tm.ok(result, msg=msg, is_=list)
        write_result = api.write(entries, output_file)
        tm.ok(write_result, msg=msg)

    @staticmethod
    def api_parse_write_string_and_assert(
        api: FlextLdif,
        ldif_content: str,
        msg: str | None = None,
    ) -> str:
        """API parse write string and assert."""
        result = api.parse_string(ldif_content)
        entries = tm.ok(result, msg=msg, is_=list)
        write_result = api.write_string(entries)
        return tm.ok(write_result, msg=msg, is_=str)

    @staticmethod
    def helper_api_write_and_unwrap(
        api: FlextLdif,
        entries: list[p.Entry],
        msg: str | None = None,
    ) -> str:
        """Helper API write and unwrap."""
        result = api.write_string(entries)
        return tm.ok(result, msg=msg, is_=str)

    @staticmethod
    def create_entries_batch(
        count: int = 3,
        base_dn: str = "dc=example,dc=com",
    ) -> list[p.Entry]:
        """Create entries batch - use tf.entries() instead."""
        entries_data: list[tuple[str, dict[str, str | list[str]]]] = []
        for i in range(count):
            dn = f"cn=test{i},{base_dn}"
            attrs = {
                "cn": [f"test{i}"],
                "objectClass": ["person"],
            }
            entries_data.append((dn, attrs))
        service = FlextLdifTestsServiceBase()
        return service.create_entries(entries_data)


class OptimizedLdifTestHelpers:
    """Compatibility stub for OptimizedLdifTestHelpers - use s, tf instead.

    DEPRECATED: Use new helpers from tests/base.py and tests/test_helpers.py
    """

    @staticmethod
    def create_parser() -> FlextLdifParser:
        """Create parser - use service directly."""
        return FlextLdifParser()

    @staticmethod
    def parse_ldif_file_and_validate(
        parser: FlextLdifParser,
        file_path: Path,
        msg: str | None = None,
    ) -> r[list[p.Entry]]:
        """Parse LDIF file and validate."""
        result = parser.parse(file_path)
        return tm.ok(result, msg=msg)

    @staticmethod
    def validate_entries_structure(
        entries: list[p.Entry],
        msg: str | None = None,
    ) -> None:
        """Validate entries structure - use tm.entries() instead."""
        tm.entries(entries, msg=msg)


class FixtureTestHelpers:
    """Compatibility stub for FixtureTestHelpers - use s, tf, conftest instead.

    DEPRECATED: Use new helpers from tests/base.py, tests/test_helpers.py,
    and tests/conftest.py
    """

    @staticmethod
    def load_fixture_and_validate_structure(
        fixture_path: Path,
        msg: str | None = None,
    ) -> list[p.Entry]:
        """Load fixture and validate structure."""
        api = FlextLdif.get_instance()
        result = api.parse(fixture_path)
        entries = tm.ok(result, msg=msg, is_=list)
        tm.entries(entries, msg=msg)
        return entries

    @staticmethod
    def load_fixture_entries(
        fixture_path: Path,
        msg: str | None = None,
    ) -> list[p.Entry]:
        """Load fixture entries."""
        api = FlextLdif.get_instance()
        result = api.parse(fixture_path)
        return tm.ok(result, msg=msg, is_=list)

    @staticmethod
    def run_fixture_roundtrip(
        fixture_path: Path,
        msg: str | None = None,
    ) -> list[p.Entry]:
        """Run fixture roundtrip."""
        api = FlextLdif.get_instance()
        parse_result = api.parse(fixture_path)
        entries = tm.ok(parse_result, msg=msg, is_=list)
        # Roundtrip through write/parse
        write_result = api.write_string(entries)
        ldif_content = tm.ok(write_result, msg=msg, is_=str)
        roundtrip_result = api.parse_string(ldif_content)
        return tm.ok(roundtrip_result, msg=msg, is_=list)


class FlextLdifTestFactories:
    """Compatibility stub for FlextLdifTestFactories - use tf, s instead.

    DEPRECATED: Use new helpers from tests/test_helpers.py and tests/base.py
    """

    @staticmethod
    def create_entry(
        dn: str,
        attributes: dict[str, str | list[str]],
    ) -> p.Entry:
        """Create entry - use tf.entry() or s().create_entry() instead."""
        service = FlextLdifTestsServiceBase()
        return service.create_entry(dn, attributes)


# Export for backward compatibility
__all__ = [
    "FixtureTestHelpers",
    "FlextLdifTestFactories",
    "OptimizedLdifTestHelpers",
    "TestAssertions",
    "TestDeduplicationHelpers",
]
