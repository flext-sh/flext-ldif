"""Entry test helpers to eliminate massive code duplication.

Provides high-level methods that replace entire test functions with single calls.
Each method replaces 15-30+ lines of duplicated test code.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from tests.helpers.test_assertions import TestAssertions

if TYPE_CHECKING:
    from flext_ldif.models import FlextLdifModels
    from flext_ldif.servers.base import FlextLdifServersBase


class EntryTestHelpers:
    """High-level entry test helpers that replace entire test functions."""

    @staticmethod
    def test_write_entry_complete(
        entry_quirk: FlextLdifServersBase.Entry,
        entry: FlextLdifModels.Entry,
        expected_dn_in_output: bool = True,
        expected_attributes: list[str] | None = None,
        must_contain: list[str] | None = None,
        must_not_contain: list[str] | None = None,
        expected_format: str | None = None,  # "add", "modify", "delete"
    ) -> str:
        """Complete entry write test - replaces entire test function.

        This method replaces 10-20 lines of duplicated test code:
        - Calls write(entry)
        - Asserts success
        - Validates DN, attributes, must_contain, must_not_contain, format
        - Returns written LDIF string

        Args:
            entry_quirk: Entry quirk instance
            entry: Entry to write
            expected_dn_in_output: Whether DN should appear in output (default: True)
            expected_attributes: Optional list of attribute names that must appear
            must_contain: Optional list of strings that must appear in output
            must_not_contain: Optional list of strings that must NOT appear
            expected_format: Optional expected format ("add", "modify", "delete")

        Returns:
            Written LDIF string

        Example:
            # Replaces entire test function:
            ldif = EntryTestHelpers.test_write_entry_complete(
                entry_quirk,
                entry,
                expected_attributes=["cn", "objectClass"],
                must_contain=["dn:", "cn: test"],
                must_not_contain=["changetype: delete"],
                expected_format="add"
            )

        """
        result = entry_quirk.write(entry)
        ldif = TestAssertions.assert_write_success(result)

        if expected_dn_in_output:
            assert entry.dn.value in ldif, (
                f"Expected DN '{entry.dn.value}' not found in output"
            )

        if expected_attributes:
            for attr_name in expected_attributes:
                assert f"{attr_name}:" in ldif or f"{attr_name.lower()}:" in ldif, (
                    f"Expected attribute '{attr_name}' not found in output"
                )

        if must_contain:
            for content in must_contain:
                assert content in ldif, f"Must contain '{content}' not found in LDIF"

        if must_not_contain:
            for content in must_not_contain:
                assert content not in ldif, (
                    f"Must not contain '{content}' found in LDIF"
                )

        if expected_format:
            format_lower = expected_format.lower()
            if format_lower == "add":
                assert "changetype: add" in ldif.lower() or "changetype:" not in ldif.lower(), (
                    "Expected add format (no changetype or changetype: add)"
                )
            elif format_lower == "modify":
                assert "changetype: modify" in ldif.lower(), (
                    "Expected modify format"
                )
            elif format_lower == "delete":
                assert "changetype: delete" in ldif.lower(), (
                    "Expected delete format"
                )

        return ldif

    @staticmethod
    def test_write_entry_modify_add_format_complete(
        entry_quirk: FlextLdifServersBase.Entry,
        entry: FlextLdifModels.Entry,
        expected_attributes_in_output: list[str] | None = None,
        must_contain: list[str] | None = None,
        should_have_final_separator: bool = True,
    ) -> str:
        """Complete _write_entry_modify_add_format test - replaces entire test function.

        This method replaces 12-18 lines of duplicated test code:
        - Calls _write_entry_modify_add_format(entry)
        - Asserts success
        - Validates attributes, must_contain, final separator
        - Returns written LDIF string

        Args:
            entry_quirk: Entry quirk instance
            entry: Entry to write in modify-add format
            expected_attributes_in_output: Optional list of attribute names
            must_contain: Optional list of strings that must appear
            should_have_final_separator: Whether output should end with newline

        Returns:
            Written LDIF string

        Example:
            # Replaces entire test function:
            ldif = EntryTestHelpers.test_write_entry_modify_add_format_complete(
                entry_quirk,
                entry,
                expected_attributes_in_output=["attributetypes"],
                must_contain=["changetype: modify", "add: attributetypes"],
                should_have_final_separator=True
            )

        """
        result = entry_quirk._write_entry_modify_add_format(entry)
        ldif = TestAssertions.assert_success(result, "Modify-add format write should succeed")
        assert isinstance(ldif, str), "Write should return string"

        if expected_attributes_in_output:
            for attr_name in expected_attributes_in_output:
                assert attr_name.lower() in ldif.lower(), (
                    f"Expected attribute '{attr_name}' not found in output"
                )

        if must_contain:
            for content in must_contain:
                assert content.lower() in ldif.lower(), (
                    f"Must contain '{content}' not found in LDIF"
                )

        if should_have_final_separator:
            assert ldif.endswith("\n"), "Output should end with newline separator"

        return ldif

    @staticmethod
    def test_write_entry_modify_format_complete(
        entry_quirk: FlextLdifServersBase.Entry,
        entry: FlextLdifModels.Entry,
        expected_operations: list[str] | None = None,  # ["add", "delete", "replace"]
        must_contain: list[str] | None = None,
        must_not_contain: list[str] | None = None,
    ) -> str:
        """Complete _write_entry_modify_format test - replaces entire test function.

        This method replaces 12-20 lines of duplicated test code:
        - Calls _write_entry_modify_format(entry)
        - Asserts success
        - Validates operations, must_contain, must_not_contain
        - Returns written LDIF string

        Args:
            entry_quirk: Entry quirk instance
            entry: Entry to write in modify format
            expected_operations: Optional list of expected operations
            must_contain: Optional list of strings that must appear
            must_not_contain: Optional list of strings that must NOT appear

        Returns:
            Written LDIF string

        Example:
            # Replaces entire test function:
            ldif = EntryTestHelpers.test_write_entry_modify_format_complete(
                entry_quirk,
                entry,
                expected_operations=["add", "delete"],
                must_contain=["changetype: modify", "add:", "delete:"],
                must_not_contain=["replace:"]
            )

        """
        result = entry_quirk._write_entry_modify_format(entry)
        ldif = TestAssertions.assert_success(result, "Modify format write should succeed")
        assert isinstance(ldif, str), "Write should return string"

        assert "changetype: modify" in ldif.lower(), (
            "Modify format should contain 'changetype: modify'"
        )

        if expected_operations:
            for op in expected_operations:
                assert f"{op.lower()}:" in ldif.lower(), (
                    f"Expected operation '{op}' not found in output"
                )

        if must_contain:
            for content in must_contain:
                assert content.lower() in ldif.lower(), (
                    f"Must contain '{content}' not found in LDIF"
                )

        if must_not_contain:
            for content in must_not_contain:
                assert content.lower() not in ldif.lower(), (
                    f"Must not contain '{content}' found in LDIF"
                )

        return ldif

    @staticmethod
    def test_parse_entry_complete(
        entry_quirk: FlextLdifServersBase.Entry,
        ldif_content: str,
        expected_entry_count: int = 1,
        expected_dn: str | None = None,
        expected_attributes: list[str] | None = None,
        should_succeed: bool = True,
        expected_error: str | None = None,
    ) -> list[FlextLdifModels.Entry] | None:
        """Complete entry parse test - replaces entire test function.

        This method replaces 10-20 lines of duplicated test code:
        - Calls parse(ldif_content)
        - Asserts success/failure
        - Validates entry count, DN, attributes
        - Returns parsed entries or None

        Args:
            entry_quirk: Entry quirk instance
            ldif_content: LDIF content string
            expected_entry_count: Expected number of entries (default: 1)
            expected_dn: Optional expected DN
            expected_attributes: Optional list of expected attribute names
            should_succeed: Whether parse should succeed (default: True)
            expected_error: Optional expected error substring if should fail

        Returns:
            List of parsed entries if success, None if failure

        Example:
            # Replaces entire test function:
            entries = EntryTestHelpers.test_parse_entry_complete(
                entry_quirk,
                "dn: cn=test,dc=example,dc=com\ncn: test\n",
                expected_entry_count=1,
                expected_dn="cn=test,dc=example,dc=com",
                expected_attributes=["cn"]
            )

        """
        result = entry_quirk.parse(ldif_content)

        if should_succeed:
            entries = TestAssertions.assert_parse_success(result, expected_entry_count)

            if expected_dn:
                assert entries[0].dn.value.lower() == expected_dn.lower(), (
                    f"Expected DN '{expected_dn}', got '{entries[0].dn.value}'"
                )

            if expected_attributes:
                for attr_name in expected_attributes:
                    assert entries[0].has_attribute(attr_name), (
                        f"Expected attribute '{attr_name}' not found"
                    )

            return entries
        else:
            TestAssertions.assert_failure(result, expected_error)
            return None

    @staticmethod
    def test_hook_pre_write_entry_complete(
        entry_quirk: FlextLdifServersBase.Entry,
        entry: FlextLdifModels.Entry,
        should_succeed: bool = True,
        expected_error: str | None = None,
        validate_modified_entry: bool = False,
    ) -> FlextLdifModels.Entry | None:
        """Complete hook_pre_write_entry test - replaces entire test function.

        This method replaces 10-18 lines of duplicated test code:
        - Calls _hook_pre_write_entry(entry)
        - Asserts success/failure
        - Optionally validates modified entry
        - Returns entry or None

        Args:
            entry_quirk: Entry quirk instance
            entry: Entry to test hook with
            should_succeed: Whether hook should succeed (default: True)
            expected_error: Optional expected error substring if should fail
            validate_modified_entry: Whether to validate returned entry (default: False)

        Returns:
            Entry if success, None if failure

        Example:
            # Replaces entire test function:
            result_entry = EntryTestHelpers.test_hook_pre_write_entry_complete(
                entry_quirk,
                entry,
                should_succeed=True,
                validate_modified_entry=True
            )

        """
        result = entry_quirk._hook_pre_write_entry(entry)

        if should_succeed:
            result_entry = TestAssertions.assert_success(result, "Hook should succeed")
            assert isinstance(result_entry, FlextLdifModels.Entry), (
                "Hook should return Entry"
            )
            if validate_modified_entry:
                TestAssertions.assert_entry_valid(result_entry)
            return result_entry
        else:
            TestAssertions.assert_failure(result, expected_error)
            return None

    @staticmethod
    def test_write_entry_with_format_options_complete(
        entry_quirk: FlextLdifServersBase.Entry,
        entry: FlextLdifModels.Entry,
        write_options: FlextLdifModels.WriteFormatOptions | None = None,
        expected_content: list[str] | None = None,
        must_contain: list[str] | None = None,
        must_not_contain: list[str] | None = None,
    ) -> str:
        """Complete write entry with format options test - replaces entire test function.

        This method replaces 15-25 lines of duplicated test code:
        - Creates entry with metadata containing write_options
        - Calls write(entry)
        - Validates output based on format options
        - Returns written LDIF string

        Args:
            entry_quirk: Entry quirk instance
            entry: Entry to write
            write_options: Optional WriteFormatOptions to apply
            expected_content: Optional list of strings that must appear
            must_contain: Optional list of strings that must appear
            must_not_contain: Optional list of strings that must NOT appear

        Returns:
            Written LDIF string

        Example:
            # Replaces entire test function:
            write_options = FlextLdifModels.WriteFormatOptions(
                add_comments=True,
                fold_lines=False
            )
            ldif = EntryTestHelpers.test_write_entry_with_format_options_complete(
                entry_quirk,
                entry,
                write_options=write_options,
                must_contain=["#"],
                must_not_contain=["changetype:"]
            )

        """
        # Add write_options to entry metadata if provided
        if write_options:
            if not entry.metadata:
                from flext_ldif.models import FlextLdifModels
                entry.metadata = FlextLdifModels.QuirkMetadata(
                    quirk_type="test",
                    extensions={},
                )
            if not entry.metadata.extensions:
                entry.metadata.extensions = {}
            entry.metadata.extensions["write_options"] = write_options

        result = entry_quirk.write(entry)
        ldif = TestAssertions.assert_write_success(result)

        if expected_content:
            for content in expected_content:
                assert content in ldif, f"Expected content '{content}' not found"

        if must_contain:
            for content in must_contain:
                assert content in ldif, f"Must contain '{content}' not found"

        if must_not_contain:
            for content in must_not_contain:
                assert content not in ldif, f"Must not contain '{content}' found"

        return ldif


__all__ = ["EntryTestHelpers"]
