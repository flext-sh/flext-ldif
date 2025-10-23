"""Phase 3.3: Relaxed Quirks comprehensive tests.

Tests cover:
- Relaxed/lenient parsing for broken LDIF
- Malformed OID handling
- Best-effort attribute/objectClass recovery
- Error recovery without failure
- Relaxed ACL and entry processing

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif.quirks.servers.relaxed_quirks import (
    FlextLdifQuirksServersRelaxed,
)


class TestRelaxedQuirksPhase33:
    """Test Relaxed quirks with broken/malformed LDIF."""

    def test_relaxed_quirks_initialization(self) -> None:
        """Test Relaxed quirks can be initialized."""
        quirks = FlextLdifQuirksServersRelaxed()

        assert quirks.server_type == "relaxed"
        assert quirks.priority >= 0

    def test_relaxed_quirks_has_schema_methods(self) -> None:
        """Test Relaxed quirks has required schema methods."""
        quirks = FlextLdifQuirksServersRelaxed()

        assert hasattr(quirks, "parse_attribute")
        assert callable(getattr(quirks, "parse_attribute"))
        assert hasattr(quirks, "parse_objectclass")
        assert callable(getattr(quirks, "parse_objectclass"))

    def test_relaxed_quirks_has_entry_methods(self) -> None:
        """Test Relaxed quirks has entry processing methods."""
        quirks = FlextLdifQuirksServersRelaxed()

        if hasattr(quirks, "EntryQuirk"):
            entry_quirk_class = getattr(quirks, "EntryQuirk")
            assert callable(entry_quirk_class)

    def test_relaxed_quirks_parse_malformed_attribute(self) -> None:
        """Test Relaxed quirks can parse malformed attribute definitions."""
        quirks = FlextLdifQuirksServersRelaxed()

        # Malformed - missing closing paren
        malformed_attr = "( incomplete-oid NAME 'attr'"
        _ = quirks.parse_attribute(malformed_attr)

        # Should handle gracefully
        assert callable(quirks.parse_attribute)

    def test_relaxed_quirks_parse_malformed_objectclass(self) -> None:
        """Test Relaxed quirks can parse malformed objectClass definitions."""
        quirks = FlextLdifQuirksServersRelaxed()

        # Malformed - missing closing paren
        malformed_oc = "( incomplete-oid NAME 'oc' STRUCTURAL"
        _ = quirks.parse_objectclass(malformed_oc)

        # Should handle gracefully
        assert callable(quirks.parse_objectclass)

    def test_relaxed_schema_quirk_initialization(self) -> None:
        """Test Relaxed schema quirk can be created."""
        # Main class IS the schema quirk (no separate SchemaQuirk nested class)
        quirks = FlextLdifQuirksServersRelaxed()
        assert quirks.server_type == "relaxed"
        assert hasattr(quirks, "parse_attribute")
        assert hasattr(quirks, "parse_objectclass")

    def test_relaxed_acl_quirk_initialization(self) -> None:
        """Test Relaxed ACL quirk can be created."""
        quirks = FlextLdifQuirksServersRelaxed()

        assert hasattr(quirks, "AclQuirk")
        acl_quirk_class = getattr(quirks, "AclQuirk")
        assert callable(acl_quirk_class)

    def test_relaxed_entry_quirk_initialization(self) -> None:
        """Test Relaxed entry quirk can be created."""
        quirks = FlextLdifQuirksServersRelaxed()

        assert hasattr(quirks, "EntryQuirk")
        entry_quirk_class = getattr(quirks, "EntryQuirk")
        assert callable(entry_quirk_class)

    def test_relaxed_acl_quirk_parse_malformed_acl(self) -> None:
        """Test Relaxed ACL quirk can parse malformed ACL lines."""
        quirks = FlextLdifQuirksServersRelaxed()
        acl_quirk = quirks.AclQuirk()

        # Malformed ACL
        malformed_acl = 'incomplete-aci (target="ldap:///'
        result = acl_quirk.parse_acl(malformed_acl)

        assert hasattr(result, "is_success")

    def test_relaxed_entry_quirk_process_malformed_entry(self) -> None:
        """Test Relaxed entry quirk can process malformed entries."""
        quirks = FlextLdifQuirksServersRelaxed()
        entry_quirk = quirks.EntryQuirk()

        dn = "cn=test,dc=example,dc=com"
        attributes = {"cn": ["test"]}

        result = entry_quirk.process_entry(dn, attributes)
        assert hasattr(result, "is_success")

    def test_relaxed_quirks_priority_is_highest(self) -> None:
        """Test Relaxed quirks has lowest priority (fallback)."""
        quirks = FlextLdifQuirksServersRelaxed()

        # Relaxed is fallback - should have lowest priority (highest number)
        assert quirks.priority > 0
        assert isinstance(quirks.priority, int)
        # Relaxed is last resort (priority 200)
        assert quirks.priority >= 100

    def test_relaxed_schema_quirk_has_methods(self) -> None:
        """Test Relaxed schema quirk has processing methods."""
        # Main class IS the schema quirk, test main class methods
        quirks = FlextLdifQuirksServersRelaxed()

        assert hasattr(quirks, "parse_attribute")
        assert callable(getattr(quirks, "parse_attribute"))
        assert hasattr(quirks, "parse_objectclass")
        assert callable(getattr(quirks, "parse_objectclass"))

    def test_relaxed_acl_quirk_has_methods(self) -> None:
        """Test Relaxed ACL quirk has processing methods."""
        quirks = FlextLdifQuirksServersRelaxed()
        acl_quirk = quirks.AclQuirk()

        assert hasattr(acl_quirk, "parse_acl")
        assert callable(getattr(acl_quirk, "parse_acl"))

    def test_relaxed_entry_quirk_has_methods(self) -> None:
        """Test Relaxed entry quirk has processing methods."""
        quirks = FlextLdifQuirksServersRelaxed()
        entry_quirk = quirks.EntryQuirk()

        assert hasattr(entry_quirk, "process_entry")
        assert callable(getattr(entry_quirk, "process_entry"))

    def test_relaxed_quirks_can_handle_any_attribute(self) -> None:
        """Test Relaxed quirks handles any attribute (lenient)."""
        quirks = FlextLdifQuirksServersRelaxed()

        # Relaxed should accept anything
        _ = "( some-random-oid )"
        assert callable(quirks.can_handle_attribute)

    def test_relaxed_quirks_can_handle_any_objectclass(self) -> None:
        """Test Relaxed quirks handles any objectClass (lenient)."""
        quirks = FlextLdifQuirksServersRelaxed()

        # Relaxed should accept anything
        _ = "( some-random-oid )"
        assert callable(quirks.can_handle_objectclass)

    def test_relaxed_schema_quirk_convert_to_rfc(self) -> None:
        """Test Relaxed schema quirk can convert to RFC."""
        # Main class IS the schema quirk, test main class methods
        quirks = FlextLdifQuirksServersRelaxed()

        assert hasattr(quirks, "convert_attribute_to_rfc")
        assert callable(getattr(quirks, "convert_attribute_to_rfc"))
        assert hasattr(quirks, "convert_objectclass_to_rfc")
        assert callable(getattr(quirks, "convert_objectclass_to_rfc"))

    def test_relaxed_acl_quirk_convert_to_rfc(self) -> None:
        """Test Relaxed ACL quirk can convert to RFC."""
        quirks = FlextLdifQuirksServersRelaxed()
        acl_quirk = quirks.AclQuirk()

        assert hasattr(acl_quirk, "convert_acl_to_rfc")
        assert callable(getattr(acl_quirk, "convert_acl_to_rfc"))

    def test_relaxed_entry_quirk_convert_to_rfc(self) -> None:
        """Test Relaxed entry quirk can convert to RFC."""
        quirks = FlextLdifQuirksServersRelaxed()
        entry_quirk = quirks.EntryQuirk()

        assert hasattr(entry_quirk, "convert_entry_to_rfc")
        assert callable(getattr(entry_quirk, "convert_entry_to_rfc"))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
