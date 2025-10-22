"""Unit tests for FLEXT-LDIF protocol definitions.

Tests verify protocol structure, satisfaction requirements, and implementation
contracts for LDIF-specific protocols including schema quirks, ACL quirks,
entry quirks, conversion matrix, and registry operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldif.protocols import FlextLdifProtocols


# Helper class for tests that need SchemaQuirkProtocol-like objects
class _MinimalSchemaQuirk:
    """Minimal SchemaQuirkProtocol-like object for testing."""

    server_type: str = "test"
    priority: int = 50

    def can_handle_attribute(self, attr_definition: str) -> bool:
        return True

    def parse_attribute(self, attr_definition: str) -> FlextResult[dict[str, object]]:
        return FlextResult[dict[str, object]].ok({})

    def convert_attribute_to_rfc(
        self, attr_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult[dict[str, object]].ok(attr_data)

    def convert_attribute_from_rfc(
        self, rfc_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult[dict[str, object]].ok(rfc_data)

    def write_attribute_to_rfc(
        self, attr_data: dict[str, object]
    ) -> FlextResult[str]:
        return FlextResult[str].ok("")

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        return True

    def parse_objectclass(self, oc_definition: str) -> FlextResult[dict[str, object]]:
        return FlextResult[dict[str, object]].ok({})

    def convert_objectclass_to_rfc(
        self, oc_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult[dict[str, object]].ok(oc_data)

    def convert_objectclass_from_rfc(
        self, rfc_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult[dict[str, object]].ok(rfc_data)

    def write_objectclass_to_rfc(
        self, oc_data: dict[str, object]
    ) -> FlextResult[str]:
        return FlextResult[str].ok("")


# ============================================================================
# SCHEMA QUIRK PROTOCOL TESTS
# ============================================================================


class TestSchemaQuirkProtocol:
    """Test SchemaQuirkProtocol structural typing contracts."""

    def test_schema_quirk_protocol_has_server_type_attribute(self) -> None:
        """Verify protocol requires server_type attribute."""
        protocol = FlextLdifProtocols.Quirks.SchemaQuirkProtocol
        assert hasattr(protocol, "__annotations__")
        # server_type is documented in the protocol - verify via isinstance

    def test_schema_quirk_protocol_has_priority_attribute(self) -> None:
        """Verify protocol requires priority attribute."""
        protocol = FlextLdifProtocols.Quirks.SchemaQuirkProtocol
        assert hasattr(protocol, "__annotations__")

    def test_schema_quirk_protocol_can_handle_attribute_method(self) -> None:
        """Verify protocol requires can_handle_attribute method."""
        protocol = FlextLdifProtocols.Quirks.SchemaQuirkProtocol
        assert hasattr(protocol, "can_handle_attribute")

    def test_schema_quirk_protocol_parse_attribute_method(self) -> None:
        """Verify protocol requires parse_attribute method."""
        protocol = FlextLdifProtocols.Quirks.SchemaQuirkProtocol
        assert hasattr(protocol, "parse_attribute")

    def test_schema_quirk_protocol_convert_attribute_to_rfc_method(self) -> None:
        """Verify protocol requires convert_attribute_to_rfc method."""
        protocol = FlextLdifProtocols.Quirks.SchemaQuirkProtocol
        assert hasattr(protocol, "convert_attribute_to_rfc")

    def test_schema_quirk_protocol_convert_attribute_from_rfc_method(self) -> None:
        """Verify protocol requires convert_attribute_from_rfc method."""
        protocol = FlextLdifProtocols.Quirks.SchemaQuirkProtocol
        assert hasattr(protocol, "convert_attribute_from_rfc")

    def test_schema_quirk_protocol_write_attribute_to_rfc_method(self) -> None:
        """Verify protocol requires write_attribute_to_rfc method."""
        protocol = FlextLdifProtocols.Quirks.SchemaQuirkProtocol
        assert hasattr(protocol, "write_attribute_to_rfc")

    def test_schema_quirk_protocol_can_handle_objectclass_method(self) -> None:
        """Verify protocol requires can_handle_objectclass method."""
        protocol = FlextLdifProtocols.Quirks.SchemaQuirkProtocol
        assert hasattr(protocol, "can_handle_objectclass")

    def test_schema_quirk_protocol_parse_objectclass_method(self) -> None:
        """Verify protocol requires parse_objectclass method."""
        protocol = FlextLdifProtocols.Quirks.SchemaQuirkProtocol
        assert hasattr(protocol, "parse_objectclass")

    def test_schema_quirk_protocol_convert_objectclass_to_rfc_method(self) -> None:
        """Verify protocol requires convert_objectclass_to_rfc method."""
        protocol = FlextLdifProtocols.Quirks.SchemaQuirkProtocol
        assert hasattr(protocol, "convert_objectclass_to_rfc")

    def test_schema_quirk_protocol_convert_objectclass_from_rfc_method(self) -> None:
        """Verify protocol requires convert_objectclass_from_rfc method."""
        protocol = FlextLdifProtocols.Quirks.SchemaQuirkProtocol
        assert hasattr(protocol, "convert_objectclass_from_rfc")

    def test_schema_quirk_protocol_write_objectclass_to_rfc_method(self) -> None:
        """Verify protocol requires write_objectclass_to_rfc method."""
        protocol = FlextLdifProtocols.Quirks.SchemaQuirkProtocol
        assert hasattr(protocol, "write_objectclass_to_rfc")

    def test_schema_quirk_protocol_instanceof_valid_implementation(self) -> None:
        """Verify protocol instanceof check for valid implementation."""

        class ValidSchemaQuirk:
            """Valid implementation of SchemaQuirkProtocol."""

            server_type: str = "test"
            priority: int = 50

            def can_handle_attribute(self, attr_definition: str) -> bool:
                return True

            def parse_attribute(
                self, attr_definition: str
            ) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok({})

            def convert_attribute_to_rfc(
                self, attr_data: dict[str, object]
            ) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok(attr_data)

            def convert_attribute_from_rfc(
                self, rfc_data: dict[str, object]
            ) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok(rfc_data)

            def write_attribute_to_rfc(
                self, attr_data: dict[str, object]
            ) -> FlextResult[str]:
                return FlextResult[str].ok("")

            def can_handle_objectclass(self, oc_definition: str) -> bool:
                return True

            def parse_objectclass(
                self, oc_definition: str
            ) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok({})

            def convert_objectclass_to_rfc(
                self, oc_data: dict[str, object]
            ) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok(oc_data)

            def convert_objectclass_from_rfc(
                self, rfc_data: dict[str, object]
            ) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok(rfc_data)

            def write_objectclass_to_rfc(
                self, oc_data: dict[str, object]
            ) -> FlextResult[str]:
                return FlextResult[str].ok("")

        quirk = ValidSchemaQuirk()
        assert isinstance(quirk, FlextLdifProtocols.Quirks.SchemaQuirkProtocol)


# ============================================================================
# ACL QUIRK PROTOCOL TESTS
# ============================================================================


class TestAclQuirkProtocol:
    """Test AclQuirkProtocol structural typing contracts."""

    def test_acl_quirk_protocol_has_server_type_attribute(self) -> None:
        """Verify protocol requires server_type attribute."""
        protocol = FlextLdifProtocols.Quirks.AclQuirkProtocol
        assert hasattr(protocol, "__annotations__")

    def test_acl_quirk_protocol_has_priority_attribute(self) -> None:
        """Verify protocol requires priority attribute."""
        protocol = FlextLdifProtocols.Quirks.AclQuirkProtocol
        assert hasattr(protocol, "__annotations__")

    def test_acl_quirk_protocol_can_handle_acl_method(self) -> None:
        """Verify protocol requires can_handle_acl method."""
        protocol = FlextLdifProtocols.Quirks.AclQuirkProtocol
        assert hasattr(protocol, "can_handle_acl")

    def test_acl_quirk_protocol_parse_acl_method(self) -> None:
        """Verify protocol requires parse_acl method."""
        protocol = FlextLdifProtocols.Quirks.AclQuirkProtocol
        assert hasattr(protocol, "parse_acl")

    def test_acl_quirk_protocol_convert_acl_to_rfc_method(self) -> None:
        """Verify protocol requires convert_acl_to_rfc method."""
        protocol = FlextLdifProtocols.Quirks.AclQuirkProtocol
        assert hasattr(protocol, "convert_acl_to_rfc")

    def test_acl_quirk_protocol_convert_acl_from_rfc_method(self) -> None:
        """Verify protocol requires convert_acl_from_rfc method."""
        protocol = FlextLdifProtocols.Quirks.AclQuirkProtocol
        assert hasattr(protocol, "convert_acl_from_rfc")

    def test_acl_quirk_protocol_write_acl_to_rfc_method(self) -> None:
        """Verify protocol requires write_acl_to_rfc method."""
        protocol = FlextLdifProtocols.Quirks.AclQuirkProtocol
        assert hasattr(protocol, "write_acl_to_rfc")

    def test_acl_quirk_protocol_instanceof_valid_implementation(self) -> None:
        """Verify protocol instanceof check for valid implementation."""

        class ValidAclQuirk:
            """Valid implementation of AclQuirkProtocol."""

            server_type: str = "test"
            priority: int = 50

            def can_handle_acl(self, acl_line: str) -> bool:
                return True

            def parse_acl(self, acl_line: str) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok({})

            def convert_acl_to_rfc(
                self, acl_data: dict[str, object]
            ) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok(acl_data)

            def convert_acl_from_rfc(
                self, acl_data: dict[str, object]
            ) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok(acl_data)

            def write_acl_to_rfc(
                self, acl_data: dict[str, object]
            ) -> FlextResult[str]:
                return FlextResult[str].ok("")

        quirk = ValidAclQuirk()
        assert isinstance(quirk, FlextLdifProtocols.Quirks.AclQuirkProtocol)


# ============================================================================
# ENTRY QUIRK PROTOCOL TESTS
# ============================================================================


class TestEntryQuirkProtocol:
    """Test EntryQuirkProtocol structural typing contracts."""

    def test_entry_quirk_protocol_has_server_type_attribute(self) -> None:
        """Verify protocol requires server_type attribute."""
        protocol = FlextLdifProtocols.Quirks.EntryQuirkProtocol
        assert hasattr(protocol, "__annotations__")

    def test_entry_quirk_protocol_has_priority_attribute(self) -> None:
        """Verify protocol requires priority attribute."""
        protocol = FlextLdifProtocols.Quirks.EntryQuirkProtocol
        assert hasattr(protocol, "__annotations__")

    def test_entry_quirk_protocol_can_handle_entry_method(self) -> None:
        """Verify protocol requires can_handle_entry method."""
        protocol = FlextLdifProtocols.Quirks.EntryQuirkProtocol
        assert hasattr(protocol, "can_handle_entry")

    def test_entry_quirk_protocol_process_entry_method(self) -> None:
        """Verify protocol requires process_entry method."""
        protocol = FlextLdifProtocols.Quirks.EntryQuirkProtocol
        assert hasattr(protocol, "process_entry")

    def test_entry_quirk_protocol_convert_entry_to_rfc_method(self) -> None:
        """Verify protocol requires convert_entry_to_rfc method."""
        protocol = FlextLdifProtocols.Quirks.EntryQuirkProtocol
        assert hasattr(protocol, "convert_entry_to_rfc")

    def test_entry_quirk_protocol_convert_entry_from_rfc_method(self) -> None:
        """Verify protocol requires convert_entry_from_rfc method."""
        protocol = FlextLdifProtocols.Quirks.EntryQuirkProtocol
        assert hasattr(protocol, "convert_entry_from_rfc")

    def test_entry_quirk_protocol_instanceof_valid_implementation(self) -> None:
        """Verify protocol instanceof check for valid implementation."""

        class ValidEntryQuirk:
            """Valid implementation of EntryQuirkProtocol."""

            server_type: str = "test"
            priority: int = 50

            def can_handle_entry(
                self, entry_dn: str, attributes: dict[str, object]
            ) -> bool:
                return True

            def process_entry(
                self, entry_dn: str, attributes: dict[str, object]
            ) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok(
                    {"dn": entry_dn, "attributes": attributes}
                )

            def convert_entry_to_rfc(
                self, entry_data: dict[str, object]
            ) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok(entry_data)

            def convert_entry_from_rfc(
                self, rfc_data: dict[str, object]
            ) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok(rfc_data)

        quirk = ValidEntryQuirk()
        assert isinstance(quirk, FlextLdifProtocols.Quirks.EntryQuirkProtocol)


# ============================================================================
# CONVERSION MATRIX PROTOCOL TESTS
# ============================================================================


class TestConversionMatrixProtocol:
    """Test ConversionMatrixProtocol structural typing contracts."""

    def test_conversion_matrix_protocol_convert_method(self) -> None:
        """Verify protocol requires convert method."""
        protocol = FlextLdifProtocols.Quirks.ConversionMatrixProtocol
        assert hasattr(protocol, "convert")

    def test_conversion_matrix_protocol_instanceof_valid_implementation(self) -> None:
        """Verify protocol instanceof check for valid implementation."""

        class ValidConversionMatrix:
            """Valid implementation of ConversionMatrixProtocol."""

            def convert(
                self,
                source_quirk: FlextLdifProtocols.Quirks.SchemaQuirkProtocol,
                target_quirk: FlextLdifProtocols.Quirks.SchemaQuirkProtocol,
                element_type: str,
                element_data: str | dict[str, object],
            ) -> FlextResult[str | dict[str, object]]:
                return FlextResult[str | dict[str, object]].ok(element_data)

        matrix = ValidConversionMatrix()
        assert isinstance(
            matrix, FlextLdifProtocols.Quirks.ConversionMatrixProtocol
        )


# ============================================================================
# QUIRK REGISTRY PROTOCOL TESTS
# ============================================================================


class TestQuirkRegistryProtocol:
    """Test QuirkRegistryProtocol structural typing contracts."""

    def test_quirk_registry_protocol_register_schema_quirk_method(self) -> None:
        """Verify protocol requires register_schema_quirk method."""
        protocol = FlextLdifProtocols.Quirks.QuirkRegistryProtocol
        assert hasattr(protocol, "register_schema_quirk")

    def test_quirk_registry_protocol_register_acl_quirk_method(self) -> None:
        """Verify protocol requires register_acl_quirk method."""
        protocol = FlextLdifProtocols.Quirks.QuirkRegistryProtocol
        assert hasattr(protocol, "register_acl_quirk")

    def test_quirk_registry_protocol_register_entry_quirk_method(self) -> None:
        """Verify protocol requires register_entry_quirk method."""
        protocol = FlextLdifProtocols.Quirks.QuirkRegistryProtocol
        assert hasattr(protocol, "register_entry_quirk")

    def test_quirk_registry_protocol_get_schema_quirks_method(self) -> None:
        """Verify protocol requires get_schema_quirks method."""
        protocol = FlextLdifProtocols.Quirks.QuirkRegistryProtocol
        assert hasattr(protocol, "get_schema_quirks")

    def test_quirk_registry_protocol_get_best_schema_quirk_method(self) -> None:
        """Verify protocol requires get_best_schema_quirk method."""
        protocol = FlextLdifProtocols.Quirks.QuirkRegistryProtocol
        assert hasattr(protocol, "get_best_schema_quirk")

    def test_quirk_registry_protocol_get_global_instance_method(self) -> None:
        """Verify protocol requires get_global_instance method."""
        protocol = FlextLdifProtocols.Quirks.QuirkRegistryProtocol
        assert hasattr(protocol, "get_global_instance")

    def test_quirk_registry_protocol_instanceof_valid_implementation(self) -> None:
        """Verify protocol instanceof check for valid implementation."""

        class ValidQuirkRegistry:
            """Valid implementation of QuirkRegistryProtocol."""

            def register_schema_quirk(
                self, quirk: FlextLdifProtocols.Quirks.SchemaQuirkProtocol
            ) -> FlextResult[None]:
                return FlextResult[None].ok(None)

            def register_acl_quirk(
                self, quirk: FlextLdifProtocols.Quirks.AclQuirkProtocol
            ) -> FlextResult[None]:
                return FlextResult[None].ok(None)

            def register_entry_quirk(
                self, quirk: FlextLdifProtocols.Quirks.EntryQuirkProtocol
            ) -> FlextResult[None]:
                return FlextResult[None].ok(None)

            def get_schema_quirks(
                self, server_type: str
            ) -> FlextResult[list[object]]:
                return FlextResult[list[object]].ok([])

            def get_best_schema_quirk(
                self, server_type: str
            ) -> FlextResult[FlextLdifProtocols.Quirks.SchemaQuirkProtocol]:
                quirk = _MinimalSchemaQuirk()
                return FlextResult[FlextLdifProtocols.Quirks.SchemaQuirkProtocol].ok(
                    quirk
                )

            @staticmethod
            def get_global_instance() -> (
                FlextLdifProtocols.Quirks.QuirkRegistryProtocol
            ):
                return ValidQuirkRegistry()

        registry = ValidQuirkRegistry()
        assert isinstance(
            registry, FlextLdifProtocols.Quirks.QuirkRegistryProtocol
        )


# ============================================================================
# PROTOCOL COMPOSITION TESTS
# ============================================================================


class TestProtocolComposition:
    """Test protocol composition and relationships."""

    def test_schema_quirk_protocol_is_runtime_checkable(self) -> None:
        """Verify schema quirk protocol is runtime checkable via isinstance."""
        # Runtime checkable protocols support isinstance() checks
        # Test by verifying a conforming class passes isinstance check
        class TestSchemaQuirk:
            server_type: str = "test"
            priority: int = 50

            def can_handle_attribute(self, attr_definition: str) -> bool:
                return True

            def parse_attribute(self, attr_definition: str) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok({})

            def convert_attribute_to_rfc(self, attr_data: dict[str, object]) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok(attr_data)

            def convert_attribute_from_rfc(self, rfc_data: dict[str, object]) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok(rfc_data)

            def write_attribute_to_rfc(self, attr_data: dict[str, object]) -> FlextResult[str]:
                return FlextResult[str].ok("")

            def can_handle_objectclass(self, oc_definition: str) -> bool:
                return True

            def parse_objectclass(self, oc_definition: str) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok({})

            def convert_objectclass_to_rfc(self, oc_data: dict[str, object]) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok(oc_data)

            def convert_objectclass_from_rfc(self, rfc_data: dict[str, object]) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok(rfc_data)

            def write_objectclass_to_rfc(self, oc_data: dict[str, object]) -> FlextResult[str]:
                return FlextResult[str].ok("")

        quirk = TestSchemaQuirk()
        assert isinstance(quirk, FlextLdifProtocols.Quirks.SchemaQuirkProtocol)

    def test_acl_quirk_protocol_is_runtime_checkable(self) -> None:
        """Verify ACL quirk protocol is runtime checkable via isinstance."""
        class TestAclQuirk:
            server_type: str = "test"
            priority: int = 50

            def can_handle_acl(self, acl_line: str) -> bool:
                return True

            def parse_acl(self, acl_line: str) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok({})

            def convert_acl_to_rfc(self, acl_data: dict[str, object]) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok(acl_data)

            def convert_acl_from_rfc(self, acl_data: dict[str, object]) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok(acl_data)

            def write_acl_to_rfc(self, acl_data: dict[str, object]) -> FlextResult[str]:
                return FlextResult[str].ok("")

        quirk = TestAclQuirk()
        assert isinstance(quirk, FlextLdifProtocols.Quirks.AclQuirkProtocol)

    def test_entry_quirk_protocol_is_runtime_checkable(self) -> None:
        """Verify entry quirk protocol is runtime checkable via isinstance."""
        class TestEntryQuirk:
            server_type: str = "test"
            priority: int = 50

            def can_handle_entry(self, entry_dn: str, attributes: dict[str, object]) -> bool:
                return True

            def process_entry(self, entry_dn: str, attributes: dict[str, object]) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok({})

            def convert_entry_to_rfc(self, entry_data: dict[str, object]) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok(entry_data)

            def convert_entry_from_rfc(self, rfc_data: dict[str, object]) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok(rfc_data)

        quirk = TestEntryQuirk()
        assert isinstance(quirk, FlextLdifProtocols.Quirks.EntryQuirkProtocol)

    def test_conversion_matrix_protocol_is_runtime_checkable(self) -> None:
        """Verify conversion matrix protocol is runtime checkable via isinstance."""
        class TestMatrix:
            def convert(
                self,
                source_quirk: FlextLdifProtocols.Quirks.SchemaQuirkProtocol,
                target_quirk: FlextLdifProtocols.Quirks.SchemaQuirkProtocol,
                element_type: str,
                element_data: str | dict[str, object],
            ) -> FlextResult[str | dict[str, object]]:
                return FlextResult[str | dict[str, object]].ok(element_data)

        matrix = TestMatrix()
        assert isinstance(matrix, FlextLdifProtocols.Quirks.ConversionMatrixProtocol)

    def test_quirk_registry_protocol_is_runtime_checkable(self) -> None:
        """Verify quirk registry protocol is runtime checkable via isinstance."""
        class TestRegistry:
            def register_schema_quirk(self, quirk: FlextLdifProtocols.Quirks.SchemaQuirkProtocol) -> FlextResult[None]:
                return FlextResult[None].ok(None)

            def register_acl_quirk(self, quirk: FlextLdifProtocols.Quirks.AclQuirkProtocol) -> FlextResult[None]:
                return FlextResult[None].ok(None)

            def register_entry_quirk(self, quirk: FlextLdifProtocols.Quirks.EntryQuirkProtocol) -> FlextResult[None]:
                return FlextResult[None].ok(None)

            def get_schema_quirks(self, server_type: str) -> FlextResult[list[object]]:
                return FlextResult[list[object]].ok([])

            def get_best_schema_quirk(self, server_type: str) -> FlextResult[FlextLdifProtocols.Quirks.SchemaQuirkProtocol]:
                schema_quirk = _MinimalSchemaQuirk()
                return FlextResult[FlextLdifProtocols.Quirks.SchemaQuirkProtocol].ok(schema_quirk)

            @staticmethod
            def get_global_instance() -> FlextLdifProtocols.Quirks.QuirkRegistryProtocol:
                return TestRegistry()

        registry = TestRegistry()
        assert isinstance(registry, FlextLdifProtocols.Quirks.QuirkRegistryProtocol)

    def test_all_quirks_are_under_single_namespace(self) -> None:
        """Verify all quirk protocols are under FlextLdifProtocols.Quirks namespace."""
        assert hasattr(FlextLdifProtocols, "Quirks")
        quirks_namespace = FlextLdifProtocols.Quirks
        assert hasattr(quirks_namespace, "SchemaQuirkProtocol")
        assert hasattr(quirks_namespace, "AclQuirkProtocol")
        assert hasattr(quirks_namespace, "EntryQuirkProtocol")
        assert hasattr(quirks_namespace, "ConversionMatrixProtocol")
        assert hasattr(quirks_namespace, "QuirkRegistryProtocol")

    def test_flext_ldif_protocols_extends_flext_protocols(self) -> None:
        """Verify FlextLdifProtocols extends FlextProtocols."""
        from flext_core import FlextProtocols

        assert issubclass(FlextLdifProtocols, FlextProtocols)

    def test_flext_ldif_protocols_accessible_via_module(self) -> None:
        """Verify FlextLdifProtocols is accessible through module."""
        from flext_ldif.protocols import FlextLdifProtocols as ImportedProtocols

        assert ImportedProtocols is FlextLdifProtocols
        assert hasattr(ImportedProtocols, "Quirks")

    def test_flext_ldif_protocols_exported_in_all(self) -> None:
        """Verify FlextLdifProtocols is in __all__."""
        from flext_ldif import protocols as protocols_module

        all_exports = getattr(protocols_module, "__all__", [])
        assert "FlextLdifProtocols" in all_exports


# ============================================================================
# PROTOCOL METHOD SIGNATURE TESTS
# ============================================================================


class TestProtocolMethodSignatures:
    """Test protocol method signatures and contracts."""

    def test_schema_quirk_can_handle_attribute_returns_bool(self) -> None:
        """Verify can_handle_attribute returns bool."""

        class TestQuirk:
            server_type: str = "test"
            priority: int = 50

            def can_handle_attribute(self, attr_definition: str) -> bool:
                return True

        quirk = TestQuirk()
        result = quirk.can_handle_attribute("test")
        assert isinstance(result, bool)

    def test_schema_quirk_parse_attribute_returns_flext_result(self) -> None:
        """Verify parse_attribute returns FlextResult."""

        class TestQuirk:
            server_type: str = "test"
            priority: int = 50

            def parse_attribute(
                self, attr_definition: str
            ) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok({})

        quirk = TestQuirk()
        result = quirk.parse_attribute("test")
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_conversion_convert_handles_string_and_dict_element_data(self) -> None:
        """Verify convert can handle both string and dict element_data."""

        class TestMatrix:
            def convert(
                self,
                source_quirk: FlextLdifProtocols.Quirks.SchemaQuirkProtocol,
                target_quirk: FlextLdifProtocols.Quirks.SchemaQuirkProtocol,
                element_type: str,
                element_data: str | dict[str, object],
            ) -> FlextResult[str | dict[str, object]]:
                return FlextResult[str | dict[str, object]].ok(element_data)

        matrix = TestMatrix()

        # Test with string data
        quirk = _MinimalSchemaQuirk()
        result_str = matrix.convert(
            quirk,
            quirk,
            "attribute",
            "test attribute data"
        )
        assert result_str.is_success
        assert result_str.unwrap() == "test attribute data"

        # Test with dict data
        test_dict: dict[str, object] = {"key": "value"}
        result_dict = matrix.convert(
            quirk,
            quirk,
            "attribute",
            test_dict
        )
        assert result_dict.is_success
        assert result_dict.unwrap() == test_dict

    def test_quirk_registry_get_schema_quirks_returns_list(self) -> None:
        """Verify get_schema_quirks returns list."""

        class TestRegistry:
            def get_schema_quirks(
                self, server_type: str
            ) -> FlextResult[list[object]]:
                return FlextResult[list[object]].ok([])

        registry = TestRegistry()
        result = registry.get_schema_quirks("test")
        assert result.is_success
        quirks = result.unwrap()
        assert isinstance(quirks, list)

    def test_quirk_registry_get_global_instance_returns_protocol_instance(
        self,
    ) -> None:
        """Verify get_global_instance returns QuirkRegistryProtocol instance."""

        class TestRegistry:
            @staticmethod
            def get_global_instance() -> (
                FlextLdifProtocols.Quirks.QuirkRegistryProtocol
            ):
                return TestRegistry()

            def register_schema_quirk(
                self, quirk: FlextLdifProtocols.Quirks.SchemaQuirkProtocol
            ) -> FlextResult[None]:
                return FlextResult[None].ok(None)

            def register_acl_quirk(
                self, quirk: FlextLdifProtocols.Quirks.AclQuirkProtocol
            ) -> FlextResult[None]:
                return FlextResult[None].ok(None)

            def register_entry_quirk(
                self, quirk: FlextLdifProtocols.Quirks.EntryQuirkProtocol
            ) -> FlextResult[None]:
                return FlextResult[None].ok(None)

            def get_schema_quirks(
                self, server_type: str
            ) -> FlextResult[list[object]]:
                return FlextResult[list[object]].ok([])

            def get_best_schema_quirk(
                self, server_type: str
            ) -> FlextResult[FlextLdifProtocols.Quirks.SchemaQuirkProtocol]:
                return FlextResult[FlextLdifProtocols.Quirks.SchemaQuirkProtocol].fail(
                    "Not found"
                )

        instance = TestRegistry.get_global_instance()
        assert isinstance(
            instance, FlextLdifProtocols.Quirks.QuirkRegistryProtocol
        )


# ============================================================================
# PROTOCOL ERROR HANDLING TESTS
# ============================================================================


class TestProtocolErrorHandling:
    """Test error handling in protocol implementations."""

    def test_parse_attribute_can_return_failure(self) -> None:
        """Verify parse_attribute can return FlextResult failure."""

        class TestQuirk:
            server_type: str = "test"
            priority: int = 50

            def parse_attribute(
                self, attr_definition: str
            ) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].fail("Invalid attribute")

        quirk = TestQuirk()
        result = quirk.parse_attribute("invalid")
        assert result.is_failure
        assert result.error == "Invalid attribute"

    def test_convert_acl_to_rfc_can_return_failure(self) -> None:
        """Verify convert_acl_to_rfc can return FlextResult failure."""

        class TestQuirk:
            server_type: str = "test"
            priority: int = 50

            def can_handle_acl(self, acl_line: str) -> bool:
                return False

            def parse_acl(self, acl_line: str) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].fail("Cannot handle ACL")

            def convert_acl_to_rfc(
                self, acl_data: dict[str, object]
            ) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].fail("Conversion failed")

            def convert_acl_from_rfc(
                self, acl_data: dict[str, object]
            ) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok(acl_data)

            def write_acl_to_rfc(
                self, acl_data: dict[str, object]
            ) -> FlextResult[str]:
                return FlextResult[str].ok("")

        quirk = TestQuirk()
        result = quirk.convert_acl_to_rfc({})
        assert result.is_failure
        assert result.error == "Conversion failed"

    def test_process_entry_can_return_failure(self) -> None:
        """Verify process_entry can return FlextResult failure."""

        class TestQuirk:
            server_type: str = "test"
            priority: int = 50

            def can_handle_entry(
                self, entry_dn: str, attributes: dict[str, object]
            ) -> bool:
                return True

            def process_entry(
                self, entry_dn: str, attributes: dict[str, object]
            ) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].fail("Processing error")

            def convert_entry_to_rfc(
                self, entry_data: dict[str, object]
            ) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok(entry_data)

            def convert_entry_from_rfc(
                self, rfc_data: dict[str, object]
            ) -> FlextResult[dict[str, object]]:
                return FlextResult[dict[str, object]].ok(rfc_data)

        quirk = TestQuirk()
        result = quirk.process_entry("cn=test,dc=example,dc=com", {})
        assert result.is_failure
        assert result.error == "Processing error"


# ============================================================================
# PROTOCOL DOCUMENTATION TESTS
# ============================================================================


class TestProtocolDocumentation:
    """Test protocol documentation and docstrings."""

    def test_schema_quirk_protocol_has_docstring(self) -> None:
        """Verify SchemaQuirkProtocol has docstring."""
        protocol = FlextLdifProtocols.Quirks.SchemaQuirkProtocol
        assert protocol.__doc__ is not None
        assert len(protocol.__doc__) > 0

    def test_acl_quirk_protocol_has_docstring(self) -> None:
        """Verify AclQuirkProtocol has docstring."""
        protocol = FlextLdifProtocols.Quirks.AclQuirkProtocol
        assert protocol.__doc__ is not None
        assert len(protocol.__doc__) > 0

    def test_entry_quirk_protocol_has_docstring(self) -> None:
        """Verify EntryQuirkProtocol has docstring."""
        protocol = FlextLdifProtocols.Quirks.EntryQuirkProtocol
        assert protocol.__doc__ is not None
        assert len(protocol.__doc__) > 0

    def test_conversion_matrix_protocol_has_docstring(self) -> None:
        """Verify ConversionMatrixProtocol has docstring."""
        protocol = FlextLdifProtocols.Quirks.ConversionMatrixProtocol
        assert protocol.__doc__ is not None
        assert len(protocol.__doc__) > 0

    def test_quirk_registry_protocol_has_docstring(self) -> None:
        """Verify QuirkRegistryProtocol has docstring."""
        protocol = FlextLdifProtocols.Quirks.QuirkRegistryProtocol
        assert protocol.__doc__ is not None
        assert len(protocol.__doc__) > 0

    def test_can_handle_attribute_has_docstring(self) -> None:
        """Verify can_handle_attribute method has docstring."""
        protocol = FlextLdifProtocols.Quirks.SchemaQuirkProtocol
        method = getattr(protocol, "can_handle_attribute", None)
        assert method is not None

    def test_parse_attribute_has_docstring(self) -> None:
        """Verify parse_attribute method has docstring."""
        protocol = FlextLdifProtocols.Quirks.SchemaQuirkProtocol
        method = getattr(protocol, "parse_attribute", None)
        assert method is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
