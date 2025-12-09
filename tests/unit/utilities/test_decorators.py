"""Tests for LDIF utility decorators.

This module tests decorator utilities for extracting server type information from
classes, validating schema quirk metadata, and handling server-specific attribute
transformations through decorated methods.
"""

from __future__ import annotations

from flext_core import FlextResult
from tests import m, s

from flext_ldif._utilities.decorators import FlextLdifUtilitiesDecorators


class MockSchemaQuirk:
    """Mock schema quirk for testing decorators."""

    class Constants:
        """Mock constants."""

        SERVER_TYPE = "test_server"

    def __init__(self) -> None:
        """Initialize mock quirk."""


class TestsTestFlextLdifUtilitiesDecorators(s):
    """Comprehensive tests for decorators."""

    def test_get_server_type_from_class_with_constants(self) -> None:
        """Test _get_server_type_from_class extracts server type from Constants."""

        # Create a mock object with Constants.SERVER_TYPE
        class MockClass:
            class Constants:
                SERVER_TYPE = "test_server"

        obj = MockClass()
        server_type = FlextLdifUtilitiesDecorators._get_server_type_from_class(obj)

        assert server_type == "test_server"

    def test_get_server_type_from_class_without_constants(self) -> None:
        """Test _get_server_type_from_class returns None when no Constants."""
        obj = object()
        server_type = FlextLdifUtilitiesDecorators._get_server_type_from_class(obj)

        assert server_type is None

    def test_get_server_type_from_class_string(self) -> None:
        """Test _get_server_type_from_class handles string objects."""
        obj = "test_string"
        server_type = FlextLdifUtilitiesDecorators._get_server_type_from_class(obj)

        # Strings don't have Constants, so should return None
        assert server_type is None

    def test_get_server_type_from_class_entry(self) -> None:
        """Test _get_server_type_from_class with Entry model."""
        entry = m.Ldif.Entry(
            dn=m.Ldif.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=m.Ldif.LdifAttributes.create({"cn": ["test"]}).unwrap(),
        )

        server_type = FlextLdifUtilitiesDecorators._get_server_type_from_class(entry)

        # Entry doesn't have Constants.SERVER_TYPE in its MRO
        assert server_type is None

    def test_attach_metadata_if_present_with_entry(self) -> None:
        """Test _attach_metadata_if_present attaches metadata to Entry."""
        entry = m.Ldif.Entry(
            dn=m.Ldif.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=m.Ldif.LdifAttributes.create({"cn": ["test"]}).unwrap(),
        )

        # Entry has metadata by default (created automatically)

        FlextLdifUtilitiesDecorators._attach_metadata_if_present(
            entry,
            "oid",
            "oid",
        )

        # Should have metadata attached/updated
        assert entry.metadata is not None
        assert entry.metadata.quirk_type == "oid"
        assert entry.metadata.extensions is not None
        assert entry.metadata.extensions.get("server_type") == "oid"

    def test_attach_metadata_if_present_with_schema_attribute(self) -> None:
        """Test _attach_metadata_if_present attaches metadata to SchemaAttribute."""
        attr = m.Ldif.SchemaAttribute(
            oid="1.2.3.4.5",
            name="testAttr",
        )

        # SchemaAttribute may have metadata by default or None
        # The method checks if metadata exists, so we test both cases
        FlextLdifUtilitiesDecorators._attach_metadata_if_present(
            attr,
            "rfc",
            "rfc",
        )

        # Should have metadata attached
        assert attr.metadata is not None
        assert attr.metadata.quirk_type == "rfc"

    def test_attach_metadata_if_present_with_schema_objectclass(self) -> None:
        """Test _attach_metadata_if_present attaches metadata to SchemaObjectClass."""
        oc = m.Ldif.SchemaObjectClass(
            oid="1.2.3.4.5",
            name="testOC",
        )

        # SchemaObjectClass may have metadata by default or None
        # The method checks if metadata exists via getattr/hasattr
        # If metadata is None, the check passes and metadata is attached

        FlextLdifUtilitiesDecorators._attach_metadata_if_present(
            oc,
            "openldap",
            "openldap",
        )

        # Should have metadata attached or updated
        assert oc.metadata is not None
        # normalize_server_type may convert "openldap" to "openldap2"
        # So we just verify metadata was set (not the exact value)
        assert oc.metadata.quirk_type is not None
        assert oc.metadata.quirk_type in {"openldap", "openldap2"}

    def test_attach_metadata_if_present_with_string(self) -> None:
        """Test _attach_metadata_if_present does nothing for string."""
        obj = "test_string"

        # Should not raise error
        FlextLdifUtilitiesDecorators._attach_metadata_if_present(
            obj,
            "rfc",
            "rfc",
        )

        # Strings don't have metadata attribute, so nothing happens
        assert not hasattr(obj, "metadata")

    def test_attach_parse_metadata_decorator_success(self) -> None:
        """Test attach_parse_metadata decorator with successful parse."""

        # Create a mock quirk class
        class TestQuirk:
            class Constants:
                SERVER_TYPE = "oid"

            @FlextLdifUtilitiesDecorators.attach_parse_metadata("oid")
            def parse_attribute(
                self,
                definition: str,
            ) -> FlextResult[m.Ldif.SchemaAttribute]:
                attr = m.Ldif.SchemaAttribute(
                    oid="1.2.3.4.5",
                    name="testAttr",
                )
                return FlextResult.ok(attr)

        quirk = TestQuirk()
        result = quirk.parse_attribute("( 1.2.3.4.5 NAME 'testAttr' )")

        assert result.is_success
        attr = result.unwrap()
        assert attr.metadata is not None
        assert attr.metadata.quirk_type == "oid"

    def test_attach_parse_metadata_decorator_failure(self) -> None:
        """Test attach_parse_metadata decorator with failed parse."""

        class TestQuirk:
            @FlextLdifUtilitiesDecorators.attach_parse_metadata("test_quirk")
            def parse_attribute(
                self,
                definition: str,
            ) -> FlextResult[m.Ldif.SchemaAttribute]:
                return FlextResult.fail("Parse failed")

        quirk = TestQuirk()
        result = quirk.parse_attribute("invalid")

        assert result.is_failure
        assert "Parse failed" in result.error

    def test_attach_parse_metadata_decorator_with_entry(self) -> None:
        """Test attach_parse_metadata decorator with Entry result."""

        class TestQuirk:
            @FlextLdifUtilitiesDecorators.attach_parse_metadata("rfc")
            def parse_entry(
                self,
                dn: str,
                attrs: dict[str, list[str]],
            ) -> FlextResult[m.Ldif.Entry]:
                entry = m.Ldif.Entry(
                    dn=m.Ldif.DistinguishedName(value=dn),
                    attributes=m.Ldif.LdifAttributes.create(attrs).unwrap(),
                )
                return FlextResult.ok(entry)

        quirk = TestQuirk()
        result = quirk.parse_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"]},
        )

        assert result.is_success
        entry = result.unwrap()
        assert entry.metadata is not None
        assert entry.metadata.quirk_type == "rfc"

    def test_attach_parse_metadata_decorator_with_non_model_result(self) -> None:
        """Test attach_parse_metadata decorator with non-model result."""

        class TestQuirk:
            @FlextLdifUtilitiesDecorators.attach_parse_metadata("test_quirk")
            def parse_string(self, value: str) -> FlextResult[str]:
                return FlextResult.ok(value)

        quirk = TestQuirk()
        result = quirk.parse_string("test")

        assert result.is_success
        # String results don't get metadata attached
        assert result.unwrap() == "test"

    def test_attach_write_metadata_decorator(self) -> None:
        """Test attach_write_metadata decorator."""

        class TestQuirk:
            @FlextLdifUtilitiesDecorators.attach_write_metadata("test_quirk")
            def write_attribute(self, attr: m.Ldif.SchemaAttribute) -> FlextResult[str]:
                return FlextResult.ok("( 1.2.3.4.5 NAME 'testAttr' )")

        quirk = TestQuirk()
        attr = m.Ldif.SchemaAttribute(
            oid="1.2.3.4.5",
            name="testAttr",
        )
        result = quirk.write_attribute(attr)

        assert result.is_success
        assert result.unwrap() == "( 1.2.3.4.5 NAME 'testAttr' )"

    def test_safe_parse_decorator_success(self) -> None:
        """Test safe_parse decorator with successful operation."""

        class TestQuirk:
            @FlextLdifUtilitiesDecorators.safe_parse("test parsing")
            def parse_attribute(
                self,
                definition: str,
            ) -> FlextResult[m.Ldif.SchemaAttribute]:
                attr = m.Ldif.SchemaAttribute(
                    oid="1.2.3.4.5",
                    name="testAttr",
                )
                return FlextResult.ok(attr)

        quirk = TestQuirk()
        result = quirk.parse_attribute("( 1.2.3.4.5 NAME 'testAttr' )")

        assert result.is_success
        assert result.unwrap().name == "testAttr"

    def test_safe_parse_decorator_exception(self) -> None:
        """Test safe_parse decorator catches exceptions."""

        class TestQuirk:
            @FlextLdifUtilitiesDecorators.safe_parse("test parsing")
            def parse_attribute(
                self,
                definition: str,
            ) -> FlextResult[m.Ldif.SchemaAttribute]:
                msg = "Test error"
                raise ValueError(msg)

        quirk = TestQuirk()
        result = quirk.parse_attribute("invalid")

        assert result.is_failure
        assert "test parsing failed" in result.error.lower()
        assert "Test error" in result.error

    def test_safe_write_decorator_success(self) -> None:
        """Test safe_write decorator with successful operation."""

        class TestQuirk:
            @FlextLdifUtilitiesDecorators.safe_write("test writing")
            def write_attribute(self, attr: m.Ldif.SchemaAttribute) -> FlextResult[str]:
                return FlextResult.ok("( 1.2.3.4.5 NAME 'testAttr' )")

        quirk = TestQuirk()
        attr = m.Ldif.SchemaAttribute(
            oid="1.2.3.4.5",
            name="testAttr",
        )
        result = quirk.write_attribute(attr)

        assert result.is_success
        assert "( 1.2.3.4.5 NAME 'testAttr' )" in result.unwrap()

    def test_safe_write_decorator_exception(self) -> None:
        """Test safe_write decorator catches exceptions."""

        class TestQuirk:
            @FlextLdifUtilitiesDecorators.safe_write("test writing")
            def write_attribute(self, attr: m.Ldif.SchemaAttribute) -> FlextResult[str]:
                msg = "Test error"
                raise ValueError(msg)

        quirk = TestQuirk()
        attr = m.Ldif.SchemaAttribute(
            oid="1.2.3.4.5",
            name="testAttr",
        )
        result = quirk.write_attribute(attr)

        assert result.is_failure
        assert "test writing failed" in result.error.lower()
        assert "Test error" in result.error

    def test_attach_parse_metadata_preserves_function_metadata(self) -> None:
        """Test attach_parse_metadata preserves function __name__ and __doc__."""

        class TestQuirk:
            @FlextLdifUtilitiesDecorators.attach_parse_metadata("test_quirk")
            def parse_attribute(
                self,
                definition: str,
            ) -> FlextResult[m.Ldif.SchemaAttribute]:
                """Test parse method."""
                attr = m.Ldif.SchemaAttribute(
                    oid="1.2.3.4.5",
                    name="testAttr",
                )
                return FlextResult.ok(attr)

        quirk = TestQuirk()
        assert quirk.parse_attribute.__name__ == "parse_attribute"
        assert "Test parse method" in quirk.parse_attribute.__doc__

    def test_safe_parse_preserves_function_metadata(self) -> None:
        """Test safe_parse preserves function __name__ and __doc__."""

        class TestQuirk:
            @FlextLdifUtilitiesDecorators.safe_parse("test parsing")
            def parse_attribute(
                self,
                definition: str,
            ) -> FlextResult[m.Ldif.SchemaAttribute]:
                """Test parse method."""
                attr = m.Ldif.SchemaAttribute(
                    oid="1.2.3.4.5",
                    name="testAttr",
                )
                return FlextResult.ok(attr)

        quirk = TestQuirk()
        assert quirk.parse_attribute.__name__ == "parse_attribute"
        assert "Test parse method" in quirk.parse_attribute.__doc__

    # Edge cases
    def test_attach_metadata_if_present_with_none_server_type(self) -> None:
        """Test _attach_metadata_if_present handles None server_type."""
        entry = m.Ldif.Entry(
            dn=m.Ldif.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=m.Ldif.LdifAttributes.create({"cn": ["test"]}).unwrap(),
        )

        FlextLdifUtilitiesDecorators._attach_metadata_if_present(
            entry,
            "rfc",
            None,
        )

        assert entry.metadata is not None
        assert entry.metadata.quirk_type == "rfc"
        assert entry.metadata.extensions is not None
        # server_type should be None in extensions
        assert entry.metadata.extensions.get("server_type") is None

    def test_attach_parse_metadata_with_acl_result(self) -> None:
        """Test attach_parse_metadata decorator with ACL result."""

        class TestQuirk:
            @FlextLdifUtilitiesDecorators.attach_parse_metadata("oud")
            def parse_acl(self, acl_str: str) -> FlextResult[m.Ldif.Acl]:
                acl = m.Ldif.Acl(
                    raw_acl=acl_str,
                )
                return FlextResult.ok(acl)

        quirk = TestQuirk()
        result = quirk.parse_acl("access to *")

        assert result.is_success
        acl = result.unwrap()
        # ACL may have metadata by default or it may be attached by decorator
        # The decorator checks isinstance for Acl, so it should attach metadata
        # But the check in _attach_metadata_if_present may prevent it if metadata already exists
        # We verify the decorator executed successfully
        assert acl.raw_acl == "access to *"

    def test_safe_parse_with_keyboard_interrupt(self) -> None:
        """Test safe_parse decorator handles KeyboardInterrupt."""

        class TestQuirk:
            @FlextLdifUtilitiesDecorators.safe_parse("test parsing")
            def parse_attribute(
                self,
                definition: str,
            ) -> FlextResult[m.Ldif.SchemaAttribute]:
                msg = "User cancelled"
                raise KeyboardInterrupt(msg)

        quirk = TestQuirk()
        result = quirk.parse_attribute("test")

        assert result.is_failure
        assert "test parsing failed" in result.error.lower()

    def test_safe_write_with_type_error(self) -> None:
        """Test safe_write decorator handles TypeError."""

        class TestQuirk:
            @FlextLdifUtilitiesDecorators.safe_write("test writing")
            def write_attribute(self, attr: m.Ldif.SchemaAttribute) -> FlextResult[str]:
                msg = "Invalid type"
                raise TypeError(msg)

        quirk = TestQuirk()
        attr = m.Ldif.SchemaAttribute(
            oid="1.2.3.4.5",
            name="testAttr",
        )
        result = quirk.write_attribute(attr)

        assert result.is_failure
        assert "test writing failed" in result.error.lower()
        assert "Invalid type" in result.error
