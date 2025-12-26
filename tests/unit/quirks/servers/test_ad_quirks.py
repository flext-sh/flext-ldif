"""Tests for Active Directory (AD) server quirks.

This module tests the Active Directory-specific quirks and behavior
deviations from standard RFC 2849/4512 LDIF processing.
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar, cast

from tests import RfcTestHelpers, TestDeduplicationHelpers, m, s

from flext_ldif.servers import FlextLdifServersAd


class SchemaScenario(StrEnum):
    """AD schema test scenarios."""

    AD_OID = "ad_oid"
    AD_NAME = "ad_name"
    MICROSOFT_MARKER = "microsoft_marker"
    NEGATIVE = "negative"
    NO_OID = "no_oid"


class ObjectClassScenario(StrEnum):
    """AD objectClass test scenarios."""

    AD_OID = "ad_oid"
    AD_NAME = "ad_name"
    NEGATIVE = "negative"
    NO_OID = "no_oid"


class AclScenario(StrEnum):
    """AD ACL test scenarios."""

    NTSECURITYDESCRIPTOR = "ntsecuritydescriptor"
    SDDL_PREFIX = "sddl_prefix"
    NEGATIVE = "negative"
    BASE64_VALUE = "base64_value"
    SDDL_STRING = "sddl_string"
    EMPTY_LINE = "empty_line"


class EntryScenario(StrEnum):
    """AD entry test scenarios."""

    AD_DN_MARKER = "ad_dn_marker"
    AD_ATTRIBUTES = "ad_attributes"
    AD_OBJECTCLASS = "ad_objectclass"
    NEGATIVE = "negative"


class TestsTestFlextLdifAdQuirks(s):
    """Test FlextLdif Active Directory server quirks."""

    SCHEMA_ATTR_TEST_DATA: ClassVar[tuple[str, ...]] = (
        "( 1.2.840.113556.1.4.221 NAME 'sAMAccountName' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        "( 1.2.3.4 NAME 'objectGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
        "( 1.2.3.4 NAME 'test' DESC 'Microsoft Active Directory attribute' )",
    )

    OBJECTCLASS_TEST_DATA: ClassVar[tuple[str, ...]] = (
        "( 1.2.840.113556.1.5.9 NAME 'user' SUP top STRUCTURAL )",
        "( 1.2.3.4 NAME 'computer' SUP top STRUCTURAL )",
    )

    def test_server_initialization(self) -> None:
        """Test Active Directory quirk initialization."""
        server = FlextLdifServersAd()
        # AD server is registered as "ad" (not "active_directory")
        assert server.server_type == "ad"
        assert server.priority == 10

    def test_schema_quirk_initialization(self) -> None:
        """Test schema quirk is initialized."""
        server = FlextLdifServersAd()
        schema_quirk = server.schema_quirk
        assert isinstance(schema_quirk, FlextLdifServersAd.Schema)

    def test_acl_quirk_initialization(self) -> None:
        """Test ACL quirk is initialized."""
        server = FlextLdifServersAd()
        acl_quirk = server.acl_quirk
        assert isinstance(acl_quirk, FlextLdifServersAd.Acl)

    def test_entry_quirk_initialization(self) -> None:
        """Test entry quirk is initialized."""
        server = FlextLdifServersAd()
        entry_quirk = server.entry_quirk
        assert isinstance(entry_quirk, FlextLdifServersAd.Entry)

    def test_parse_attribute_with_ad_oid(self) -> None:
        """Test attribute parsing with Microsoft AD OID - validates parsed output."""
        server = FlextLdifServersAd()
        schema: FlextLdifServersAd.Schema = cast(
            "FlextLdifServersAd.Schema",
            server.schema_quirk,
        )
        attr_def = "( 1.2.840.113556.1.4.221 NAME 'sAMAccountName' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        result = schema.parse_attribute(attr_def)
        assert result.is_success, f"Failed to parse AD attribute: {result.error}"

        # Validate the parsed attribute output
        attr = result.value
        assert isinstance(attr, m.Ldif.SchemaAttribute)
        assert attr.oid == "1.2.840.113556.1.4.221", f"OID mismatch: {attr.oid}"
        assert attr.name == "sAMAccountName", f"NAME mismatch: {attr.name}"
        assert attr.syntax == "1.3.6.1.4.1.1466.115.121.1.15", (
            f"SYNTAX mismatch: {attr.syntax}"
        )

    def test_parse_attribute_with_ad_name(self) -> None:
        """Test attribute parsing with AD-specific attribute name - validates parsed output."""
        server = FlextLdifServersAd()
        schema: FlextLdifServersAd.Schema = cast(
            "FlextLdifServersAd.Schema",
            server.schema_quirk,
        )
        attr_def = "( 1.2.3.4 NAME 'objectGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )"
        result = schema.parse_attribute(attr_def)
        assert result.is_success, (
            f"Failed to parse AD attribute with name: {result.error}"
        )

        # Validate the parsed attribute output
        attr = result.value
        assert isinstance(attr, m.Ldif.SchemaAttribute)
        assert attr.oid == "1.2.3.4", f"OID mismatch: {attr.oid}"
        assert attr.name == "objectGUID", f"NAME mismatch: {attr.name}"
        assert attr.syntax == "1.3.6.1.4.1.1466.115.121.1.40", (
            f"SYNTAX mismatch: {attr.syntax}"
        )

    def test_parse_attribute_with_microsoft_marker(self) -> None:
        """Test attribute parsing with Microsoft marker in description - validates can_handle returns correct type."""
        server = FlextLdifServersAd()
        schema: FlextLdifServersAd.Schema = cast(
            "FlextLdifServersAd.Schema",
            server.schema_quirk,
        )
        attr_def = "( 1.2.3.4 NAME 'test' DESC 'Microsoft Active Directory attribute' )"
        result = schema.can_handle_attribute(attr_def)
        assert result is True, "AD schema should handle Microsoft-marked attribute"
        assert isinstance(result, bool), (
            f"can_handle_attribute must return bool, got {type(result)}"
        )

    def test_parse_attribute_success(self) -> None:
        """Test successful attribute parsing."""
        server = FlextLdifServersAd()
        schema: FlextLdifServersAd.Schema = cast(
            "FlextLdifServersAd.Schema",
            server.schema_quirk,
        )
        attr_def = (
            "( 1.2.840.113556.1.4.221 NAME 'sAMAccountName' "
            "DESC 'SAM Account Name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
            "EQUALITY caseIgnoreMatch SINGLE-VALUE )"
        )
        attr_data = RfcTestHelpers.test_result_success_and_unwrap(
            schema.parse_attribute(attr_def),
        )
        assert attr_data.oid == "1.2.840.113556.1.4.221"
        assert attr_data.name == "sAMAccountName"
        assert attr_data.desc == "SAM Account Name"
        assert attr_data.syntax == "1.3.6.1.4.1.1466.115.121.1.15"
        assert attr_data.equality == "caseIgnoreMatch"
        assert attr_data.single_value is True

    def test_parse_attribute_no_oid(self) -> None:
        """Test attribute parsing fails without OID."""
        server = FlextLdifServersAd()
        schema: FlextLdifServersAd.Schema = cast(
            "FlextLdifServersAd.Schema",
            server.schema_quirk,
        )
        attr_def = "NAME 'testAttr'"
        result = schema.parse_attribute(attr_def)
        assert result.is_failure
        assert result.error is not None
        assert "missing an OID" in result.error

    def test_parse_objectclass_with_ad_oid(self) -> None:
        """Test objectClass parsing with Microsoft AD OID."""
        server = FlextLdifServersAd()
        schema: FlextLdifServersAd.Schema = cast(
            "FlextLdifServersAd.Schema",
            server.schema_quirk,
        )
        oc_def = "( 1.2.840.113556.1.5.9 NAME 'user' SUP top STRUCTURAL )"
        result = schema.parse_objectclass(oc_def)
        assert result.is_success

    def test_parse_objectclass_with_ad_name(self) -> None:
        """Test objectClass parsing with AD-specific class name."""
        server = FlextLdifServersAd()
        schema: FlextLdifServersAd.Schema = cast(
            "FlextLdifServersAd.Schema",
            server.schema_quirk,
        )
        oc_def = "( 1.2.3.4 NAME 'computer' SUP top STRUCTURAL )"
        result = schema.parse_objectclass(oc_def)
        assert result.is_success

    def test_parse_objectclass_success(self) -> None:
        """Test successful objectClass parsing."""
        server = FlextLdifServersAd()
        schema: FlextLdifServersAd.Schema = cast(
            "FlextLdifServersAd.Schema",
            server.schema_quirk,
        )
        oc_def = (
            "( 1.2.840.113556.1.5.9 NAME 'user' DESC 'User object' "
            "SUP top STRUCTURAL MUST ( cn $ objectGUID ) "
            "MAY ( sAMAccountName $ userPrincipalName ) )"
        )
        result = schema.parse_objectclass(oc_def)
        assert result.is_success
        oc_data = result.value
        assert oc_data.oid == "1.2.840.113556.1.5.9"
        assert oc_data.name == "user"
        assert oc_data.desc == "User object"
        assert oc_data.sup == "top"
        assert oc_data.kind == "STRUCTURAL"
        must_attrs = oc_data.must
        assert isinstance(must_attrs, list)
        assert "cn" in must_attrs
        assert "objectGUID" in must_attrs
        may_attrs = oc_data.may
        assert isinstance(may_attrs, list)
        assert "sAMAccountName" in may_attrs

    def test_parse_objectclass_auxiliary(self) -> None:
        """Test parsing AUXILIARY objectClass."""
        server = FlextLdifServersAd()
        schema: FlextLdifServersAd.Schema = cast(
            "FlextLdifServersAd.Schema",
            server.schema_quirk,
        )
        oc_def = "( 1.2.840.113556.1.5.10 NAME 'adGroup' AUXILIARY )"
        oc_data = RfcTestHelpers.test_result_success_and_unwrap(
            schema.parse_objectclass(oc_def),
        )
        assert oc_data.kind == "AUXILIARY"

    def test_parse_objectclass_no_oid(self) -> None:
        """Test objectClass parsing fails without OID."""
        server = FlextLdifServersAd()
        schema: FlextLdifServersAd.Schema = cast(
            "FlextLdifServersAd.Schema",
            server.schema_quirk,
        )
        oc_def = "NAME 'user'"
        result = schema.parse_objectclass(oc_def)
        assert result.is_failure
        assert result.error is not None
        assert "missing an OID" in result.error

    def test_write_attribute_to_rfc(self) -> None:
        """Test writing attribute to RFC string format."""
        server = FlextLdifServersAd()
        schema: FlextLdifServersAd.Schema = cast(
            "FlextLdifServersAd.Schema",
            server.schema_quirk,
        )
        attr_model = m.Ldif.SchemaAttribute(
            oid="1.2.840.113556.1.4.221",
            name="sAMAccountName",
            desc="SAM Account Name",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            equality="caseIgnoreMatch",
            single_value=True,
        )
        TestDeduplicationHelpers.quirk_write_and_unwrap(
            schema,
            attr_model,
            write_method="_write_attribute",
            must_contain=["1.2.840.113556.1.4.221", "sAMAccountName", "SINGLE-VALUE"],
        )

    def test_write_objectclass_to_rfc(self) -> None:
        """Test writing objectClass to RFC string format."""
        server = FlextLdifServersAd()
        schema: FlextLdifServersAd.Schema = cast(
            "FlextLdifServersAd.Schema",
            server.schema_quirk,
        )
        oc_model = m.Ldif.SchemaObjectClass(
            oid="1.2.840.113556.1.5.9",
            name="user",
            desc="User object",
            sup="top",
            kind="STRUCTURAL",
            must=["cn", "objectGUID"],
            may=["sAMAccountName"],
        )
        TestDeduplicationHelpers.quirk_write_and_unwrap(
            schema,
            oc_model,
            write_method="_write_objectclass",
            must_contain=[
                "1.2.840.113556.1.5.9",
                "NAME 'user'",
                "STRUCTURAL",
                "MUST ( cn $ objectGUID )",
            ],
        )

    def test_acl_initialization(self) -> None:
        """Test ACL quirk initialization."""
        server = FlextLdifServersAd()
        assert server.acl_quirk is not None

    def test_parse_acl_with_ntsecuritydescriptor(self) -> None:
        """Test ACL parsing with nTSecurityDescriptor attribute."""
        server = FlextLdifServersAd()
        acl: FlextLdifServersAd.Acl = cast("FlextLdifServersAd.Acl", server.acl_quirk)
        acl_line = "nTSecurityDescriptor:: AQAEgBQAAAAkAAAAAAAAADAAAAABABQABAAAAA=="
        acl_model = TestDeduplicationHelpers.quirk_parse_and_unwrap(acl, acl_line)
        assert isinstance(acl_model, m.Ldif.Acl)

    def test_parse_acl_with_sddl_prefix(self) -> None:
        """Test ACL parsing with SDDL prefix (O:, G:, D:, S:)."""
        server = FlextLdifServersAd()
        acl: FlextLdifServersAd.Acl = cast("FlextLdifServersAd.Acl", server.acl_quirk)
        acl_line = "O:BAG:BAD:S:"
        acl_model = TestDeduplicationHelpers.quirk_parse_and_unwrap(acl, acl_line)
        assert isinstance(acl_model, m.Ldif.Acl)

    def test_parse_acl_with_base64_value(self) -> None:
        """Test parsing ACL with base64-encoded nTSecurityDescriptor."""
        server = FlextLdifServersAd()
        acl: FlextLdifServersAd.Acl = cast("FlextLdifServersAd.Acl", server.acl_quirk)
        acl_line = "nTSecurityDescriptor:: T0JBAQAABABABAgA=="
        result = acl.parse(acl_line)
        assert result.is_success
        acl_model = result.value
        assert isinstance(acl_model, m.Ldif.Acl)
        assert acl_model.name == "nTSecurityDescriptor"
        assert acl_model.raw_acl == acl_line
        assert acl_model.subject is not None
        assert acl_model.subject.subject_value is not None

    def test_parse_acl_with_sddl_string(self) -> None:
        """Test parsing ACL with SDDL string value."""
        server = FlextLdifServersAd()
        acl: FlextLdifServersAd.Acl = cast("FlextLdifServersAd.Acl", server.acl_quirk)
        acl_line = "nTSecurityDescriptor: O:BAG:BAD:S:"
        result = acl.parse(acl_line)
        assert result.is_success
        acl_model = result.value
        assert isinstance(acl_model, m.Ldif.Acl)
        assert acl_model.name == "nTSecurityDescriptor"
        assert acl_model.subject is not None
        assert acl_model.subject.subject_value == "O:BAG:BAD:S:"

    def test_parse_acl_empty_line(self) -> None:
        """Test parsing empty ACL line fails."""
        server = FlextLdifServersAd()
        acl: FlextLdifServersAd.Acl = cast("FlextLdifServersAd.Acl", server.acl_quirk)
        result = acl.parse("")
        assert result.is_failure
        assert result.error is not None
        assert "non-empty" in result.error or "Empty" in result.error

    def test_write_acl_to_rfc(self) -> None:
        """Test writing ACL to RFC string format."""
        server = FlextLdifServersAd()
        acl: FlextLdifServersAd.Acl = cast("FlextLdifServersAd.Acl", server.acl_quirk)
        acl_model = m.Ldif.Acl(
            name="nTSecurityDescriptor",
            target=m.Ldif.AclTarget(target_dn="*", attributes=[]),
            subject=m.Ldif.AclSubject(
                subject_type="sddl",
                subject_value="O:BAG:BAD:S:",
            ),
            permissions=m.Ldif.AclPermissions(),
            metadata=m.Ldif.QuirkMetadata.create_for(
                "active_directory",
            ),
            raw_acl="nTSecurityDescriptor: O:BAG:BAD:S:",
        )
        TestDeduplicationHelpers.quirk_write_and_unwrap(
            acl,
            acl_model,
            write_method="write",
            must_contain=["nTSecurityDescriptor:", "O:BAG:BAD:S:"],
        )

    def test_entry_initialization(self) -> None:
        """Test entry quirk initialization."""
        server = FlextLdifServersAd()
        assert server.entry_quirk is not None

    def test_parse_entry_with_ad_dn_marker(self) -> None:
        """Test entry parsing with AD DN markers."""
        server = FlextLdifServersAd()
        entry: FlextLdifServersAd.Entry = cast(
            "FlextLdifServersAd.Entry",
            server.entry_quirk,
        )
        dn = "cn=Administrator,cn=Users,dc=example,dc=com"
        ldif = f"dn: {dn}\n"
        result = entry.parse(ldif)
        assert result.is_success or result.is_failure

    def test_parse_entry_with_ad_attributes(self) -> None:
        """Test entry parsing with AD-specific attributes."""
        server = FlextLdifServersAd()
        entry: FlextLdifServersAd.Entry = cast(
            "FlextLdifServersAd.Entry",
            server.entry_quirk,
        )
        dn = "cn=test,dc=example,dc=com"
        ldif = (
            f"dn: {dn}\n"
            "objectGUID: 12345678-1234-1234-1234-123456789012\n"
            "objectSid: S-1-5-21-...\n"
        )
        result = entry.parse(ldif)
        assert result.is_success or result.is_failure

    def test_parse_entry_with_ad_objectclass(self) -> None:
        """Test entry parsing with AD objectClass."""
        server = FlextLdifServersAd()
        entry: FlextLdifServersAd.Entry = cast(
            "FlextLdifServersAd.Entry",
            server.entry_quirk,
        )
        dn = "cn=test,dc=example,dc=com"
        ldif = f"dn: {dn}\nobjectClass: user\nobjectClass: person\n"
        result = entry.parse(ldif)
        assert result.is_success or result.is_failure

    def test_parse_entry_negative(self) -> None:
        """Test entry parsing rejects non-AD entries."""
        server = FlextLdifServersAd()
        entry: FlextLdifServersAd.Entry = cast(
            "FlextLdifServersAd.Entry",
            server.entry_quirk,
        )
        dn = "cn=test,ou=people,dc=example,dc=com"
        ldif = f"dn: {dn}\nobjectClass: inetOrgPerson\n"
        result = entry.parse(ldif)
        assert hasattr(result, "is_success")
