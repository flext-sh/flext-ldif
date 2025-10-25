"""Tests for Active Directory quirks implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.servers.ad_quirks import FlextLdifQuirksServersAd


class TestActiveDirectorySchemaQuirks:
    """Tests for Active Directory schema quirk handling."""

    def test_initialization(self) -> None:
        """Test Active Directory quirk initialization."""
        quirk = FlextLdifQuirksServersAd()

        assert quirk.server_type == "active_directory"
        assert quirk.priority == 15

    def test_can_handle_attribute_with_ad_oid(self) -> None:
        """Test attribute detection with Microsoft AD OID."""
        quirk = FlextLdifQuirksServersAd()

        # Microsoft-owned OID namespace
        attr_def = "( 1.2.840.113556.1.4.221 NAME 'sAMAccountName' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        assert quirk.can_handle_attribute(attr_def) is True

    def test_can_handle_attribute_with_ad_name(self) -> None:
        """Test attribute detection with AD-specific attribute name."""
        quirk = FlextLdifQuirksServersAd()

        attr_def = "( 1.2.3.4 NAME 'objectGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )"
        assert quirk.can_handle_attribute(attr_def) is True

    def test_can_handle_attribute_with_microsoft_marker(self) -> None:
        """Test attribute detection with Microsoft marker in description."""
        quirk = FlextLdifQuirksServersAd()

        attr_def = "( 1.2.3.4 NAME 'test' DESC 'Microsoft Active Directory attribute' )"
        assert quirk.can_handle_attribute(attr_def) is True

    def test_can_handle_attribute_negative(self) -> None:
        """Test attribute detection rejects non-AD attributes."""
        quirk = FlextLdifQuirksServersAd()

        attr_def = "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        assert quirk.can_handle_attribute(attr_def) is False

    def test_parse_attribute_success(self) -> None:
        """Test successful attribute parsing."""
        quirk = FlextLdifQuirksServersAd()

        attr_def = (
            "( 1.2.840.113556.1.4.221 NAME 'sAMAccountName' "
            "DESC 'SAM Account Name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
            "EQUALITY caseIgnoreMatch SINGLE-VALUE )"
        )
        result = quirk.parse_attribute(attr_def)

        assert result.is_success
        attr_data = result.unwrap()
        assert attr_data.oid == "1.2.840.113556.1.4.221"
        assert attr_data.name == "sAMAccountName"
        assert attr_data.desc == "SAM Account Name"
        assert attr_data.syntax == "1.3.6.1.4.1.1466.115.121.1.15"
        assert attr_data.equality == "caseIgnoreMatch"
        assert attr_data.single_value is True

    def test_parse_attribute_no_oid(self) -> None:
        """Test attribute parsing fails without OID."""
        quirk = FlextLdifQuirksServersAd()

        attr_def = "NAME 'testAttr'"
        result = quirk.parse_attribute(attr_def)

        assert result.is_failure
        assert result.error is not None
        assert result.error is not None
        assert "missing an OID" in result.error

    def test_can_handle_objectclass_with_ad_oid(self) -> None:
        """Test objectClass detection with Microsoft AD OID."""
        quirk = FlextLdifQuirksServersAd()

        oc_def = "( 1.2.840.113556.1.5.9 NAME 'user' SUP top STRUCTURAL )"
        assert quirk.can_handle_objectclass(oc_def) is True

    def test_can_handle_objectclass_with_ad_name(self) -> None:
        """Test objectClass detection with AD-specific class name."""
        quirk = FlextLdifQuirksServersAd()

        oc_def = "( 1.2.3.4 NAME 'computer' SUP top STRUCTURAL )"
        assert quirk.can_handle_objectclass(oc_def) is True

    def test_can_handle_objectclass_negative(self) -> None:
        """Test objectClass detection rejects non-AD classes."""
        quirk = FlextLdifQuirksServersAd()

        # Use objectClass that doesn't contain any AD markers
        oc_def = "( 2.5.6.6 NAME 'posixAccount' SUP top STRUCTURAL )"
        assert quirk.can_handle_objectclass(oc_def) is False

    def test_parse_objectclass_success(self) -> None:
        """Test successful objectClass parsing."""
        quirk = FlextLdifQuirksServersAd()

        oc_def = (
            "( 1.2.840.113556.1.5.9 NAME 'user' DESC 'User object' "
            "SUP top STRUCTURAL MUST ( cn $ objectGUID ) "
            "MAY ( sAMAccountName $ userPrincipalName ) )"
        )
        result = quirk.parse_objectclass(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
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
        quirk = FlextLdifQuirksServersAd()

        oc_def = "( 1.2.840.113556.1.5.10 NAME 'adGroup' AUXILIARY )"
        result = quirk.parse_objectclass(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
        assert oc_data.kind == "AUXILIARY"

    def test_parse_objectclass_no_oid(self) -> None:
        """Test objectClass parsing fails without OID."""
        quirk = FlextLdifQuirksServersAd()

        oc_def = "NAME 'user'"
        result = quirk.parse_objectclass(oc_def)

        assert result.is_failure
        assert result.error is not None
        assert result.error is not None
        assert "missing an OID" in result.error

    def test_convert_attribute_to_rfc(self) -> None:
        """Test converting AD attribute to RFC format."""
        quirk = FlextLdifQuirksServersAd()

        attr_model = FlextLdifModels.SchemaAttribute(
            oid="1.2.840.113556.1.4.221",
            name="sAMAccountName",
            desc="SAM Account Name",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            equality="caseIgnoreMatch",
            single_value=True,
        )

        result = quirk.convert_attribute_to_rfc(attr_model)
        assert result.is_success
        rfc_data = result.unwrap()
        assert isinstance(rfc_data, FlextLdifModels.SchemaAttribute)
        assert rfc_data.oid == "1.2.840.113556.1.4.221"
        assert rfc_data.name == "sAMAccountName"

    def test_convert_attribute_from_rfc(self) -> None:
        """Test converting RFC attribute to AD format."""
        quirk = FlextLdifQuirksServersAd()

        rfc_model = FlextLdifModels.SchemaAttribute(
            oid="1.2.840.113556.1.4.221",
            name="sAMAccountName",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )

        result = quirk.convert_attribute_from_rfc(rfc_model)
        assert result.is_success
        ad_data = result.unwrap()
        assert isinstance(ad_data, FlextLdifModels.SchemaAttribute)
        assert ad_data.oid == "1.2.840.113556.1.4.221"

    def test_convert_objectclass_to_rfc(self) -> None:
        """Test converting AD objectClass to RFC format."""
        quirk = FlextLdifQuirksServersAd()

        oc_model = FlextLdifModels.SchemaObjectClass(
            oid="1.2.840.113556.1.5.9",
            name="user",
            sup="top",
            kind="STRUCTURAL",
            must=["cn", "objectGUID"],
            may=["sAMAccountName"],
        )

        result = quirk.convert_objectclass_to_rfc(oc_model)
        assert result.is_success
        rfc_data = result.unwrap()
        assert isinstance(rfc_data, FlextLdifModels.SchemaObjectClass)
        assert rfc_data.oid == "1.2.840.113556.1.5.9"
        assert rfc_data.name == "user"

    def test_convert_objectclass_from_rfc(self) -> None:
        """Test converting RFC objectClass to AD format."""
        quirk = FlextLdifQuirksServersAd()

        rfc_model = FlextLdifModels.SchemaObjectClass(
            oid="1.2.840.113556.1.5.9",
            name="user",
            kind="STRUCTURAL",
        )

        result = quirk.convert_objectclass_from_rfc(rfc_model)
        assert result.is_success
        ad_data = result.unwrap()
        assert isinstance(ad_data, FlextLdifModels.SchemaObjectClass)
        assert ad_data.oid == "1.2.840.113556.1.5.9"

    def test_write_attribute_to_rfc(self) -> None:
        """Test writing attribute to RFC string format."""
        quirk = FlextLdifQuirksServersAd()

        attr_model = FlextLdifModels.SchemaAttribute(
            oid="1.2.840.113556.1.4.221",
            name="sAMAccountName",
            desc="SAM Account Name",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            equality="caseIgnoreMatch",
            single_value=True,
        )

        result = quirk.write_attribute_to_rfc(attr_model)
        assert result.is_success
        attr_str = result.unwrap()
        assert "( 1.2.840.113556.1.4.221" in attr_str
        assert "NAME 'sAMAccountName'" in attr_str
        assert "SINGLE-VALUE" in attr_str

    def test_write_objectclass_to_rfc(self) -> None:
        """Test writing objectClass to RFC string format."""
        quirk = FlextLdifQuirksServersAd()

        oc_model = FlextLdifModels.SchemaObjectClass(
            oid="1.2.840.113556.1.5.9",
            name="user",
            desc="User object",
            sup="top",
            kind="STRUCTURAL",
            must=["cn", "objectGUID"],
            may=["sAMAccountName"],
        )

        result = quirk.write_objectclass_to_rfc(oc_model)
        assert result.is_success
        oc_str = result.unwrap()
        assert "( 1.2.840.113556.1.5.9" in oc_str
        assert "NAME 'user'" in oc_str
        assert "STRUCTURAL" in oc_str
        assert "MUST ( cn $ objectGUID )" in oc_str


class TestActiveDirectoryAclQuirks:
    """Tests for Active Directory ACL quirk handling."""

    def test_acl_quirk_initialization(self) -> None:
        """Test ACL quirk initialization."""
        main_quirk = FlextLdifQuirksServersAd()
        acl_quirk = main_quirk.AclQuirk()

        # Nested quirks use base class defaults
        assert acl_quirk.server_type == "generic"
        assert acl_quirk.priority == 100

    def test_can_handle_acl_with_ntsecuritydescriptor(self) -> None:
        """Test ACL detection with nTSecurityDescriptor attribute."""
        main_quirk = FlextLdifQuirksServersAd()
        acl_quirk = main_quirk.AclQuirk()

        acl_line = "nTSecurityDescriptor:: AQAEgBQAAAAkAAAAAAAAADAAAAABABQABAAAAA=="
        assert acl_quirk.can_handle_acl(acl_line) is True

    def test_can_handle_acl_with_sddl_prefix(self) -> None:
        """Test ACL detection with SDDL prefix (O:, G:, D:, S:)."""
        main_quirk = FlextLdifQuirksServersAd()
        acl_quirk = main_quirk.AclQuirk()

        # SDDL strings start with O:, G:, D:, or S:
        acl_line = "O:BAG:BAD:S:"
        assert acl_quirk.can_handle_acl(acl_line) is True

    def test_can_handle_acl_negative(self) -> None:
        """Test ACL detection rejects non-AD ACLs."""
        main_quirk = FlextLdifQuirksServersAd()
        acl_quirk = main_quirk.AclQuirk()

        acl_line = "olcAccess: to * by self write"
        assert acl_quirk.can_handle_acl(acl_line) is False

    def test_parse_acl_with_base64_value(self) -> None:
        """Test parsing ACL with base64-encoded nTSecurityDescriptor."""
        main_quirk = FlextLdifQuirksServersAd()
        acl_quirk = main_quirk.AclQuirk()

        acl_line = "nTSecurityDescriptor:: T0JBAQAABABABAgA=="
        result = acl_quirk.parse_acl(acl_line)

        assert result.is_success
        acl_model = result.unwrap()
        assert isinstance(acl_model, FlextLdifModels.Acl)
        assert acl_model.name == "nTSecurityDescriptor"
        assert acl_model.raw_acl == acl_line
        # Base64 decoded value stored in subject_value
        assert acl_model.subject.subject_value is not None

    def test_parse_acl_with_sddl_string(self) -> None:
        """Test parsing ACL with SDDL string value."""
        main_quirk = FlextLdifQuirksServersAd()
        acl_quirk = main_quirk.AclQuirk()

        acl_line = "nTSecurityDescriptor: O:BAG:BAD:S:"
        result = acl_quirk.parse_acl(acl_line)

        assert result.is_success
        acl_model = result.unwrap()
        assert isinstance(acl_model, FlextLdifModels.Acl)
        assert acl_model.name == "nTSecurityDescriptor"
        assert acl_model.subject.subject_value == "O:BAG:BAD:S:"

    def test_parse_acl_empty_line(self) -> None:
        """Test parsing empty ACL line fails."""
        main_quirk = FlextLdifQuirksServersAd()
        acl_quirk = main_quirk.AclQuirk()

        result = acl_quirk.parse_acl("")
        assert result.is_failure
        assert result.error is not None
        assert result.error is not None
        assert "Empty ACL line" in result.error

    def test_convert_acl_to_rfc(self) -> None:
        """Test converting AD ACL to RFC format."""
        main_quirk = FlextLdifQuirksServersAd()
        acl_quirk = main_quirk.AclQuirk()

        # Create AD ACL model (use "active_directory" not "ad")
        acl_model = FlextLdifModels.Acl(
            name="nTSecurityDescriptor",
            target=FlextLdifModels.AclTarget(target_dn="*", attributes=[]),
            subject=FlextLdifModels.AclSubject(
                subject_type="sddl", subject_value="O:BAG:BAD:S:"
            ),
            permissions=FlextLdifModels.AclPermissions(),
            server_type="active_directory",
            raw_acl="nTSecurityDescriptor: O:BAG:BAD:S:",
        )

        result = acl_quirk.convert_acl_to_rfc(acl_model)
        assert result.is_success
        rfc_model = result.unwrap()
        assert isinstance(rfc_model, FlextLdifModels.Acl)
        assert rfc_model.server_type == "generic"  # RFC conversion changes to generic
        assert rfc_model.name == "nTSecurityDescriptor"

    def test_convert_acl_from_rfc(self) -> None:
        """Test converting RFC ACL to AD format."""
        main_quirk = FlextLdifQuirksServersAd()
        acl_quirk = main_quirk.AclQuirk()

        # Create RFC ACL model (use "generic" for RFC)
        rfc_model = FlextLdifModels.Acl(
            name="nTSecurityDescriptor",
            target=FlextLdifModels.AclTarget(target_dn="*", attributes=[]),
            subject=FlextLdifModels.AclSubject(
                subject_type="sddl", subject_value="O:BAG:BAD:S:"
            ),
            permissions=FlextLdifModels.AclPermissions(),
            server_type="generic",
            raw_acl="nTSecurityDescriptor: O:BAG:BAD:S:",
        )

        result = acl_quirk.convert_acl_from_rfc(rfc_model)
        assert result.is_success
        ad_model = result.unwrap()
        assert isinstance(ad_model, FlextLdifModels.Acl)
        assert ad_model.server_type == "generic"  # Nested quirks use base defaults
        assert ad_model.name == "nTSecurityDescriptor"

    def test_write_acl_to_rfc(self) -> None:
        """Test writing ACL to RFC string format."""
        main_quirk = FlextLdifQuirksServersAd()
        acl_quirk = main_quirk.AclQuirk()

        # Create AD ACL model (use "active_directory" not "ad")
        acl_model = FlextLdifModels.Acl(
            name="nTSecurityDescriptor",
            target=FlextLdifModels.AclTarget(target_dn="*", attributes=[]),
            subject=FlextLdifModels.AclSubject(
                subject_type="sddl", subject_value="O:BAG:BAD:S:"
            ),
            permissions=FlextLdifModels.AclPermissions(),
            server_type="active_directory",
            raw_acl="nTSecurityDescriptor: O:BAG:BAD:S:",
        )

        result = acl_quirk.write_acl_to_rfc(acl_model)
        assert result.is_success
        acl_str = result.unwrap()
        assert "nTSecurityDescriptor:" in acl_str
        assert "O:BAG:BAD:S:" in acl_str


class TestActiveDirectoryEntryQuirks:
    """Tests for Active Directory entry quirk handling."""

    def test_entry_quirk_initialization(self) -> None:
        """Test entry quirk initialization."""
        main_quirk = FlextLdifQuirksServersAd()
        entry_quirk = main_quirk.EntryQuirk()

        assert entry_quirk.server_type == "generic"
        assert entry_quirk.priority == 100

    def test_can_handle_entry_with_ad_dn_marker(self) -> None:
        """Test entry detection with AD DN markers."""
        main_quirk = FlextLdifQuirksServersAd()
        entry_quirk = main_quirk.EntryQuirk()

        # AD DN markers: cn=users, cn=computers, cn=configuration, etc.
        dn = "cn=Administrator,cn=Users,dc=example,dc=com"
        attributes: dict[str, object] = {}

        assert entry_quirk.can_handle_entry(dn, attributes) is True

    def test_can_handle_entry_with_ad_attributes(self) -> None:
        """Test entry detection with AD-specific attributes."""
        main_quirk = FlextLdifQuirksServersAd()
        entry_quirk = main_quirk.EntryQuirk()

        dn = "cn=test,dc=example,dc=com"
        attributes: dict[str, object] = {
            "objectGUID": "12345678-1234-1234-1234-123456789012",
            "objectSid": "S-1-5-21-...",
        }

        assert entry_quirk.can_handle_entry(dn, attributes) is True

    def test_can_handle_entry_with_ad_objectclass(self) -> None:
        """Test entry detection with AD objectClass."""
        main_quirk = FlextLdifQuirksServersAd()
        entry_quirk = main_quirk.EntryQuirk()

        dn = "cn=test,dc=example,dc=com"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["user", "person"]
        }

        assert entry_quirk.can_handle_entry(dn, attributes) is True

    def test_can_handle_entry_negative(self) -> None:
        """Test entry detection rejects non-AD entries."""
        main_quirk = FlextLdifQuirksServersAd()
        entry_quirk = main_quirk.EntryQuirk()

        dn = "cn=test,ou=people,dc=example,dc=com"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["inetOrgPerson"]
        }

        assert entry_quirk.can_handle_entry(dn, attributes) is False

    def test_process_entry_success(self) -> None:
        """Test successful entry processing."""
        main_quirk = FlextLdifQuirksServersAd()
        entry_quirk = main_quirk.EntryQuirk()

        dn = "cn=Administrator,cn=Users,dc=example,dc=com"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["user", "person"],
            "cn": "Administrator",
            "sAMAccountName": "Administrator",
        }

        result = entry_quirk.process_entry(dn, attributes)
        assert result.is_success
        processed = result.unwrap()
        assert FlextLdifConstants.DictKeys.OBJECTCLASS in processed
        assert processed["cn"] == "Administrator"
        assert processed["sAMAccountName"] == "Administrator"

    def test_process_entry_with_config_dn(self) -> None:
        """Test entry processing with cn=configuration DN."""
        main_quirk = FlextLdifQuirksServersAd()
        entry_quirk = main_quirk.EntryQuirk()

        dn = "cn=Schema,cn=Configuration,dc=example,dc=com"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["container"]
        }

        result = entry_quirk.process_entry(dn, attributes)
        assert result.is_success
        processed = result.unwrap()
        assert FlextLdifConstants.DictKeys.OBJECTCLASS in processed

    def test_process_entry_with_traditional_dit(self) -> None:
        """Test entry processing with traditional DIT (ou= present)."""
        main_quirk = FlextLdifQuirksServersAd()
        entry_quirk = main_quirk.EntryQuirk()

        dn = "cn=John,ou=Sales,dc=example,dc=com"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["user"]
        }

        result = entry_quirk.process_entry(dn, attributes)
        assert result.is_success
        processed = result.unwrap()
        assert FlextLdifConstants.DictKeys.OBJECTCLASS in processed

    def test_convert_entry_to_rfc(self) -> None:
        """Test converting AD entry to RFC format."""
        main_quirk = FlextLdifQuirksServersAd()
        entry_quirk = main_quirk.EntryQuirk()

        entry_data: dict[str, object] = {
            "dn": "cn=test,dc=example,dc=com",
            "server_type": "active_directory",
            "is_config_entry": False,
            "is_traditional_dit": False,
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["user"],
            "cn": "test",
        }

        result = entry_quirk.convert_entry_to_rfc(entry_data)
        assert result.is_success
        rfc_entry = result.unwrap()
        # AD-specific metadata should be removed
        assert "server_type" not in rfc_entry
        assert "is_config_entry" not in rfc_entry
        assert "is_traditional_dit" not in rfc_entry
        # Standard attributes should remain
        assert rfc_entry["dn"] == "cn=test,dc=example,dc=com"
        assert rfc_entry[FlextLdifConstants.DictKeys.OBJECTCLASS] == ["user"]
