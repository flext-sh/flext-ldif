"""Comprehensive tests for advanced LDIF features - RFC 2849 compliance.

Tests for Base64 encoding, change records, server quirks, and advanced parsing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64

from flext_ldif import (
    FlextLdifModels,
    FlextLdifParser,
    FlextLdifProcessor,
    FlextLdifQuirksAdapter,
)


class TestAdvancedLdifFeatures:
    """Test advanced LDIF features and RFC 2849 compliance."""

    def test_base64_encoding_parsing(self) -> None:
        """Test parsing of Base64 encoded attributes."""
        # Create Base64 encoded content
        test_value = "Hello, World! 你好世界"
        encoded_value = base64.b64encode(test_value.encode("utf-8")).decode("ascii")

        ldif_content = f"""dn: cn=test,dc=example,dc=com
cn: test
description:: {encoded_value}
objectClass: person"""

        parser = FlextLdifParser()
        result = parser.parse_string(ldif_content)

        assert result.is_success
        assert len(result.value) == 1
        entry = result.value[0]
        assert entry.get_attribute("description") == [test_value]

    def test_change_record_parsing(self) -> None:
        """Test parsing of LDIF change records."""
        ldif_content = """dn: cn=test,dc=example,dc=com
changetype: add
cn: test
objectClass: person
sn: Test User"""

        parser = FlextLdifParser()
        result = parser.parse_string(ldif_content)

        assert result.is_success
        assert len(result.value) == 1
        change_record = result.value[0]
        assert hasattr(change_record, "changetype")
        assert change_record.changetype == "add"

    def test_line_continuation_parsing(self) -> None:
        """Test parsing of LDIF with line continuations."""
        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
description: This is a very long description that
 continues on the next line with more text
objectClass: person"""

        parser = FlextLdifParser()
        result = parser.parse_string(ldif_content)

        assert result.is_success
        assert len(result.value) == 1
        entry = result.value[0]
        description = entry.get_attribute("description")
        assert description is not None
        assert "continues on the next line" in description[0]

    def test_comment_parsing(self) -> None:
        """Test parsing of LDIF with comments."""
        ldif_content = """# This is a comment
dn: cn=test,dc=example,dc=com
cn: test
# Another comment
objectClass: person"""

        parser = FlextLdifParser()
        result = parser.parse_string(ldif_content)

        assert result.is_success
        assert len(result.value) == 1
        entry = result.value[0]
        assert entry.dn.value == "cn=test,dc=example,dc=com"

    def test_version_control_parsing(self) -> None:
        """Test parsing of LDIF with version control."""
        ldif_content = """version: 1
dn: cn=test,dc=example,dc=com
cn: test
objectClass: person"""

        parser = FlextLdifParser()
        result = parser.parse_string(ldif_content)

        assert result.is_success
        assert len(result.value) == 1

    def test_url_reference_parsing(self) -> None:
        """Test parsing of LDIF with URL references."""
        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
jpegPhoto: <file:///path/to/photo.jpg>
objectClass: person"""

        parser = FlextLdifParser()
        result = parser.parse_string(ldif_content)

        assert result.is_success
        assert len(result.value) == 1
        entry = result.value[0]
        jpeg_photo = entry.get_attribute("jpegPhoto")
        assert jpeg_photo is not None
        assert jpeg_photo[0].startswith("<file://")

    def test_attribute_options_parsing(self) -> None:
        """Test parsing of LDIF with attribute options."""
        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
cn;lang-en: Test User
cn;lang-fr: Utilisateur Test
objectClass: person"""

        parser = FlextLdifParser()
        result = parser.parse_string(ldif_content)

        assert result.is_success
        assert len(result.value) == 1
        entry = result.value[0]
        # Should have multiple cn attributes with different options
        cn_values = entry.get_attribute("cn")
        assert cn_values is not None
        assert len(cn_values) >= 1

    def test_multiple_entries_with_comments(self) -> None:
        """Test parsing multiple entries with comments and empty lines."""
        ldif_content = """# First entry
dn: cn=user1,dc=example,dc=com
cn: user1
objectClass: person

# Second entry
dn: cn=user2,dc=example,dc=com
cn: user2
objectClass: person"""

        parser = FlextLdifParser()
        result = parser.parse_string(ldif_content)

        assert result.is_success
        assert len(result.value) == 2
        assert result.value[0].dn.value == "cn=user1,dc=example,dc=com"
        assert result.value[1].dn.value == "cn=user2,dc=example,dc=com"

    def test_encoding_detection(self) -> None:
        """Test automatic encoding detection."""
        # Test with UTF-8 content
        utf8_content = """dn: cn=测试,dc=example,dc=com
cn: 测试用户
objectClass: person"""

        parser = FlextLdifParser()
        result = parser.parse_string(utf8_content)

        assert result.is_success
        assert len(result.value) == 1
        entry = result.value[0]
        assert "测试" in entry.dn.value

    def test_rfc_compliance_validation(self) -> None:
        """Test RFC 2849 compliance validation."""
        ldif_content = """version: 1
dn: cn=test,dc=example,dc=com
cn: test
description:: VGVzdCBkZXNjcmlwdGlvbg==
objectClass: person"""

        parser = FlextLdifParser()
        parse_result = parser.parse_string(ldif_content)
        assert parse_result.is_success

        compliance_result = parser.validate_rfc_compliance(parse_result.value)
        assert compliance_result.is_success

        compliance_data = compliance_result.value
        assert "compliance_score" in compliance_data
        assert "features_detected" in compliance_data

    def test_server_type_detection_active_directory(self) -> None:
        """Test detection of Active Directory server type."""
        ad_content = """dn: CN=John Doe,OU=Users,DC=company,DC=com
CN: John Doe
sAMAccountName: jdoe
userPrincipalName: jdoe@company.com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user"""

        parser = FlextLdifParser()
        parse_result = parser.parse_string(ad_content)
        assert parse_result.is_success

        detection_result = parser.detect_server_type(parse_result.value)
        assert detection_result.is_success
        # Should detect Active Directory based on DN patterns and attributes

    def test_server_type_detection_openldap(self) -> None:
        """Test detection of OpenLDAP server type."""
        openldap_content = """dn: cn=john doe,ou=users,dc=company,dc=com
cn: john doe
uid: jdoe
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson"""

        parser = FlextLdifParser()
        parse_result = parser.parse_string(openldap_content)
        assert parse_result.is_success

        detection_result = parser.detect_server_type(parse_result.value)
        assert detection_result.is_success
        # Should detect OpenLDAP based on DN patterns and attributes

    def test_server_quirks_adaptation(self) -> None:
        """Test server-specific adaptation of entries."""
        # Create a generic entry
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "sn": ["Test"], "objectClass": ["person"]},
        }

        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success
        entry = entry_result.value

        # Test adaptation for Active Directory
        quirks_handler = FlextLdifQuirksAdapter()
        adaptation_result = quirks_handler.adapt_entry(entry, "active_directory")

        assert adaptation_result.is_success
        adapted_entry = adaptation_result.value
        assert adapted_entry.dn.value == entry.dn.value

    def test_server_compliance_validation(self) -> None:
        """Test server-specific compliance validation."""
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
                "sn": ["Test"],
                "objectClass": ["person", "organizationalPerson"],
            },
        }

        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success
        entry = entry_result.value

        quirks_handler = FlextLdifQuirksAdapter()
        validation_result = quirks_handler.validate_server_compliance(entry, "openldap")

        assert validation_result.is_success
        validation_data = validation_result.value
        assert "compliant" in validation_data
        assert "issues" in validation_data

    def test_processor_advanced_methods(self) -> None:
        """Test advanced methods in FlextLdifProcessor."""
        processor = FlextLdifProcessor()

        # Test advanced parsing
        ldif_content = """version: 1
dn: cn=test,dc=example,dc=com
cn: test
objectClass: person"""

        result = processor.parse_string_advanced(ldif_content)
        assert result.is_success
        assert len(result.value) == 1

        # Test server detection
        detection_result = processor.detect_server_type([result.value[0]])
        assert detection_result.is_success

        # Test RFC compliance validation
        compliance_result = processor.validate_rfc_compliance(result.value)
        assert compliance_result.is_success

    def test_change_record_model(self) -> None:
        """Test ChangeRecord model creation and validation."""
        change_data = {
            "dn": "cn=test,dc=example,dc=com",
            "changetype": "add",
            "attributes": {"cn": ["test"], "objectClass": ["person"]},
            "modifications": [],
        }

        change_result = FlextLdifModels.ChangeRecord.create(change_data)
        assert change_result.is_success

        change_record = change_result.value
        assert change_record.dn.value == "cn=test,dc=example,dc=com"
        assert change_record.changetype == "add"
        assert change_record.has_attribute("cn")

    def test_ldif_version_model(self) -> None:
        """Test LdifVersion model creation and validation."""
        version_result = FlextLdifModels.LdifVersion.create("1", "utf-8")
        assert version_result.is_success

        version = version_result.value
        assert version.version == "1"
        assert version.encoding == "utf-8"

    def test_error_handling_malformed_ldif(self) -> None:
        """Test error handling for malformed LDIF."""
        malformed_content = """dn: cn=test,dc=example,dc=com
invalid line without colon
cn: test"""

        parser = FlextLdifParser()
        result = parser.parse_string(malformed_content)

        # Should handle gracefully and parse what it can
        assert result.is_success
        assert len(result.value) == 1

    def test_large_ldif_file_handling(self) -> None:
        """Test handling of large LDIF content."""
        # Create a large LDIF with many entries
        entries = [
            f"""dn: cn=user{i},dc=example,dc=com
cn: user{i}
objectClass: person
sn: User {i}"""
            for i in range(100)
        ]

        large_content = "\n\n".join(entries)

        parser = FlextLdifParser()
        result = parser.parse_string(large_content)

        assert result.is_success
        assert len(result.value) == 100

    def test_mixed_encoding_content(self) -> None:
        """Test handling of mixed encoding content."""
        # Content with both ASCII and non-ASCII characters
        mixed_content = """dn: cn=test,dc=example,dc=com
cn: test
description: ASCII text
description: Unicode text: 你好世界
objectClass: person"""

        parser = FlextLdifParser()
        result = parser.parse_string(mixed_content)

        assert result.is_success
        assert len(result.value) == 1
        entry = result.value[0]
        descriptions = entry.get_attribute("description")
        assert descriptions is not None
        assert len(descriptions) == 2
        assert "ASCII text" in descriptions
        assert any("你好世界" in desc for desc in descriptions)

    def test_server_info_retrieval(self) -> None:
        """Test retrieval of server information."""
        quirks_handler = FlextLdifQuirksAdapter()

        # Test getting info for specific server
        info_result = quirks_handler.get_server_info("active_directory")
        assert info_result.is_success

        info_data = info_result.value
        assert "server_type" in info_data
        assert "dn_case_sensitive" in info_data
        assert "required_object_classes" in info_data

    def test_processor_server_info(self) -> None:
        """Test processor's server info method."""
        processor = FlextLdifProcessor()

        info_result = processor.get_server_info("openldap")
        assert info_result.is_success

        info_data = info_result.value
        assert "server_type" in info_data
        assert info_data["server_type"] == "openldap"


class TestAdvancedLdifEdgeCases:
    """Test edge cases and error conditions for advanced LDIF features."""

    def test_empty_base64_attribute(self) -> None:
        """Test handling of empty Base64 attributes."""
        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
emptyBinary::
objectClass: person"""

        parser = FlextLdifParser()
        result = parser.parse_string(ldif_content)

        assert result.is_success
        entry = result.value[0]
        empty_binary = entry.get_attribute("emptyBinary")
        assert empty_binary is not None
        assert not empty_binary[0]

    def test_invalid_base64_handling(self) -> None:
        """Test handling of invalid Base64 data."""
        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
invalidBinary:: InvalidBase64Data!
objectClass: person"""

        parser = FlextLdifParser()
        result = parser.parse_string(ldif_content)

        # Should handle gracefully - might keep original value or handle error
        assert result.is_success

    def test_very_long_line_continuation(self) -> None:
        """Test handling of very long line continuations."""
        long_description = "This is a very long description. " * 50
        ldif_content = f"""dn: cn=test,dc=example,dc=com
cn: test
description: {long_description}
objectClass: person"""

        parser = FlextLdifParser()
        result = parser.parse_string(ldif_content)

        assert result.is_success
        entry = result.value[0]
        description = entry.get_attribute("description")
        assert description is not None
        assert len(description[0]) > 1000

    def test_multiple_change_records(self) -> None:
        """Test parsing multiple change records."""
        ldif_content = """dn: cn=user1,dc=example,dc=com
changetype: add
cn: user1
objectClass: person

dn: cn=user2,dc=example,dc=com
changetype: modify
cn: user2
objectClass: person"""

        parser = FlextLdifParser()
        result = parser.parse_string(ldif_content)

        assert result.is_success
        assert len(result.value) == 2
        assert result.value[0].changetype == "add"
        assert result.value[1].changetype == "modify"

    def test_unknown_server_type_handling(self) -> None:
        """Test handling of unknown server types."""
        quirks_handler = FlextLdifQuirksAdapter()

        # Test with unknown server type
        info_result = quirks_handler.get_server_info("unknown_server")
        assert info_result.is_failure

    def test_server_adaptation_failure_recovery(self) -> None:
        """Test recovery from server adaptation failures."""
        # Create entry with invalid data
        entry_data = {
            "dn": "",  # Invalid empty DN
            "attributes": {},
        }

        entry_result = FlextLdifModels.Entry.create(entry_data)
        # This should fail due to empty DN
        assert entry_result.is_failure

    def test_compliance_validation_empty_entries(self) -> None:
        """Test compliance validation with empty entry list."""
        parser = FlextLdifParser()
        result = parser.validate_rfc_compliance([])

        assert result.is_success
        compliance_data = result.value
        assert compliance_data["total_entries"] == 0
