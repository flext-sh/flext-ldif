"""Comprehensive unit tests for FlextLdifUtilities functionality.

Tests all utility functions and classes with real validation.
"""

from __future__ import annotations

from flext_core import FlextResult

from flext_ldif.utilities import FlextLdifUtilities


class TestFlextLdifUtilitiesDnUtilities:
    """Test suite for DN utilities."""

    def test_parse_dn_components_valid(self) -> None:
        """Test parsing valid DN components."""
        dn = "cn=test,ou=users,dc=example,dc=com"

        result = FlextLdifUtilities.DnUtilities.parse_dn_components(dn)

        assert result.is_success
        components = result.unwrap()
        assert isinstance(components, list)
        assert len(components) > 0

    def test_parse_dn_components_invalid(self) -> None:
        """Test parsing invalid DN components."""
        invalid_dn = "invalid-dn-format"

        result = FlextLdifUtilities.DnUtilities.parse_dn_components(invalid_dn)

        # Should handle gracefully
        assert isinstance(result, FlextResult)

    def test_normalize_dn_components(self) -> None:
        """Test normalizing DN components."""
        dn = "CN=test,OU=users,DC=example,DC=com"

        result = FlextLdifUtilities.DnUtilities.normalize_dn_components(dn)

        assert result.is_success
        normalized = result.unwrap()
        assert isinstance(normalized, str)
        # Should be lowercase
        assert normalized == dn.lower()

    def test_extract_dn_components(self) -> None:
        """Test extracting DN components as tuples."""
        dn = "cn=test,ou=users,dc=example,dc=com"

        result = FlextLdifUtilities.DnUtilities.extract_dn_components(dn)

        assert result.is_success
        components = result.unwrap()
        assert isinstance(components, list)
        assert len(components) > 0

        # Each component should be a (key, value) tuple
        for comp in components:
            assert isinstance(comp, tuple)
            assert len(comp) == 2

    def test_build_dn_from_components(self) -> None:
        """Test building DN from components."""
        components = [
            ("cn", "test"),
            ("ou", "users"),
            ("dc", "example"),
            ("dc", "com"),
        ]

        result = FlextLdifUtilities.DnUtilities.build_dn_from_components(components)

        assert result.is_success
        dn = result.unwrap()
        assert isinstance(dn, str)
        assert "cn=test" in dn
        assert "dc=com" in dn


class TestFlextLdifUtilitiesAttributeUtilities:
    """Test suite for attribute utilities."""

    def test_normalize_attribute_name(self) -> None:
        """Test normalizing attribute names."""
        result = FlextLdifUtilities.AttributeUtilities.normalize_attribute_name("CN")

        assert result.is_success
        normalized = result.unwrap()
        assert normalized == "cn"

    def test_validate_attribute_name(self) -> None:
        """Test validating attribute names."""
        # Valid names
        valid_names = ["cn", "sn", "mail", "telephoneNumber"]

        for name in valid_names:
            result = FlextLdifUtilities.AttributeUtilities.validate_attribute_name(name)
            assert result.is_success

    def test_parse_attribute_options(self) -> None:
        """Test parsing attribute options."""
        attr_with_options = "userCertificate;binary"

        result = FlextLdifUtilities.AttributeUtilities.parse_attribute_options(
            attr_with_options
        )

        assert result.is_success
        parsed = result.unwrap()
        assert isinstance(parsed, dict)
        assert "name" in parsed
        assert "options" in parsed
        assert parsed["name"] == "userCertificate"
        assert "binary" in parsed["options"]

    def test_encode_binary_value(self) -> None:
        """Test encoding binary values."""
        binary_data = b"test binary data"

        result = FlextLdifUtilities.EncodingUtilities.encode_binary_value(binary_data)

        assert result.is_success
        encoded = result.unwrap()
        assert isinstance(encoded, str)

    def test_decode_binary_value(self) -> None:
        """Test decoding binary values."""
        base64_data = "dGVzdCBiaW5hcnkgZGF0YQ=="  # "test binary data" in base64

        result = FlextLdifUtilities.EncodingUtilities.decode_binary_value(base64_data)

        assert result.is_success
        decoded = result.unwrap()
        assert isinstance(decoded, bytes)
        assert decoded == b"test binary data"


class TestFlextLdifUtilitiesSchemaUtilities:
    """Test suite for schema utilities."""

    def test_validate_object_class_hierarchy(self) -> None:
        """Test validating object class hierarchy."""
        # Simple hierarchy
        hierarchy = {
            "person": [],
            "organizationalPerson": ["person"],
            "inetOrgPerson": ["organizationalPerson"],
        }

        result = FlextLdifUtilities.SchemaUtilities.validate_object_class_hierarchy(
            hierarchy
        )

        assert result.is_success

    # TODO: Implement schema conflict detection
    # def test_detect_schema_conflicts(self) -> None:
    #     """Test detecting schema conflicts."""
    #     # Create conflicting definitions
    #     # Create schema definitions with different attributes
    #     schema_defs = {
    #         "cn": {"syntax": "1.3.6.1.4.1.1466.115.121.1.15", "single_value": False},
    #         "givenName": {"syntax": "1.3.6.1.4.1.1466.115.121.1.15", "single_value": True},
    #     }
    #
    #     result = FlextLdifUtilities.SchemaUtilities.detect_schema_conflicts(schema_defs)
    #
    #     assert result.is_success
    #     conflicts = result.unwrap()
    #     assert isinstance(conflicts, list)


class TestFlextLdifUtilitiesAclUtilities:
    """Test suite for ACL utilities."""

    def test_parse_acl_target(self) -> None:
        """Test parsing ACL target."""
        acl_target = "entry"

        result = FlextLdifUtilities.AclUtilities.parse_acl_target(acl_target)

        assert result.is_success
        parsed = result.unwrap()
        assert isinstance(parsed, dict)

    def test_validate_acl_permissions(self) -> None:
        """Test validating ACL permissions."""
        permissions = ["read", "write", "search"]

        result = FlextLdifUtilities.AclUtilities.validate_acl_permissions(permissions)

        assert result.is_success

    def test_normalize_acl_subject(self) -> None:
        """Test normalizing ACL subject."""
        subject = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"

        result = FlextLdifUtilities.AclUtilities.normalize_acl_subject(subject)

        assert result.is_success
        normalized = result.unwrap()
        assert isinstance(normalized, str)


class TestFlextLdifUtilitiesValidationUtilities:
    """Test suite for validation utilities."""

    def test_validate_dn_format(self) -> None:
        """Test validating DN format."""
        valid_dn = "cn=test,ou=users,dc=example,dc=com"
        invalid_dn = "invalid-dn-format"

        # Valid DN
        result = FlextLdifUtilities.ValidationUtilities.validate_dn_format(valid_dn)
        assert result.is_success

        # Invalid DN
        result = FlextLdifUtilities.ValidationUtilities.validate_dn_format(invalid_dn)
        assert result.is_failure

    def test_validate_attribute_values(self) -> None:
        """Test validating attribute values."""
        values = ["test@example.com"]

        result = FlextLdifUtilities.ValidationUtilities.validate_attribute_values(
            "mail", values
        )

        assert result.is_success

    def test_validate_url_format(self) -> None:
        """Test validating URL format."""
        valid_url = "https://example.com"
        invalid_url = "not-a-url"

        # Valid URL
        result = FlextLdifUtilities.ValidationUtilities.validate_url_format(valid_url)
        assert result.is_success

        # Invalid URL
        result = FlextLdifUtilities.ValidationUtilities.validate_url_format(invalid_url)
        assert result.is_failure

    def test_validate_phone_format(self) -> None:
        """Test validating phone number format."""
        valid_phone = "+1-555-123-4567"
        invalid_phone = "not-a-phone"

        # Valid phone
        result = FlextLdifUtilities.ValidationUtilities.validate_phone_format(
            valid_phone
        )
        assert result.is_success

        # Invalid phone
        result = FlextLdifUtilities.ValidationUtilities.validate_phone_format(
            invalid_phone
        )
        assert result.is_failure


class TestFlextLdifUtilitiesConversionUtilities:
    """Test suite for conversion utilities."""

    def test_ldif_to_dict_conversion(self) -> None:
        """Test converting LDIF to dictionary."""
        ldif_content = """dn: cn=test,dc=example,dc=com
cn: Test User
sn: User
"""

        result = FlextLdifUtilities.ConversionUtilities.ldif_to_dict(ldif_content)

        assert result.is_success
        data = result.unwrap()
        assert isinstance(data, dict)
        assert "entries" in data

    def test_dict_to_ldif_conversion(self) -> None:
        """Test converting dictionary to LDIF."""
        data = {
            "entries": [
                {
                    "dn": "cn=test,dc=example,dc=com",
                    "attributes": {
                        "cn": ["Test User"],
                        "sn": ["User"],
                    },
                }
            ]
        }

        result = FlextLdifUtilities.ConversionUtilities.dict_to_ldif(data)

        assert result.is_success
        ldif_content = result.unwrap()
        assert isinstance(ldif_content, str)
        assert "dn:" in ldif_content

    def test_normalize_ldif_format(self) -> None:
        """Test normalizing LDIF format."""
        ldif_content = "dn: cn=test,dc=example,dc=com\ncn: Test User\n"

        result = FlextLdifUtilities.ConversionUtilities.normalize_ldif_format(
            ldif_content
        )

        assert result.is_success
        normalized = result.unwrap()
        assert isinstance(normalized, str)


class TestFlextLdifUtilitiesProcessors:
    """Test suite for processor utilities."""

    def test_create_processor(self) -> None:
        """Test creating a processor."""

        def test_processor(data: dict) -> dict:
            return {**data, "processed": True}

        result = FlextLdifUtilities.Processors.create_processor("test", test_processor)

        assert result.is_success
        processor_id = result.unwrap()
        assert isinstance(processor_id, str)

    def test_register_processor(self) -> None:
        """Test registering a processor."""
        processors = {}

        def test_processor(data: dict) -> dict:
            return {**data, "registered": True}

        result = FlextLdifUtilities.Processors.register_processor(
            "test", test_processor, processors
        )

        assert result.is_success

    def test_process_entries_batch(self) -> None:
        """Test processing entries in batch."""
        processors = {}

        # Register a processor
        def test_processor(data: dict) -> dict:
            return {**data, "processed": True}

        reg_result = FlextLdifUtilities.Processors.register_processor(
            "test", test_processor, processors
        )
        assert reg_result.is_success

        # Process entries
        entries = [
            {"dn": "cn=test1", "attributes": {"cn": ["test1"]}},
            {"dn": "cn=test2", "attributes": {"cn": ["test2"]}},
        ]

        result = FlextLdifUtilities.Processors.process_entries_batch(
            "test", entries, processors
        )

        assert result.is_success
        processed = result.unwrap()
        assert isinstance(processed, list)
        assert len(processed) == 2

    def test_get_processor_stats(self) -> None:
        """Test getting processor statistics."""
        processors = {}

        result = FlextLdifUtilities.Processors.get_processor_stats(processors)

        assert result.is_success
        stats = result.unwrap()
        assert isinstance(stats, dict)
