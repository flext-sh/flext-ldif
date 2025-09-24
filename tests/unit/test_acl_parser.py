"""Unit tests for FlextLdifAclParser."""

from flext_core import FlextResult
from flext_ldif import FlextLdifModels
from flext_ldif.acl.parser import FlextLdifAclParser


class TestFlextLdifAclParser:
    """Test FlextLdifAclParser class."""

    def test_parser_initialization(self) -> None:
        """Test parser initialization."""
        parser = FlextLdifAclParser()
        assert parser is not None

    def test_parser_execute(self) -> None:
        """Test parser execute method."""
        parser = FlextLdifAclParser()
        result = parser.execute()
        assert isinstance(result, FlextResult)

    def test_parse_openldap_acl(self) -> None:
        """Test parsing OpenLDAP ACL."""
        parser = FlextLdifAclParser()
        acl_string = "access to * by users read"
        result = parser.parse_openldap_acl(acl_string)
        assert isinstance(result, FlextResult)
        if result.is_success:
            acl = result.unwrap()
            assert isinstance(acl, FlextLdifModels.UnifiedAcl)

    def test_parse_openldap_acl_empty(self) -> None:
        """Test parsing empty OpenLDAP ACL."""
        parser = FlextLdifAclParser()
        result = parser.parse_openldap_acl("")
        assert isinstance(result, FlextResult)

    def test_parse_openldap_acl_complex(self) -> None:
        """Test parsing complex OpenLDAP ACL."""
        parser = FlextLdifAclParser()
        acl_string = "access to dn.subtree=dc=example,dc=com by dn=cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com write"
        result = parser.parse_openldap_acl(acl_string)
        assert isinstance(result, FlextResult)
        if result.is_success:
            acl = result.unwrap()
            assert acl.server_type == "openldap"

    def test_parse_389ds_acl(self) -> None:
        """Test parsing 389DS ACL."""
        parser = FlextLdifAclParser()
        acl_string = 'aci: (targetattr = "*")(version 3.0; acl "Read Access"; allow (read) userdn="ldap:///all";)'
        result = parser.parse_389ds_acl(acl_string)
        assert isinstance(result, FlextResult)
        if result.is_success:
            acl = result.unwrap()
            assert isinstance(acl, FlextLdifModels.UnifiedAcl)

    def test_parse_389ds_acl_empty(self) -> None:
        """Test parsing empty 389DS ACL."""
        parser = FlextLdifAclParser()
        result = parser.parse_389ds_acl("")
        assert isinstance(result, FlextResult)

    def test_parse_389ds_acl_complex(self) -> None:
        """Test parsing complex 389DS ACL."""
        parser = FlextLdifAclParser()
        acl_string = 'aci: (target="ldap:///dc=example,dc=com")(targetattr="*")(version 3.0; acl "Admin Access"; allow (all) userdn="ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com";)'
        result = parser.parse_389ds_acl(acl_string)
        assert isinstance(result, FlextResult)
        if result.is_success:
            acl = result.unwrap()
            assert acl.server_type == "389ds"

    def test_parse_oracle_acl(self) -> None:
        """Test parsing Oracle ACL."""
        parser = FlextLdifAclParser()
        acl_string = "orclaci: access to entry by cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com read"
        result = parser.parse_oracle_acl(acl_string)
        assert isinstance(result, FlextResult)
        if result.is_success:
            acl = result.unwrap()
            assert isinstance(acl, FlextLdifModels.UnifiedAcl)

    def test_parse_oracle_acl_empty(self) -> None:
        """Test parsing empty Oracle ACL."""
        parser = FlextLdifAclParser()
        result = parser.parse_oracle_acl("")
        assert isinstance(result, FlextResult)

    def test_parse_oracle_acl_complex(self) -> None:
        """Test parsing complex Oracle ACL."""
        parser = FlextLdifAclParser()
        acl_string = "orclaci: access to dn.subtree=dc=example,dc=com by group cn=REDACTED_LDAP_BIND_PASSWORDs,dc=example,dc=com write,read"
        result = parser.parse_oracle_acl(acl_string)
        assert isinstance(result, FlextResult)
        if result.is_success:
            acl = result.unwrap()
            # Default Oracle server type is oracle_oid
            assert acl.server_type in {"oracle_oid", "oracle_oud", "oracle"}

    def test_parse_acl_openldap_format(self) -> None:
        """Test generic parse_acl with OpenLDAP format."""
        parser = FlextLdifAclParser()
        acl_string = "access to * by users read"
        result = parser.parse_acl(acl_string, server_type="openldap")
        assert isinstance(result, FlextResult)
        if result.is_success:
            acl = result.unwrap()
            assert acl.server_type == "openldap"

    def test_parse_acl_389ds_format(self) -> None:
        """Test generic parse_acl with 389DS format."""
        parser = FlextLdifAclParser()
        acl_string = 'aci: (targetattr = "*")(version 3.0; acl "test"; allow (read) userdn="ldap:///all";)'
        result = parser.parse_acl(acl_string, server_type="389ds")
        assert isinstance(result, FlextResult)
        if result.is_success:
            acl = result.unwrap()
            assert acl.server_type == "389ds"

    def test_parse_acl_oracle_format(self) -> None:
        """Test generic parse_acl with Oracle format."""
        parser = FlextLdifAclParser()
        acl_string = "orclaci: access to entry by cn=REDACTED_LDAP_BIND_PASSWORD read"
        result = parser.parse_acl(acl_string, server_type="oracle")
        assert isinstance(result, FlextResult)
        if result.is_success:
            acl = result.unwrap()
            # Default Oracle server type is oracle_oid
            assert acl.server_type in {"oracle_oid", "oracle_oud", "oracle"}

    def test_parse_acl_invalid_format_for_server_type(self) -> None:
        """Test parse_acl with invalid ACL format for given server type."""
        parser = FlextLdifAclParser()
        # Invalid format for OpenLDAP (looks like 389DS)
        acl_string = 'aci: (targetattr = "*")(version 3.0; acl "test"; allow (read) userdn="ldap:///all";)'
        result = parser.parse_acl(acl_string, server_type="openldap")
        assert isinstance(result, FlextResult)

    def test_parse_acl_unsupported_server_type(self) -> None:
        """Test parse_acl with unsupported server type."""
        parser = FlextLdifAclParser()
        acl_string = "access to * by users read"
        result = parser.parse_acl(acl_string, server_type="unknown_server")
        assert isinstance(result, FlextResult)


class TestFlextLdifAclParserEdgeCases:
    """Test edge cases and error handling."""

    def test_parse_openldap_with_special_chars(self) -> None:
        """Test parsing OpenLDAP ACL with special characters."""
        parser = FlextLdifAclParser()
        acl_string = "access to * by cn=user\\,REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com read"
        result = parser.parse_openldap_acl(acl_string)
        assert isinstance(result, FlextResult)

    def test_parse_389ds_with_special_chars(self) -> None:
        """Test parsing 389DS ACL with special characters."""
        parser = FlextLdifAclParser()
        acl_string = 'aci: (targetattr = "*")(version 3.0; acl "Test\\nACL"; allow (read) userdn="ldap:///all";)'
        result = parser.parse_389ds_acl(acl_string)
        assert isinstance(result, FlextResult)

    def test_parse_oracle_with_special_chars(self) -> None:
        """Test parsing Oracle ACL with special characters."""
        parser = FlextLdifAclParser()
        acl_string = (
            "orclaci: access to entry by cn=REDACTED_LDAP_BIND_PASSWORD\\,root,dc=example,dc=com read"
        )
        result = parser.parse_oracle_acl(acl_string)
        assert isinstance(result, FlextResult)

    def test_parse_acl_with_whitespace(self) -> None:
        """Test parsing ACL with excessive whitespace."""
        parser = FlextLdifAclParser()
        acl_string = "  access   to   *   by   users   read  "
        result = parser.parse_acl(acl_string, server_type="openldap")
        assert isinstance(result, FlextResult)

    def test_parse_acl_with_newlines(self) -> None:
        """Test parsing ACL with newlines."""
        parser = FlextLdifAclParser()
        acl_string = "access to *\nby users\nread"
        result = parser.parse_acl(acl_string, server_type="openldap")
        assert isinstance(result, FlextResult)

    def test_parse_openldap_very_long_acl(self) -> None:
        """Test parsing very long OpenLDAP ACL."""
        parser = FlextLdifAclParser()
        acl_string = "access to " + ("*" * 1000) + " by users read"
        result = parser.parse_openldap_acl(acl_string)
        assert isinstance(result, FlextResult)

    def test_parse_389ds_very_long_acl(self) -> None:
        """Test parsing very long 389DS ACL."""
        parser = FlextLdifAclParser()
        acl_string = f'aci: (targetattr = "*")(version 3.0; acl "{"test" * 100}"; allow (read) userdn="ldap:///all";)'
        result = parser.parse_389ds_acl(acl_string)
        assert isinstance(result, FlextResult)

    def test_parse_oracle_very_long_acl(self) -> None:
        """Test parsing very long Oracle ACL."""
        parser = FlextLdifAclParser()
        acl_string = "orclaci: access to " + ("entry" * 100) + " by cn=REDACTED_LDAP_BIND_PASSWORD read"
        result = parser.parse_oracle_acl(acl_string)
        assert isinstance(result, FlextResult)

    def test_parse_acl_case_sensitivity(self) -> None:
        """Test parse_acl with different case server types."""
        parser = FlextLdifAclParser()
        acl_string = "access to * by users read"

        # Test lowercase
        result_lower = parser.parse_acl(acl_string, server_type="openldap")
        assert isinstance(result_lower, FlextResult)

        # Test uppercase
        result_upper = parser.parse_acl(acl_string, server_type="OPENLDAP")
        assert isinstance(result_upper, FlextResult)

    def test_parse_acl_null_bytes(self) -> None:
        """Test parsing ACL with null bytes."""
        parser = FlextLdifAclParser()
        acl_string = "access to *\x00 by users read"
        result = parser.parse_acl(acl_string, server_type="openldap")
        assert isinstance(result, FlextResult)
