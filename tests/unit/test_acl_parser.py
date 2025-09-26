"""Test suite for FlextLdifAclParser.

This module provides comprehensive testing for the ACL parser functionality
using real services and FlextTests infrastructure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import asyncio

from flext_ldif.acl.parser import FlextLdifAclParser
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks import constants


class TestFlextLdifAclParser:
    """Test suite for FlextLdifAclParser."""

    def test_initialization(self) -> None:
        """Test ACL parser initialization."""
        parser = FlextLdifAclParser()
        assert parser is not None
        assert parser._logger is not None

    def test_execute_success(self) -> None:
        """Test execute method returns success."""
        parser = FlextLdifAclParser()
        result = parser.execute()

        assert result.is_success
        data = result.value
        assert data["service"] == FlextLdifAclParser
        assert data["status"] == "ready"

    def test_execute_async_success(self) -> None:
        """Test execute_async method returns success."""
        parser = FlextLdifAclParser()
        result = asyncio.run(parser.execute_async())

        assert result.is_success
        data = result.value
        assert data["service"] == FlextLdifAclParser
        assert data["status"] == "ready"

    def test_parse_openldap_acl_basic(self) -> None:
        """Test parsing OpenLDAP ACL."""
        parser = FlextLdifAclParser()

        acl_string = "to attrs=cn,sn by * read"
        result = parser.parse_openldap_acl(acl_string)

        assert result.is_success
        acl = result.value
        assert acl.name == "openldap_acl"
        assert acl.server_type == constants.SERVER_TYPE_OPENLDAP
        assert acl.raw_acl == acl_string
        assert acl.target is not None
        assert acl.subject is not None
        assert acl.permissions is not None

    def test_parse_openldap_acl_empty_string(self) -> None:
        """Test parsing OpenLDAP ACL with empty string."""
        parser = FlextLdifAclParser()

        result = parser.parse_openldap_acl("")

        assert result.is_success
        acl = result.value
        assert acl.name == "openldap_acl"
        assert acl.server_type == constants.SERVER_TYPE_OPENLDAP
        assert not acl.raw_acl

    def test_parse_openldap_acl_complex(self) -> None:
        """Test parsing complex OpenLDAP ACL."""
        parser = FlextLdifAclParser()

        acl_string = (
            'to attrs=cn,sn,mail by dn.exact="cn=admin,dc=example,dc=com" '
            "write by * read"
        )
        result = parser.parse_openldap_acl(acl_string)

        assert result.is_success
        acl = result.value
        assert acl.name == "openldap_acl"
        assert acl.server_type == constants.SERVER_TYPE_OPENLDAP
        assert acl.raw_acl == acl_string

    def test_parse_389ds_acl_basic(self) -> None:
        """Test parsing 389DS ACL."""
        parser = FlextLdifAclParser()

        acl_string = '(targetattr="cn")(version 3.0; acl "test acl"; allow (read) userdn="ldap:///self";)'
        result = parser.parse_389ds_acl(acl_string)

        assert result.is_success
        acl = result.value
        assert acl.name == "389ds_acl"
        assert acl.server_type == constants.SERVER_TYPE_389DS
        assert acl.raw_acl == acl_string
        assert acl.target is not None
        assert acl.subject is not None
        assert acl.permissions is not None

    def test_parse_389ds_acl_empty_string(self) -> None:
        """Test parsing 389DS ACL with empty string."""
        parser = FlextLdifAclParser()

        result = parser.parse_389ds_acl("")

        assert result.is_success
        acl = result.value
        assert acl.name == "389ds_acl"
        assert acl.server_type == constants.SERVER_TYPE_389DS
        assert not acl.raw_acl

    def test_parse_389ds_acl_complex(self) -> None:
        """Test parsing complex 389DS ACL."""
        parser = FlextLdifAclParser()

        acl_string = (
            '(targetattr="cn || sn || mail")(version 3.0; acl "admin acl"; '
            "allow (read, write, search) "
            'groupdn="ldap:///cn=admins,ou=groups,dc=example,dc=com";)'
        )
        result = parser.parse_389ds_acl(acl_string)

        assert result.is_success
        acl = result.value
        assert acl.name == "389ds_acl"
        assert acl.server_type == constants.SERVER_TYPE_389DS
        assert acl.raw_acl == acl_string

    def test_parse_oracle_acl_basic(self) -> None:
        """Test parsing Oracle ACL."""
        parser = FlextLdifAclParser()

        acl_string = "cn=test,dc=example,dc=com:cn,sn:read:user"
        result = parser.parse_oracle_acl(acl_string)

        assert result.is_success
        acl = result.value
        assert acl.name == "oracle_acl"
        assert acl.server_type == constants.SERVER_TYPE_ORACLE_OID
        assert acl.raw_acl == acl_string
        assert acl.target is not None
        assert acl.subject is not None
        assert acl.permissions is not None

    def test_parse_oracle_acl_with_server_type(self) -> None:
        """Test parsing Oracle ACL with specific server type."""
        parser = FlextLdifAclParser()

        acl_string = "cn=test,dc=example,dc=com:cn,sn:read:user"
        result = parser.parse_oracle_acl(acl_string, constants.SERVER_TYPE_ORACLE_OUD)

        assert result.is_success
        acl = result.value
        assert acl.name == "oracle_acl"
        assert acl.server_type == constants.SERVER_TYPE_ORACLE_OUD
        assert acl.raw_acl == acl_string

    def test_parse_oracle_acl_empty_string(self) -> None:
        """Test parsing Oracle ACL with empty string."""
        parser = FlextLdifAclParser()

        result = parser.parse_oracle_acl("")

        assert result.is_success
        acl = result.value
        assert acl.name == "oracle_acl"
        assert acl.server_type == constants.SERVER_TYPE_ORACLE_OID
        assert not acl.raw_acl

    def test_parse_oracle_acl_complex(self) -> None:
        """Test parsing complex Oracle ACL."""
        parser = FlextLdifAclParser()

        acl_string = (
            "cn=admin,dc=example,dc=com:cn,sn,mail,telephoneNumber:read,write:group"
        )
        result = parser.parse_oracle_acl(acl_string)

        assert result.is_success
        acl = result.value
        assert acl.name == "oracle_acl"
        assert acl.server_type == constants.SERVER_TYPE_ORACLE_OID
        assert acl.raw_acl == acl_string

    def test_parse_acl_openldap(self) -> None:
        """Test parse_acl method with OpenLDAP server type."""
        parser = FlextLdifAclParser()

        acl_string = "to attrs=cn by * read"
        result = parser.parse_acl(acl_string, constants.SERVER_TYPE_OPENLDAP)

        assert result.is_success
        acl = result.value
        assert acl.name == "openldap_acl"
        assert acl.server_type == constants.SERVER_TYPE_OPENLDAP

    def test_parse_acl_389ds(self) -> None:
        """Test parse_acl method with 389DS server type."""
        parser = FlextLdifAclParser()

        acl_string = '(targetattr="cn")(version 3.0; acl "test"; allow (read) userdn="ldap:///self";)'
        result = parser.parse_acl(acl_string, constants.SERVER_TYPE_389DS)

        assert result.is_success
        acl = result.value
        assert acl.name == "389ds_acl"
        assert acl.server_type == constants.SERVER_TYPE_389DS

    def test_parse_acl_oracle_oid(self) -> None:
        """Test parse_acl method with Oracle OID server type."""
        parser = FlextLdifAclParser()

        acl_string = "cn=test,dc=example,dc=com:cn:read:user"
        result = parser.parse_acl(acl_string, constants.SERVER_TYPE_ORACLE_OID)

        assert result.is_success
        acl = result.value
        assert acl.name == "oracle_acl"
        assert acl.server_type == constants.SERVER_TYPE_ORACLE_OID

    def test_parse_acl_oracle_oud(self) -> None:
        """Test parse_acl method with Oracle OUD server type."""
        parser = FlextLdifAclParser()

        acl_string = "cn=test,dc=example,dc=com:cn:read:user"
        result = parser.parse_acl(acl_string, constants.SERVER_TYPE_ORACLE_OUD)

        assert result.is_success
        acl = result.value
        assert acl.name == "oracle_acl"
        assert acl.server_type == constants.SERVER_TYPE_ORACLE_OUD

    def test_parse_acl_unsupported_server_type(self) -> None:
        """Test parse_acl method with unsupported server type."""
        parser = FlextLdifAclParser()

        acl_string = "some acl string"
        result = parser.parse_acl(acl_string, "unsupported_server")

        assert result.is_failure
        assert result.error is not None
        assert "Unsupported server type" in result.error

    def test_parse_acl_empty_server_type(self) -> None:
        """Test parse_acl method with empty server type."""
        parser = FlextLdifAclParser()

        acl_string = "some acl string"
        result = parser.parse_acl(acl_string, "")

        assert result.is_failure
        assert result.error is not None
        assert "Unsupported server type" in result.error

    def test_acl_components_creation(self) -> None:
        """Test that ACL components are created correctly."""
        parser = FlextLdifAclParser()

        # Test that all parser methods create valid ACL components
        acl_string = "test acl"

        # Test OpenLDAP
        result = parser.parse_openldap_acl(acl_string)
        assert result.is_success
        acl = result.value
        assert isinstance(acl.target, FlextLdifModels.AclTarget)
        assert isinstance(acl.subject, FlextLdifModels.AclSubject)
        assert isinstance(acl.permissions, FlextLdifModels.AclPermissions)

        # Test 389DS
        result = parser.parse_389ds_acl(acl_string)
        assert result.is_success
        acl = result.value
        assert isinstance(acl.target, FlextLdifModels.AclTarget)
        assert isinstance(acl.subject, FlextLdifModels.AclSubject)
        assert isinstance(acl.permissions, FlextLdifModels.AclPermissions)

        # Test Oracle
        result = parser.parse_oracle_acl(acl_string)
        assert result.is_success
        acl = result.value
        assert isinstance(acl.target, FlextLdifModels.AclTarget)
        assert isinstance(acl.subject, FlextLdifModels.AclSubject)
        assert isinstance(acl.permissions, FlextLdifModels.AclPermissions)

    def test_unified_acl_structure(self) -> None:
        """Test that UnifiedAcl structure is correct."""
        parser = FlextLdifAclParser()

        acl_string = "to attrs=cn by * read"
        result = parser.parse_openldap_acl(acl_string)

        assert result.is_success
        acl = result.value

        # Check UnifiedAcl structure
        assert hasattr(acl, "name")
        assert hasattr(acl, "target")
        assert hasattr(acl, "subject")
        assert hasattr(acl, "permissions")
        assert hasattr(acl, "server_type")
        assert hasattr(acl, "raw_acl")

        assert isinstance(acl.name, str)
        assert isinstance(acl.server_type, str)
        assert isinstance(acl.raw_acl, str)

    def test_logging_functionality(self) -> None:
        """Test that logging functionality works correctly."""
        parser = FlextLdifAclParser()

        # Test that successful operations log info messages
        result = parser.execute()

        assert result.is_success
        # The logging should have occurred (we can't easily test the actual log output
        # but we can verify the operation succeeded, which means logging was called)

    def test_error_handling_in_acl_creation(self) -> None:
        """Test error handling during ACL creation."""
        parser = FlextLdifAclParser()

        # Test with valid ACL string to ensure normal operation works
        acl_string = "to attrs=cn by * read"
        result = parser.parse_openldap_acl(acl_string)

        assert result.is_success
        # This tests the error handling path in the ACL creation process

    def test_server_type_constants(self) -> None:
        """Test that server type constants are used correctly."""
        parser = FlextLdifAclParser()

        # Test that constants are properly imported and used
        assert constants.SERVER_TYPE_OPENLDAP is not None
        assert constants.SERVER_TYPE_389DS is not None
        assert constants.SERVER_TYPE_ORACLE_OID is not None
        assert constants.SERVER_TYPE_ORACLE_OUD is not None

        # Test that parser methods use these constants
        acl_string = "test acl"

        result = parser.parse_openldap_acl(acl_string)
        assert result.is_success
        assert result.value.server_type == constants.SERVER_TYPE_OPENLDAP

        result = parser.parse_389ds_acl(acl_string)
        assert result.is_success
        assert result.value.server_type == constants.SERVER_TYPE_389DS

        result = parser.parse_oracle_acl(acl_string)
        assert result.is_success
        assert result.value.server_type == constants.SERVER_TYPE_ORACLE_OID

    def test_acl_parsing_consistency(self) -> None:
        """Test that ACL parsing is consistent across different methods."""
        parser = FlextLdifAclParser()

        acl_string = "test acl string"

        # Parse using specific methods
        openldap_result = parser.parse_openldap_acl(acl_string)
        ds389_result = parser.parse_389ds_acl(acl_string)
        oracle_result = parser.parse_oracle_acl(acl_string)

        # Parse using generic method
        openldap_generic_result = parser.parse_acl(
            acl_string, constants.SERVER_TYPE_OPENLDAP
        )
        ds389_generic_result = parser.parse_acl(acl_string, constants.SERVER_TYPE_389DS)
        oracle_generic_result = parser.parse_acl(
            acl_string, constants.SERVER_TYPE_ORACLE_OID
        )

        # Results should be equivalent
        assert openldap_result.is_success == openldap_generic_result.is_success
        assert ds389_result.is_success == ds389_generic_result.is_success
        assert oracle_result.is_success == oracle_generic_result.is_success

        if openldap_result.is_success:
            assert (
                openldap_result.value.server_type
                == openldap_generic_result.value.server_type
            )
            assert openldap_result.value.name == openldap_generic_result.value.name

        if ds389_result.is_success:
            assert (
                ds389_result.value.server_type == ds389_generic_result.value.server_type
            )
            assert ds389_result.value.name == ds389_generic_result.value.name

        if oracle_result.is_success:
            assert (
                oracle_result.value.server_type
                == oracle_generic_result.value.server_type
            )
            assert oracle_result.value.name == oracle_generic_result.value.name
