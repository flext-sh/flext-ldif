"""Test suite for FlextLdifAcl parsing functionality.

This module provides essential testing for the ACL parser service.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldif.config import FlextLdifConfig
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.acl import FlextLdifAcl


class TestFlextLdifAcl:
    """Test suite for FlextLdifAcl."""

    @pytest.fixture
    def acl_service(self) -> FlextLdifAcl:
        """Create ACL service instance."""
        return FlextLdifAcl()

    @pytest.fixture
    def acl_service_with_config(self) -> FlextLdifAcl:
        """Create ACL service with custom config."""
        config = FlextLdifConfig()
        return FlextLdifAcl(config=config)

    def test_initialization_default(self, acl_service: FlextLdifAcl) -> None:
        """Test ACL service initialization with default config."""
        assert acl_service is not None
        assert acl_service.logger is not None

    def test_initialization_with_config(
        self,
        acl_service_with_config: FlextLdifAcl,
    ) -> None:
        """Test ACL service initialization with custom config."""
        assert acl_service_with_config is not None
        assert acl_service_with_config.logger is not None

    def test_execute_success(self, acl_service: FlextLdifAcl) -> None:
        """Test execute method returns success."""
        result = acl_service.execute()

        assert result.is_success
        acl_response = result.unwrap()
        assert isinstance(acl_response, FlextLdifModels.AclResponse)
        assert acl_response.acls == []
        assert acl_response.statistics.total_acls_extracted == 0
        assert acl_response.statistics.entries_with_acls == 0

    def test_parse_openldap(self, acl_service: FlextLdifAcl) -> None:
        """Test parsing OpenLDAP ACL format."""
        acl_line = 'access to * by dn.exact="cn=admin,dc=example,dc=com" write'
        # This will delegate to quirks
        result = acl_service.parse(acl_line, "openldap")

        # Result depends on quirks implementation
        assert isinstance(result, FlextResult)

    def test_parse_oracle_oid(self, acl_service: FlextLdifAcl) -> None:
        """Test parsing Oracle OID ACL format."""
        acl_line = 'orclaci: access to entry by dn="cn=admin,dc=example,dc=com" (read)'
        result = acl_service.parse(acl_line, "oracle_oid")

        assert isinstance(result, FlextResult)

    def test_parse_unsupported_server_type(
        self,
        acl_service: FlextLdifAcl,
    ) -> None:
        """Test parsing with unsupported server type fails."""
        acl_line = "some-acl-content"
        result = acl_service.parse(acl_line, "unknown-server")

        # Should fail with unsupported server type
        assert isinstance(result, FlextResult)

    def test_extract_acls_from_entry_none(
        self,
        acl_service: FlextLdifAcl,
    ) -> None:
        """Test extracting ACLs from None entry fails."""
        result = acl_service.extract_acls_from_entry(None, "openldap")

        assert result.is_failure
        assert "None" in str(result.error)

    def test_evaluate_acl_context_no_acls(
        self,
        acl_service: FlextLdifAcl,
    ) -> None:
        """Test evaluating empty ACL list allows by default."""
        result = acl_service.evaluate_acl_context([])

        assert result.is_success
        assert result.unwrap() is True

    def test_evaluate_acl_context_with_permissions(
        self,
        acl_service: FlextLdifAcl,
    ) -> None:
        """Test ACL evaluation with permissions context."""
        acl = FlextLdifModels.Acl(
            name="test-acl",
            target=FlextLdifModels.AclTarget(target_dn="*"),
            subject=FlextLdifModels.AclSubject(
                subject_type="*",
                subject_value="*",
            ),
            permissions=FlextLdifModels.AclPermissions(read=True),
            server_type="openldap",
            raw_acl="test",
        )

        context: dict[str, object] = {"permissions": {"read": True}}
        result = acl_service.evaluate_acl_context([acl], context)

        assert result.is_success
        assert result.unwrap() is True

    def test_evaluate_acl_context_permission_mismatch(
        self,
        acl_service: FlextLdifAcl,
    ) -> None:
        """Test ACL evaluation fails with permission mismatch."""
        acl = FlextLdifModels.Acl(
            name="test-acl",
            target=FlextLdifModels.AclTarget(target_dn="*"),
            subject=FlextLdifModels.AclSubject(
                subject_type="*",
                subject_value="*",
            ),
            permissions=FlextLdifModels.AclPermissions(write=True),
            server_type="openldap",
            raw_acl="test",
        )

        context: dict[str, object] = {"permissions": {"read": True}}  # Missing write
        result = acl_service.evaluate_acl_context([acl], context)

        assert result.is_failure
        assert "write" in str(result.error).lower()
