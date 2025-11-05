"""Comprehensive tests for advanced ACL conversion utilities.

Tests demonstrate zero-data-loss OID→OUD conversion using the advanced hook-based
system with FlextLdifUtilities.AclConverter and related utilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import pytest

from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.utilities import FlextLdifUtilities


class TestAdvancedAclConversion:
    """Test advanced ACL conversion with hook-based utilities."""

    def test_comprehensive_oid_to_oud_conversion(self) -> None:
        """Test complete OID→OUD conversion preserving all data."""
        # Complex OID ACL with all special features
        oid_acl_content = (
            'orclentrylevelaci: access to entry by group="cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com" '
            "added_object_constraint=(objectClass=person) filter=((dept=engineering) & (location=usa)) "
            "(self_write, proxy, browse, auth)"
        )

        # Parse with OID quirk
        oid = FlextLdifServersOid()
        parse_result = oid.parse(oid_acl_content)

        assert parse_result.is_success
        oid_acl = parse_result.unwrap()

        # Verify comprehensive metadata extraction
        assert oid_acl.metadata is not None
        assert oid_acl.metadata.extensions is not None
        extensions = oid_acl.metadata.extensions

        # Check all OID-specific features captured
        assert extensions["acl_type"] == "orclentrylevelaci"
        assert "objectClass=person" in extensions["added_object_constraint"]
        assert "(dept=engineering) & (location=usa)" in extensions["filter_clause"]
        assert "multi_subject_blocks" in extensions
        assert "oid_specific_permissions" in extensions

        # Verify conversion metadata
        assert oud_acl.metadata is not None
        assert oud_acl.metadata.server_type == "oracle_oud"
        oud_extensions = oud_acl.metadata.extensions
        assert oud_extensions["converted_from_oid"] is True
        assert "oud_conversion_comments" in oud_extensions

        # Verify permission conversion (self_write → write, proxy removed)
        assert oud_acl.permissions.write is True  # Promoted from self_write
        assert oud_acl.permissions.read is True  # From browse
        assert oud_acl.permissions.search is True  # From browse
        assert oud_acl.permissions.compare is True  # From auth
        assert oud_acl.permissions.proxy is False  # Not supported in OUD

        # Verify comprehensive comment generation
        comments = oud_extensions["oud_conversion_comments"]
        comment_text = "\n".join(comments)
        assert "OID filter clause:" in comment_text
        assert "OID entry-level constraint:" in comment_text
        assert "Converted to OUD targattrfilters" in comment_text

    def test_permission_mapper_advanced_features(self) -> None:
        """Test advanced permission mapping utilities."""
        mapper = FlextLdifUtilities.PermissionMapper

        # Test permission compatibility matrix
        assert mapper.is_permission_supported("self_write", "oracle_oid") is True
        assert mapper.is_permission_supported("self_write", "oracle_oud") is False
        assert mapper.is_permission_supported("proxy", "oracle_oud") is False

        # Test unsupported permission detection
        oid_permissions = ["read", "write", "self_write", "proxy", "browse"]
        unsupported = mapper.get_unsupported_permissions(oid_permissions, "oracle_oud")
        assert "self_write" in unsupported
        assert "proxy" in unsupported
        assert "browse" in unsupported
        assert "read" not in unsupported
        assert "write" not in unsupported

        # Test permission alternatives
        alternatives = mapper.suggest_permission_alternatives(
            "self_write", "oracle_oud"
        )
        assert "write" in alternatives

        browse_alternatives = mapper.suggest_permission_alternatives(
            "browse", "oracle_oud"
        )
        assert "read" in browse_alternatives
        assert "search" in browse_alternatives

        proxy_alternatives = mapper.suggest_permission_alternatives(
            "proxy", "oracle_oud"
        )
        assert len(proxy_alternatives) == 0  # No equivalent

    def test_subject_transformer_advanced_classification(self) -> None:
        """Test advanced subject classification and transformation."""
        transformer = FlextLdifUtilities.SubjectTransformer

        # Test comprehensive subject classification
        test_subjects = [
            ("*", "anonymous"),
            ("self", "self"),
            ('group="cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com"', "group_dn"),
            ('"cn=john,ou=users,dc=example,dc=com"', "user_dn"),
            ("dnattr=(manager)", "dynamic_group_dnattr"),
            ("guidattr=(memberGuid)", "dynamic_group_guidattr"),
            ("groupattr=(uniqueMember)", "dynamic_group_attr"),
            ('userattr="department#GROUPDN"', "bind_rules"),
            ("unknown_format", "user_dn"),  # Fallback
        ]

        for subject_str, expected_type in test_subjects:
            classified = transformer.classify_subject_type(subject_str)
            assert classified == expected_type, f"Failed for {subject_str}"

        # Test value extraction
        assert (
            transformer.extract_subject_value('group="cn=test"', "group_dn")
            == "cn=test"
        )
        assert (
            transformer.extract_subject_value(
                "dnattr=(manager)", "dynamic_group_dnattr"
            )
            == "manager"
        )
        assert transformer.extract_subject_value('"cn=user"', "user_dn") == "cn=user"

    def test_metadata_processor_feature_analysis(self) -> None:
        """Test advanced metadata processing and feature analysis."""
        processor = FlextLdifUtilities.MetadataProcessor

        # Create metadata with OID features
        metadata = FlextLdifModels.QuirkMetadata(
            original_format="orclentrylevelaci: test",
            quirk_type="oid",
            server_type="oracle_oid",
            extensions={
                "acl_type": "orclentrylevelaci",
                "filter_clause": "(objectClass=person)",
                "added_object_constraint": "objectClass=user",
                "multi_subjects": [{"subject": "self", "permissions": "read"}],
                "oid_permissions": ["self_write", "proxy"],
                "unconvertible_features": [],
            },
        )

        # Test feature extraction
        features = processor.extract_oid_features(metadata)
        assert features["acl_type"] == "orclentrylevelaci"
        assert features["filter_clause"] == "(objectClass=person)"
        assert features["added_object_constraint"] == "objectClass=user"
        assert len(features["multi_subjects"]) == 1
        assert "self_write" in features["oid_permissions"]

        # Test convertibility analysis
        assert (
            processor.is_feature_convertible(
                "filter_clause", "(objectClass=person)", "oracle_oud"
            )
            is True
        )
        assert (
            processor.is_feature_convertible(
                "filter_clause", "((a=b) & (c=d))", "oracle_oud"
            )
            is False
        )
        assert (
            processor.is_feature_convertible(
                "added_object_constraint", "objectClass=person", "oracle_oud"
            )
            is True
        )
        assert (
            processor._are_permissions_convertible(["read", "write"], "oracle_oud")
            is True
        )
        assert (
            processor._are_permissions_convertible(
                ["self_write", "proxy"], "oracle_oud"
            )
            is False
        )

    def test_hook_system_extensibility(self) -> None:
        """Test that the hook system allows extension and customization."""
        converter = FlextLdifUtilities.AclConverter

        # Test hook registration
        def custom_permission_hook(permissions, source, target):
            return ["custom_read", "custom_write"], []

        converter.register_permission_hook(
            "test_source", "test_target", custom_permission_hook
        )

        # Verify hook is registered
        key = ("test_source", "test_target")
        assert key in converter._permission_hooks
        assert len(converter._permission_hooks[key]) == 1

        # Test comment hook registration
        def custom_comment_hook(metadata_info, source, target):
            return [f"# Custom conversion from {source} to {target}"]

        converter.register_comment_hook(
            "test_source", "test_target", custom_comment_hook
        )

        # Test comment generation with hook
        comments = converter.generate_conversion_comments(
            {}, "test_source", "test_target"
        )
        assert "# Custom conversion from test_source to test_target" in comments

    def test_zero_data_loss_roundtrip(self) -> None:
        """Test that OID→OUD conversion preserves all data without loss."""
        # Complex OID ACL with maximum features
        complex_oid_acl = (
            "orclaci: access to attr=(cn,sn,mail) filter=((objectClass=person) & (dept=hr)) "
            'by group="cn=managers,ou=groups,dc=example,dc=com" (self_write, proxy, browse) '
            "by dnattr=(manager) (read, search) "
            "by guidattr=(memberGuid) (compare)"
        )

        # Parse with OID
        oid = FlextLdifServersOid()
        parse_result = oid.parse(complex_oid_acl)
        assert parse_result.is_success

        parse_result.unwrap()

        # Verify all original data is preserved in metadata
        assert "original_oid_features" in converted_metadata
        original_features = converted_metadata["original_oid_features"]

        # Check that all original OID features are documented
        assert original_features["filter_clause"] != ""
        assert (
            len(original_features["multi_subjects"]) >= 2
        )  # Multiple subjects preserved
        assert len(original_features["oid_permissions"]) > 0

        # Verify conversion comments document everything
        comments = converted_metadata.get("oud_conversion_comments", [])
        comment_text = "\n".join(comments)

        # All features should be mentioned in comments
        assert "filter" in comment_text.lower()
        assert (
            "multi-subject" in comment_text.lower()
            or len(original_features["multi_subjects"]) <= 1
        )

        # Verify the converted ACL is functional
        assert converted_acl.server_type == "oracle_oud"
        assert converted_acl.permissions is not None
        assert converted_acl.target is not None
        assert converted_acl.subject is not None

    def test_advanced_utilities_integration(self) -> None:
        """Test that all advanced utilities work together seamlessly."""
        # Create a complex conversion scenario
        oid_acl_data = FlextLdifModels.Acl(
            name="Complex OID ACL",
            target=FlextLdifModels.AclTarget(
                target_dn="*", attributes=["cn", "sn", "mail"]
            ),
            subject=FlextLdifModels.AclSubject(
                subject_type="bind_rules", subject_value='userattr="department#GROUPDN"'
            ),
            permissions=FlextLdifModels.AclPermissions(
                read=True, write=True, self_write=True, proxy=True
            ),
            server_type="oracle_oid",
            raw_acl="orclaci: complex test",
            metadata=FlextLdifModels.QuirkMetadata(
                original_format="orclaci: test",
                quirk_type="oid",
                server_type="oracle_oid",
                extensions={
                    "acl_type": "orclaci",
                    "filter_clause": "(dept=engineering)",
                    "oid_specific_permissions": ["self_write", "proxy"],
                },
            ),
        )

        # Test full conversion pipeline using advanced utilities
        converter = FlextLdifUtilities.AclConverter

        result = converter.convert_acl_with_hooks(
            oid_acl_data, "oracle_oid", "oracle_oud"
        )
        assert result.is_success

        converted_acl = result.unwrap()

        # Verify comprehensive conversion
        assert converted_acl.server_type == "oracle_oud"
        assert converted_acl.permissions.write is True  # self_write promoted
        assert converted_acl.permissions.proxy is False  # proxy removed

        # Verify metadata preservation
        assert converted_acl.metadata is not None
        assert converted_acl.metadata.extensions["converted_from"] == "oracle_oid"
        assert "conversion_comments" in converted_acl.metadata.extensions
        assert "original_metadata" in converted_acl.metadata.extensions

    def test_performance_and_scalability(self) -> None:
        """Test that advanced utilities perform well with multiple conversions."""
        import time

        # Create multiple test ACLs
        test_acls = []
        for i in range(10):
            acl = FlextLdifModels.Acl(
                name=f"Test ACL {i}",
                target=FlextLdifModels.AclTarget(target_dn="*", attributes=[]),
                subject=FlextLdifModels.AclSubject(
                    subject_type="self", subject_value="self"
                ),
                permissions=FlextLdifModels.AclPermissions(
                    read=True, write=True, self_write=True
                ),
                server_type="oracle_oid",
                raw_acl=f"orclaci: test {i}",
                metadata=FlextLdifModels.QuirkMetadata(
                    quirk_type="oid",
                    server_type="oracle_oid",
                    extensions={
                        "acl_type": "orclaci",
                        "oid_specific_permissions": ["self_write"],
                    },
                ),
            )
            test_acls.append(acl)

        # Time the conversions
        start_time = time.time()

        converter = FlextLdifUtilities.AclConverter
        converted_count = 0

        for acl in test_acls:
            result = converter.convert_acl_with_hooks(acl, "oracle_oid", "oracle_oud")
            if result.is_success:
                converted_count += 1

        end_time = time.time()
        elapsed = end_time - start_time

        # Verify all conversions succeeded
        assert converted_count == len(test_acls)

        # Verify reasonable performance (should complete quickly)
        assert elapsed < 1.0  # Less than 1 second for 10 conversions

        # Calculate conversion rate
        conversions_per_second = len(test_acls) / elapsed
        assert conversions_per_second > 10  # At least 10 conversions per second


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
