"""Comprehensive tests for advanced server quirks utilities with complex transformation scenarios.

Tests demonstrate the complete ecosystem of server-to-server transformations using:
- Generalized subject transformation mapping
- Advanced permission matrices
- Attribute name transformations
- DN format transformations
- Schema migration planning
- Operational attribute handling
- Server capability analysis
- Migration feasibility assessment

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import pytest
from flext_core import FlextResult

from flext_ldif.models import FlextLdifModels
from flext_ldif.utilities import FlextLdifUtilities


class TestAdvancedServerQuirksComprehensive:
    """Test comprehensive server quirks with advanced transformation utilities."""

    def test_generalized_subject_transformation_matrix(self) -> None:
        """Test the advanced subject transformation mapping system."""
        transformer = FlextLdifUtilities.AclConverter

        # Test Oracle OID → OUD transformations
        oid_subject = FlextLdifModels.AclSubject(
            subject_type="dynamic_group_dnattr", subject_value="manager"
        )

        transformed_subject = transformer.transform_subject_advanced(
            oid_subject, "oracle_oid", "oracle_oud"
        )

        assert transformed_subject is not None
        assert transformed_subject.subject_type == "bind_rules"
        assert 'userattr="manager#LDAPURL"' in transformed_subject.subject_value

        # Test wildcard transformations (generic across servers)
        anonymous_subject = FlextLdifModels.AclSubject(
            subject_type="anonymous", subject_value="*"
        )

        transformed_generic = transformer.transform_subject_advanced(
            anonymous_subject, "any_server", "any_target"
        )

        assert transformed_generic.subject_type == "anonymous"
        assert transformed_generic.subject_value == "*"

    def test_advanced_permission_transformation_matrix(self) -> None:
        """Test complex permission transformations between multiple server types."""
        mapper = FlextLdifUtilities.PermissionMapper

        # Test Oracle OID extended permissions
        oid_permissions = [
            "self_write",
            "proxy",
            "browse",
            "auth",
            "filterread",
            "export",
        ]
        allowed, denied, log = mapper.transform_permissions_advanced(
            oid_permissions, "oracle_oid", "oracle_oud"
        )

        # Verify transformations
        assert "write" in allowed  # self_write → write
        assert "read" in allowed and "search" in allowed  # browse → read + search
        assert "compare" in allowed  # auth → compare
        assert "proxy" in denied  # Not supported in OUD

        # Check transformation log
        assert log["self_write"] == ["write"]
        assert set(log["browse"]) == {"read", "search"}
        assert log["proxy"] == []  # Denied

        # Test Active Directory → Oracle OUD
        ad_permissions = [
            "control_access",
            "create_child",
            "delete_child",
            "read_property",
        ]
        ad_allowed, _ad_denied, _ad_log = mapper.transform_permissions_advanced(
            ad_permissions, "active_directory", "oracle_oud"
        )

        assert "write" in ad_allowed  # control_access → write
        assert "add" in ad_allowed  # create_child → add
        assert "delete" in ad_allowed  # delete_child → delete
        assert "read" in ad_allowed  # read_property → read

    def test_comprehensive_attribute_name_mapping(self) -> None:
        """Test advanced attribute name transformations across multiple servers."""
        mapper = FlextLdifUtilities.AttributeNameMapper

        # Test Oracle OID → OUD mappings
        test_mappings = [
            ("orclguid", "oracle_oid", "oracle_oud", "entryUUID"),
            ("orclobjectguid", "oracle_oid", "oracle_oud", "entryUUID"),
            (
                "createTimestamp",
                "oracle_oid",
                "oracle_oud",
                "createTimestamp",
            ),  # Preserved
        ]

        for attr, source, target, expected in test_mappings:
            transformed = mapper.transform_attribute_name(attr, source, target)
            assert transformed == expected, (
                f"Failed for {attr}: expected {expected}, got {transformed}"
            )

        # Test Active Directory → Oracle OUD mappings
        ad_mappings = [
            ("objectGUID", "active_directory", "oracle_oud", "entryUUID"),
            ("sAMAccountName", "active_directory", "oracle_oud", "uid"),
            ("userPrincipalName", "active_directory", "oracle_oud", "mail"),
            ("whenCreated", "active_directory", "oracle_oud", "createTimestamp"),
        ]

        for attr, source, target, expected in ad_mappings:
            transformed = mapper.transform_attribute_name(attr, source, target)
            assert transformed == expected

        # Test attribute alias resolution
        aliases = mapper.get_attribute_aliases("cn", "oracle_oud")
        assert "commonName" in aliases
        assert "cn" in aliases

        # Test case normalization
        normalized = mapper.normalize_attribute_case("CN", "oracle_oud")
        assert normalized == "cn"  # OUD prefers lowercase

        preserved_case = mapper.normalize_attribute_case("CN", "active_directory")
        assert preserved_case == "CN"  # AD preserves case

    def test_advanced_dn_transformation_system(self) -> None:
        """Test sophisticated DN format transformations between servers."""
        transformer = FlextLdifUtilities.DnTransformer

        # Test Active Directory → Oracle OUD DN transformation
        ad_dn = "CN=John Smith,OU=Users,DC=example,DC=com"
        transformed_dn = transformer.transform_dn(
            ad_dn, "active_directory", "oracle_oud"
        )

        # OUD prefers lowercase attribute names with space after comma
        expected_components = ["cn=john smith", "ou=users", "dc=example", "dc=com"]
        transformed_lower = transformed_dn.lower()

        for component in expected_components:
            assert component in transformed_lower

        # Test DN validation
        validation = transformer.validate_dn_format("cn=test,ou=users", "oracle_oud")
        assert validation["valid"] is True
        assert validation["components_count"] == 2

        # Test invalid DN
        invalid_validation = transformer.validate_dn_format("", "oracle_oud")
        assert invalid_validation["valid"] is False
        assert "DN is empty" in invalid_validation["issues"]

    def test_schema_transformation_and_migration_planning(self) -> None:
        """Test advanced schema transformation utilities."""
        transformer = FlextLdifUtilities.SchemaTransformer

        # Test object class transformations
        test_oc_mappings = [
            ("orcluser", "oracle_oid", "oracle_oud", "inetOrgPerson"),
            ("orclgroup", "oracle_oid", "oracle_oud", "groupOfNames"),
            ("user", "active_directory", "oracle_oud", "inetOrgPerson"),
            ("group", "active_directory", "oracle_oud", "groupOfNames"),
        ]

        for oc, source, target, expected in test_oc_mappings:
            transformed = transformer.transform_objectclass(oc, source, target)
            assert transformed == expected

        # Test required attributes checking
        required_attrs = transformer.get_required_attributes(
            "inetOrgPerson", "oracle_oud"
        )
        assert "cn" in required_attrs
        assert "sn" in required_attrs

        # Test entry completeness validation
        test_entry_attrs = {
            "cn": ["John Smith"],
            "sn": ["Smith"],
            "mail": ["john@example.com"],
        }
        validation = transformer.validate_entry_completeness(
            ["inetOrgPerson"], test_entry_attrs, "oracle_oud"
        )
        assert validation["valid"] is True
        assert validation["completeness_score"] == 1.0

        # Test incomplete entry
        incomplete_attrs = {"cn": ["John Smith"]}  # Missing required 'sn'
        incomplete_validation = transformer.validate_entry_completeness(
            ["inetOrgPerson"], incomplete_attrs, "oracle_oud"
        )
        assert incomplete_validation["valid"] is False
        assert len(incomplete_validation["missing_attributes"]) > 0

        # Test migration plan generation
        sample_entries = [
            {
                "objectClass": ["orcluser"],
                "cn": ["John"],
                "sn": ["Smith"],
                "orclguid": ["123"],
            },
            {
                "objectClass": ["orclgroup"],
                "cn": ["Admins"],
                "member": ["cn=John"],
                "orclguid": ["456"],
            },
        ]

        migration_plan = transformer.suggest_schema_migration_plan(
            sample_entries, "oracle_oid", "oracle_oud"
        )

        assert "objectclass_usage" in migration_plan
        assert "transformation_plan" in migration_plan
        assert migration_plan["objectclass_usage"]["orcluser"] == 1
        assert migration_plan["objectclass_usage"]["orclgroup"] == 1

        # Check transformation suggestions
        transformations = migration_plan["transformation_plan"]
        oc_transformations = [
            t for t in transformations if t["type"] == "objectclass_transformation"
        ]
        assert len(oc_transformations) > 0

    def test_operational_attribute_handling_advanced(self) -> None:
        """Test sophisticated operational attribute management."""
        handler = FlextLdifUtilities.OperationalAttributeHandler

        # Test operational attribute detection across servers
        test_attrs = [
            ("createTimestamp", "oracle_oid", True),
            ("orclguid", "oracle_oid", True),
            ("entryUUID", "oracle_oud", True),
            ("cn", "oracle_oid", False),  # Not operational
            ("objectGUID", "active_directory", True),
            ("sAMAccountName", "active_directory", False),  # Not operational
        ]

        for attr, server, expected in test_attrs:
            result = handler.is_operational_attribute(attr, server)
            assert result == expected, (
                f"Failed for {attr} on {server}: expected {expected}, got {result}"
            )

        # Test preservation rules
        assert (
            handler.should_preserve_on_migration("createTimestamp", "oracle_oid")
            is True
        )
        assert handler.should_preserve_on_migration("orclguid", "oracle_oid") is False

        # Test attribute filtering
        mixed_attrs = {
            "cn": ["John Smith"],
            "createTimestamp": ["20250101000000Z"],
            "orclguid": ["12345"],
            "mail": ["john@example.com"],
        }

        filtered = handler.filter_operational_attributes(
            mixed_attrs, "oracle_oid", preserve_important=True
        )
        assert "cn" in filtered  # Non-operational preserved
        assert "mail" in filtered  # Non-operational preserved
        assert "createTimestamp" in filtered  # Important operational preserved
        assert "orclguid" not in filtered  # Non-important operational removed

        # Test operational attribute transformation
        transformed = handler.transform_operational_attributes(
            mixed_attrs, "oracle_oid", "oracle_oud"
        )

        # Should transform orclguid → entryUUID (if supported by transformation rules)
        assert "cn" in transformed
        assert "createTimestamp" in transformed  # Should be preserved

    def test_server_capability_matrix_and_migration_analysis(self) -> None:
        """Test comprehensive server capability analysis."""
        capability_matrix = FlextLdifUtilities.ServerCapabilityMatrix

        # Test capability retrieval
        oid_caps = capability_matrix.get_server_capabilities("oracle_oid")
        oud_caps = capability_matrix.get_server_capabilities("oracle_oud")

        assert oid_caps["acl_model"] == "orcl_aci"
        assert oud_caps["acl_model"] == "rfc_aci"
        assert oid_caps["max_dn_length"] == 1000
        assert (
            oud_caps["max_attribute_value_size"] > oid_caps["max_attribute_value_size"]
        )

        # Test migration feasibility analysis
        feasibility = capability_matrix.analyze_migration_feasibility(
            "oracle_oid", "oracle_oud"
        )

        assert feasibility["feasible"] is True  # OID→OUD should be feasible
        assert feasibility["feasibility_score"] > 0.5
        assert (
            len(feasibility["migration_notes"]) > 0
        )  # Should note ACL transformation needed

        # Test problematic migration (AD → OpenLDAP for example)
        problematic = capability_matrix.analyze_migration_feasibility(
            "active_directory", "openldap"
        )
        assert "migration_notes" in problematic

        # Test migration strategy recommendation
        strategy = capability_matrix.recommend_migration_strategy(
            "oracle_oid", "oracle_oud", "medium"
        )

        assert strategy["recommended_strategy"] in {
            "direct_migration",
            "phased_migration",
            "staged_migration_with_validation",
        }
        assert "estimated_effort" in strategy
        assert "migration_phases" in strategy
        assert "required_tools" in strategy

        # Test enterprise-scale migration
        enterprise_strategy = capability_matrix.recommend_migration_strategy(
            "oracle_oid", "oracle_oud", "enterprise"
        )

        # Enterprise migrations should be more complex
        assert (
            enterprise_strategy["estimated_effort"]["estimated_person_days"]
            > strategy["estimated_effort"]["estimated_person_days"]
        )

    def test_comprehensive_compatibility_analysis(self) -> None:
        """Test comprehensive cross-server compatibility analysis."""
        # Test permission compatibility
        perm_mapper = FlextLdifUtilities.PermissionMapper

        oid_oud_compat = perm_mapper.analyze_permission_compatibility(
            "oracle_oid", "oracle_oud"
        )
        assert "compatible_permissions" in oid_oud_compat
        assert "source_only_permissions" in oid_oud_compat
        assert "compatibility_score" in oid_oud_compat

        # OID has more permissions than OUD, so compatibility score should be < 1.0
        assert oid_oud_compat["compatibility_score"] < 1.0
        assert "self_write" in oid_oud_compat["source_only_permissions"]
        assert "proxy" in oid_oud_compat["source_only_permissions"]

        # Test operational attribute compatibility
        op_handler = FlextLdifUtilities.OperationalAttributeHandler
        op_compat = op_handler.analyze_operational_compatibility(
            "oracle_oid", "oracle_oud"
        )

        assert "compatible_operational_attrs" in op_compat
        assert "at_risk_important_attrs" in op_compat
        assert "createTimestamp" in op_compat["compatible_operational_attrs"]

        # Test attribute compatibility
        attr_mapper = FlextLdifUtilities.AttributeNameMapper
        test_attributes = ["cn", "sn", "orclguid", "createTimestamp", "mail"]

        attr_compat = attr_mapper.analyze_attribute_compatibility(
            test_attributes, "oracle_oid", "oracle_oud"
        )

        assert "transformable_attributes" in attr_compat
        assert "preserved_attributes" in attr_compat
        assert "compatibility_score" in attr_compat

        # Should find orclguid → entryUUID transformation
        transformable_names = [
            t["original"] for t in attr_compat["transformable_attributes"]
        ]
        assert "orclguid" in transformable_names

    def test_end_to_end_migration_scenario(self) -> None:
        """Test complete end-to-end migration scenario using all utilities."""
        # Scenario: Migrate Oracle OID environment to Oracle OUD

        # 1. Analyze server capabilities
        capability_matrix = FlextLdifUtilities.ServerCapabilityMatrix
        feasibility = capability_matrix.analyze_migration_feasibility(
            "oracle_oid", "oracle_oud"
        )
        assert feasibility["feasible"] is True

        # 2. Plan schema transformations
        schema_transformer = FlextLdifUtilities.SchemaTransformer
        sample_entries = [
            {
                "objectClass": ["orcluser", "top"],
                "cn": ["John Smith"],
                "sn": ["Smith"],
                "orclguid": ["12345-abcde"],
                "createTimestamp": ["20250101000000Z"],
                "mail": ["john@example.com"],
            },
            {
                "objectClass": ["orclgroup", "top"],
                "cn": ["Engineering"],
                "orclguid": ["67890-fghij"],
                "member": ["cn=John Smith,ou=people,dc=example,dc=com"],
            },
        ]

        migration_plan = schema_transformer.suggest_schema_migration_plan(
            sample_entries, "oracle_oid", "oracle_oud"
        )

        assert migration_plan["migration_complexity_score"] > 0

        # 3. Analyze attribute transformations
        attr_mapper = FlextLdifUtilities.AttributeNameMapper
        attributes_to_migrate = [
            "cn",
            "sn",
            "orclguid",
            "createTimestamp",
            "mail",
            "member",
        ]

        attr_analysis = attr_mapper.analyze_attribute_compatibility(
            attributes_to_migrate, "oracle_oid", "oracle_oud"
        )

        # Should identify orclguid transformation
        assert len(attr_analysis["transformable_attributes"]) > 0

        # 4. Check operational attribute handling
        op_handler = FlextLdifUtilities.OperationalAttributeHandler
        op_analysis = op_handler.analyze_operational_compatibility(
            "oracle_oid", "oracle_oud"
        )

        # Should identify at-risk attributes
        assert isinstance(op_analysis["at_risk_important_attrs"], list)

        # 5. Generate migration strategy
        strategy = capability_matrix.recommend_migration_strategy(
            "oracle_oid", "oracle_oud", "medium"
        )

        assert "FlextLdifUtilities" in strategy["required_tools"]
        assert len(strategy["migration_phases"]) >= 3

        # 6. Verify all systems work together
        total_complexity = (
            migration_plan["migration_complexity_score"]
            + len(attr_analysis["transformable_attributes"])
            + len(op_analysis["at_risk_important_attrs"])
        )

        # Should have identified transformation needs
        assert total_complexity > 0

        # Migration should still be feasible despite complexity
        assert strategy["feasibility_score"] > 0.5

    def test_advanced_hook_system_integration(self) -> None:
        """Test advanced hook system with real transformation scenarios."""
        converter = FlextLdifUtilities.AclConverter

        # Register custom transformation hook
        def custom_oid_oud_hook(acl, source_server, target_server):
            if source_server == "oracle_oid" and target_server == "oracle_oud":
                # Custom transformation logic
                enhanced_acl = acl.model_copy(
                    update={
                        "name": f"[CUSTOM TRANSFORMED] {acl.name}",
                        "server_type": target_server,
                    }
                )
                return FlextResult.ok(enhanced_acl)
            return FlextResult.fail("Not applicable")

        converter.register_conversion_hook(
            "oracle_oid", "oracle_oud", custom_oid_oud_hook
        )

        # Test that custom hook is used
        test_acl = FlextLdifModels.Acl(
            name="Test ACL",
            target=FlextLdifModels.AclTarget(target_dn="*", attributes=[]),
            subject=FlextLdifModels.AclSubject(
                subject_type="self", subject_value="self"
            ),
            permissions=FlextLdifModels.AclPermissions(read=True),
            server_type="oracle_oid",
            raw_acl="test",
        )

        result = converter.convert_acl_with_hooks(test_acl, "oracle_oid", "oracle_oud")
        assert result.is_success

        converted_acl = result.unwrap()
        assert "[CUSTOM TRANSFORMED]" in converted_acl.name
        assert converted_acl.server_type == "oracle_oud"

    def test_performance_and_scalability_advanced_utilities(self) -> None:
        """Test performance characteristics of advanced utilities."""
        import time

        # Create large dataset for testing
        large_attribute_list = [f"attr_{i}" for i in range(1000)]
        large_permission_list = [
            "read",
            "write",
            "add",
            "delete",
        ] * 250  # 1000 permissions

        # Test attribute mapper performance
        attr_mapper = FlextLdifUtilities.AttributeNameMapper

        start_time = time.time()
        compatibility_results = []

        for _i in range(10):  # 10 iterations with 1000 attributes each
            result = attr_mapper.analyze_attribute_compatibility(
                large_attribute_list, "oracle_oid", "oracle_oud"
            )
            compatibility_results.append(result)

        attr_elapsed = time.time() - start_time

        # Should complete within reasonable time
        assert attr_elapsed < 5.0  # Less than 5 seconds for 10k attribute analyses
        assert len(compatibility_results) == 10
        assert all(
            result["compatibility_score"] >= 0 for result in compatibility_results
        )

        # Test permission mapper performance
        perm_mapper = FlextLdifUtilities.PermissionMapper

        start_time = time.time()
        permission_results = []

        for _i in range(10):  # 10 iterations with 1000 permissions each
            allowed, denied, log = perm_mapper.transform_permissions_advanced(
                large_permission_list, "oracle_oid", "oracle_oud"
            )
            permission_results.append((allowed, denied, log))

        perm_elapsed = time.time() - start_time

        # Should complete within reasonable time
        assert (
            perm_elapsed < 3.0
        )  # Less than 3 seconds for 10k permission transformations
        assert len(permission_results) == 10

        # Test migration feasibility analysis performance
        capability_matrix = FlextLdifUtilities.ServerCapabilityMatrix

        start_time = time.time()
        feasibility_results = []

        server_pairs = [
            ("oracle_oid", "oracle_oud"),
            ("active_directory", "oracle_oud"),
            ("389ds", "oracle_oud"),
            ("openldap", "oracle_oud"),
        ]

        for _i in range(25):  # 100 total analyses (25 * 4 pairs)
            for source, target in server_pairs:
                result = capability_matrix.analyze_migration_feasibility(source, target)
                feasibility_results.append(result)

        feasibility_elapsed = time.time() - start_time

        # Should complete within reasonable time
        assert (
            feasibility_elapsed < 2.0
        )  # Less than 2 seconds for 100 feasibility analyses
        assert len(feasibility_results) == 100
        assert all(result["feasibility_score"] >= 0 for result in feasibility_results)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
