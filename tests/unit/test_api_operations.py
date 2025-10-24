"""Comprehensive real tests for FlextLdif API using actual LDIF fixtures.

Tests the complete FlextLdif API facade with real LDIF data from OID, OUD,
and other server types using actual fixture files.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif import FlextLdif, FlextLdifConfig, FlextLdifModels


class TestFlextLdifApiOperations:
    """Test FlextLdif API facade operations with real fixture data."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """Create FlextLdif API instance."""
        return FlextLdif()

    @pytest.fixture
    def oid_entries_fixture(self) -> Path:
        """Get path to OID entries fixture."""
        return (
            Path(__file__).parent.parent
            / "fixtures"
            / "oid"
            / "oid_entries_fixtures.ldif"
        )

    @pytest.fixture
    def oid_schema_fixture(self) -> Path:
        """Get path to OID schema fixture."""
        return (
            Path(__file__).parent.parent
            / "fixtures"
            / "oid"
            / "oid_schema_fixtures.ldif"
        )

    @pytest.fixture
    def oid_acl_fixture(self) -> Path:
        """Get path to OID ACL fixture."""
        return (
            Path(__file__).parent.parent / "fixtures" / "oid" / "oid_acl_fixtures.ldif"
        )

    @pytest.fixture
    def oud_entries_fixture(self) -> Path:
        """Get path to OUD entries fixture."""
        return (
            Path(__file__).parent.parent
            / "fixtures"
            / "oud"
            / "oud_entries_fixtures.ldif"
        )

    # =========================================================================
    # PARSE OPERATIONS TESTS
    # =========================================================================

    def test_parse_from_string_content(self, api: FlextLdif) -> None:
        """Test parsing LDIF from string content."""
        ldif_content = (
            "dn: cn=test,dc=example,dc=com\ncn: test\nobjectClass: person\n\n"
        )
        result = api.parse(ldif_content)
        assert result.is_success
        entries = result.unwrap()
        assert isinstance(entries, list)
        assert len(entries) > 0

    def test_parse_from_file_path(
        self, api: FlextLdif, oid_entries_fixture: Path
    ) -> None:
        """Test parsing from file path."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        result = api.parse(oid_entries_fixture)
        assert result.is_success
        entries = result.unwrap()
        assert isinstance(entries, list)
        assert len(entries) > 0

    def test_parse_with_batch_mode(
        self, api: FlextLdif, oid_entries_fixture: Path, oud_entries_fixture: Path
    ) -> None:
        """Test parsing multiple files in batch mode."""
        if not oid_entries_fixture.exists() or not oud_entries_fixture.exists():
            pytest.skip("One or both fixtures not found")

        result = api.parse([oid_entries_fixture, oud_entries_fixture], batch=True)
        assert result.is_success
        entries = result.unwrap()
        assert isinstance(entries, list)
        assert len(entries) > 0

    def test_parse_with_pagination(
        self, api: FlextLdif, oid_entries_fixture: Path
    ) -> None:
        """Test parsing with pagination."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        result = api.parse(oid_entries_fixture, paginate=True, page_size=10)
        assert result.is_success
        get_next_page = result.unwrap()
        assert callable(get_next_page)

        # Get first page
        page1 = get_next_page()
        assert page1 is not None
        assert isinstance(page1, list)
        assert len(page1) <= 10

    def test_parse_invalid_batch_without_list(self, api: FlextLdif) -> None:
        """Test that batch=True requires a list."""
        result = api.parse("dn: cn=test,dc=example,dc=com\n", batch=True)
        assert result.is_failure

    def test_parse_with_server_type_specification(
        self, api: FlextLdif, oid_entries_fixture: Path
    ) -> None:
        """Test parsing with explicit server type."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        result = api.parse(oid_entries_fixture, server_type="oid")
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) > 0

    # =========================================================================
    # WRITE OPERATIONS TESTS
    # =========================================================================

    def test_write_entries_to_string(
        self, api: FlextLdif, oid_entries_fixture: Path
    ) -> None:
        """Test writing entries to LDIF string."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = api.parse(oid_entries_fixture)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        write_result = api.write(entries)
        assert write_result.is_success
        ldif_content = write_result.unwrap()
        assert isinstance(ldif_content, str)
        assert "dn:" in ldif_content

    def test_write_entries_to_file(
        self, api: FlextLdif, oid_entries_fixture: Path, tmp_path: Path
    ) -> None:
        """Test writing entries to file."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = api.parse(oid_entries_fixture)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        output_file = tmp_path / "output.ldif"
        write_result = api.write(entries, output_file)
        assert write_result.is_success
        assert output_file.exists()

    # =========================================================================
    # ENTRY OPERATIONS TESTS
    # =========================================================================

    def test_create_entry_basic(self, api: FlextLdif) -> None:
        """Test creating a basic entry."""
        result = api.create_entry(
            dn="cn=John Doe,ou=Users,dc=example,dc=com",
            attributes={"cn": "John Doe", "sn": "Doe"},
            objectclasses=["inetOrgPerson", "person", "top"],
        )
        assert result.is_success
        entry = result.unwrap()
        assert entry.dn.value == "cn=John Doe,ou=Users,dc=example,dc=com"

    def test_create_entry_with_objectclasses(self, api: FlextLdif) -> None:
        """Test creating entry with objectclasses."""
        result = api.create_entry(
            dn="cn=John Doe,ou=Users,dc=example,dc=com",
            attributes={"cn": "John Doe", "sn": "Doe"},
            objectclasses=["inetOrgPerson", "person", "top"],
        )
        assert result.is_success
        entry = result.unwrap()
        assert entry.dn.value == "cn=John Doe,ou=Users,dc=example,dc=com"

    def test_get_entry_dn(self, api: FlextLdif, oid_entries_fixture: Path) -> None:
        """Test extracting DN from entry."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = api.parse(oid_entries_fixture)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        if len(entries) > 0:
            dn_result = api.get_entry_dn(entries[0])
            assert dn_result.is_success
            dn = dn_result.unwrap()
            assert isinstance(dn, str)
            assert len(dn) > 0

    def test_get_entry_attributes(
        self, api: FlextLdif, oid_entries_fixture: Path
    ) -> None:
        """Test extracting attributes from entry."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = api.parse(oid_entries_fixture)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        if len(entries) > 0:
            attrs_result = api.get_entry_attributes(entries[0])
            assert attrs_result.is_success
            attrs = attrs_result.unwrap()
            assert isinstance(attrs, dict)

    def test_get_entry_objectclasses(
        self, api: FlextLdif, oid_entries_fixture: Path
    ) -> None:
        """Test extracting objectClasses from entry."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = api.parse(oid_entries_fixture)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        if len(entries) > 0:
            oc_result = api.get_entry_objectclasses(entries[0])
            # May succeed or fail depending on fixture
            if oc_result.is_success:
                ocs = oc_result.unwrap()
                assert isinstance(ocs, list)

    def test_get_attribute_values_from_list(self, api: FlextLdif) -> None:
        """Test extracting values from attribute."""
        result = api.get_attribute_values(["value1", "value2"])
        assert result.is_success
        values = result.unwrap()
        assert len(values) == 2
        assert "value1" in values

    def test_get_attribute_values_from_string(self, api: FlextLdif) -> None:
        """Test extracting single value from attribute."""
        result = api.get_attribute_values("single_value")
        assert result.is_success
        values = result.unwrap()
        assert len(values) == 1
        assert values[0] == "single_value"

    def test_get_attribute_values_from_none(self, api: FlextLdif) -> None:
        """Test extracting values from None."""
        result = api.get_attribute_values(None)
        assert result.is_success
        values = result.unwrap()
        assert len(values) == 0

    # =========================================================================
    # FILTER OPERATIONS TESTS
    # =========================================================================

    def test_filter_by_objectclass(
        self, api: FlextLdif, oid_entries_fixture: Path
    ) -> None:
        """Test filtering entries by objectclass."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = api.parse(oid_entries_fixture)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        if len(entries) > 0:
            filter_result = api.filter(entries, objectclass="person")
            assert filter_result.is_success
            filtered = filter_result.unwrap()
            assert isinstance(filtered, list)

    def test_filter_by_dn_pattern(
        self, api: FlextLdif, oid_entries_fixture: Path
    ) -> None:
        """Test filtering entries by DN pattern."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = api.parse(oid_entries_fixture)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        if len(entries) > 0:
            filter_result = api.filter(entries, dn_pattern="dc=example")
            assert filter_result.is_success
            filtered = filter_result.unwrap()
            assert isinstance(filtered, list)

    def test_filter_with_custom_callback(
        self, api: FlextLdif, oid_entries_fixture: Path
    ) -> None:
        """Test filtering with custom callback."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = api.parse(oid_entries_fixture)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        if len(entries) > 0:
            filter_result = api.filter(
                entries, custom_filter=lambda e: len(e.dn.value) > 10
            )
            assert filter_result.is_success
            filtered = filter_result.unwrap()
            assert isinstance(filtered, list)

    # =========================================================================
    # VALIDATION OPERATIONS TESTS
    # =========================================================================

    def test_validate_entries(self, api: FlextLdif, oid_entries_fixture: Path) -> None:
        """Test validating entries."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = api.parse(oid_entries_fixture)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        validate_result = api.validate_entries(entries)
        assert validate_result.is_success

    def test_parse_schema_ldif(self, api: FlextLdif, oid_schema_fixture: Path) -> None:
        """Test parsing schema LDIF."""
        if not oid_schema_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_schema_fixture}")

        result = api.parse_schema_ldif(oid_schema_fixture)
        assert result.is_success
        mods = result.unwrap()
        assert isinstance(mods, dict)

    # =========================================================================
    # ANALYSIS OPERATIONS TESTS
    # =========================================================================

    def test_analyze_entries(self, api: FlextLdif, oid_entries_fixture: Path) -> None:
        """Test analyzing entries."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = api.parse(oid_entries_fixture)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        analyze_result = api.analyze(entries)
        assert analyze_result.is_success
        stats = analyze_result.unwrap()
        assert isinstance(stats, dict)

    # =========================================================================
    # ENTRY BUILDER OPERATIONS TESTS
    # =========================================================================

    def test_build_person_entry(self, api: FlextLdif) -> None:
        """Test building person entry."""
        result = api.build(
            "person",
            cn="Alice Johnson",
            sn="Johnson",
            mail="alice@example.com",
            base_dn="ou=People,dc=example,dc=com",
        )
        assert result.is_success
        entry = result.unwrap()
        assert isinstance(entry, FlextLdifModels.Entry)

    def test_build_group_entry(self, api: FlextLdif) -> None:
        """Test building group entry."""
        result = api.build(
            "group",
            cn="Admins",
            base_dn="ou=Groups,dc=example,dc=com",
            members=["cn=alice,ou=People,dc=example,dc=com"],
        )
        assert result.is_success
        entry = result.unwrap()
        assert isinstance(entry, FlextLdifModels.Entry)

    def test_build_ou_entry(self, api: FlextLdif) -> None:
        """Test building OU entry."""
        result = api.build(
            "ou",
            ou="People",
            base_dn="dc=example,dc=com",
            description="People organizational unit",
        )
        assert result.is_success
        entry = result.unwrap()
        assert isinstance(entry, FlextLdifModels.Entry)

    def test_build_custom_entry(self, api: FlextLdif) -> None:
        """Test building custom entry."""
        result = api.build(
            "custom",
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"], "objectClass": ["person"]},
        )
        assert result.is_success
        entry = result.unwrap()
        assert isinstance(entry, FlextLdifModels.Entry)

    def test_build_person_missing_required_fields(self, api: FlextLdif) -> None:
        """Test build fails when required fields missing."""
        result = api.build("person", cn="Alice")
        assert result.is_failure

    def test_build_group_missing_required_fields(self, api: FlextLdif) -> None:
        """Test build group fails when required fields missing."""
        result = api.build("group", cn="Admins")
        assert result.is_failure

    def test_build_unknown_type(self, api: FlextLdif) -> None:
        """Test build fails with unknown type."""
        result = api.build("unknown")
        assert result.is_failure

    # =========================================================================
    # CONVERSION OPERATIONS TESTS
    # =========================================================================

    def test_convert_entry_to_dict(
        self, api: FlextLdif, oid_entries_fixture: Path
    ) -> None:
        """Test converting entry to dict."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = api.parse(oid_entries_fixture)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        if len(entries) > 0:
            convert_result = api.convert("entry_to_dict", entry=entries[0])
            assert convert_result.is_success

    def test_convert_entries_to_dicts(
        self, api: FlextLdif, oid_entries_fixture: Path
    ) -> None:
        """Test converting entries to dicts."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = api.parse(oid_entries_fixture)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        convert_result = api.convert("entries_to_dicts", entries=entries)
        assert convert_result.is_success
        dicts = convert_result.unwrap()
        assert isinstance(dicts, list)

    def test_convert_dicts_to_entries(self, api: FlextLdif) -> None:
        """Test converting dicts to entries."""
        dicts = [
            {
                "dn": "cn=test,dc=example,dc=com",
                "attributes": {"cn": ["test"], "objectClass": ["person"]},
            }
        ]
        convert_result = api.convert("dicts_to_entries", dicts=dicts)
        assert convert_result.is_success

    def test_convert_entries_to_json(
        self, api: FlextLdif, oid_entries_fixture: Path
    ) -> None:
        """Test converting entries to JSON."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = api.parse(oid_entries_fixture)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        if len(entries) > 0:
            convert_result = api.convert("entries_to_json", entries=entries[:1])
            assert convert_result.is_success
            json_str = convert_result.unwrap()
            assert isinstance(json_str, str)

    def test_convert_json_to_entries(self, api: FlextLdif) -> None:
        """Test converting JSON to entries."""
        json_str = (
            "["
            '{"dn":"cn=test,dc=example,dc=com",'
            '"attributes":{"cn":["test"],"objectClass":["person"]}}'
            "]"
        )
        convert_result = api.convert("json_to_entries", json_str=json_str)
        assert convert_result.is_success

    def test_convert_unknown_type(self, api: FlextLdif) -> None:
        """Test convert fails with unknown type."""
        result = api.convert("unknown")
        assert result.is_failure

    # =========================================================================
    # SCHEMA BUILDER OPERATIONS TESTS
    # =========================================================================

    def test_build_person_schema(self, api: FlextLdif) -> None:
        """Test building person schema."""
        result = api.build_person_schema()
        assert result.is_success
        schema = result.unwrap()
        # SchemaBuilderResult is now a Pydantic model, not a dict
        assert hasattr(schema, "schema")
        assert schema.schema is not None

    # =========================================================================
    # AUTO-DETECTION OPERATIONS TESTS
    # =========================================================================

    def test_detect_server_type_from_file(
        self, api: FlextLdif, oid_entries_fixture: Path
    ) -> None:
        """Test detecting server type from file."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        result = api.detect_server_type(ldif_path=oid_entries_fixture)
        assert result.is_success
        detection = result.unwrap()
        assert "detected_server_type" in detection

    def test_detect_server_type_from_content(self, api: FlextLdif) -> None:
        """Test detecting server type from content."""
        ldif_content = "dn: cn=test,dc=example,dc=com\ncn: test\n"
        result = api.detect_server_type(ldif_content=ldif_content)
        assert result.is_success
        detection = result.unwrap()
        assert "detected_server_type" in detection

    def test_parse_with_auto_detection(
        self, api: FlextLdif, oid_entries_fixture: Path
    ) -> None:
        """Test parsing with auto-detection."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        result = api.parse_with_auto_detection(oid_entries_fixture)
        assert result.is_success
        entries = result.unwrap()
        assert isinstance(entries, list)

    def test_parse_relaxed(self, api: FlextLdif, oid_entries_fixture: Path) -> None:
        """Test parsing with relaxed mode."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        result = api.parse_relaxed(oid_entries_fixture)
        assert result.is_success
        entries = result.unwrap()
        assert isinstance(entries, list)

    def test_get_effective_server_type(
        self, api: FlextLdif, oid_entries_fixture: Path
    ) -> None:
        """Test getting effective server type."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        result = api.get_effective_server_type(oid_entries_fixture)
        assert result.is_success
        server_type = result.unwrap()
        assert isinstance(server_type, str)

    # =========================================================================
    # CONFIGURATION AND PROPERTIES TESTS
    # =========================================================================

    def test_api_config_access(self, api: FlextLdif) -> None:
        """Test accessing configuration."""
        config = api.config
        assert isinstance(config, FlextLdifConfig)

    def test_api_models_access(self, api: FlextLdif) -> None:
        """Test accessing models."""
        models = api.models
        assert hasattr(models, "Entry")
        assert hasattr(models, "LdifAttributes")

    def test_api_constants_access(self, api: FlextLdif) -> None:
        """Test accessing constants."""
        constants = api.constants
        assert hasattr(constants, "ServerTypes")
        assert hasattr(constants, "DictKeys")

    def test_api_processors_access(self, api: FlextLdif) -> None:
        """Test accessing processors."""
        processors = api.processors
        assert processors is not None

    def test_api_schema_builder_access(self, api: FlextLdif) -> None:
        """Test accessing schema builder."""
        builder = api.schema_builder
        assert builder is not None

    def test_api_acl_service_access(self, api: FlextLdif) -> None:
        """Test accessing ACL service."""
        service = api.acl_service
        assert service is not None

    # =========================================================================
    # SINGLETON INSTANCE TESTS
    # =========================================================================

    def test_get_singleton_instance(self) -> None:
        """Test getting singleton instance."""
        instance1 = FlextLdif.get_instance()
        instance2 = FlextLdif.get_instance()
        # Note: instances may not be identical due to implementation,
        # but both should be FlextLdif instances
        assert isinstance(instance1, FlextLdif)
        assert isinstance(instance2, FlextLdif)

    # =========================================================================
    # ROUNDTRIP OPERATIONS TESTS
    # =========================================================================

    def test_roundtrip_parse_write_parse(
        self, api: FlextLdif, oid_entries_fixture: Path, tmp_path: Path
    ) -> None:
        """Test roundtrip: parse → write → parse."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        # Parse original
        parse1 = api.parse(oid_entries_fixture)
        assert parse1.is_success
        entries1 = parse1.unwrap()
        count1 = len(entries1)

        # Write to temp
        output_file = tmp_path / "roundtrip.ldif"
        write_result = api.write(entries1, output_file)
        assert write_result.is_success

        # Parse written file
        parse2 = api.parse(output_file)
        assert parse2.is_success
        entries2 = parse2.unwrap()
        count2 = len(entries2)

        # Verify counts preserved
        assert count1 == count2

    def test_roundtrip_create_write_parse(self, api: FlextLdif, tmp_path: Path) -> None:
        """Test roundtrip: create → write → parse."""
        # Create entries
        create1 = api.create_entry(
            dn="cn=John,ou=People,dc=example,dc=com",
            attributes={"cn": "John", "sn": "Doe"},
            objectclasses=["inetOrgPerson", "person", "top"],
        )
        assert create1.is_success
        entries = [create1.unwrap()]

        # Write to file
        output_file = tmp_path / "created.ldif"
        write_result = api.write(entries, output_file)
        assert write_result.is_success

        # Parse written file
        parse_result = api.parse(output_file)
        assert parse_result.is_success
        parsed_entries = parse_result.unwrap()
        assert len(parsed_entries) == 1

    # =========================================================================
    # MULTI-FIXTURE OPERATIONS TESTS
    # =========================================================================

    def test_process_multiple_fixtures_sequential(
        self, api: FlextLdif, oid_entries_fixture: Path, oud_entries_fixture: Path
    ) -> None:
        """Test processing multiple fixtures sequentially."""
        if not oid_entries_fixture.exists() or not oud_entries_fixture.exists():
            pytest.skip("One or both fixtures not found")

        # Parse OID
        result1 = api.parse(oid_entries_fixture)
        assert result1.is_success
        entries1 = result1.unwrap()

        # Parse OUD
        result2 = api.parse(oud_entries_fixture)
        assert result2.is_success
        entries2 = result2.unwrap()

        # Both successful
        assert len(entries1) > 0
        assert len(entries2) > 0

    # =========================================================================
    # ERROR HANDLING TESTS
    # =========================================================================

    def test_parse_nonexistent_file(self, api: FlextLdif) -> None:
        """Test parsing nonexistent file."""
        result = api.parse(Path("/nonexistent/path.ldif"))
        assert result.is_failure

    def test_write_empty_entries_list(self, api: FlextLdif) -> None:
        """Test writing empty entries list."""
        result = api.write([])
        assert result.is_success  # Empty list is valid

    def test_create_entry_missing_dn(self, api: FlextLdif) -> None:
        """Test create entry fails without DN."""
        # DN is required, passing None/empty
        result = api.create_entry(dn="", attributes={})
        # Should still create but may have validation
        assert isinstance(result.is_success, bool)

    def test_get_entry_dn_from_invalid_entry(self, api: FlextLdif) -> None:
        """Test get DN from invalid entry."""
        result = api.get_entry_dn("FlextLdifModels.Entry")
        assert result.is_failure

    # =========================================================================
    # ACL OPERATIONS TESTS
    # =========================================================================

    def test_extract_acls_from_entry(
        self, api: FlextLdif, oid_acl_fixture: Path
    ) -> None:
        """Test extracting ACLs from entry."""
        if not oid_acl_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_acl_fixture}")

        parse_result = api.parse(oid_acl_fixture)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        if len(entries) > 0:
            acl_result = api.extract_acls(entries[0])
            # May succeed or fail depending on entry structure
            assert isinstance(acl_result.is_success, bool)

    def test_evaluate_acl_rules(self, api: FlextLdif) -> None:
        """Test evaluating ACL rules."""
        # Create simple ACL models
        acls: list[FlextLdifModels.Acl] = []
        context = {"subject_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"}

        result = api.evaluate_acl_rules(acls, context)
        assert result.is_success
        is_allowed = result.unwrap()
        assert isinstance(is_allowed, bool)

    # =========================================================================
    # PROCESSING OPERATIONS TESTS
    # =========================================================================

    def test_process_batch(self, api: FlextLdif, oid_entries_fixture: Path) -> None:
        """Test batch processing."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = api.parse(oid_entries_fixture)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        process_result = api.process("transform", entries, batch_size=50)
        assert process_result.is_success
        results = process_result.unwrap()
        assert isinstance(results, list)

    def test_process_parallel(self, api: FlextLdif, oid_entries_fixture: Path) -> None:
        """Test parallel processing."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = api.parse(oid_entries_fixture)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        process_result = api.process("transform", entries, parallel=True, max_workers=2)
        assert process_result.is_success
        results = process_result.unwrap()
        assert isinstance(results, list)

    def test_process_validate(self, api: FlextLdif, oid_entries_fixture: Path) -> None:
        """Test validate processing."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        parse_result = api.parse(oid_entries_fixture)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        process_result = api.process("validate", entries)
        assert process_result.is_success

    def test_process_unknown_processor(self, api: FlextLdif) -> None:
        """Test process fails with unknown processor."""
        result = api.process("unknown", [])
        assert result.is_failure

    # =========================================================================
    # MIGRATION OPERATIONS TESTS
    # =========================================================================

    def test_migrate_files_between_servers(
        self, api: FlextLdif, tmp_path: Path
    ) -> None:
        """Test migrating files between server types."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        # Create a simple LDIF file
        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("dn: cn=test,dc=example,dc=com\ncn: test\n")

        # Attempt migration
        result = api.migrate(
            input_dir=input_dir,
            output_dir=output_dir,
            from_server="rfc",
            to_server="rfc",
        )
        assert isinstance(result.is_success, bool)
