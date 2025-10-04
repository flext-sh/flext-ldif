"""Test suite for FlextLdifModels.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult
from pydantic import ValidationError

from flext_ldif.models import FlextLdifModels


class TestFlextLdifModels:
    """Test suite for FlextLdifModels."""

    def test_dn_creation(self) -> None:
        """Test DN model creation."""
        dn = FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com")
        assert dn.value == "cn=test,dc=example,dc=com"

    def test_dn_validation(self) -> None:
        """Test DN validation."""
        # Valid DN
        dn = FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com")
        assert dn.value == "cn=test,dc=example,dc=com"

        # Empty DN should fail
        with pytest.raises(ValidationError):
            FlextLdifModels.DistinguishedName(value="")

        # DN too long should fail
        long_dn = "cn=" + "x" * 2048 + ",dc=example,dc=com"
        with pytest.raises(ValidationError):
            FlextLdifModels.DistinguishedName(value=long_dn)

    def test_dn_normalization(self) -> None:
        """Test DN normalization."""
        # Test case normalization
        dn = FlextLdifModels.DistinguishedName(value="CN=Test,DC=Example,DC=Com")
        assert dn.value == "CN=Test,DC=Example,DC=Com"  # Should preserve case

    def test_attribute_values_creation(self) -> None:
        """Test AttributeValues model creation."""
        values = FlextLdifModels.AttributeValues(values=["value1", "value2"])
        assert values.values == ["value1", "value2"]

    def test_attribute_values_validation(self) -> None:
        """Test AttributeValues validation."""
        # Valid values
        values = FlextLdifModels.AttributeValues(values=["value1", "value2"])
        assert len(values.values) == 2

        # Empty values should be allowed
        empty_values = FlextLdifModels.AttributeValues(values=[])
        assert empty_values.values == []

    def test_attribute_values_single_value(self) -> None:
        """Test AttributeValues single value property."""
        values = FlextLdifModels.AttributeValues(values=["single_value"])
        assert values.single_value == "single_value"

        empty_values = FlextLdifModels.AttributeValues(values=[])
        assert empty_values.single_value is None

    def test_attributes_creation(self) -> None:
        """Test Attributes model creation."""
        attrs = FlextLdifModels.LdifAttributes(
            attributes={
                "cn": FlextLdifModels.AttributeValues(values=["test"]),
                "sn": FlextLdifModels.AttributeValues(values=["user"]),
            }
        )
        assert len(attrs.attributes) == 2
        assert "cn" in attrs.attributes
        assert "sn" in attrs.attributes

    def test_attributes_get_attribute(self) -> None:
        """Test getting attributes by name."""
        attrs = FlextLdifModels.LdifAttributes(
            attributes={
                "cn": FlextLdifModels.AttributeValues(values=["test"]),
            }
        )

        cn_attr = attrs.get_attribute("cn")
        assert cn_attr is not None
        assert cn_attr.values == ["test"]

        # Non-existent attribute
        missing_attr = attrs.get_attribute("missing")
        assert missing_attr is None

    def test_attributes_add_attribute(self) -> None:
        """Test adding attributes."""
        attrs = FlextLdifModels.LdifAttributes(attributes={})

        attrs.add_attribute("cn", "test")
        cn_attr = attrs.get_attribute("cn")
        assert cn_attr is not None
        assert cn_attr.values == ["test"]

    def test_attributes_add_attribute_multiple_values(self) -> None:
        """Test adding attributes with multiple values."""
        attrs = FlextLdifModels.LdifAttributes(attributes={})

        attrs.add_attribute("cn", ["test1", "test2"])
        cn_attr = attrs.get_attribute("cn")
        assert cn_attr is not None
        assert cn_attr.values == ["test1", "test2"]

    def test_attributes_remove_attribute(self) -> None:
        """Test removing attributes."""
        attrs = FlextLdifModels.LdifAttributes(
            attributes={
                "cn": FlextLdifModels.AttributeValues(values=["test"]),
            }
        )

        attrs.remove_attribute("cn")
        cn_attr = attrs.get_attribute("cn")
        assert cn_attr is None

    def test_attributes_remove_nonexistent_attribute(self) -> None:
        """Test removing non-existent attribute."""
        attrs = FlextLdifModels.LdifAttributes(attributes={})

        # Should not raise error
        attrs.remove_attribute("nonexistent")

    def test_entry_creation(self) -> None:
        """Test Entry model creation."""
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                }
            ),
        )
        assert entry.dn.value == "cn=test,dc=example,dc=com"
        assert "cn" in entry.attributes.attributes

    def test_entry_validation(self) -> None:
        """Test Entry validation."""
        # Valid entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(attributes={}),
        )
        assert entry.dn.value == "cn=test,dc=example,dc=com"

    def test_entry_from_ldif_string(self) -> None:
        """Test creating entry from LDIF string."""
        ldif_string = """dn: cn=test,dc=example,dc=com
cn: test
sn: user
"""

        result = FlextLdifModels.Entry.from_ldif_string(ldif_string)
        assert isinstance(result, FlextResult)
        assert result.is_success

        entry = result.value
        assert entry.dn.value == "cn=test,dc=example,dc=com"
        assert entry.attributes.get_attribute("cn") is not None
        assert entry.attributes.get_attribute("sn") is not None

    def test_entry_from_ldif_string_invalid(self) -> None:
        """Test creating entry from invalid LDIF string."""
        invalid_ldif = "invalid ldif content"

        result = FlextLdifModels.Entry.from_ldif_string(invalid_ldif)
        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_entry_from_ldif_string_empty(self) -> None:
        """Test creating entry from empty LDIF string."""
        result = FlextLdifModels.Entry.from_ldif_string("")
        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_entry_to_ldif_string(self) -> None:
        """Test converting entry to LDIF string."""
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                    "sn": FlextLdifModels.AttributeValues(values=["user"]),
                }
            ),
        )

        ldif_string = entry.to_ldif_string()
        assert isinstance(ldif_string, str)
        assert "dn: cn=test,dc=example,dc=com" in ldif_string
        assert "cn: test" in ldif_string
        assert "sn: user" in ldif_string

    def test_entry_to_ldif_string_with_indent(self) -> None:
        """Test converting entry to LDIF string with indentation."""
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                }
            ),
        )

        ldif_string = entry.to_ldif_string(indent=4)
        assert isinstance(ldif_string, str)
        assert "dn: cn=test,dc=example,dc=com" in ldif_string

    def test_search_config_creation(self) -> None:
        """Test SearchConfig model creation."""
        config = FlextLdifModels.SearchConfig(
            base_dn="dc=example,dc=com",
            search_filter="(objectClass=person)",
            attributes=["cn", "sn"],
        )
        assert config.base_dn == "dc=example,dc=com"
        assert config.search_filter == "(objectClass=person)"
        assert config.attributes == ["cn", "sn"]

    def test_search_config_validation(self) -> None:
        """Test SearchConfig validation."""
        # Valid config
        config = FlextLdifModels.SearchConfig(
            base_dn="dc=example,dc=com",
            search_filter="(objectClass=person)",
            attributes=["cn", "sn"],
        )
        assert config.base_dn == "dc=example,dc=com"

        # Empty base_dn should fail
        with pytest.raises(ValidationError):
            FlextLdifModels.SearchConfig(
                base_dn="",
                search_filter="(objectClass=person)",
                attributes=["cn"],
            )

    def test_search_config_default_filter(self) -> None:
        """Test SearchConfig with default filter."""
        config = FlextLdifModels.SearchConfig(
            base_dn="dc=example,dc=com",
            attributes=["cn", "sn"],
        )
        assert config.search_filter == "(objectClass=*)"

    def test_search_config_empty_attributes(self) -> None:
        """Test SearchConfig with empty attributes."""
        config = FlextLdifModels.SearchConfig(
            base_dn="dc=example,dc=com",
            search_filter="(objectClass=person)",
            attributes=[],
        )
        assert config.attributes == []

    def test_ldif_document_creation(self) -> None:
        """Test LdifDocument model creation."""
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value="cn=test1,dc=example,dc=com"
                ),
                attributes=FlextLdifModels.LdifAttributes(attributes={}),
            ),
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value="cn=test2,dc=example,dc=com"
                ),
                attributes=FlextLdifModels.LdifAttributes(attributes={}),
            ),
        ]

        document = FlextLdifModels.LdifDocument(entries=entries, domain_events=[])
        assert len(document.entries) == 2

    def test_ldif_document_validation(self) -> None:
        """Test LdifDocument validation."""
        # Valid document
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
                attributes=FlextLdifModels.LdifAttributes(attributes={}),
            ),
        ]

        document = FlextLdifModels.LdifDocument(entries=entries, domain_events=[])
        assert len(document.entries) == 1

    def test_ldif_document_empty(self) -> None:
        """Test LdifDocument with empty entries."""
        document = FlextLdifModels.LdifDocument(entries=[], domain_events=[])
        assert len(document.entries) == 0

    def test_ldif_document_to_string(self) -> None:
        """Test converting LdifDocument to string."""
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={
                        "cn": FlextLdifModels.AttributeValues(values=["test"]),
                    }
                ),
            ),
        ]

        document = FlextLdifModels.LdifDocument(entries=entries, domain_events=[])
        ldif_string = document.to_ldif_string()

        assert isinstance(ldif_string, str)
        assert "dn: cn=test,dc=example,dc=com" in ldif_string
        assert "cn: test" in ldif_string

    def test_ldif_document_from_string(self) -> None:
        """Test creating LdifDocument from string."""
        ldif_string = """dn: cn=test1,dc=example,dc=com
cn: test1

dn: cn=test2,dc=example,dc=com
cn: test2
"""

        result = FlextLdifModels.LdifDocument.from_ldif_string(ldif_string)
        assert isinstance(result, FlextResult)
        assert result.is_success

        document = result.value
        assert len(document.entries) == 2
        assert document.entries[0].dn.value == "cn=test1,dc=example,dc=com"
        assert document.entries[1].dn.value == "cn=test2,dc=example,dc=com"

    def test_ldif_document_from_string_invalid(self) -> None:
        """Test creating LdifDocument from invalid string."""
        invalid_ldif = "invalid ldif content"

        result = FlextLdifModels.LdifDocument.from_ldif_string(invalid_ldif)
        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_ldif_document_from_string_empty(self) -> None:
        """Test creating LdifDocument from empty string."""
        result = FlextLdifModels.LdifDocument.from_ldif_string("")
        assert isinstance(result, FlextResult)
        assert result.is_success

        document = result.value
        assert len(document.entries) == 0

    def test_model_serialization(self) -> None:
        """Test model serialization."""
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                }
            ),
        )

        # Test model_dump
        data = entry.model_dump()
        assert isinstance(data, dict)
        assert data["dn"]["value"] == "cn=test,dc=example,dc=com"

    def test_model_deserialization(self) -> None:
        """Test model deserialization."""
        data = {
            "dn": {"value": "cn=test,dc=example,dc=com"},
            "attributes": {
                "attributes": {
                    "cn": {"values": ["test"]},
                    "objectClass": {"values": ["person"]},
                }
            },
        }

        entry = FlextLdifModels.Entry.model_validate(data)
        assert entry.dn.value == "cn=test,dc=example,dc=com"
        assert entry.attributes.get_attribute("cn") is not None

    def test_model_validation_errors(self) -> None:
        """Test model validation errors."""
        # Invalid DN
        with pytest.raises(ValidationError):
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value=""),  # Empty DN
                attributes=FlextLdifModels.LdifAttributes(attributes={}),
            )

    def test_model_inheritance(self) -> None:
        """Test that models properly inherit from FlextModels."""
        # Test that all models are properly structured
        assert hasattr(FlextLdifModels, "DistinguishedName")
        assert hasattr(FlextLdifModels, "AttributeValues")
        assert hasattr(FlextLdifModels, "LdifAttributes")
        assert hasattr(FlextLdifModels, "Entry")
        assert hasattr(FlextLdifModels, "SearchConfig")
        assert hasattr(FlextLdifModels, "LdifDocument")

    def test_model_methods(self) -> None:
        """Test that model methods work correctly."""
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                }
            ),
        )

        # Test that methods exist and are callable
        assert hasattr(entry, "to_ldif_string")
        assert callable(entry.to_ldif_string)

        assert hasattr(FlextLdifModels.Entry, "from_ldif_string")
        assert callable(FlextLdifModels.Entry.from_ldif_string)

        assert hasattr(FlextLdifModels.LdifDocument, "from_ldif_string")
        assert callable(FlextLdifModels.LdifDocument.from_ldif_string)

    def test_edge_cases(self) -> None:
        """Test edge cases in models."""
        # Test DN with special characters
        dn = FlextLdifModels.DistinguishedName(value="cn=test+user,dc=example,dc=com")
        assert dn.value == "cn=test+user,dc=example,dc=com"

        # Test attributes with special characters
        attrs = FlextLdifModels.LdifAttributes(
            attributes={
                "cn;lang-en": FlextLdifModels.AttributeValues(values=["test"]),
            }
        )
        assert "cn;lang-en" in attrs.attributes

        # Test empty attribute values
        attrs = FlextLdifModels.LdifAttributes(
            attributes={
                "cn": FlextLdifModels.AttributeValues(values=[""]),
            }
        )
        cn_attr = attrs.get_attribute("cn")
        assert cn_attr is not None
        assert cn_attr.values == [""]

    def test_ldif_processing_result_creation(self) -> None:
        """Test LdifProcessingResult model creation."""
        result = FlextLdifModels.LdifProcessingResult(
            status="success",
            entries=[],
            errors=[],
            warnings=[],
            statistics={"processed": 10},
        )
        assert result.status == "success"
        assert result.is_success is True
        assert result.entry_count == 0
        assert result.error_count == 0

    def test_service_status_creation(self) -> None:
        """Test ServiceStatus model creation."""
        status = FlextLdifModels.ServiceStatus(
            service_name="ldif_processor",
            status="healthy",
            configuration={"max_entries": 1000},
            statistics={"processed": 500},
            capabilities=["parse", "validate"],
        )
        assert status.service_name == "ldif_processor"
        assert status.status == "healthy"
        assert status.is_operational is True
        assert "max_entries" in status.configuration
        assert status.capabilities == ["parse", "validate"]

    def test_parse_query_creation(self) -> None:
        """Test ParseQuery model creation."""
        query = FlextLdifModels.ParseQuery(
            source="dn: cn=test,dc=example,dc=com\ncn: test",
            format="rfc",
            encoding="utf-8",
            strict=True,
        )
        assert query.source == "dn: cn=test,dc=example,dc=com\ncn: test"
        assert query.format == "rfc"
        assert query.encoding == "utf-8"
        assert query.strict is True

    def test_validate_query_creation(self) -> None:
        """Test ValidateQuery model creation."""
        query = FlextLdifModels.ValidateQuery(
            entries=[
                FlextLdifModels.Entry(
                    dn=FlextLdifModels.DistinguishedName(
                        value="cn=test,dc=example,dc=com"
                    ),
                    attributes=FlextLdifModels.LdifAttributes(attributes={}),
                )
            ],
            schema_validation=True,
        )
        assert len(query.entries) == 1
        assert query.schema_validation is True

    def test_analyze_query_creation(self) -> None:
        """Test AnalyzeQuery model creation."""
        query = FlextLdifModels.AnalyzeQuery(
            ldif_content="dn: cn=test,dc=example,dc=com\ncn: test",
            analysis_types=["statistics", "validation"],
        )
        assert query.ldif_content == "dn: cn=test,dc=example,dc=com\ncn: test"
        assert query.analysis_types == ["statistics", "validation"]

    def test_write_command_creation(self) -> None:
        """Test WriteCommand model creation."""
        command = FlextLdifModels.WriteCommand(
            entries=[
                FlextLdifModels.Entry(
                    dn=FlextLdifModels.DistinguishedName(
                        value="cn=test,dc=example,dc=com"
                    ),
                    attributes=FlextLdifModels.LdifAttributes(attributes={}),
                )
            ],
            output_path="/tmp/test.ldif",
            format_options={"indent": 2},
        )
        assert len(command.entries) == 1
        assert command.output_path == "/tmp/test.ldif"
        assert command.format_options == {"indent": 2}

    def test_migrate_command_creation(self) -> None:
        """Test MigrateCommand model creation."""
        command = FlextLdifModels.MigrateCommand(
            entries=[
                FlextLdifModels.Entry(
                    dn=FlextLdifModels.DistinguishedName(
                        value="cn=test,dc=example,dc=com"
                    ),
                    attributes=FlextLdifModels.LdifAttributes(attributes={}),
                )
            ],
            source_format="rfc",
            target_format="oid",
        )
        assert len(command.entries) == 1
        assert command.source_format == "rfc"
        assert command.target_format == "oid"

    def test_register_quirk_command_creation(self) -> None:
        """Test RegisterQuirkCommand model creation."""
        command = FlextLdifModels.RegisterQuirkCommand(
            quirk_type="schema",
            quirk_impl=lambda x: x,
        )
        assert command.quirk_type == "schema"
        assert callable(command.quirk_impl)

    def test_entry_parsed_event_creation(self) -> None:
        """Test EntryParsedEvent creation."""
        event = FlextLdifModels.EntryParsedEvent(
            entry_count=5,
            source_type="file",
            format_detected="rfc",
            timestamp="2025-01-01T00:00:00Z",
        )
        assert event.entry_count == 5
        assert event.source_type == "file"
        assert event.format_detected == "rfc"
        assert event.event_type == "entry.parsed"
        assert event.aggregate_id == "ldif-parser"

    def test_entries_validated_event_creation(self) -> None:
        """Test EntriesValidatedEvent creation."""
        event = FlextLdifModels.EntriesValidatedEvent(
            entry_count=10,
            is_valid=True,
            error_count=0,
            strict_mode=True,
            timestamp="2025-01-01T00:00:00Z",
        )
        assert event.entry_count == 10
        assert event.is_valid is True
        assert event.error_count == 0
        assert event.strict_mode is True
        assert event.event_type == "entries.validated"
        assert event.aggregate_id == "ldif-validator"

    def test_analytics_generated_event_creation(self) -> None:
        """Test AnalyticsGeneratedEvent creation."""
        event = FlextLdifModels.AnalyticsGeneratedEvent(
            entry_count=20,
            statistics={"total_attrs": 100, "unique_dns": 15},
            timestamp="2025-01-01T00:00:00Z",
        )
        assert event.entry_count == 20
        assert event.statistics == {"total_attrs": 100, "unique_dns": 15}
        assert event.event_type == "analytics.generated"
        assert event.aggregate_id == "ldif-analytics"

    def test_entries_written_event_creation(self) -> None:
        """Test EntriesWrittenEvent creation."""
        event = FlextLdifModels.EntriesWrittenEvent(
            entry_count=8,
            output_path="/tmp/output.ldif",
            format_used="rfc",
            timestamp="2025-01-01T00:00:00Z",
        )
        assert event.entry_count == 8
        assert event.output_path == "/tmp/output.ldif"
        assert event.format_used == "rfc"
        assert event.event_type == "entries.written"
        assert event.aggregate_id == "ldif-writer"

    def test_migration_completed_event_creation(self) -> None:
        """Test MigrationCompletedEvent creation."""
        event = FlextLdifModels.MigrationCompletedEvent(
            source_entries=15,
            target_entries=15,
            migration_type="format_conversion",
            timestamp="2025-01-01T00:00:00Z",
        )
        assert event.source_entries == 15
        assert event.target_entries == 15
        assert event.migration_type == "format_conversion"
        assert event.event_type == "migration.completed"
        assert event.aggregate_id == "ldif-migration"

    def test_quirk_registered_event_creation(self) -> None:
        """Test QuirkRegisteredEvent creation."""
        event = FlextLdifModels.QuirkRegisteredEvent(
            server_type="openldap",
            quirk_name="special_handling",
            timestamp="2025-01-01T00:00:00Z",
        )
        assert event.server_type == "openldap"
        assert event.quirk_name == "special_handling"
        assert event.event_type == "quirk.registered"
        assert event.aggregate_id == "ldif-quirks"

    def test_schema_object_class_creation(self) -> None:
        """Test SchemaObjectClass model creation."""
        obj_class = FlextLdifModels.SchemaObjectClass(
            name="person",
            oid="2.5.6.6",
            description="Person object class",
            required_attributes=["cn", "sn"],
            optional_attributes=["telephoneNumber", "seeAlso"],
            must=["cn", "sn"],
            may=["telephoneNumber", "seeAlso"],
            structural=True,
        )
        assert obj_class.name == "person"
        assert obj_class.oid == "2.5.6.6"
        assert obj_class.description == "Person object class"
        assert obj_class.required_attributes == ["cn", "sn"]
        assert obj_class.optional_attributes == ["telephoneNumber", "seeAlso"]
        assert obj_class.must == ["cn", "sn"]
        assert obj_class.may == ["telephoneNumber", "seeAlso"]
        assert obj_class.structural is True
        assert obj_class.attribute_summary["required_count"] == 2
        assert obj_class.attribute_summary["is_structural"] is True

    def test_schema_object_class_create_method(self) -> None:
        """Test SchemaObjectClass.create method."""
        result = FlextLdifModels.SchemaObjectClass.create(
            name="organizationalUnit",
            oid="2.5.6.5",
            description="Organizational unit",
            required_attributes=["ou"],
        )
        assert result.is_success
        obj_class = result.value
        assert obj_class.name == "organizationalUnit"
        assert obj_class.oid == "2.5.6.5"
        assert obj_class.required_attributes == ["ou"]

    def test_schema_discovery_result_creation(self) -> None:
        """Test SchemaDiscoveryResult model creation."""
        result = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={
                "person": FlextLdifModels.SchemaObjectClass(
                    name="person",
                    oid="2.5.6.6",
                    description="Person class",
                    required_attributes=["cn"],
                )
            },
            attributes={
                "cn": FlextLdifModels.SchemaAttribute(
                    name="cn",
                    oid="2.5.4.3",
                    description="Common name",
                    syntax="1.3.6.1.4.1.1466.115.121.1.15",
                )
            },
            server_type="openldap",
            entry_count=100,
        )
        assert len(result.object_classes) == 1
        assert len(result.attributes) == 1
        assert result.server_type == "openldap"
        assert result.entry_count == 100

    def test_schema_attribute_creation(self) -> None:
        """Test SchemaAttribute model creation."""
        attr = FlextLdifModels.SchemaAttribute(
            name="cn",
            oid="2.5.4.3",
            description="Common name attribute",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            single_valued=False,
            user_modifiable=True,
        )
        assert attr.name == "cn"
        assert attr.oid == "2.5.4.3"
        assert attr.description == "Common name attribute"
        assert attr.syntax == "1.3.6.1.4.1.1466.115.121.1.15"
        assert attr.single_valued is False
        assert attr.user_modifiable is True
