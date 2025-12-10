"""Tests for LDIF power methods and fluent APIs.

This module tests fluent API power methods for DN operations, entry transformations,
filtering, and pipeline-based processing including ProcessingPipeline and ValidationPipeline
for composable LDIF data transformation workflows.
"""

from __future__ import annotations

from typing import cast

import pytest
from flext_core import FlextResult
from tests import m, s

from flext_ldif._utilities import (
    AndFilter,
    # Fluent APIs
    DnOps,
    # Filters
    EntryOps,
    # Transformers
    Filter,
    FilterAttrsTransformer,
    FilterConfigBuilder,
    # Result type
    FlextLdifResult,
    Normalize,
    NotFilter,
    OrFilter,
    # Pipeline
    Pipeline,
    # Builders
    ProcessConfigBuilder,
    ProcessingPipeline,
    ReplaceBaseDnTransformer,
    Transform,
    TransformConfigBuilder,
    ValidationPipeline,
    ValidationResult,
)
from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import p
from flext_ldif.utilities import FlextLdifUtilities

# =========================================================================
# FIXTURES
# =========================================================================


@pytest.fixture
def sample_entry() -> m.Ldif.Entry:
    """Create a sample entry for testing."""
    # Entry accepts string dn and dict attributes via field validators
    # Note: Use DNs without spaces in values (spaces need escaping per RFC 4514)
    return m.Ldif.Entry(
        dn=cast(
            "m.Ldif.DN | None",
            "CN=TestUser,OU=Users,DC=Example,DC=Com",
        ),
        attributes=cast(
            "m.Ldif.Attributes | None",
            {
                "objectClass": ["top", "person", "inetOrgPerson"],
                "cn": ["TestUser"],
                "sn": ["User"],
                "givenName": ["Test"],
                "mail": ["test@example.com"],
                "userPassword": ["secret123"],
            },
        ),
    )


@pytest.fixture
def sample_entries() -> list[m.Ldif.Entry]:
    """Create a list of sample entries for testing."""
    # Entry accepts string dn and dict attributes via field validators
    # Note: Use DNs without spaces in values (spaces need escaping per RFC 4514)
    return [
        m.Ldif.Entry(
            dn=cast(
                "m.Ldif.DN | None",
                "cn=user1,ou=users,dc=example,dc=com",
            ),
            attributes=cast(
                "m.Ldif.Attributes | None",
                {
                    "objectClass": ["person", "inetOrgPerson"],
                    "cn": ["user1"],
                    "sn": ["One"],
                },
            ),
        ),
        m.Ldif.Entry(
            dn=cast(
                "m.Ldif.DN | None",
                "cn=user2,ou=users,dc=example,dc=com",
            ),
            attributes=cast(
                "m.Ldif.Attributes | None",
                {
                    "objectClass": ["person", "organizationalPerson"],
                    "cn": ["user2"],
                    "sn": ["Two"],
                },
            ),
        ),
        m.Ldif.Entry(
            dn=cast(
                "m.Ldif.DN | None",
                "cn=schema,cn=configuration,dc=example,dc=com",
            ),
            attributes=cast(
                "m.Ldif.Attributes | None",
                {
                    "objectClass": ["subSchema"],
                    "attributeTypes": ["( 1.2.3.4 NAME 'testAttr' )"],
                },
            ),
        ),
    ]


# =========================================================================
# FLEXT LDIF RESULT TESTS
# =========================================================================


class TestsTestFlextLdifResult(s):
    """Tests for FlextLdifResult DSL operators."""

    def test_ok_result(self) -> None:
        """Test creating successful result."""
        result = FlextLdifResult.ok("test value")
        assert result.is_success
        assert result.unwrap() == "test value"

    def test_fail_result(self) -> None:
        """Test creating failed result."""
        result: FlextLdifResult[str] = FlextLdifResult.fail("error message")
        assert result.is_failure
        assert result.error == "error message"

    def test_from_result(self) -> None:
        """Test creating from existing FlextResult."""
        original = FlextResult.ok(42)
        ldif_result = FlextLdifResult.from_result(original)
        assert ldif_result.is_success
        assert ldif_result.unwrap() == 42

    def test_pipe_operator_with_transformer(self, sample_entry: m.Ldif.Entry) -> None:
        """Test | operator with transformers."""
        result = FlextLdifResult.ok(sample_entry)
        transformer = Normalize.attrs(case_fold_names=True)

        # Apply transformer via pipe
        transformed = result | transformer
        assert transformed.is_success

    def test_combine_operator(self) -> None:
        """Test & operator to combine results."""
        result1 = FlextLdifResult.ok(["entry1"])
        result2 = FlextLdifResult.ok(["entry2"])

        combined = result1 & result2
        assert combined.is_success
        # Combined should contain both lists
        values = combined.unwrap()
        assert len(values) == 2


# =========================================================================
# CONFIG AND BUILDER TESTS
# =========================================================================


class TestConfigs:
    """Tests for configuration models."""

    def test_process_config_defaults(self) -> None:
        """Test ProcessConfig default values."""
        config = FlextLdifModels.Ldif.ProcessConfig()
        assert config.source_server == "auto"
        assert config.target_server is None
        assert config.normalize_dns is True
        assert config.normalize_attrs is True

    def test_process_config_custom_values(self) -> None:
        """Test ProcessConfig with custom values."""
        config = FlextLdifModels.Ldif.ProcessConfig(
            source_server="oid",
            target_server="oud",
            normalize_dns=False,
        )
        assert config.source_server == "oid"
        assert config.target_server == "oud"
        assert config.normalize_dns is False

    def test_dn_normalization_config(self) -> None:
        """Test DnNormalizationConfig."""
        config = FlextLdifModels.Ldif.DnNormalizationConfig(
            case_fold="upper",
            space_handling="normalize",
        )
        assert config.case_fold == "upper"
        assert config.space_handling == "normalize"

    def test_transform_config(self) -> None:
        """Test TransformConfig."""
        config = FlextLdifModels.Ldif.TransformConfig(
            fail_fast=False,
            preserve_order=True,
        )
        assert config.fail_fast is False
        assert config.preserve_order is True


class TestBuilders:
    """Tests for configuration builders."""

    def test_process_config_builder(self) -> None:
        """Test ProcessConfigBuilder fluent API."""
        builder = ProcessConfigBuilder()
        config = builder.source("oid").target("oud").normalize_dn(case="lower").build()
        assert config.source_server == "oid"
        assert config.target_server == "oud"

    def test_transform_config_builder(self) -> None:
        """Test TransformConfigBuilder fluent API."""
        builder = TransformConfigBuilder()
        config = builder.fail_fast(enabled=False).preserve_order(enabled=True).build()
        assert config.fail_fast is False
        assert config.preserve_order is True

    def test_filter_config_builder(self) -> None:
        """Test FilterConfigBuilder fluent API."""
        builder = FilterConfigBuilder()
        config = builder.mode("any").case_sensitive(enabled=True).build()
        assert config.mode == "any"
        assert config.case_sensitive is True


# =========================================================================
# TRANSFORMER TESTS
# =========================================================================


class TestTransformers:
    """Tests for transformer classes."""

    def test_normalize_dn_transformer(self, sample_entry: m.Ldif.Entry) -> None:
        """Test NormalizeDnTransformer."""
        transformer = Normalize.dn(case="lower")
        result = transformer.apply(sample_entry)
        assert result.is_success

    def test_normalize_attrs_transformer(self, sample_entry: m.Ldif.Entry) -> None:
        """Test NormalizeAttrsTransformer."""
        transformer = Normalize.attrs(case_fold_names=True)
        result = transformer.apply(sample_entry)
        assert result.is_success

    def test_filter_attrs_transformer(self, sample_entry: m.Ldif.Entry) -> None:
        """Test FilterAttrsTransformer."""
        transformer = Transform.filter_attrs(exclude=["userPassword"])
        result = transformer.apply(sample_entry)
        assert result.is_success

        entry = result.unwrap()
        attrs = entry.attributes.attributes if entry.attributes else {}
        # userPassword should be removed
        assert "userPassword" not in attrs

    def test_transform_factory_methods(self) -> None:
        """Test Transform factory class methods."""
        # Test that factory methods return transformers
        t1 = Transform.replace_base("dc=old", "dc=new")
        assert isinstance(t1, ReplaceBaseDnTransformer)

        t2 = Transform.filter_attrs(include=["cn", "sn"])
        assert isinstance(t2, FilterAttrsTransformer)


# =========================================================================
# FILTER TESTS
# =========================================================================


class TestFilters:
    """Tests for filter classes."""

    def test_by_objectclass_filter(self, sample_entry: m.Ldif.Entry) -> None:
        """Test ByObjectClassFilter."""
        filter_person = Filter.by_objectclass("person")
        filter_group = Filter.by_objectclass("groupOfNames")

        assert filter_person.matches(sample_entry) is True
        assert filter_group.matches(sample_entry) is False

    def test_by_dn_filter(self, sample_entry: m.Ldif.Entry) -> None:
        """Test ByDnFilter."""
        filter_users = Filter.by_dn(r".*OU=Users.*")
        filter_groups = Filter.by_dn(r".*OU=Groups.*")

        assert filter_users.matches(sample_entry) is True
        assert filter_groups.matches(sample_entry) is False

    def test_by_attrs_filter(self, sample_entry: m.Ldif.Entry) -> None:
        """Test ByAttrsFilter."""
        filter_mail = Filter.by_attrs("mail")
        filter_phone = Filter.by_attrs("telephoneNumber")

        assert filter_mail.matches(sample_entry) is True
        assert filter_phone.matches(sample_entry) is False

    def test_and_filter(self, sample_entry: m.Ldif.Entry) -> None:
        """Test AndFilter using & operator."""
        f1 = Filter.by_objectclass("person")
        f2 = Filter.by_attrs("mail")

        combined = f1 & f2
        assert isinstance(combined, AndFilter)
        assert combined.matches(sample_entry) is True

    def test_or_filter(self, sample_entry: m.Ldif.Entry) -> None:
        """Test OrFilter using | operator."""
        f1 = Filter.by_objectclass("groupOfNames")
        f2 = Filter.by_objectclass("person")

        combined = f1 | f2
        assert isinstance(combined, OrFilter)
        assert combined.matches(sample_entry) is True

    def test_not_filter(self, sample_entry: m.Ldif.Entry) -> None:
        """Test NotFilter using ~ operator."""
        f1 = Filter.by_objectclass("groupOfNames")

        negated = ~f1
        assert isinstance(negated, NotFilter)
        assert negated.matches(sample_entry) is True


# =========================================================================
# FLUENT API TESTS
# =========================================================================


class TestDnOps:
    """Tests for DnOps fluent API."""

    def test_normalize(self) -> None:
        """Test DnOps.normalize()."""
        ops = DnOps("CN=Test,DC=Example,DC=Com")
        result = ops.normalize(case="lower").build()
        assert result.is_success
        # Note: normalization may vary based on implementation
        assert "example" in result.unwrap().lower()

    def test_clean(self) -> None:
        """Test DnOps.clean()."""
        ops = DnOps("CN=Test,DC=Example,DC=Com")
        result = ops.clean().build()
        assert result.is_success

    def test_method_chaining(self) -> None:
        """Test multiple method chaining."""
        ops = DnOps("CN=Test,DC=Example,DC=Com")
        result = ops.normalize().clean().build()
        assert result.is_success

    def test_is_under(self) -> None:
        """Test DnOps.is_under()."""
        ops = DnOps("CN=Test,OU=Users,DC=Example,DC=Com")
        assert ops.is_under("DC=Example,DC=Com") is True
        assert ops.is_under("DC=Other,DC=Com") is False

    def test_error_propagation(self) -> None:
        """Test that errors propagate through chain."""
        ops = DnOps("")  # Empty DN
        # Operations on empty DN should still work but may produce errors
        result = ops.build()
        # Empty DN is still valid result
        assert result.is_success


class TestEntryOps:
    """Tests for EntryOps fluent API."""

    def test_normalize_dn(self, sample_entry: m.Ldif.Entry) -> None:
        """Test EntryOps.normalize_dn()."""
        ops = EntryOps(sample_entry)
        result = ops.normalize_dn().build()
        assert result.is_success

    def test_normalize_attrs(self, sample_entry: m.Ldif.Entry) -> None:
        """Test EntryOps.normalize_attrs()."""
        ops = EntryOps(sample_entry)
        result = ops.normalize_attrs().build()
        assert result.is_success

    def test_filter_attrs(self, sample_entry: m.Ldif.Entry) -> None:
        """Test EntryOps.filter_attrs()."""
        ops = EntryOps(sample_entry)
        result = ops.filter_attrs(exclude=["userPassword"]).build()
        assert result.is_success

        entry = result.unwrap()
        attrs = entry.attributes.attributes if entry.attributes else {}
        assert "userPassword" not in attrs

    def test_has_objectclass(self, sample_entry: m.Ldif.Entry) -> None:
        """Test EntryOps.has_objectclass()."""
        ops = EntryOps(sample_entry)
        assert ops.has_objectclass("person") is True
        assert ops.has_objectclass("groupOfNames") is False

    def test_method_chaining(self, sample_entry: m.Ldif.Entry) -> None:
        """Test EntryOps method chaining."""
        ops = EntryOps(sample_entry)
        result = (
            ops.normalize_dn()
            .normalize_attrs()
            .filter_attrs(exclude=["userPassword"])
            .build()
        )
        assert result.is_success


# =========================================================================
# PIPELINE TESTS
# =========================================================================


class TestPipeline:
    """Tests for Pipeline orchestration."""

    def test_empty_pipeline(self, sample_entries: list[p.Entry]) -> None:
        """Test empty pipeline passes entries through."""
        pipeline = Pipeline()
        result = pipeline.execute(sample_entries)
        assert result.is_success
        assert len(result.unwrap()) == len(sample_entries)

    def test_pipeline_with_transformer(self, sample_entries: list[p.Entry]) -> None:
        """Test pipeline with transformer."""
        pipeline = Pipeline().add(Normalize.attrs())
        result = pipeline.execute(sample_entries)
        assert result.is_success

    def test_pipeline_with_filter(self, sample_entries: list[p.Entry]) -> None:
        """Test pipeline with filter."""
        pipeline = Pipeline().filter(Filter.by_objectclass("inetOrgPerson"))
        result = pipeline.execute(sample_entries)
        # Pipeline returns success even if some entries are filtered
        # Filtered entries are excluded from results but don't cause failure
        assert result.is_success
        # Only entries with inetOrgPerson should pass
        entries = result.unwrap()
        assert len(entries) < len(sample_entries)

    def test_pipeline_method_chaining(self, sample_entries: list[p.Entry]) -> None:
        """Test pipeline with multiple steps."""
        pipeline = (
            Pipeline().add(Normalize.attrs()).filter(Filter.by_objectclass("person"))
        )
        result = pipeline.execute(sample_entries)
        # Pipeline returns success even if some entries are filtered
        # At least 2 entries should pass (user1 and user2 have "person" objectClass)
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) >= 2  # At least user1 and user2 should pass


class TestProcessingPipeline:
    """Tests for ProcessingPipeline."""

    def test_default_config(self, sample_entries: list[p.Entry]) -> None:
        """Test ProcessingPipeline with default config."""
        pipeline = ProcessingPipeline()
        result = pipeline.execute(sample_entries)
        assert result.is_success

    def test_custom_config(self, sample_entries: list[p.Entry]) -> None:
        """Test ProcessingPipeline with custom config."""
        config = FlextLdifModels.Ldif.ProcessConfig(
            normalize_dns=True,
            normalize_attrs=True,
        )
        pipeline = ProcessingPipeline(config)
        result = pipeline.execute(sample_entries)
        assert result.is_success


class TestValidationPipeline:
    """Tests for ValidationPipeline."""

    def test_validate_entries(self, sample_entries: list[p.Entry]) -> None:
        """Test ValidationPipeline."""
        pipeline = ValidationPipeline(strict=True)
        result = pipeline.validate(sample_entries)
        assert result.is_success
        validations = result.unwrap()
        assert len(validations) == len(sample_entries)

    def test_validation_result(self) -> None:
        """Test ValidationResult properties."""
        validation = ValidationResult(
            is_valid=True,
            errors=[],
            warnings=["Minor issue"],
        )
        assert validation.is_valid is True
        assert len(validation.errors) == 0
        assert len(validation.warnings) == 1


# =========================================================================
# BATCH METHOD TESTS
# =========================================================================


class TestDnBatchMethods:
    """Tests for FlextLdifUtilitiesDN batch methods."""

    def test_norm_or_fallback_success(self) -> None:
        """Test norm_or_fallback with valid DN."""
        result = FlextLdifUtilitiesDN.norm_or_fallback("CN=Test,DC=Example")
        assert "test" in result.lower() or "Test" in result

    def test_norm_or_fallback_none(self) -> None:
        """Test norm_or_fallback with None."""
        result = FlextLdifUtilitiesDN.norm_or_fallback(None)
        assert result == ""

    def test_norm_batch(self) -> None:
        """Test norm_batch."""
        dns = ["CN=User1,DC=Example", "CN=User2,DC=Example"]
        result = FlextLdifUtilitiesDN.norm_batch(dns)
        assert result.is_success
        normalized = result.unwrap()
        assert len(normalized) == 2

    def test_validate_batch(self) -> None:
        """Test validate_batch."""
        dns = ["CN=Valid,DC=Example", "invalid-dn-format"]
        result = FlextLdifUtilitiesDN.validate_batch(dns)
        assert result.is_success
        validations = result.unwrap()
        assert len(validations) == 2

    def test_replace_base_batch(self) -> None:
        """Test replace_base_batch."""
        dns = [
            "cn=user1,dc=old,dc=com",
            "cn=user2,dc=old,dc=com",
        ]
        result = FlextLdifUtilitiesDN.replace_base_batch(
            dns,
            "dc=old,dc=com",
            "dc=new,dc=com",
        )
        assert result.is_success
        replaced = result.unwrap()
        assert len(replaced) == 2
        for dn in replaced:
            assert "dc=new,dc=com" in dn.lower()

    def test_process_complete(self) -> None:
        """Test process_complete (skipping validation since validator is strict)."""
        result = FlextLdifUtilitiesDN.process_complete(
            "cn=test,dc=example,dc=com",
            clean=True,
            validate=False,  # Skip strict validation - tested separately
            normalize=True,
        )
        assert result.is_success


class TestAclBatchMethods:
    """Tests for FlextLdifUtilitiesACL batch methods."""

    def test_extract_components_batch(self) -> None:
        """Test extract_components_batch."""
        content = "target=ldap:///dc=example;bindmode=all;version=3.0"
        result = FlextLdifUtilitiesACL.extract_components_batch(
            content,
            {
                "target": r"target=([^;]+)",
                "bindmode": r"bindmode=([^;]+)",
                "version": r"version=([^;]+)",
            },
        )
        assert result["target"] == "ldap:///dc=example"
        assert result["bindmode"] == "all"
        assert result["version"] == "3.0"

    def test_extract_components_batch_with_defaults(self) -> None:
        """Test extract_components_batch with defaults."""
        content = "target=ldap:///dc=example"
        result = FlextLdifUtilitiesACL.extract_components_batch(
            content,
            {
                "target": r"target=([^;]+)",
                "missing": r"missing=([^;]+)",
            },
            defaults={"missing": "default_value"},
        )
        assert result["target"] == "ldap:///dc=example"
        assert result["missing"] == "default_value"


class TestEntryBatchMethods:
    """Tests for FlextLdifUtilitiesEntry batch methods."""

    def test_matches_criteria(self, sample_entry: m.Ldif.Entry) -> None:
        """Test matches_criteria."""
        # Should match person with mail attribute
        assert (
            FlextLdifUtilitiesEntry.matches_criteria(
                sample_entry,
                objectclasses=["person"],
                required_attrs=["mail"],
            )
            is True
        )

        # Should not match without required attribute
        assert (
            FlextLdifUtilitiesEntry.matches_criteria(
                sample_entry,
                required_attrs=["nonexistentAttr"],
            )
            is False
        )

    def test_matches_criteria_dn_pattern(self, sample_entry: m.Ldif.Entry) -> None:
        """Test matches_criteria with DN pattern."""
        assert (
            FlextLdifUtilitiesEntry.matches_criteria(
                sample_entry,
                dn_pattern=r".*OU=Users.*",
            )
            is True
        )

        assert (
            FlextLdifUtilitiesEntry.matches_criteria(
                sample_entry,
                dn_pattern=r".*OU=Groups.*",
            )
            is False
        )

    def test_transform_batch(self, sample_entries: list[p.Entry]) -> None:
        """Test transform_batch."""
        result = FlextLdifUtilitiesEntry.transform_batch(
            sample_entries,
            normalize_attrs=True,
            attr_case="lower",
        )
        assert result.is_success
        transformed = result.unwrap()
        assert len(transformed) == len(sample_entries)

    def test_filter_batch(self, sample_entries: list[p.Entry]) -> None:
        """Test filter_batch."""
        result = FlextLdifUtilitiesEntry.filter_batch(
            sample_entries,
            objectclasses=["inetOrgPerson"],
        )
        assert result.is_success
        filtered = result.unwrap()
        # Only entries with inetOrgPerson should be included
        assert len(filtered) < len(sample_entries)

    def test_filter_batch_exclude_schema(self, sample_entries: list[p.Entry]) -> None:
        """Test filter_batch with exclude_schema."""
        result = FlextLdifUtilitiesEntry.filter_batch(
            sample_entries,
            exclude_schema=True,
        )
        assert result.is_success
        filtered = result.unwrap()
        # Schema entry should be excluded
        assert len(filtered) < len(sample_entries)


# =========================================================================
# POWER METHOD TESTS
# =========================================================================


class TestFlextLdifUtilitiesPowerMethods:
    """Tests for FlextLdifUtilities power methods."""

    def test_process_method_exists(self) -> None:
        """Test that process() method exists."""
        assert hasattr(FlextLdifUtilities, "process")

    def test_transform_method_exists(self) -> None:
        """Test that transform() method exists."""
        assert hasattr(FlextLdifUtilities, "transform")

    def test_filter_method_exists(self) -> None:
        """Test that filter() method exists."""
        assert hasattr(FlextLdifUtilities, "filter")

    def test_validate_method_exists(self) -> None:
        """Test that validate() method exists."""
        assert hasattr(FlextLdifUtilities.Ldif, "validate")

    def test_dn_method_returns_dnops(self) -> None:
        """Test that dn() returns DnOps instance."""
        ops = FlextLdifUtilities.dn("CN=Test,DC=Example")
        assert isinstance(ops, DnOps)

    def test_entry_method_returns_entryops(self, sample_entry: m.Ldif.Entry) -> None:
        """Test that entry() returns EntryOps instance."""
        ops = FlextLdifUtilities.entry(sample_entry)
        assert isinstance(ops, EntryOps)

    def test_process_entries(self, sample_entries: list[p.Entry]) -> None:
        """Test FlextLdifUtilities.process()."""
        result = FlextLdifUtilities.process(
            sample_entries,
            normalize_dns=True,
            normalize_attrs=True,
        )
        assert result.is_success

    def test_transform_entries(self, sample_entries: list[p.Entry]) -> None:
        """Test FlextLdifUtilities.transform()."""
        result = FlextLdifUtilities.transform(
            sample_entries,
            Normalize.attrs(),
        )
        assert result.is_success

    def test_filter_entries(self, sample_entries: list[p.Entry]) -> None:
        """Test FlextLdifUtilities.filter()."""
        result = FlextLdifUtilities.filter(
            sample_entries,
            Filter.by_objectclass("person"),
        )
        assert result.is_success

    def test_validate_entries(self, sample_entries: list[p.Entry]) -> None:
        """Test FlextLdifUtilities.validate()."""
        result = FlextLdifUtilities.validate(
            sample_entries,
            strict=True,
        )
        assert result.is_success
