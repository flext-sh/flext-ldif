"""Tests for server-specific Pydantic validators.

This module tests server-specific validation rules for entries and their metadata,
including validation of ObjectClasses, ACL formats, DN case handling, and encoding
rules specific to different LDAP server implementations.
"""

from __future__ import annotations

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.validation import (
    AclFormatRules,
    DnCaseRules,
    EncodingRules,
    ServerValidationRules,
)

from tests import m, s


def get_validation_metadata(
    entry: m.Ldif.Entry,
) -> FlextLdifModelsDomains.ValidationMetadata | None:
    """Helper to get validation_metadata from entry.metadata.validation_results."""
    if not hasattr(entry, "metadata"):
        return None
    metadata = getattr(entry, "metadata", None)
    if not metadata or not hasattr(metadata, "validation_results"):
        return None
    result = getattr(metadata, "validation_results", None)
    if isinstance(result, FlextLdifModelsDomains.ValidationMetadata):
        return result
    return None


# =============================================================================
# HELPER FUNCTIONS - Server Validation Rule Injection (mimics servers/* behavior)
# =============================================================================


def inject_oud_validation_rules() -> ServerValidationRules:
    """Create OUD validation rules for injection into metadata.extensions."""
    return ServerValidationRules(
        requires_objectclass=True,
        requires_naming_attr=True,
        requires_binary_option=True,
        encoding_rules=EncodingRules(default_encoding="utf-8"),
        dn_case_rules=DnCaseRules(preserve_case=True),
        acl_format_rules=AclFormatRules(
            format="aci",
            attribute_name="aci",
            requires_target=False,
            requires_subject=False,
        ),
        track_deletions=False,
        track_modifications=False,
        track_conversions=False,
    )


def inject_oid_validation_rules() -> ServerValidationRules:
    """Create OID validation rules for injection into metadata.extensions."""
    return ServerValidationRules(
        requires_objectclass=False,  # OID is lenient
        requires_naming_attr=False,  # OID allows missing naming attr
        requires_binary_option=False,
        encoding_rules=EncodingRules(default_encoding="utf-8"),
        dn_case_rules=DnCaseRules(preserve_case=True),
        acl_format_rules=AclFormatRules(
            format="aci",
            attribute_name="aci",
            requires_target=False,
            requires_subject=False,
        ),
        track_deletions=False,
        track_modifications=False,
        track_conversions=False,
    )


def inject_openldap_validation_rules() -> ServerValidationRules:
    """Create OpenLDAP validation rules for injection into metadata.extensions."""
    return ServerValidationRules(
        requires_objectclass=False,  # OpenLDAP flexible schema
        requires_naming_attr=False,
        requires_binary_option=True,  # But strict on ;binary
        encoding_rules=EncodingRules(default_encoding="utf-8"),
        dn_case_rules=DnCaseRules(preserve_case=True),
        acl_format_rules=AclFormatRules(
            format="aci",
            attribute_name="aci",
            requires_target=False,
            requires_subject=False,
        ),
        track_deletions=False,
        track_modifications=False,
        track_conversions=False,
    )


def inject_ad_validation_rules() -> ServerValidationRules:
    """Create Active Directory validation rules for injection into metadata.extensions."""
    return ServerValidationRules(
        requires_objectclass=True,  # AD is STRICT on objectClass
        requires_naming_attr=True,  # AD is STRICT - REQUIRES naming attr in entry
        requires_binary_option=False,
        encoding_rules=EncodingRules(default_encoding="utf-8"),
        dn_case_rules=DnCaseRules(preserve_case=True),
        acl_format_rules=AclFormatRules(
            format="aci",
            attribute_name="aci",
            requires_target=False,
            requires_subject=False,
        ),
        track_deletions=False,
        track_modifications=False,
        track_conversions=False,
    )


class TestsFlextLdifOidServerSpecificValidation(s):
    """Oracle Internet Directory (OID) server-specific validation tests."""

    def test_oid_allows_missing_objectclass(self) -> None:
        """Validate OID allows entries without objectClass (lenient mode)."""
        # Create OID entry without objectClass
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value="cn=test,dc=example,dc=com"),
            attributes=m.Ldif.Attributes(attributes={"cn": ["test"]}),
            metadata=m.Ldif.QuirkMetadata(quirk_type="oid"),
        )

        # Should validate without errors (OID is lenient)
        assert entry.dn is not None
        assert entry.dn.value == "cn=test,dc=example,dc=com"

        # Check RFC violation is captured (not server-specific)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert validation_metadata.rfc_violations is not None
        rfc_violations_obj = validation_metadata.rfc_violations
        assert isinstance(rfc_violations_obj, list)
        assert any("objectClass" in v for v in rfc_violations_obj)

        # No server-specific violations (OID allows this)
        validation_metadata = get_validation_metadata(entry)
        if validation_metadata is not None:
            assert validation_metadata.server_specific_violations == []

    def test_oid_allows_missing_naming_attribute(self) -> None:
        """Validate OID allows missing naming attribute from RDN (lenient)."""
        # Create OID entry with missing naming attribute
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value="cn=test,dc=example,dc=com"),
            attributes=m.Ldif.Attributes(
                attributes={
                    "objectClass": ["person"],
                    # Missing 'cn' attribute
                },
            ),
            metadata=m.Ldif.QuirkMetadata(quirk_type="oid"),
        )

        # Check RFC violation is captured (SHOULD have naming attr)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert validation_metadata.rfc_violations is not None
        rfc_violations_obj = validation_metadata.rfc_violations
        assert isinstance(rfc_violations_obj, list)
        assert any("Naming attribute" in v for v in rfc_violations_obj)

        # No server-specific violations (OID allows this)
        validation_metadata = get_validation_metadata(entry)
        if validation_metadata is not None:
            assert validation_metadata.server_specific_violations == []

    def test_oid_binary_attribute_without_option_allowed(self) -> None:
        """Validate OID allows binary attributes without ;binary (auto-detect)."""
        # Create OID entry with binary data without ;binary option
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value="cn=test,dc=example,dc=com"),
            attributes=m.Ldif.Attributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": ["test"],
                    "userCertificate": ["\x00\x01\x02\x03"],  # Binary data
                },
            ),
            metadata=m.Ldif.QuirkMetadata(quirk_type="oid"),
        )

        # Check RFC violation is captured (MAY need ;binary)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert validation_metadata.rfc_violations is not None

        # No server-specific violations (OID auto-detects)
        validation_metadata = get_validation_metadata(entry)
        if validation_metadata is not None:
            assert validation_metadata.server_specific_violations == []


class TestOudServerSpecificValidation:
    """Oracle Unified Directory (OUD) server-specific validation tests."""

    def test_oud_requires_objectclass(self) -> None:
        """Validate OUD requires objectClass attribute (stricter than RFC)."""
        # Create OUD entry without objectClass
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value="cn=test,dc=example,dc=com"),
            attributes=m.Ldif.Attributes(attributes={"cn": ["test"]}),
            metadata=m.Ldif.QuirkMetadata(
                quirk_type="oud",
                extensions=m.Ldif.DynamicMetadata(
                    validation_rules=inject_oud_validation_rules().model_dump(),
                ),
            ),
        )

        # Check server-specific violation is captured (OUD REQUIRES objectClass)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert validation_metadata.server_specific_violations is not None
        violations_obj = validation_metadata.server_specific_violations
        assert isinstance(violations_obj, list)
        assert any("objectClass" in v for v in violations_obj)

    def test_oud_requires_naming_attribute(self) -> None:
        """Validate OUD requires naming attribute from RDN (stricter than RFC)."""
        # Create OUD entry with missing naming attribute
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value="cn=test,dc=example,dc=com"),
            attributes=m.Ldif.Attributes(
                attributes={
                    "objectClass": ["person"],
                    # Missing 'cn' attribute
                },
            ),
            metadata=m.Ldif.QuirkMetadata(
                quirk_type="oud",
                extensions=m.Ldif.DynamicMetadata(
                    validation_rules=inject_oud_validation_rules().model_dump(),
                ),
            ),
        )

        # Check server-specific violation is captured (OUD REQUIRES naming attr)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert validation_metadata.server_specific_violations is not None
        violations_obj = validation_metadata.server_specific_violations
        assert isinstance(violations_obj, list)
        assert any("naming attribute" in v.lower() for v in violations_obj)

    def test_oud_requires_binary_option(self) -> None:
        """Validate OUD requires ;binary option for binary attributes."""
        # Create OUD entry with binary data without ;binary option
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value="cn=test,dc=example,dc=com"),
            attributes=m.Ldif.Attributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": ["test"],
                    "userCertificate": ["\x00\x01\x02\x03"],  # Binary data
                },
            ),
            metadata=m.Ldif.QuirkMetadata(
                quirk_type="oud",
                extensions=m.Ldif.DynamicMetadata(
                    validation_rules=inject_oud_validation_rules().model_dump(),
                ),
            ),
        )

        # Check server-specific violation is captured (OUD REQUIRES ;binary)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert validation_metadata.server_specific_violations is not None
        violations_obj = validation_metadata.server_specific_violations
        assert isinstance(violations_obj, list)
        assert any(";binary" in v.lower() for v in violations_obj)

    def test_oud_valid_entry_with_all_requirements(self) -> None:
        """Validate OUD accepts fully compliant entry."""
        # Create fully compliant OUD entry
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value="cn=test,dc=example,dc=com"),
            attributes=m.Ldif.Attributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": ["test"],
                    "userCertificate;binary": ["base64encodeddata"],
                },
            ),
            metadata=m.Ldif.QuirkMetadata(
                quirk_type="oud",
                extensions=m.Ldif.DynamicMetadata(
                    validation_rules=inject_oud_validation_rules().model_dump(),
                ),
            ),
        )

        # No violations
        validation_metadata = get_validation_metadata(entry)
        if validation_metadata is not None:
            assert validation_metadata.rfc_violations == []
        validation_metadata = get_validation_metadata(entry)
        if validation_metadata is not None:
            assert validation_metadata.server_specific_violations == []


class TestOpenLdapServerSpecificValidation:
    """OpenLDAP server-specific validation tests."""

    def test_openldap_allows_missing_objectclass(self) -> None:
        """Validate OpenLDAP allows entries without objectClass (flexible)."""
        # Create OpenLDAP entry without objectClass
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value="cn=test,dc=example,dc=com"),
            attributes=m.Ldif.Attributes(attributes={"cn": ["test"]}),
            metadata=m.Ldif.QuirkMetadata(
                quirk_type="openldap",
                extensions=m.Ldif.DynamicMetadata(
                    validation_rules=inject_openldap_validation_rules().model_dump(),
                ),
            ),
        )

        # RFC violation captured (SHOULD have objectClass)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert validation_metadata.rfc_violations is not None

        # No server-specific violations (OpenLDAP allows this)
        validation_metadata = get_validation_metadata(entry)
        if validation_metadata is not None:
            assert validation_metadata.server_specific_violations == []

    def test_openldap_requires_binary_option(self) -> None:
        """Validate OpenLDAP 2.x requires ;binary option for binary attributes."""
        # Create OpenLDAP entry with binary data without ;binary option
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value="cn=test,dc=example,dc=com"),
            attributes=m.Ldif.Attributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": ["test"],
                    "userCertificate": ["\x00\x01\x02\x03"],  # Binary data
                },
            ),
            metadata=m.Ldif.QuirkMetadata(
                quirk_type="openldap",
                extensions=m.Ldif.DynamicMetadata(
                    validation_rules=inject_openldap_validation_rules().model_dump(),
                ),
            ),
        )

        # Check server-specific violation is captured (OpenLDAP REQUIRES ;binary)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert validation_metadata.server_specific_violations is not None
        violations_obj = validation_metadata.server_specific_violations
        assert isinstance(violations_obj, list)
        assert any(";binary" in v.lower() for v in violations_obj)

    def test_openldap_schema_entry_detection(self) -> None:
        """Validate OpenLDAP schema entry detection (cn=schema, cn=subschema)."""
        # Create OpenLDAP schema entry without objectClass
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value="cn=subschema"),
            attributes=m.Ldif.Attributes(
                attributes={
                    "attributeTypes": ["( 1.2.3.4 NAME 'test' )"],
                },
            ),
            metadata=m.Ldif.QuirkMetadata(
                quirk_type="openldap",
                extensions=m.Ldif.DynamicMetadata(
                    validation_rules=inject_openldap_validation_rules().model_dump(),
                ),
            ),
        )

        # Schema entries are exempt from objectClass requirement
        # No objectClass violation
        validation_metadata = get_validation_metadata(entry)
        if validation_metadata is not None:
            rfc_violations = validation_metadata.rfc_violations
            if isinstance(rfc_violations, list):
                assert not any("objectClass" in v for v in rfc_violations)


class TestActiveDirectoryServerSpecificValidation:
    """Active Directory (AD) server-specific validation tests."""

    def test_ad_requires_objectclass(self) -> None:
        """Validate AD requires objectClass attribute (strict mode)."""
        # Create AD entry without objectClass
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value="cn=test,dc=example,dc=com"),
            attributes=m.Ldif.Attributes(attributes={"cn": ["test"]}),
            metadata=m.Ldif.QuirkMetadata(
                quirk_type="ad",
                extensions=m.Ldif.DynamicMetadata(
                    validation_rules=inject_ad_validation_rules().model_dump(),
                ),
            ),
        )

        # Check server-specific violation is captured (AD REQUIRES objectClass)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert validation_metadata.server_specific_violations is not None
        violations_obj = validation_metadata.server_specific_violations
        assert isinstance(violations_obj, list)
        assert any("objectclass" in v.lower() for v in violations_obj)

    def test_ad_requires_naming_attribute(self) -> None:
        """Validate AD requires naming attribute from RDN."""
        # Create AD entry with missing naming attribute
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value="cn=test,dc=example,dc=com"),
            attributes=m.Ldif.Attributes(
                attributes={
                    "objectClass": ["user"],
                    # Missing 'cn' attribute
                },
            ),
            metadata=m.Ldif.QuirkMetadata(
                quirk_type="ad",
                extensions=m.Ldif.DynamicMetadata(
                    validation_rules=inject_ad_validation_rules().model_dump(),
                ),
            ),
        )

        # Check server-specific violation is captured (AD REQUIRES naming attr)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert validation_metadata.server_specific_violations is not None
        violations_obj = validation_metadata.server_specific_violations
        assert isinstance(violations_obj, list)
        assert any("naming attribute" in v.lower() for v in violations_obj)

    def test_ad_binary_attribute_without_option_allowed(self) -> None:
        """Validate AD allows binary attributes without ;binary (auto-detect)."""
        # Create AD entry with objectGUID without ;binary option
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value="cn=test,dc=example,dc=com"),
            attributes=m.Ldif.Attributes(
                attributes={
                    "objectClass": ["user"],
                    "cn": ["test"],
                    "objectGUID": ["\x00\x01\x02\x03"],  # Binary GUID
                },
            ),
            metadata=m.Ldif.QuirkMetadata(
                quirk_type="ad",
                extensions=m.Ldif.DynamicMetadata(
                    validation_rules=inject_ad_validation_rules().model_dump(),
                ),
            ),
        )

        # RFC violation captured (MAY need ;binary)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert validation_metadata.rfc_violations is not None

        # No server-specific violations (AD auto-detects)
        validation_metadata = get_validation_metadata(entry)
        if validation_metadata is not None:
            assert validation_metadata.server_specific_violations == []


class TestRfcBaselineValidation:
    """RFC baseline validation tests (pure RFC 2849/4512 compliance)."""

    def test_rfc_objectclass_should_be_present(self) -> None:
        """Validate RFC baseline: objectClass SHOULD be present (warning)."""
        # Create RFC entry without objectClass
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value="cn=test,dc=example,dc=com"),
            attributes=m.Ldif.Attributes(attributes={"cn": ["test"]}),
            metadata=m.Ldif.QuirkMetadata(quirk_type="rfc"),
        )

        # RFC violation captured (SHOULD have objectClass)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert validation_metadata.rfc_violations is not None
        rfc_violations_obj = validation_metadata.rfc_violations
        assert isinstance(rfc_violations_obj, list)
        assert any("RFC 4512" in v and "objectClass" in v for v in rfc_violations_obj)

        # No server-specific violations (pure RFC mode)
        validation_metadata = get_validation_metadata(entry)
        if validation_metadata is not None:
            assert validation_metadata.server_specific_violations == []

    def test_rfc_naming_attribute_should_be_present(self) -> None:
        """Validate RFC baseline: naming attribute SHOULD be present (warning)."""
        # Create RFC entry with missing naming attribute
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value="cn=test,dc=example,dc=com"),
            attributes=m.Ldif.Attributes(
                attributes={
                    "objectClass": ["person"],
                    # Missing 'cn' attribute
                },
            ),
            metadata=m.Ldif.QuirkMetadata(quirk_type="rfc"),
        )

        # RFC violation captured (SHOULD have naming attr)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert validation_metadata.rfc_violations is not None
        rfc_violations_obj = validation_metadata.rfc_violations
        assert isinstance(rfc_violations_obj, list)
        assert any(
            "RFC 4512 § 2.3" in v and "Naming attribute" in v
            for v in rfc_violations_obj
        )

        # No server-specific violations (pure RFC mode)
        validation_metadata = get_validation_metadata(entry)
        if validation_metadata is not None:
            assert validation_metadata.server_specific_violations == []

    def test_rfc_binary_attribute_may_need_option(self) -> None:
        """Validate RFC baseline: binary attributes MAY need ;binary (warning)."""
        # Create RFC entry with binary data without ;binary option
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value="cn=test,dc=example,dc=com"),
            attributes=m.Ldif.Attributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": ["test"],
                    "userCertificate": ["\x00\x01\x02\x03"],  # Binary data
                },
            ),
            metadata=m.Ldif.QuirkMetadata(quirk_type="rfc"),
        )

        # RFC violation captured (MAY need ;binary)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert validation_metadata.rfc_violations is not None
        rfc_violations_obj = validation_metadata.rfc_violations
        assert isinstance(rfc_violations_obj, list)
        assert any("RFC 2849" in v and ";binary" in v for v in rfc_violations_obj)

        # No server-specific violations (pure RFC mode)
        validation_metadata = get_validation_metadata(entry)
        if validation_metadata is not None:
            assert validation_metadata.server_specific_violations == []

    def test_rfc_valid_entry_no_violations(self) -> None:
        """Validate RFC accepts fully compliant entry with no violations."""
        # Create fully compliant RFC entry
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value="cn=test,dc=example,dc=com"),
            attributes=m.Ldif.Attributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": ["test"],
                    "sn": ["Test"],
                },
            ),
            metadata=m.Ldif.QuirkMetadata(quirk_type="rfc"),
        )

        # No violations
        validation_metadata = get_validation_metadata(entry)
        if validation_metadata is not None:
            assert validation_metadata.rfc_violations == []
        validation_metadata = get_validation_metadata(entry)
        if validation_metadata is not None:
            assert validation_metadata.server_specific_violations == []


class TestMetadataCapture:
    """Tests for comprehensive metadata capture during validation."""

    def test_validation_server_type_captured(self) -> None:
        """Validate server_type is captured in metadata.extensions."""
        # Create entry with server type
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value="cn=test,dc=example,dc=com"),
            attributes=m.Ldif.Attributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": ["test"],
                },
            ),
            metadata=m.Ldif.QuirkMetadata(
                quirk_type="oud",
                extensions=m.Ldif.DynamicMetadata(
                    validation_rules=inject_oud_validation_rules().model_dump(),
                ),
            ),
        )

        # Check validation_server_type is captured
        assert entry.metadata is not None
        assert entry.metadata.extensions is not None
        assert "validation_server_type" in entry.metadata.extensions
        assert entry.metadata.extensions["validation_server_type"] == "oud"

    def test_rfc_violations_in_extensions(self) -> None:
        """Validate RFC violations are preserved in metadata.extensions."""
        # Create entry with RFC violations
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value="cn=test,dc=example,dc=com"),
            attributes=m.Ldif.Attributes(
                attributes={},
            ),  # Missing objectClass and cn
            metadata=m.Ldif.QuirkMetadata(quirk_type="rfc"),
        )

        # Check RFC violations in validation_results
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert entry.metadata is not None
        assert entry.metadata.extensions is not None
        assert validation_metadata.rfc_violations is not None
        rfc_violations_validation = validation_metadata.rfc_violations
        assert isinstance(rfc_violations_validation, list)
        assert len(rfc_violations_validation) > 0

    def test_server_specific_violations_in_extensions(self) -> None:
        """Validate server-specific violations are preserved in metadata.extensions."""
        # Create OUD entry with violations
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value="cn=test,dc=example,dc=com"),
            attributes=m.Ldif.Attributes(
                attributes={},
            ),  # Missing objectClass and cn
            metadata=m.Ldif.QuirkMetadata(
                quirk_type="oud",
                extensions=m.Ldif.DynamicMetadata(
                    validation_rules=inject_oud_validation_rules().model_dump(),
                ),
            ),
        )

        # Check server-specific violations in validation_results
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert entry.metadata is not None
        assert entry.metadata.extensions is not None
        assert validation_metadata.server_specific_violations is not None
        server_violations_validation = validation_metadata.server_specific_violations
        assert isinstance(server_violations_validation, list)
        assert len(server_violations_validation) > 0


__all__ = [
    "TestActiveDirectoryServerSpecificValidation",
    "TestMetadataCapture",
    "TestOidServerSpecificValidation",
    "TestOpenLdapServerSpecificValidation",
    "TestOudServerSpecificValidation",
    "TestRfcBaselineValidation",
]
