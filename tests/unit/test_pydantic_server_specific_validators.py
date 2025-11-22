"""Expert tests for server-specific Entry validators - FASE 9.

Tests validate that Entry.validate_entry_consistency applies correct
server-specific rules based on self.metadata.server_type while maintaining
RFC baseline.

Coverage:
- OID (Oracle Internet Directory) - lenient objectClass, binary auto-detect
- OUD (Oracle Unified Directory) - strict objectClass, naming attr, ;binary
- OpenLDAP - flexible schema, strict ;binary
- Active Directory - strict objectClass, auto-detect binary
- RFC baseline - pure RFC 2849/4512 compliance

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import FlextLdifModels


def get_validation_metadata(entry: object) -> dict[str, object] | None:
    """Helper to get validation_metadata from entry.metadata.validation_results."""
    if not hasattr(entry, "metadata"):
        return None
    metadata = getattr(entry, "metadata", None)
    if not metadata or not hasattr(metadata, "validation_results"):
        return None
    return getattr(metadata, "validation_results", None)


# =============================================================================
# HELPER FUNCTIONS - Server Validation Rule Injection (mimics servers/* behavior)
# =============================================================================


def inject_oud_validation_rules() -> dict[str, object]:
    """Create OUD validation rules dict for injection into metadata.extensions."""
    return {
        "requires_objectclass": True,
        "requires_naming_attr": True,
        "requires_binary_option": True,
        "auto_detect_binary": False,
    }


def inject_oid_validation_rules() -> dict[str, object]:
    """Create OID validation rules dict for injection into metadata.extensions."""
    return {
        "requires_objectclass": False,  # OID is lenient
        "requires_naming_attr": False,  # OID allows missing naming attr
        "requires_binary_option": False,
        "auto_detect_binary": True,  # OID auto-detects binary
    }


def inject_openldap_validation_rules() -> dict[str, object]:
    """Create OpenLDAP validation rules dict for injection into metadata.extensions."""
    return {
        "requires_objectclass": False,  # OpenLDAP flexible schema
        "requires_naming_attr": False,
        "requires_binary_option": True,  # But strict on ;binary
        "auto_detect_binary": False,
        "flexible_schema": True,
    }


def inject_ad_validation_rules() -> dict[str, object]:
    """Create Active Directory validation rules dict for injection into metadata.extensions."""
    return {
        "requires_objectclass": True,  # AD is STRICT on objectClass
        "requires_naming_attr": True,  # AD is STRICT - REQUIRES naming attr in entry
        "requires_binary_option": False,
        "auto_detect_binary": True,  # AD auto-detects binary
    }


class TestOidServerSpecificValidation:
    """Oracle Internet Directory (OID) server-specific validation tests."""

    def test_oid_allows_missing_objectclass(self) -> None:
        """Validate OID allows entries without objectClass (lenient mode)."""
        # Create OID entry without objectClass
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(attributes={"cn": ["test"]}),
            metadata=FlextLdifModels.QuirkMetadata(quirk_type="oid"),
        )

        # Should validate without errors (OID is lenient)
        assert entry.dn is not None
        assert entry.dn.value == "cn=test,dc=example,dc=com"

        # Check RFC violation is captured (not server-specific)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert "rfc_violations" in validation_metadata
        rfc_violations_obj = validation_metadata["rfc_violations"]
        assert isinstance(rfc_violations_obj, list)
        assert any("objectClass" in v for v in rfc_violations_obj)

        # No server-specific violations (OID allows this)
        validation_metadata = get_validation_metadata(entry)
        if validation_metadata is not None:
            assert "server_specific_violations" not in validation_metadata

    def test_oid_allows_missing_naming_attribute(self) -> None:
        """Validate OID allows missing naming attribute from RDN (lenient)."""
        # Create OID entry with missing naming attribute
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": ["person"],
                    # Missing 'cn' attribute
                },
            ),
            metadata=FlextLdifModels.QuirkMetadata(quirk_type="oid"),
        )

        # Check RFC violation is captured (SHOULD have naming attr)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert "rfc_violations" in validation_metadata
        rfc_violations_obj = validation_metadata["rfc_violations"]
        assert isinstance(rfc_violations_obj, list)
        assert any("Naming attribute" in v for v in rfc_violations_obj)

        # No server-specific violations (OID allows this)
        validation_metadata = get_validation_metadata(entry)
        if validation_metadata is not None:
            assert "server_specific_violations" not in validation_metadata

    def test_oid_binary_attribute_without_option_allowed(self) -> None:
        """Validate OID allows binary attributes without ;binary (auto-detect)."""
        # Create OID entry with binary data without ;binary option
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": ["test"],
                    "userCertificate": ["\x00\x01\x02\x03"],  # Binary data
                },
            ),
            metadata=FlextLdifModels.QuirkMetadata(quirk_type="oid"),
        )

        # Check RFC violation is captured (MAY need ;binary)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert "rfc_violations" in validation_metadata

        # No server-specific violations (OID auto-detects)
        validation_metadata = get_validation_metadata(entry)
        if validation_metadata is not None:
            assert "server_specific_violations" not in validation_metadata


class TestOudServerSpecificValidation:
    """Oracle Unified Directory (OUD) server-specific validation tests."""

    def test_oud_requires_objectclass(self) -> None:
        """Validate OUD requires objectClass attribute (stricter than RFC)."""
        # Create OUD entry without objectClass
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(attributes={"cn": ["test"]}),
            metadata=FlextLdifModels.QuirkMetadata(
                quirk_type="oud",
                extensions={"validation_rules": inject_oud_validation_rules()},
            ),
        )

        # Check server-specific violation is captured (OUD REQUIRES objectClass)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert "server_specific_violations" in validation_metadata
        violations_obj = validation_metadata["server_specific_violations"]
        assert isinstance(violations_obj, list)
        assert any("objectClass" in v for v in violations_obj)

    def test_oud_requires_naming_attribute(self) -> None:
        """Validate OUD requires naming attribute from RDN (stricter than RFC)."""
        # Create OUD entry with missing naming attribute
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": ["person"],
                    # Missing 'cn' attribute
                },
            ),
            metadata=FlextLdifModels.QuirkMetadata(
                quirk_type="oud",
                extensions={"validation_rules": inject_oud_validation_rules()},
            ),
        )

        # Check server-specific violation is captured (OUD REQUIRES naming attr)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert "server_specific_violations" in validation_metadata
        violations_obj = validation_metadata["server_specific_violations"]
        assert isinstance(violations_obj, list)
        assert any("naming attribute" in v.lower() for v in violations_obj)

    def test_oud_requires_binary_option(self) -> None:
        """Validate OUD requires ;binary option for binary attributes."""
        # Create OUD entry with binary data without ;binary option
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": ["test"],
                    "userCertificate": ["\x00\x01\x02\x03"],  # Binary data
                },
            ),
            metadata=FlextLdifModels.QuirkMetadata(
                quirk_type="oud",
                extensions={"validation_rules": inject_oud_validation_rules()},
            ),
        )

        # Check server-specific violation is captured (OUD REQUIRES ;binary)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert "server_specific_violations" in validation_metadata
        violations_obj = validation_metadata["server_specific_violations"]
        assert isinstance(violations_obj, list)
        assert any(";binary" in v.lower() for v in violations_obj)

    def test_oud_valid_entry_with_all_requirements(self) -> None:
        """Validate OUD accepts fully compliant entry."""
        # Create fully compliant OUD entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": ["test"],
                    "userCertificate;binary": ["base64encodeddata"],
                },
            ),
            metadata=FlextLdifModels.QuirkMetadata(
                quirk_type="oud",
                extensions={"validation_rules": inject_oud_validation_rules()},
            ),
        )

        # No violations
        validation_metadata = get_validation_metadata(entry)
        if validation_metadata is not None:
            assert "rfc_violations" not in validation_metadata
        validation_metadata = get_validation_metadata(entry)
        if validation_metadata is not None:
            assert "server_specific_violations" not in validation_metadata


class TestOpenLdapServerSpecificValidation:
    """OpenLDAP server-specific validation tests."""

    def test_openldap_allows_missing_objectclass(self) -> None:
        """Validate OpenLDAP allows entries without objectClass (flexible)."""
        # Create OpenLDAP entry without objectClass
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(attributes={"cn": ["test"]}),
            metadata=FlextLdifModels.QuirkMetadata(
                quirk_type="openldap",
                extensions={"validation_rules": inject_openldap_validation_rules()},
            ),
        )

        # RFC violation captured (SHOULD have objectClass)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert "rfc_violations" in validation_metadata

        # No server-specific violations (OpenLDAP allows this)
        validation_metadata = get_validation_metadata(entry)
        if validation_metadata is not None:
            assert "server_specific_violations" not in validation_metadata

    def test_openldap_requires_binary_option(self) -> None:
        """Validate OpenLDAP 2.x requires ;binary option for binary attributes."""
        # Create OpenLDAP entry with binary data without ;binary option
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": ["test"],
                    "userCertificate": ["\x00\x01\x02\x03"],  # Binary data
                },
            ),
            metadata=FlextLdifModels.QuirkMetadata(
                quirk_type="openldap",
                extensions={"validation_rules": inject_openldap_validation_rules()},
            ),
        )

        # Check server-specific violation is captured (OpenLDAP REQUIRES ;binary)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert "server_specific_violations" in validation_metadata
        violations_obj = validation_metadata["server_specific_violations"]
        assert isinstance(violations_obj, list)
        assert any(";binary" in v.lower() for v in violations_obj)

    def test_openldap_schema_entry_detection(self) -> None:
        """Validate OpenLDAP schema entry detection (cn=schema, cn=subschema)."""
        # Create OpenLDAP schema entry without objectClass
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=subschema"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "attributeTypes": ["( 1.2.3.4 NAME 'test' )"],
                },
            ),
            metadata=FlextLdifModels.QuirkMetadata(
                quirk_type="openldap",
                extensions={"validation_rules": inject_openldap_validation_rules()},
            ),
        )

        # Schema entries are exempt from objectClass requirement
        # No objectClass violation
        validation_metadata = get_validation_metadata(entry)
        if validation_metadata is not None:
            rfc_violations = validation_metadata.get("rfc_violations")
            if isinstance(rfc_violations, list):
                assert not any("objectClass" in v for v in rfc_violations)


class TestActiveDirectoryServerSpecificValidation:
    """Active Directory (AD) server-specific validation tests."""

    def test_ad_requires_objectclass(self) -> None:
        """Validate AD requires objectClass attribute (strict mode)."""
        # Create AD entry without objectClass
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(attributes={"cn": ["test"]}),
            metadata=FlextLdifModels.QuirkMetadata(
                quirk_type="ad",
                extensions={"validation_rules": inject_ad_validation_rules()},
            ),
        )

        # Check server-specific violation is captured (AD REQUIRES objectClass)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert "server_specific_violations" in validation_metadata
        violations_obj = validation_metadata["server_specific_violations"]
        assert isinstance(violations_obj, list)
        assert any("objectclass" in v.lower() for v in violations_obj)

    def test_ad_requires_naming_attribute(self) -> None:
        """Validate AD requires naming attribute from RDN."""
        # Create AD entry with missing naming attribute
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": ["user"],
                    # Missing 'cn' attribute
                },
            ),
            metadata=FlextLdifModels.QuirkMetadata(
                quirk_type="ad",
                extensions={"validation_rules": inject_ad_validation_rules()},
            ),
        )

        # Check server-specific violation is captured (AD REQUIRES naming attr)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert "server_specific_violations" in validation_metadata
        violations_obj = validation_metadata["server_specific_violations"]
        assert isinstance(violations_obj, list)
        assert any("naming attribute" in v.lower() for v in violations_obj)

    def test_ad_binary_attribute_without_option_allowed(self) -> None:
        """Validate AD allows binary attributes without ;binary (auto-detect)."""
        # Create AD entry with objectGUID without ;binary option
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": ["user"],
                    "cn": ["test"],
                    "objectGUID": ["\x00\x01\x02\x03"],  # Binary GUID
                },
            ),
            metadata=FlextLdifModels.QuirkMetadata(
                quirk_type="ad",
                extensions={"validation_rules": inject_ad_validation_rules()},
            ),
        )

        # RFC violation captured (MAY need ;binary)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert "rfc_violations" in validation_metadata

        # No server-specific violations (AD auto-detects)
        validation_metadata = get_validation_metadata(entry)
        if validation_metadata is not None:
            assert "server_specific_violations" not in validation_metadata


class TestRfcBaselineValidation:
    """RFC baseline validation tests (pure RFC 2849/4512 compliance)."""

    def test_rfc_objectclass_should_be_present(self) -> None:
        """Validate RFC baseline: objectClass SHOULD be present (warning)."""
        # Create RFC entry without objectClass
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(attributes={"cn": ["test"]}),
            metadata=FlextLdifModels.QuirkMetadata(quirk_type="rfc"),
        )

        # RFC violation captured (SHOULD have objectClass)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert "rfc_violations" in validation_metadata
        rfc_violations_obj = validation_metadata["rfc_violations"]
        assert isinstance(rfc_violations_obj, list)
        assert any("RFC 4512" in v and "objectClass" in v for v in rfc_violations_obj)

        # No server-specific violations (pure RFC mode)
        validation_metadata = get_validation_metadata(entry)
        if validation_metadata is not None:
            assert "server_specific_violations" not in validation_metadata

    def test_rfc_naming_attribute_should_be_present(self) -> None:
        """Validate RFC baseline: naming attribute SHOULD be present (warning)."""
        # Create RFC entry with missing naming attribute
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": ["person"],
                    # Missing 'cn' attribute
                },
            ),
            metadata=FlextLdifModels.QuirkMetadata(quirk_type="rfc"),
        )

        # RFC violation captured (SHOULD have naming attr)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert "rfc_violations" in validation_metadata
        rfc_violations_obj = validation_metadata.get("rfc_violations")
        assert isinstance(rfc_violations_obj, list)
        assert any(
            "RFC 4512 § 2.3" in v and "Naming attribute" in v
            for v in rfc_violations_obj
        )

        # No server-specific violations (pure RFC mode)
        validation_metadata = get_validation_metadata(entry)
        if validation_metadata is not None:
            assert "server_specific_violations" not in validation_metadata

    def test_rfc_binary_attribute_may_need_option(self) -> None:
        """Validate RFC baseline: binary attributes MAY need ;binary (warning)."""
        # Create RFC entry with binary data without ;binary option
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": ["test"],
                    "userCertificate": ["\x00\x01\x02\x03"],  # Binary data
                },
            ),
            metadata=FlextLdifModels.QuirkMetadata(quirk_type="rfc"),
        )

        # RFC violation captured (MAY need ;binary)
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert "rfc_violations" in validation_metadata
        rfc_violations_obj = validation_metadata.get("rfc_violations")
        assert isinstance(rfc_violations_obj, list)
        assert any("RFC 2849" in v and ";binary" in v for v in rfc_violations_obj)

        # No server-specific violations (pure RFC mode)
        validation_metadata = get_validation_metadata(entry)
        if validation_metadata is not None:
            assert "server_specific_violations" not in validation_metadata

    def test_rfc_valid_entry_no_violations(self) -> None:
        """Validate RFC accepts fully compliant entry with no violations."""
        # Create fully compliant RFC entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": ["test"],
                    "sn": ["Test"],
                },
            ),
            metadata=FlextLdifModels.QuirkMetadata(quirk_type="rfc"),
        )

        # No violations
        validation_metadata = get_validation_metadata(entry)
        if validation_metadata is not None:
            assert "rfc_violations" not in validation_metadata
        validation_metadata = get_validation_metadata(entry)
        if validation_metadata is not None:
            assert "server_specific_violations" not in validation_metadata


class TestMetadataCapture:
    """Tests for comprehensive metadata capture during validation."""

    def test_validation_server_type_captured(self) -> None:
        """Validate server_type is captured in metadata.extensions."""
        # Create entry with server type
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": ["test"],
                },
            ),
            metadata=FlextLdifModels.QuirkMetadata(
                quirk_type="oud",
                extensions={"validation_rules": inject_oud_validation_rules()},
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
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={},
            ),  # Missing objectClass and cn
            metadata=FlextLdifModels.QuirkMetadata(quirk_type="rfc"),
        )

        # Check RFC violations in both locations
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert entry.metadata is not None
        assert entry.metadata.extensions is not None
        assert "rfc_violations" in validation_metadata
        assert "rfc_violations" in entry.metadata.extensions
        rfc_violations_validation = validation_metadata["rfc_violations"]
        rfc_violations_extensions = entry.metadata.extensions["rfc_violations"]
        assert isinstance(rfc_violations_validation, list)
        assert isinstance(rfc_violations_extensions, list)
        assert rfc_violations_validation == rfc_violations_extensions

    def test_server_specific_violations_in_extensions(self) -> None:
        """Validate server-specific violations are preserved in metadata.extensions."""
        # Create OUD entry with violations
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={},
            ),  # Missing objectClass and cn
            metadata=FlextLdifModels.QuirkMetadata(
                quirk_type="oud",
                extensions={"validation_rules": inject_oud_validation_rules()},
            ),
        )

        # Check server-specific violations in both locations
        validation_metadata = get_validation_metadata(entry)
        assert validation_metadata is not None
        assert entry.metadata is not None
        assert entry.metadata.extensions is not None
        assert "server_specific_violations" in validation_metadata
        assert "server_specific_violations" in entry.metadata.extensions
        server_violations_validation = validation_metadata["server_specific_violations"]
        server_violations_extensions = entry.metadata.extensions[
            "server_specific_violations"
        ]
        assert isinstance(server_violations_validation, list)
        assert isinstance(server_violations_extensions, list)
        assert server_violations_validation == server_violations_extensions


__all__ = [
    "TestActiveDirectoryServerSpecificValidation",
    "TestMetadataCapture",
    "TestOidServerSpecificValidation",
    "TestOpenLdapServerSpecificValidation",
    "TestOudServerSpecificValidation",
    "TestRfcBaselineValidation",
]
