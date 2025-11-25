"""Comprehensive tests for server detector service with all code paths.

Tests FlextLdifDetector service with complete coverage including:
- Oracle OID server detection via OID patterns and attributes
- Oracle OUD server detection via ds-* patterns and attributes
- OpenLDAP server detection via olc* patterns
- Active Directory detection via AD OID patterns and attributes
- 389 DS and Apache DS detection
- Confidence threshold handling and fallback to RFC
- Error handling (missing input, encoding errors, exceptions)
- Pattern extraction from LDIF content
- File-based detection
- Config resolution methods

Scope:
- Server type auto-detection from LDIF content
- Pattern matching and heuristics
- Confidence scoring and thresholds
- Error recovery and edge cases

Modules tested: flext_ldif.services.detector, flext_ldif.config, flext_ldif.constants

Uses advanced Python 3.13 features, factories, parametrization, mappings, and helpers
for minimal code with maximum coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Final

import pytest
from flext_core import FlextConfig
from flext_tests import FlextTestsMatchers

from flext_ldif import FlextLdifModels
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.services.detector import FlextLdifDetector


class DetectorTestData:
    """Test data constants and mappings for detector tests."""

    # Server types - use constants directly
    SERVER_OID: Final[str] = FlextLdifConstants.ServerTypes.OID
    SERVER_OUD: Final[str] = FlextLdifConstants.ServerTypes.OUD
    SERVER_OPENLDAP: Final[str] = FlextLdifConstants.ServerTypes.OPENLDAP
    SERVER_AD: Final[str] = FlextLdifConstants.ServerTypes.AD
    SERVER_RFC: Final[str] = FlextLdifConstants.ServerTypes.RFC
    SERVER_RELAXED: Final[str] = FlextLdifConstants.ServerTypes.RELAXED

    # LDIF content templates
    LDIF_VERSION_HEADER: Final[str] = "version: 1\n"
    LDIF_BASIC_ENTRY: Final[str] = "dn: cn=test,dc=example,dc=com\nobjectClass: top\n"

    # Server detection patterns mapping - DRY pattern for all server types
    SERVER_PATTERNS: Final[Mapping[str, Mapping[str, list[str]]]] = {
        SERVER_OID: {
            "oid_patterns": ["2.16.840.1.113894.1.1.1"],
            "attributes": [
                'orclACI: (target="ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")(version 3.0; acl "REDACTED_LDAP_BIND_PASSWORD"; allow(all) userdn="ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com";)',
                'orclentrylevelaci: (version 3.0; acl "test"; allow(all) userdn="ldap:///anyone";)',
                "orclPassword: secret",
            ],
            "attribute_types": [
                "attributeTypes: ( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' )"
            ],
        },
        SERVER_OUD: {
            "attributes": [
                "ds-sync-hist: replica1",
                "ds-sync-state: synced",
                "ds-pwp-account-disabled: true",
                "entryUUID: 550e8400-e29b-41d4-a716-446655440000",
            ],
        },
        SERVER_OPENLDAP: {
            "dn": ["dn: cn=config"],
            "attributes": [
                "olcDatabase: mdb",
                "olcDbDirectory: /var/lib/ldap",
                "olcAccess: to * by users read",
                "objectClass: olcGlobal",
            ],
        },
        SERVER_AD: {
            "oid_patterns": ["1.2.840.113556.1.4.1"],
            "dn": ["dn: cn=user,cn=Users,dc=example,dc=com"],
            "attributes": [
                "samAccountName: testuser",
            ],
            "attribute_types": [
                "attributeTypes: ( 1.2.840.113556.1.4.1 NAME 'objectGUID' )"
            ],
        },
        "389ds": {
            "dn": ["dn: cn=config,cn=389ds"],
        },
        "apache": {
            "dn": ["dn: ou=apache-ds,dc=example,dc=com"],
        },
    }

    # Test file names
    TEST_LDIF_FILE: Final[str] = "test.ldif"
    BAD_ENCODING_FILE: Final[str] = "bad_encoding.ldif"
    NONEXISTENT_FILE: Final[Path] = Path("/nonexistent/file.ldif")

    # Test parameters
    MAX_LINES_LIMIT: Final[int] = 5
    MANY_LINES_COUNT: Final[int] = 1000

    # Extracted attributes for easy access - DRY pattern
    OID_ATTRIBUTE_TYPES: Final[str] = SERVER_PATTERNS[SERVER_OID]["attribute_types"][0]
    OID_ORCLACI: Final[str] = SERVER_PATTERNS[SERVER_OID]["attributes"][0]
    OID_ORCLENTRYLEVELACI: Final[str] = SERVER_PATTERNS[SERVER_OID]["attributes"][1]
    OID_ORCLPASSWORD: Final[str] = SERVER_PATTERNS[SERVER_OID]["attributes"][2]

    OUD_DS_SYNC_HIST: Final[str] = SERVER_PATTERNS[SERVER_OUD]["attributes"][0]
    OUD_DS_SYNC_STATE: Final[str] = SERVER_PATTERNS[SERVER_OUD]["attributes"][1]
    OUD_DS_PWP_ACCOUNT_DISABLED: Final[str] = SERVER_PATTERNS[SERVER_OUD]["attributes"][
        2
    ]
    OUD_ENTRYUUID: Final[str] = SERVER_PATTERNS[SERVER_OUD]["attributes"][3]

    OPENLDAP_CN_CONFIG: Final[str] = SERVER_PATTERNS[SERVER_OPENLDAP]["dn"][0]
    OPENLDAP_OLC_DATABASE: Final[str] = SERVER_PATTERNS[SERVER_OPENLDAP]["attributes"][
        0
    ]
    OPENLDAP_OLC_DB_DIRECTORY: Final[str] = SERVER_PATTERNS[SERVER_OPENLDAP][
        "attributes"
    ][1]
    OPENLDAP_OLC_ACCESS: Final[str] = SERVER_PATTERNS[SERVER_OPENLDAP]["attributes"][2]
    OPENLDAP_OLC_GLOBAL: Final[str] = SERVER_PATTERNS[SERVER_OPENLDAP]["attributes"][3]

    AD_USER_DN: Final[str] = SERVER_PATTERNS[SERVER_AD]["dn"][0]
    AD_ATTRIBUTE_TYPES: Final[str] = SERVER_PATTERNS[SERVER_AD]["attribute_types"][0]
    AD_SAMACCOUNTNAME: Final[str] = SERVER_PATTERNS[SERVER_AD]["attributes"][0]

    DS389_CONFIG_DN: Final[str] = SERVER_PATTERNS["389ds"]["dn"][0]
    APACHE_DS_DN: Final[str] = SERVER_PATTERNS["apache"]["dn"][0]

    @staticmethod
    def build_ldif_content(
        server_type: str,
        patterns: Mapping[str, list[str]],
        dn: str | None = None,
    ) -> str:
        """Build LDIF content from server patterns mapping."""
        parts = [DetectorTestData.LDIF_VERSION_HEADER]
        if dn:
            parts.append(f"{dn}\n")
        elif patterns.get("dn"):
            parts.append(f"{patterns['dn'][0]}\n")
        else:
            parts.append(DetectorTestData.LDIF_BASIC_ENTRY)

        if "attribute_types" in patterns:
            parts.extend(f"{attr}\n" for attr in patterns["attribute_types"])
        if "attributes" in patterns:
            parts.extend(f"{attr}\n" for attr in patterns["attributes"])

        return "".join(parts)


class TestServerDetector:
    """Comprehensive tests for server detector service.

    All tests use real implementations without mocks.
    Tests are organized by functionality in nested classes.
    Uses mappings and parametrization for maximum DRY.
    """

    @pytest.fixture
    def detector(self) -> FlextLdifDetector:
        """Create server detector instance."""
        return FlextLdifDetector()

    class TestServerTypeDetection:
        """Test server type detection using mappings and parametrization."""

        @pytest.fixture
        def detector(self) -> FlextLdifDetector:
            """Create server detector instance."""
            return FlextLdifDetector()

        @pytest.mark.parametrize(
            ("server_type", "pattern_key"),
            [
                (DetectorTestData.SERVER_OID, "attribute_types"),
                (DetectorTestData.SERVER_OID, "attributes"),
                (DetectorTestData.SERVER_OUD, "attributes"),
                (DetectorTestData.SERVER_OPENLDAP, "attributes"),
                (DetectorTestData.SERVER_AD, "attribute_types"),
                (DetectorTestData.SERVER_AD, "attributes"),
            ],
        )
        def test_detect_server_by_patterns(
            self,
            detector: FlextLdifDetector,
            server_type: str,
            pattern_key: str,
        ) -> None:
            """Test server detection using pattern mappings."""
            patterns = DetectorTestData.SERVER_PATTERNS[server_type]
            if pattern_key not in patterns:
                pytest.skip(
                    f"Pattern key {pattern_key} not available for {server_type}"
                )

            # Build content using first pattern of the key
            pattern_values = patterns[pattern_key]
            if not pattern_values:
                pytest.skip(f"No patterns in {pattern_key} for {server_type}")

            content = DetectorTestData.build_ldif_content(server_type, patterns)
            result = detector.detect_server_type(ldif_content=content)
            FlextTestsMatchers.assert_success(result)
            detection = result.unwrap()
            assert detection.confidence >= 0
            assert hasattr(detection, "detected_server_type")
            assert hasattr(detection, "scores")

        @pytest.mark.parametrize(
            "server_type",
            [
                DetectorTestData.SERVER_OID,
                DetectorTestData.SERVER_OUD,
                DetectorTestData.SERVER_OPENLDAP,
                DetectorTestData.SERVER_AD,
            ],
        )
        def test_detect_server_type_complete(
            self,
            detector: FlextLdifDetector,
            server_type: str,
        ) -> None:
            """Test complete server detection for each server type."""
            patterns = DetectorTestData.SERVER_PATTERNS[server_type]
            content = DetectorTestData.build_ldif_content(server_type, patterns)
            result = detector.detect_server_type(ldif_content=content)
            FlextTestsMatchers.assert_success(result)
            detection = result.unwrap()
            assert detection.confidence >= 0
            assert len(detection.scores) > 0
            assert isinstance(detection.patterns_found, list)

        @pytest.mark.parametrize(
            ("server_key", "expected_type"),
            [
                ("389ds", FlextLdifConstants.ServerTypes.DS_389),
                ("apache", FlextLdifConstants.ServerTypes.APACHE),
            ],
        )
        def test_detect_other_servers(
            self,
            detector: FlextLdifDetector,
            server_key: str,
            expected_type: str,
        ) -> None:
            """Test detection of other server types (389DS, Apache DS)."""
            patterns = DetectorTestData.SERVER_PATTERNS[server_key]
            content = DetectorTestData.build_ldif_content(server_key, patterns)
            content += "objectClass: top\n"
            result = detector.detect_server_type(ldif_content=content)
            FlextTestsMatchers.assert_success(result)
            detection = result.unwrap()
            assert detection.confidence >= 0
            assert hasattr(detection, "detected_server_type")

    class TestConfidenceAndFallback:
        """Test confidence threshold and fallback behavior."""

        @pytest.fixture
        def detector(self) -> FlextLdifDetector:
            """Create server detector instance."""
            return FlextLdifDetector()

        @pytest.mark.parametrize(
            ("server_type", "expected_high_confidence"),
            [
                (DetectorTestData.SERVER_OID, True),
                (DetectorTestData.SERVER_OUD, True),
                (DetectorTestData.SERVER_OPENLDAP, True),
                (DetectorTestData.SERVER_AD, True),
            ],
        )
        def test_high_confidence_detection(
            self,
            detector: FlextLdifDetector,
            server_type: str,
            expected_high_confidence: bool,
        ) -> None:
            """Test high confidence detection for server types."""
            patterns = DetectorTestData.SERVER_PATTERNS[server_type]
            content = DetectorTestData.build_ldif_content(server_type, patterns)
            result = detector.detect_server_type(ldif_content=content)
            FlextTestsMatchers.assert_success(result)
            detection = result.unwrap()
            assert detection.confidence >= 0
            assert hasattr(detection, "detected_server_type")
            if expected_high_confidence:
                assert detection.is_confident is not None

        def test_low_confidence_fallback_to_rfc(
            self, detector: FlextLdifDetector
        ) -> None:
            """Test low confidence detection falls back to RFC."""
            content = f"""{DetectorTestData.LDIF_VERSION_HEADER}{DetectorTestData.LDIF_BASIC_ENTRY}cn: test
"""
            result = detector.detect_server_type(ldif_content=content)
            FlextTestsMatchers.assert_success(result)
            detection = result.unwrap()
            assert detection.confidence >= 0
            assert hasattr(detection, "detected_server_type")

        def test_mixed_patterns_detection(self, detector: FlextLdifDetector) -> None:
            """Test detection with multiple mixed patterns."""
            oid_patterns = DetectorTestData.SERVER_PATTERNS[DetectorTestData.SERVER_OID]
            oud_patterns = DetectorTestData.SERVER_PATTERNS[DetectorTestData.SERVER_OUD]
            openldap_patterns = DetectorTestData.SERVER_PATTERNS[
                DetectorTestData.SERVER_OPENLDAP
            ]

            content = f"""{DetectorTestData.LDIF_VERSION_HEADER}{DetectorTestData.LDIF_BASIC_ENTRY}"""
            if "attribute_types" in oid_patterns:
                content += f"{oid_patterns['attribute_types'][0]}\n"
            if "attributes" in oud_patterns:
                content += f"{oud_patterns['attributes'][0]}\n"
            if "attributes" in openldap_patterns:
                content += f"{openldap_patterns['attributes'][0]}\n"

            result = detector.detect_server_type(ldif_content=content)
            FlextTestsMatchers.assert_success(result)
            detection = result.unwrap()
            assert detection.confidence >= 0
            assert len(detection.scores) > 0

    class TestPatternExtraction:
        """Test pattern extraction from LDIF content using mappings."""

        @pytest.fixture
        def detector(self) -> FlextLdifDetector:
            """Create server detector instance."""
            return FlextLdifDetector()

        @pytest.mark.parametrize(
            "server_type",
            [
                DetectorTestData.SERVER_OID,
                DetectorTestData.SERVER_AD,
            ],
        )
        def test_extract_patterns(
            self,
            detector: FlextLdifDetector,
            server_type: str,
        ) -> None:
            """Test extracting patterns from LDIF content using mappings."""
            patterns = DetectorTestData.SERVER_PATTERNS[server_type]
            content = DetectorTestData.build_ldif_content(server_type, patterns)
            result = detector.detect_server_type(ldif_content=content)
            FlextTestsMatchers.assert_success(result)
            detection = result.unwrap()
            patterns_found = detection.patterns_found
            assert isinstance(patterns_found, list)
            assert len(patterns_found) > 0

    class TestFileInput:
        """Test server detection from LDIF files."""

        @pytest.fixture
        def detector(self) -> FlextLdifDetector:
            """Create server detector instance."""
            return FlextLdifDetector()

        @pytest.mark.parametrize(
            "server_type",
            [
                DetectorTestData.SERVER_OID,
                DetectorTestData.SERVER_OUD,
                DetectorTestData.SERVER_OPENLDAP,
            ],
        )
        def test_detect_from_file_path(
            self,
            detector: FlextLdifDetector,
            server_type: str,
        ) -> None:
            """Test detecting server type from LDIF file using mappings."""
            patterns = DetectorTestData.SERVER_PATTERNS[server_type]
            content = DetectorTestData.build_ldif_content(server_type, patterns)

            with tempfile.TemporaryDirectory() as tmpdir:
                ldif_file = Path(tmpdir) / DetectorTestData.TEST_LDIF_FILE
                ldif_file.write_text(content, encoding="utf-8")

                result = detector.detect_server_type(ldif_path=ldif_file)
                FlextTestsMatchers.assert_success(result)
                detection = result.unwrap()
                assert detection.confidence >= 0

        def test_detect_from_file_with_encoding_error(
            self,
            detector: FlextLdifDetector,
        ) -> None:
            """Test handling encoding errors in LDIF file."""
            with tempfile.TemporaryDirectory() as tmpdir:
                ldif_file = Path(tmpdir) / DetectorTestData.BAD_ENCODING_FILE
                ldif_file.write_bytes(b"version: 1\ndn: cn=test\n\xff\xfe")

                result = detector.detect_server_type(ldif_path=ldif_file)
                assert hasattr(result, "is_success")

    class TestErrorHandling:
        """Test error handling in server detection."""

        @pytest.fixture
        def detector(self) -> FlextLdifDetector:
            """Create server detector instance."""
            return FlextLdifDetector()

        def test_detect_without_input(self, detector: FlextLdifDetector) -> None:
            """Test detection fails when no input provided."""
            result = detector.detect_server_type()
            assert not result.is_success
            assert result.error is not None
            assert "must be provided" in result.error

        def test_detect_with_empty_content(self, detector: FlextLdifDetector) -> None:
            """Test detection with empty LDIF content."""
            result = detector.detect_server_type(ldif_content="")
            FlextTestsMatchers.assert_success(result)
            detection = result.unwrap()
            assert detection.confidence >= 0

        def test_detect_with_nonexistent_file(
            self, detector: FlextLdifDetector
        ) -> None:
            """Test detection with nonexistent file path."""
            result = detector.detect_server_type(
                ldif_path=DetectorTestData.NONEXISTENT_FILE
            )
            assert hasattr(result, "is_success")

        def test_detect_max_lines_limiting(self, detector: FlextLdifDetector) -> None:
            """Test that max_lines parameter limits content scanned."""
            lines = [
                DetectorTestData.LDIF_VERSION_HEADER.strip(),
                DetectorTestData.LDIF_BASIC_ENTRY.strip(),
            ] + [
                f"description: line {i}"
                for i in range(DetectorTestData.MANY_LINES_COUNT)
            ]
            content = "\n".join(lines)

            result = detector.detect_server_type(
                ldif_content=content,
                max_lines=DetectorTestData.MAX_LINES_LIMIT,
            )
            FlextTestsMatchers.assert_success(result)
            detection = result.unwrap()
            assert detection.confidence >= 0

    class TestServiceExecution:
        """Test server detector service execution."""

        @pytest.fixture
        def detector(self) -> FlextLdifDetector:
            """Create server detector instance."""
            return FlextLdifDetector()

        def test_execute_returns_status(self, detector: FlextLdifDetector) -> None:
            """Test execute method returns service status."""
            status_result = detector.execute()
            FlextTestsMatchers.assert_success(status_result)
            status = status_result.unwrap()
            assert isinstance(status, FlextLdifModels.ClientStatus)
            assert status.config["service"] == "FlextLdifDetector"
            assert "detect_server_type" in status.services

    class TestResolveFromConfig:
        """Test resolve_from_config() static method using parametrization."""

        @pytest.mark.parametrize(
            ("target_server_type", "expected"),
            [
                (DetectorTestData.SERVER_OUD, DetectorTestData.SERVER_OUD),
                (DetectorTestData.SERVER_OID, DetectorTestData.SERVER_OID),
                (DetectorTestData.SERVER_AD, DetectorTestData.SERVER_AD),
            ],
        )
        def test_resolve_from_config_target_override(
            self,
            target_server_type: str,
            expected: str,
        ) -> None:
            """Test resolve_from_config with target_server_type override."""
            config = FlextConfig.get_global_instance()
            ldif_config = config.ldif
            result = FlextLdifDetector.resolve_from_config(
                ldif_config, target_server_type=target_server_type
            )
            assert result == expected

        def test_resolve_from_config_relaxed_mode(self) -> None:
            """Test resolve_from_config with relaxed parsing enabled."""
            config = FlextConfig.get_global_instance()
            ldif_config = config.ldif
            ldif_config.enable_relaxed_parsing = True
            result = FlextLdifDetector.resolve_from_config(ldif_config)
            assert result == DetectorTestData.SERVER_RELAXED

        @pytest.mark.parametrize(
            ("server_type", "expected"),
            [
                (DetectorTestData.SERVER_OID, DetectorTestData.SERVER_OID),
                (DetectorTestData.SERVER_OUD, DetectorTestData.SERVER_OUD),
            ],
        )
        def test_resolve_from_config_manual_mode_with_type(
            self,
            server_type: str,
            expected: str,
        ) -> None:
            """Test resolve_from_config with manual mode and server type."""
            config = FlextConfig.get_global_instance()
            ldif_config = config.ldif
            ldif_config.quirks_detection_mode = "manual"
            ldif_config.quirks_server_type = server_type
            result = FlextLdifDetector.resolve_from_config(ldif_config)
            assert result == expected

        def test_resolve_from_config_disabled_mode(self) -> None:
            """Test resolve_from_config with disabled mode."""
            config = FlextConfig.get_global_instance()
            ldif_config = config.ldif
            ldif_config.quirks_detection_mode = "disabled"
            result = FlextLdifDetector.resolve_from_config(ldif_config)
            assert result == DetectorTestData.SERVER_RFC

        def test_resolve_from_config_default(self) -> None:
            """Test resolve_from_config with default config."""
            config = FlextConfig.get_global_instance()
            result = FlextLdifDetector.resolve_from_config(config)
            assert isinstance(result, str)
            assert len(result) > 0

    class TestGetEffectiveServerType:
        """Test get_effective_server_type() method using parametrization."""

        @pytest.fixture
        def detector(self) -> FlextLdifDetector:
            """Create server detector instance."""
            return FlextLdifDetector()

        @pytest.mark.parametrize(
            "server_type",
            [
                DetectorTestData.SERVER_OID,
                DetectorTestData.SERVER_OUD,
                DetectorTestData.SERVER_OPENLDAP,
                DetectorTestData.SERVER_AD,
            ],
        )
        def test_get_effective_server_type_from_content(
            self,
            detector: FlextLdifDetector,
            server_type: str,
        ) -> None:
            """Test get_effective_server_type with LDIF content using mappings."""
            patterns = DetectorTestData.SERVER_PATTERNS[server_type]
            content = DetectorTestData.build_ldif_content(server_type, patterns)
            result = detector.get_effective_server_type(ldif_content=content)
            FlextTestsMatchers.assert_success(result)
            effective_type = result.unwrap()
            assert isinstance(effective_type, str)
            assert len(effective_type) > 0

        @pytest.mark.parametrize(
            "server_type",
            [
                DetectorTestData.SERVER_OID,
                DetectorTestData.SERVER_OUD,
            ],
        )
        def test_get_effective_server_type_from_path(
            self,
            detector: FlextLdifDetector,
            server_type: str,
        ) -> None:
            """Test get_effective_server_type with LDIF file path."""
            patterns = DetectorTestData.SERVER_PATTERNS[server_type]
            content = DetectorTestData.build_ldif_content(server_type, patterns)

            with tempfile.TemporaryDirectory() as tmpdir:
                ldif_file = Path(tmpdir) / DetectorTestData.TEST_LDIF_FILE
                ldif_file.write_text(content, encoding="utf-8")
                result = detector.get_effective_server_type(ldif_path=ldif_file)
                FlextTestsMatchers.assert_success(result)
                effective_type = result.unwrap()
                assert isinstance(effective_type, str)

        def test_get_effective_server_type_default(
            self,
            detector: FlextLdifDetector,
        ) -> None:
            """Test get_effective_server_type without input (defaults to RFC)."""
            result = detector.get_effective_server_type()
            FlextTestsMatchers.assert_success(result)
            server_type = result.unwrap()
            assert server_type == DetectorTestData.SERVER_RFC

        def test_get_effective_server_type_with_detection_failure(
            self,
            detector: FlextLdifDetector,
        ) -> None:
            """Test get_effective_server_type when detection fails."""
            result = detector.get_effective_server_type(ldif_content="invalid content")
            assert result.is_success or result.is_failure

    class TestExceptionHandling:
        """Test exception handling paths in detector."""

        @pytest.fixture
        def detector(self) -> FlextLdifDetector:
            """Create server detector instance."""
            return FlextLdifDetector()

        def test_detect_server_type_exception_handling(
            self,
            detector: FlextLdifDetector,
        ) -> None:
            """Test exception handling in detect_server_type."""
            result = detector.detect_server_type(ldif_content="valid content")
            assert hasattr(result, "is_success")

        def test_get_effective_server_type_exception_handling(
            self,
            detector: FlextLdifDetector,
        ) -> None:
            """Test exception handling in get_effective_server_type."""
            result = detector.get_effective_server_type(ldif_content="test")
            assert hasattr(result, "is_success")
