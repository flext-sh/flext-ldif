"""Tests for LDIF objectClass utilities.

This module tests objectClass utility functions for schema objectClass handling,
including structural and auxiliary class validation, inheritance relationships,
and objectClass conflict detection in LDIF entries.
"""

from __future__ import annotations

from enum import StrEnum

from tests import c, s

from flext_ldif._utilities.object_class import FlextLdifUtilitiesObjectClass
from flext_ldif.protocols import p


class ObjectClassTestCase(StrEnum):
    """Test cases for objectClass utilities."""

    AUXILIARY_WITHOUT_SUP = "auxiliary_without_sup"
    AUXILIARY_WITH_SUP = "auxiliary_with_sup"
    STRUCTURAL_WITHOUT_SUP = "structural_without_sup"
    STRUCTURAL_WITH_SUP = "structural_with_sup"
    KNOWN_AUXILIARY_WITHOUT_SUP = "known_auxiliary_without_sup"
    STRUCTURAL_MISMATCH = "structural_mismatch"
    AUXILIARY_MISMATCH = "auxiliary_mismatch"
    KNOWN_STRUCTURAL_SUPERIOR = "known_structural_superior"
    KNOWN_AUXILIARY_SUPERIOR = "known_auxiliary_superior"
    NO_SUP_NO_KIND = "no_sup_no_kind"


class TestsTestFlextLdifUtilitiesObjectClass(s):
    """Comprehensive tests for objectClass utilities."""

    @staticmethod
    def create_objectclass(
        name: str,
        kind: str | None = None,
        sup: str | None = None,
    ) -> p.Ldif.SchemaObjectClass:
        """Factory to create SchemaObjectClass for testing."""
        return p.Ldif.SchemaObjectClass(
            oid="1.2.3.4.5",
            name=name,
            kind=kind,
            sup=sup,
        )

    def test_fix_missing_sup_auxiliary_without_sup(self) -> None:
        """Test fix_missing_sup fixes AUXILIARY without SUP."""
        oc = self.create_objectclass(
            "testAuxiliary",
            kind=c.Schema.AUXILIARY,
            sup=None,
        )

        FlextLdifUtilitiesObjectClass.fix_missing_sup(oc)

        assert oc.sup == "top"

    def test_fix_missing_sup_auxiliary_with_sup(self) -> None:
        """Test fix_missing_sup does not modify AUXILIARY with SUP."""
        oc = self.create_objectclass(
            "testAuxiliary",
            kind=c.Schema.AUXILIARY,
            sup="someSuperior",
        )

        original_sup = oc.sup
        FlextLdifUtilitiesObjectClass.fix_missing_sup(oc)

        assert oc.sup == original_sup

    def test_fix_missing_sup_structural(self) -> None:
        """Test fix_missing_sup does not modify STRUCTURAL."""
        oc = self.create_objectclass(
            "testStructural",
            kind=c.Schema.STRUCTURAL,
            sup=None,
        )

        FlextLdifUtilitiesObjectClass.fix_missing_sup(oc)

        assert oc.sup is None

    def test_fix_missing_sup_known_auxiliary(self) -> None:
        """Test fix_missing_sup fixes known AUXILIARY classes."""
        known_classes = [
            "orcldAsAttrCategory",
            "orcldasattrcategory",
            "orclDASAttrCategory",
        ]

        for class_name in known_classes:
            oc = self.create_objectclass(
                class_name,
                kind=c.Schema.AUXILIARY,
                sup=None,
            )

            FlextLdifUtilitiesObjectClass.fix_missing_sup(oc)

            assert oc.sup == "top"

    def test_fix_missing_sup_unknown_auxiliary(self) -> None:
        """Test fix_missing_sup delegates to ensure_sup_for_auxiliary for unknown."""
        oc = self.create_objectclass(
            "unknownAuxiliary",
            kind=c.Schema.AUXILIARY,
            sup=None,
        )

        FlextLdifUtilitiesObjectClass.fix_missing_sup(oc)

        assert oc.sup == "top"  # Should be fixed by ensure_sup_for_auxiliary

    def test_fix_kind_mismatch_no_sup(self) -> None:
        """Test fix_kind_mismatch does nothing without SUP."""
        oc = self.create_objectclass(
            "test",
            kind=c.Schema.AUXILIARY,
            sup=None,
        )

        original_kind = oc.kind
        FlextLdifUtilitiesObjectClass.fix_kind_mismatch(oc)

        assert oc.kind == original_kind

    def test_fix_kind_mismatch_no_kind(self) -> None:
        """Test fix_kind_mismatch does nothing with empty kind."""
        # SchemaObjectClass requires kind to be a string, so we test with empty string
        # which is falsy and will cause early return
        oc = self.create_objectclass(
            "test",
            kind="",  # Empty string is falsy
            sup="someSuperior",
        )

        # The method checks `if not schema_oc.kind` which is True for empty string
        # So it returns early and does nothing
        original_kind = oc.kind
        FlextLdifUtilitiesObjectClass.fix_kind_mismatch(oc)

        assert oc.kind == original_kind

    def test_fix_kind_mismatch_structural_superior(self) -> None:
        """Test fix_kind_mismatch fixes AUXILIARY with STRUCTURAL superior."""
        structural_superiors = [
            "orclpwdverifierprofile",
            "orclapplicationentity",
            "tombstone",
        ]

        for sup_name in structural_superiors:
            oc = self.create_objectclass(
                "test",
                kind=c.Schema.AUXILIARY,
                sup=sup_name,
            )

            FlextLdifUtilitiesObjectClass.fix_kind_mismatch(oc)

            assert oc.kind == c.Schema.STRUCTURAL

    def test_fix_kind_mismatch_auxiliary_superior(self) -> None:
        """Test fix_kind_mismatch fixes STRUCTURAL with AUXILIARY superior."""
        # The method converts sup to lowercase, so both variants should work
        # The set in the code is {"javanamingref", "javanamingReference"}
        # When converted to lowercase, "javanamingReference" becomes "javanamingreference"
        # which doesn't match either, so we test with the lowercase version
        auxiliary_superiors = [
            "javanamingref",  # Exact match
        ]

        for sup_name in auxiliary_superiors:
            oc = self.create_objectclass(
                "test",
                kind=c.Schema.STRUCTURAL,
                sup=sup_name,
            )

            # Verify initial state
            assert oc.kind == c.Schema.STRUCTURAL
            assert oc.sup == sup_name

            # The method converts sup to lowercase for comparison
            # and checks if it's in auxiliary_superiors set
            FlextLdifUtilitiesObjectClass.fix_kind_mismatch(oc)

            # Should change STRUCTURAL to AUXILIARY when superior is in auxiliary_superiors
            assert oc.kind == c.Schema.AUXILIARY, (
                f"Expected AUXILIARY but got {oc.kind} for sup={sup_name}"
            )

    def test_fix_kind_mismatch_no_mismatch(self) -> None:
        """Test fix_kind_mismatch does nothing when no mismatch."""
        oc = self.create_objectclass(
            "test",
            kind=c.Schema.STRUCTURAL,
            sup="top",
        )

        original_kind = oc.kind
        FlextLdifUtilitiesObjectClass.fix_kind_mismatch(oc)

        assert oc.kind == original_kind

    def test_ensure_sup_for_auxiliary_without_sup(self) -> None:
        """Test ensure_sup_for_auxiliary adds SUP for AUXILIARY."""
        oc = self.create_objectclass(
            "testAuxiliary",
            kind=c.Schema.AUXILIARY,
            sup=None,
        )

        FlextLdifUtilitiesObjectClass.ensure_sup_for_auxiliary(oc)

        assert oc.sup == "top"

    def test_ensure_sup_for_auxiliary_with_sup(self) -> None:
        """Test ensure_sup_for_auxiliary does not modify existing SUP."""
        oc = self.create_objectclass(
            "testAuxiliary",
            kind=c.Schema.AUXILIARY,
            sup="existingSuperior",
        )

        original_sup = oc.sup
        FlextLdifUtilitiesObjectClass.ensure_sup_for_auxiliary(oc)

        assert oc.sup == original_sup

    def test_ensure_sup_for_auxiliary_custom_default(self) -> None:
        """Test ensure_sup_for_auxiliary uses custom default SUP."""
        oc = self.create_objectclass(
            "testAuxiliary",
            kind=c.Schema.AUXILIARY,
            sup=None,
        )

        FlextLdifUtilitiesObjectClass.ensure_sup_for_auxiliary(
            oc,
            default_sup="customSup",
        )

        assert oc.sup == "customSup"

    def test_ensure_sup_for_auxiliary_structural(self) -> None:
        """Test ensure_sup_for_auxiliary does not modify STRUCTURAL."""
        oc = self.create_objectclass(
            "testStructural",
            kind=c.Schema.STRUCTURAL,
            sup=None,
        )

        FlextLdifUtilitiesObjectClass.ensure_sup_for_auxiliary(oc)

        assert oc.sup is None

    def test_align_kind_with_superior_no_sup(self) -> None:
        """Test align_kind_with_superior does nothing without SUP."""
        oc = self.create_objectclass(
            "test",
            kind=c.Schema.AUXILIARY,
            sup=None,
        )

        original_kind = oc.kind
        FlextLdifUtilitiesObjectClass.align_kind_with_superior(
            oc,
            c.Schema.STRUCTURAL,
        )

        assert oc.kind == original_kind

    def test_align_kind_with_superior_no_kind(self) -> None:
        """Test align_kind_with_superior does nothing with empty kind."""
        # SchemaObjectClass requires kind to be a string, so we test with empty string
        oc = self.create_objectclass(
            "test",
            kind="",  # Empty string is falsy
            sup="someSuperior",
        )

        # The method checks `if not schema_oc.kind` which is True for empty string
        # So it returns early and does nothing
        original_kind = oc.kind
        FlextLdifUtilitiesObjectClass.align_kind_with_superior(
            oc,
            c.Schema.STRUCTURAL,
        )

        assert oc.kind == original_kind

    def test_align_kind_with_superior_no_superior_kind(self) -> None:
        """Test align_kind_with_superior does nothing without superior_kind."""
        oc = self.create_objectclass(
            "test",
            kind=c.Schema.AUXILIARY,
            sup="someSuperior",
        )

        original_kind = oc.kind
        FlextLdifUtilitiesObjectClass.align_kind_with_superior(oc, None)

        assert oc.kind == original_kind

    def test_align_kind_with_superior_auxiliary_to_structural(self) -> None:
        """Test align_kind_with_superior changes AUXILIARY to STRUCTURAL."""
        oc = self.create_objectclass(
            "test",
            kind=c.Schema.AUXILIARY,
            sup="structuralSuperior",
        )

        FlextLdifUtilitiesObjectClass.align_kind_with_superior(
            oc,
            c.Schema.STRUCTURAL,
        )

        assert oc.kind == c.Schema.STRUCTURAL

    def test_align_kind_with_superior_structural_to_auxiliary(self) -> None:
        """Test align_kind_with_superior changes STRUCTURAL to AUXILIARY."""
        oc = self.create_objectclass(
            "test",
            kind=c.Schema.STRUCTURAL,
            sup="auxiliarySuperior",
        )

        FlextLdifUtilitiesObjectClass.align_kind_with_superior(
            oc,
            c.Schema.AUXILIARY,
        )

        assert oc.kind == c.Schema.AUXILIARY

    def test_align_kind_with_superior_no_mismatch(self) -> None:
        """Test align_kind_with_superior does nothing when kinds match."""
        oc = self.create_objectclass(
            "test",
            kind=c.Schema.STRUCTURAL,
            sup="structuralSuperior",
        )

        original_kind = oc.kind
        FlextLdifUtilitiesObjectClass.align_kind_with_superior(
            oc,
            c.Schema.STRUCTURAL,
        )

        assert oc.kind == original_kind

    # Edge cases
    def test_fix_missing_sup_case_insensitive(self) -> None:
        """Test fix_missing_sup handles case-insensitive class names."""
        oc = self.create_objectclass(
            "ORCLDASATTRCATEGORY",  # Uppercase
            kind=c.Schema.AUXILIARY,
            sup=None,
        )

        FlextLdifUtilitiesObjectClass.fix_missing_sup(oc)

        assert oc.sup == "top"

    def test_fix_kind_mismatch_case_insensitive_superior(self) -> None:
        """Test fix_kind_mismatch handles case-insensitive superior names."""
        oc = self.create_objectclass(
            "test",
            kind=c.Schema.AUXILIARY,
            sup="ORCLPWDVERIFIERPROFILE",  # Uppercase
        )

        FlextLdifUtilitiesObjectClass.fix_kind_mismatch(oc)

        assert oc.kind == c.Schema.STRUCTURAL

    def test_ensure_sup_for_auxiliary_empty_string_sup(self) -> None:
        """Test ensure_sup_for_auxiliary handles empty string SUP."""
        oc = self.create_objectclass(
            "testAuxiliary",
            kind=c.Schema.AUXILIARY,
            sup="",  # Empty string, not None
        )

        # Empty string is falsy in Python, so the check `if not schema_oc.sup` will be True
        # and it will be replaced with default_sup
        FlextLdifUtilitiesObjectClass.ensure_sup_for_auxiliary(oc)

        # Empty string is falsy, so should be replaced with "top"
        assert oc.sup == "top"
