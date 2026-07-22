"""Behavioral tests for the public ``u.Ldif`` utilities contract.

Every test asserts observable public behavior only: return values, ``r[T]``
outcomes for fallible operations, public model state after in-place fixes, and
invariants (round-trip, idempotence, sign symmetry). No private attributes,
internal-collaborator spying, or line-coverage pokes.
"""

from __future__ import annotations

import pytest

from flext_tests import tm
from tests import c, m, u


@pytest.mark.unit
class TestsFlextLdifUtilitiesCore:
    """Public contract of DN, schema, and server-type LDIF utilities."""

    # ---- DN splitting -------------------------------------------------

    @pytest.mark.parametrize(
        ("dn", "expected"),
        [
            (
                "cn=John,ou=Users,dc=example,dc=com",
                ["cn=John", "ou=Users", "dc=example", "dc=com"],
            ),
            (
                "cn=Test\\, User,ou=Users,dc=example,dc=com",
                ["cn=Test\\, User", "ou=Users", "dc=example", "dc=com"],
            ),
            (
                "cn=Test\\, User\\\\More,ou=Users\\, Group,dc=example",
                ["cn=Test\\, User\\\\More", "ou=Users\\, Group", "dc=example"],
            ),
            ("cn=test", ["cn=test"]),
        ],
    )
    def test_split_preserves_escaped_separators(
        self, dn: str, expected: list[str]
    ) -> None:
        """Split keeps escaped commas/backslashes inside their component."""
        tm.that(u.Ldif.split(dn), eq=expected)

    def test_split_empty_dn_yields_no_components(self) -> None:
        """An empty DN string splits into zero components."""
        tm.that(u.Ldif.split(""), empty=True)

    def test_dn_model_accepts_escaped_commas(self) -> None:
        """The DN model preserves an escaped-comma value verbatim."""
        dn = m.Ldif.DN(value="cn=Test\\, User,ou=Users,dc=example,dc=com")
        tm.that(dn.value, eq="cn=Test\\, User,ou=Users,dc=example,dc=com")

    # ---- DN validation ------------------------------------------------

    @pytest.mark.parametrize(
        "dn",
        [
            "cn=John,dc=example,dc=com",
            "ou=Users,dc=example,dc=com",
            "cn=REDACTED_LDAP_BIND_PASSWORD,o=example",
            "cn=Test\\, User,dc=example,dc=com",
            "cn=Test\\5CUser,dc=example,dc=com",
            "cn=Test#User,dc=example,dc=com",
            "cn=Test\\2BUser,dc=example,dc=com",
            "cn=Test\\3DUser,dc=example,dc=com",
        ],
    )
    def test_validate_accepts_wellformed_dns(self, dn: str) -> None:
        """Well-formed DNs (including hex escapes) validate as True."""
        tm.that(u.Ldif.validate(dn), eq=True)

    @pytest.mark.parametrize(
        "dn",
        [
            "",
            "no_equals_sign",
            "cn=",
            "=value",
            "cn=test,",
            ",cn=test",
            "cn=test,,ou=users",
            "cn=test\\",
            "cn=test\\Z",
            "cn=test\\XY",
        ],
    )
    def test_validate_rejects_malformed_dns(self, dn: str) -> None:
        """Empty attrs, empty components, and bad escapes validate as False."""
        tm.that(u.Ldif.validate(dn), eq=False)

    # ---- DN parsing / comparison -------------------------------------

    def test_parse_returns_attribute_value_pairs(self) -> None:
        """Parse yields ordered (attr, value) pairs for every component."""
        parsed = tm.ok(u.Ldif.parse("cn=John,ou=Users,dc=example"))
        tm.that(list(parsed), eq=[("cn", "John"), ("ou", "Users"), ("dc", "example")])

    @pytest.mark.parametrize(
        ("bad_dn", "error_fragment"),
        [("", "empty"), ("no_equals", "missing '=' separator")],
    )
    def test_parse_reports_failure_for_malformed_dn(
        self, bad_dn: str, error_fragment: str
    ) -> None:
        """Parse returns a failure result describing the malformed input."""
        tm.fail(u.Ldif.parse(bad_dn), contains=error_fragment)

    def test_compare_dns_reports_failure_when_operand_missing(self) -> None:
        """compare_dns fails (not silently defaults) when an operand is None."""
        tm.fail(u.Ldif.compare_dns(None, "cn=x,dc=y"), contains="must be provided")

    def test_compare_dns_is_reflexive(self) -> None:
        """Comparing a DN to itself yields equality (0)."""
        result = tm.ok(u.Ldif.compare_dns("cn=John,dc=example", "cn=John,dc=example"))
        tm.that(result, eq=0)

    def test_compare_dns_is_case_insensitive_on_equal_values(self) -> None:
        """DNs differing only by case compare equal."""
        result = tm.ok(u.Ldif.compare_dns("cn=John,dc=Example", "cn=john,dc=example"))
        tm.that(result, eq=0)

    def test_compare_dns_is_antisymmetric(self) -> None:
        """Swapping arguments flips the sign of the ordering."""
        forward = tm.ok(u.Ldif.compare_dns("cn=alpha,dc=x", "cn=beta,dc=x"))
        backward = tm.ok(u.Ldif.compare_dns("cn=beta,dc=x", "cn=alpha,dc=x"))
        tm.that(forward, eq=-backward)
        tm.that(forward < 0, eq=True)

    # ---- DN value escaping -------------------------------------------

    @pytest.mark.parametrize(
        "value", ["Test, Value", "plain", "a+b=c", "trailing ", " leading"]
    )
    def test_esc_unesc_roundtrip_is_identity(self, value: str) -> None:
        """unesc(esc(value)) reconstructs the original value."""
        tm.that(u.Ldif.unesc(u.Ldif.esc(value)), eq=value)

    def test_esc_encodes_reserved_comma(self) -> None:
        """A reserved comma is escaped away so it can't act as a separator."""
        escaped = u.Ldif.esc("Test, Value")
        tm.that("," not in escaped.replace("\\,", ""), eq=True)
        tm.that(escaped, eq="Test\\2c Value")

    def test_unesc_decodes_escaped_comma(self) -> None:
        """Unesc turns an escaped comma back into a literal comma."""
        tm.that(u.Ldif.unesc("Test\\,Value"), eq="Test,Value")

    # ---- DN cleaning --------------------------------------------------

    def test_clean_dn_removes_padding_around_equals_and_commas(self) -> None:
        """clean_dn collapses stray whitespace around '=' and separators."""
        cleaned = u.Ldif.clean_dn("  cn = John  ,  ou = Users  ,  dc = example  ")
        tm.that(" = " not in cleaned, eq=True)
        tm.that(" , " not in cleaned, eq=True)

    def test_clean_dn_is_idempotent(self) -> None:
        """Cleaning an already-clean DN returns it unchanged."""
        once = u.Ldif.clean_dn("  cn = John  ,  ou = Users  ")
        tm.that(u.Ldif.clean_dn(once), eq=once)

    # ---- ObjectClass fixes (in-place, observed via public state) -----

    @pytest.mark.parametrize("kind", ["AUXILIARY", c.Ldif.SchemaKind.AUXILIARY])
    def test_fix_missing_sup_sets_top_for_auxiliary_without_sup(
        self, kind: str
    ) -> None:
        """An AUXILIARY class lacking SUP gains the 'top' superior."""
        oc = m.Ldif.SchemaObjectClass(
            oid="1.2.3.4", name="orcldasattrcategory", kind=kind, sup=None
        )
        u.Ldif.fix_missing_sup(oc)
        tm.that(oc.sup, eq="top")

    def test_fix_missing_sup_preserves_existing_sup(self) -> None:
        """An AUXILIARY class that already has a SUP is left untouched."""
        oc = m.Ldif.SchemaObjectClass(
            oid="1.2.3.4.5",
            name="testAuxiliary",
            kind=c.Ldif.SchemaKind.AUXILIARY,
            sup="top",
        )
        u.Ldif.fix_missing_sup(oc)
        tm.that(oc.sup, eq="top")

    def test_fix_missing_sup_ignores_structural_classes(self) -> None:
        """STRUCTURAL classes are not given a synthetic SUP."""
        oc = m.Ldif.SchemaObjectClass(
            oid="1.2.3.4.6",
            name="testStructural",
            kind=c.Ldif.SchemaKind.STRUCTURAL,
            sup=None,
        )
        u.Ldif.fix_missing_sup(oc)
        tm.that(oc.sup, none=True)

    @pytest.mark.parametrize(
        ("start_kind", "sup", "expected_kind"),
        [
            (
                c.Ldif.SchemaKind.AUXILIARY,
                "orclpwdverifierprofile",
                c.Ldif.SchemaKind.STRUCTURAL,
            ),
            (
                c.Ldif.SchemaKind.STRUCTURAL,
                "javanamingref",
                c.Ldif.SchemaKind.AUXILIARY,
            ),
        ],
    )
    def test_fix_kind_mismatch_aligns_kind_to_superior(
        self, start_kind: c.Ldif.SchemaKind, sup: str, expected_kind: c.Ldif.SchemaKind
    ) -> None:
        """Kind is corrected to match the kind of its declared superior."""
        oc = m.Ldif.SchemaObjectClass(
            oid="1.2.3.4.9", name="testClass", kind=start_kind, sup=sup
        )
        u.Ldif.fix_kind_mismatch(oc)
        tm.that(oc.kind, eq=expected_kind)

    # ---- Attribute-name normalization --------------------------------

    def test_normalize_name_strips_binary_suffix_and_normalizes_separators(
        self,
    ) -> None:
        """normalize_name drops ';binary' and canonicalizes underscores."""
        tm.that(u.Ldif.normalize_name("testAttr_name;binary"), eq="testAttr-name")

    def test_normalize_name_applies_custom_char_replacements(self) -> None:
        """Custom char replacements are honored."""
        tm.that(
            u.Ldif.normalize_name("test_attr_name", char_replacements={"_": "-"}),
            eq="test-attr-name",
        )

    def test_normalize_name_passes_none_through(self) -> None:
        """A None name normalizes to None."""
        tm.that(u.Ldif.normalize_name(None), none=True)

    @pytest.mark.parametrize(
        ("equality", "substr", "expected"),
        [
            (None, None, (None, None)),
            ("caseIgnoreMatch", None, ("caseIgnoreMatch", None)),
            (
                "caseIgnoreMatch",
                "caseIgnoreSubstringsMatch",
                ("caseIgnoreMatch", "caseIgnoreSubstringsMatch"),
            ),
        ],
    )
    def test_normalize_matching_rules_returns_equality_substr_pair(
        self,
        equality: str | None,
        substr: str | None,
        expected: tuple[str | None, str | None],
    ) -> None:
        """Matching-rule normalization returns an (equality, substr) pair."""
        tm.that(u.Ldif.normalize_matching_rules(equality, substr), eq=expected)

    # ---- Schema extension extraction ---------------------------------

    def test_extract_extensions_empty_definition_yields_none(self) -> None:
        """An empty schema definition exposes no extensions."""
        tm.that(u.Ldif.extract_extensions(""), empty=True)

    def test_extract_extensions_captures_x_prefixed_extensions(self) -> None:
        """X- prefixed extension values are captured under their key."""
        result = u.Ldif.extract_extensions(
            "( 1.2.3 NAME 'test' X-CUSTOM 'value' X-OTHER 'data' )"
        )
        tm.that(result.get("X-CUSTOM"), eq=["value"])
        tm.that(result.get("X-OTHER"), eq=["data"])

    def test_extract_extensions_captures_desc(self) -> None:
        """A DESC clause is exposed as its own extension key."""
        result = u.Ldif.extract_extensions(
            "( 1.2.3 NAME 'test' DESC 'Test attribute' )"
        )
        tm.that(result.get("DESC"), eq=["Test attribute"])

    def test_unfold_lines_joins_rfc2849_continuations(self) -> None:
        """A space-prefixed continuation line is folded back onto its base."""
        result = u.Ldif.unfold_lines(
            "dn: cn=verylongname\n withfoldedcontinuation,dc=example,dc=com\n"
        )
        tm.that(
            any("verylongnamewithfoldedcontinuation" in line for line in result),
            eq=True,
        )

    # ---- Server-type operations --------------------------------------

    @pytest.mark.parametrize(
        ("raw", "expected"), [("oracle_oid", "oid"), ("rfc", "rfc")]
    )
    def test_normalize_server_type_maps_aliases_to_canonical(
        self, raw: str, expected: str
    ) -> None:
        """Vendor aliases normalize to their canonical server type."""
        tm.that(u.Ldif.normalize_server_type(raw), eq=expected)

    def test_matches_recognizes_allowed_server_type(self) -> None:
        """Matches is True only when the type is among the allowed set."""
        tm.that(u.Ldif.matches("oid", "oid", "oud"), eq=True)
        tm.that(u.Ldif.matches("ad", "oid", "oud"), eq=False)

    @pytest.mark.parametrize(
        ("server_type", "flag", "expected"),
        [
            ("openldap", "requires_binary_option", True),
            ("openldap", "requires_objectclass", False),
            ("novell_edirectory", "requires_objectclass", True),
            ("novell_edirectory", "requires_naming_attr", False),
            (c.Ldif.ServerTypes.DS389, "requires_objectclass", True),
            (c.Ldif.ServerTypes.DS389, "requires_binary_option", False),
        ],
    )
    def test_validation_rule_flags_derive_from_server_capabilities(
        self, server_type: str | c.Ldif.ServerTypes, flag: str, expected: bool
    ) -> None:
        """Validation flags reflect each server type's declared capabilities."""
        tm.that(u.Ldif.validation_rule_flags(server_type)[flag], eq=expected)
