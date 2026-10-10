"""Behavioral tests for the Novell eDirectory (NDS) LDIF server.

These tests exercise the PUBLIC contract of :class:`FlextLdifServersNovell`:
schema attribute/objectClass detection and parsing, ACL recognition, and
entry detection/normalisation. Only observable behaviour is asserted — return
values, ``r[T]`` outcomes, and public model state — never private attributes
or internal collaborators.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif.servers.novell import FlextLdifServersNovell
from tests import c, m, tm, u


class TestsFlextLdifNovellServers:
    """Public-behaviour tests for the Novell eDirectory server."""

    @staticmethod
    @pytest.fixture
    def novell_server() -> FlextLdifServersNovell:
        """Create a Novell eDirectory server instance.

        Returns:
            The resulting ``FlextLdifServersNovell``.
        """
        return FlextLdifServersNovell()

    @staticmethod
    @pytest.fixture
    def schema_server(
        novell_server: FlextLdifServersNovell,
    ) -> FlextLdifServersNovell.Schema:
        """Expose the schema sub-server through the public facade property.

        Returns:
            The resulting ``FlextLdifServersNovell.Schema``.
        """
        server = novell_server.schema_server
        assert isinstance(server, FlextLdifServersNovell.Schema)
        return server

    @staticmethod
    @pytest.fixture
    def acl_server(
        novell_server: FlextLdifServersNovell,
    ) -> FlextLdifServersNovell.Acl:
        """Expose the ACL sub-server through the public facade property.

        Returns:
            The resulting ``FlextLdifServersNovell.Acl``.
        """
        server = novell_server.acl_server
        assert isinstance(server, FlextLdifServersNovell.Acl)
        return server

    @staticmethod
    @pytest.fixture
    def entry_server(
        novell_server: FlextLdifServersNovell,
    ) -> FlextLdifServersNovell.Entry:
        """Expose the entry sub-server through the public facade property.

        Returns:
            The resulting ``FlextLdifServersNovell.Entry``.
        """
        server = novell_server.entry_server
        assert isinstance(server, FlextLdifServersNovell.Entry)
        return server

    # ── Schema: attribute detection ─────────────────────────────────────

    @staticmethod
    @pytest.mark.parametrize("test_case", c.Tests.NOVELL_ATTRIBUTE_TEST_CASES)
    def test_can_handle_attribute_matches_expected_verdict(
        test_case: m.Tests.AttributeTestCase,
        schema_server: FlextLdifServersNovell.Schema,
    ) -> None:
        """Novell attribute definitions are recognised, RFC ones are not."""
        result = schema_server.can_handle_attribute(test_case.attr_definition)
        tm.that(result is test_case.expected_can_handle, eq=True)

    # ── Schema: attribute parsing ───────────────────────────────────────

    @staticmethod
    def test_parse_attribute_exposes_all_declared_properties(
        schema_server: FlextLdifServersNovell.Schema,
    ) -> None:
        """A full attribute definition parses into every advertised property."""
        attr_def = (
            "( 2.16.840.1.113719.1.1.4.1.501 NAME 'nspmPasswordPolicyDN' "
            "DESC 'Password Policy DN' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )"
        )
        u.Tests.assert_server_schema_parse_and_properties(
            schema_server,
            attr_def,
            expectations=u.Tests.SchemaExpectations(
                oid="2.16.840.1.113719.1.1.4.1.501",
                name="nspmPasswordPolicyDN",
                desc="Password Policy DN",
                syntax="1.3.6.1.4.1.1466.115.121.1.12",
                single_value=True,
            ),
        )

    @staticmethod
    def test_parse_attribute_extracts_syntax_length(
        schema_server: FlextLdifServersNovell.Schema,
    ) -> None:
        """A bounded syntax ``{256}`` yields the base syntax plus its length."""
        attr_def = (
            "( 2.16.840.1.113719.1.1.4.1.1 NAME 'nspmAdminGroup' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )"
        )
        u.Tests.assert_server_schema_parse_and_properties(
            schema_server,
            attr_def,
            expectations=u.Tests.SchemaExpectations(
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                length=256,
            ),
        )

    @staticmethod
    def test_parse_attribute_without_oid_fails_with_reason(
        schema_server: FlextLdifServersNovell.Schema,
    ) -> None:
        """An attribute definition missing its OID returns a descriptive failure."""
        tm.fail(
            schema_server.parse_attribute(
                "NAME 'nspmPasswordPolicy' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15",
            ),
            has="missing an OID",
        )

    # ── Schema: objectClass detection ───────────────────────────────────

    @staticmethod
    @pytest.mark.parametrize("test_case", c.Tests.NOVELL_OBJECTCLASS_TEST_CASES)
    def test_can_handle_objectclass_matches_expected_verdict(
        test_case: m.Tests.ObjectClassTestCase,
        schema_server: FlextLdifServersNovell.Schema,
    ) -> None:
        """Novell objectClass definitions are recognised, RFC ones are not."""
        result = schema_server.can_handle_objectclass(test_case.oc_definition)
        tm.that(result is test_case.expected_can_handle, eq=True)

    # ── Schema: objectClass parsing ─────────────────────────────────────

    @staticmethod
    def test_parse_objectclass_structural_exposes_kind_sup_must_may(
        schema_server: FlextLdifServersNovell.Schema,
    ) -> None:
        """A STRUCTURAL objectClass exposes its kind, superior, MUST and MAY."""
        oc_def = (
            "( 2.16.840.1.113719.2.2.6.1 NAME 'ndsPerson' DESC 'NDS Person' "
            "SUP top STRUCTURAL MUST ( cn ) MAY ( loginDisabled ) )"
        )
        u.Tests.assert_server_schema_parse_and_properties(
            schema_server,
            oc_def,
            expectations=u.Tests.SchemaExpectations(
                oid="2.16.840.1.113719.2.2.6.1",
                name="ndsPerson",
                kind="STRUCTURAL",
                sup="top",
                must=["cn"],
                may=["loginDisabled"],
            ),
        )

    @staticmethod
    def test_parse_objectclass_auxiliary_reports_auxiliary_kind(
        schema_server: FlextLdifServersNovell.Schema,
    ) -> None:
        """An AUXILIARY objectClass reports the AUXILIARY kind."""
        oc_def = (
            "( 2.16.840.1.113719.2.2.6.2 NAME 'nspmPasswordPolicy' "
            "AUXILIARY MAY ( nspmPasswordPolicyDN ) )"
        )
        u.Tests.assert_server_schema_parse_and_properties(
            schema_server,
            oc_def,
            expectations=u.Tests.SchemaExpectations(kind="AUXILIARY"),
        )

    @staticmethod
    def test_parse_objectclass_abstract_reports_abstract_kind(
        schema_server: FlextLdifServersNovell.Schema,
    ) -> None:
        """An ABSTRACT objectClass reports the ABSTRACT kind."""
        oc_def = "( 2.16.840.1.113719.2.2.6.3 NAME 'ndsbase' ABSTRACT )"
        u.Tests.assert_server_schema_parse_and_properties(
            schema_server,
            oc_def,
            expectations=u.Tests.SchemaExpectations(kind="ABSTRACT"),
        )

    @staticmethod
    def test_parse_objectclass_without_oid_fails_with_reason(
        schema_server: FlextLdifServersNovell.Schema,
    ) -> None:
        """An objectClass definition missing its OID returns a descriptive failure."""
        tm.fail(
            schema_server.parse_objectclass("NAME 'ndsPerson' SUP top STRUCTURAL"),
            has="missing an OID",
        )

    # ── ACL recognition ─────────────────────────────────────────────────

    @staticmethod
    @pytest.mark.parametrize(
        ("acl_line", "expected"),
        [
            pytest.param("acl: cn=admin#trustee#RW", True, id="acl-attribute"),
            pytest.param("inheritedACL: cn=x#trustee#R", True, id="inherited-acl"),
            pytest.param("ACL: cn=x#trustee#R", True, id="acl-uppercase"),
            pytest.param("aci: something", False, id="non-novell-aci"),
            pytest.param("cn: value", False, id="ordinary-attribute"),
            pytest.param("", False, id="empty-line"),
            pytest.param("   ", False, id="blank-line"),
        ],
    )
    def test_can_handle_acl_recognises_edirectory_acl_lines(
        acl_line: str,
        *,
        expected: bool,
        acl_server: FlextLdifServersNovell.Acl,
    ) -> None:
        """ACL recognition keys off the ``acl``/``inheritedacl`` attribute name."""
        tm.that(acl_server.can_handle(acl_line) is expected, eq=True)

    @staticmethod
    @pytest.mark.parametrize(
        ("acl_line", "expected_name", "expected_payload"),
        [
            pytest.param(
                "acl: cn=admin#trustee#RW",
                "acl",
                "cn=admin#trustee#RW",
                id="name-and-payload",
            ),
            pytest.param("acl:", "acl", "", id="name-without-payload"),
            pytest.param(
                "  inheritedACL:  cn=x#trustee#R  ",
                "inheritedACL",
                "cn=x#trustee#R",
                id="surrounding-whitespace-trimmed",
            ),
        ],
    )
    def test_splitacl_line_separates_attribute_name_from_payload(
        acl_line: str,
        expected_name: str,
        expected_payload: str,
    ) -> None:
        """Splitting an ACL line yields the trimmed attribute name and payload."""
        attr_name, payload = FlextLdifServersNovell.Acl.splitacl_line(acl_line)
        tm.that(attr_name == expected_name, eq=True)
        tm.that(payload == expected_payload, eq=True)

    # ── Entry detection ─────────────────────────────────────────────────

    @staticmethod
    @pytest.mark.parametrize("test_case", c.Tests.NOVELL_ENTRY_TEST_CASES)
    def test_can_handle_entry_matches_expected_verdict(
        test_case: m.Tests.EntryTestCase,
        entry_server: FlextLdifServersNovell.Entry,
    ) -> None:
        """Novell entries (by DN marker, attribute, or objectClass) are detected."""
        result = entry_server.can_handle(test_case.entry_dn, test_case.attributes)
        tm.that(result is test_case.expected_can_handle, eq=True)

    @staticmethod
    def test_can_handle_entry_rejects_empty_dn(
        entry_server: FlextLdifServersNovell.Entry,
    ) -> None:
        """An empty DN is never treated as an eDirectory entry."""
        tm.that(
            entry_server.can_handle("", {"objectClass": ["ndsperson"]}) is False,
            eq=True,
        )

    # ── Entry normalisation ─────────────────────────────────────────────

    @staticmethod
    def test_process_entry_stamps_server_type_and_preserves_attributes(
        entry_server: FlextLdifServersNovell.Entry,
    ) -> None:
        """Processing an entry preserves attributes and stamps the server type."""
        entry = m.Ldif.Entry.model_validate({
            "dn": "cn=user,o=Example",
            "attributes": {"cn": ["user"], "objectClass": ["ndsperson"]},
        })
        processed: m.Ldif.Entry = tm.ok(entry_server.process_entry(entry))
        assert isinstance(processed, m.Ldif.Entry)
        assert processed.attributes is not None
        attributes = processed.attributes.attributes
        tm.that(attributes["cn"] == ["user"], eq=True)
        tm.that(attributes["objectClass"] == ["ndsperson"], eq=True)
        tm.that(
            attributes[c.Ldif.ServerMetadataKeys.SERVER_TYPE]
            == [FlextLdifServersNovell.Constants.SERVER_TYPE],
            eq=True,
        )

    @staticmethod
    def test_process_entry_without_attributes_is_identity(
        entry_server: FlextLdifServersNovell.Entry,
    ) -> None:
        """An entry with no attributes is returned unchanged and successfully."""
        entry = m.Ldif.Entry.model_validate({
            "dn": "cn=user,o=Example",
            "attributes": {},
        })
        processed: m.Ldif.Entry = tm.ok(entry_server.process_entry(entry))
        assert isinstance(processed, m.Ldif.Entry)
        assert processed.attributes is not None
        tm.that(dict(processed.attributes.attributes) == {}, eq=True)
