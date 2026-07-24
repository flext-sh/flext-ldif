"""Behavioral tests for the Novell eDirectory (NDS) LDIF server.

These tests exercise the PUBLIC contract of :class:`FlextLdifServersNovell`:
schema attribute/objectClass detection and parsing, ACL recognition, and
entry detection/normalisation. Only observable behaviour is asserted — return
values, ``r[T]`` outcomes, and public model state — never private attributes
or internal collaborators.
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from flext_ldif.servers.novell import FlextLdifServersNovell
from tests import c, m, p, u


class TestsFlextLdifNovellServers:
    """Public-behaviour tests for the Novell eDirectory server."""

    @pytest.fixture
    def novell_server(self) -> p.Ldif.ServerServer:
        """Create a Novell eDirectory server instance."""
        return FlextLdifServersNovell()

    @pytest.fixture
    def schema_server(self, novell_server: p.Ldif.ServerServer) -> p.Ldif.SchemaServer:
        """Expose the schema sub-server through the public facade property."""
        server = novell_server.schema_server
        tm.that(server, is_=FlextLdifServersNovell.Schema)
        return server

    @pytest.fixture
    def acl_server(self, novell_server: p.Ldif.ServerServer) -> p.Ldif.AclServer:
        """Expose the ACL sub-server through the public facade property."""
        server = novell_server.acl_server
        tm.that(server, is_=FlextLdifServersNovell.Acl)
        return server

    @pytest.fixture
    def entry_server(
        self, novell_server: p.Ldif.ServerServer
    ) -> p.Tests.ProcessEntryServer:
        """Expose the entry sub-server through the public facade property."""
        server = novell_server.entry_server
        tm.that(server, is_=FlextLdifServersNovell.Entry)
        # mro-0ftd.3.6.1: narrow the public extension structurally, without a cast.
        if not isinstance(server, p.Tests.ProcessEntryServer):
            msg = "Novell entry server lacks process_entry"
            raise AssertionError(msg)
        return server

    # ── Schema: attribute detection ─────────────────────────────────────

    # mro-0ftd.3.6: consume modeled cases from their canonical facade.
    @pytest.mark.parametrize("test_case", m.Tests.NOVELL_ATTRIBUTE_TEST_CASES)
    def test_can_handle_attribute_matches_expected_verdict(
        self, test_case: p.Tests.AttributeTestCase, schema_server: p.Ldif.SchemaServer
    ) -> None:
        """Novell attribute definitions are recognised, RFC ones are not."""
        result = schema_server.can_handle_attribute(test_case.attr_definition)
        tm.that(result is test_case.expected_can_handle, eq=True)

    # ── Schema: attribute parsing ───────────────────────────────────────

    def test_parse_attribute_exposes_all_declared_properties(
        self, schema_server: p.Ldif.SchemaServer
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
            expected_oid="2.16.840.1.113719.1.1.4.1.501",
            expected_name="nspmPasswordPolicyDN",
            expected_desc="Password Policy DN",
            expected_syntax="1.3.6.1.4.1.1466.115.121.1.12",
            expected_single_value=True,
        )

    def test_parse_attribute_extracts_syntax_length(
        self, schema_server: p.Ldif.SchemaServer
    ) -> None:
        """A bounded syntax ``{256}`` yields the base syntax plus its length."""
        attr_def = (
            "( 2.16.840.1.113719.1.1.4.1.1 NAME 'nspmAdminGroup' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )"
        )
        u.Tests.assert_server_schema_parse_and_properties(
            schema_server,
            attr_def,
            expected_syntax="1.3.6.1.4.1.1466.115.121.1.15",
            expected_length=256,
        )

    def test_parse_attribute_without_oid_fails_with_reason(
        self, schema_server: p.Ldif.SchemaServer
    ) -> None:
        """An attribute definition missing its OID returns a descriptive failure."""
        tm.fail(
            schema_server.parse_attribute(
                "NAME 'nspmPasswordPolicy' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15"
            ),
            has="missing an OID",
        )

    # ── Schema: objectClass detection ───────────────────────────────────

    @pytest.mark.parametrize("test_case", m.Tests.NOVELL_OBJECTCLASS_TEST_CASES)
    def test_can_handle_objectclass_matches_expected_verdict(
        self, test_case: p.Tests.ObjectClassTestCase, schema_server: p.Ldif.SchemaServer
    ) -> None:
        """Novell objectClass definitions are recognised, RFC ones are not."""
        result = schema_server.can_handle_objectclass(test_case.oc_definition)
        tm.that(result is test_case.expected_can_handle, eq=True)

    # ── Schema: objectClass parsing ─────────────────────────────────────

    def test_parse_objectclass_structural_exposes_kind_sup_must_may(
        self, schema_server: p.Ldif.SchemaServer
    ) -> None:
        """A STRUCTURAL objectClass exposes its kind, superior, MUST and MAY."""
        oc_def = (
            "( 2.16.840.1.113719.2.2.6.1 NAME 'ndsPerson' DESC 'NDS Person' "
            "SUP top STRUCTURAL MUST ( cn ) MAY ( loginDisabled ) )"
        )
        u.Tests.assert_server_schema_parse_and_properties(
            schema_server,
            oc_def,
            expected_oid="2.16.840.1.113719.2.2.6.1",
            expected_name="ndsPerson",
            expected_kind="STRUCTURAL",
            expected_sup="top",
            expected_must=["cn"],
            expected_may=["loginDisabled"],
        )

    def test_parse_objectclass_auxiliary_reports_auxiliary_kind(
        self, schema_server: p.Ldif.SchemaServer
    ) -> None:
        """An AUXILIARY objectClass reports the AUXILIARY kind."""
        oc_def = (
            "( 2.16.840.1.113719.2.2.6.2 NAME 'nspmPasswordPolicy' "
            "AUXILIARY MAY ( nspmPasswordPolicyDN ) )"
        )
        u.Tests.assert_server_schema_parse_and_properties(
            schema_server, oc_def, expected_kind="AUXILIARY"
        )

    def test_parse_objectclass_abstract_reports_abstract_kind(
        self, schema_server: p.Ldif.SchemaServer
    ) -> None:
        """An ABSTRACT objectClass reports the ABSTRACT kind."""
        oc_def = "( 2.16.840.1.113719.2.2.6.3 NAME 'ndsbase' ABSTRACT )"
        u.Tests.assert_server_schema_parse_and_properties(
            schema_server, oc_def, expected_kind="ABSTRACT"
        )

    def test_parse_objectclass_without_oid_fails_with_reason(
        self, schema_server: p.Ldif.SchemaServer
    ) -> None:
        """An objectClass definition missing its OID returns a descriptive failure."""
        tm.fail(
            schema_server.parse_objectclass("NAME 'ndsPerson' SUP top STRUCTURAL"),
            has="missing an OID",
        )

    # ── ACL recognition ─────────────────────────────────────────────────

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
        self, acl_line: str, expected: bool, acl_server: p.Ldif.AclServer
    ) -> None:
        """ACL recognition keys off the ``acl``/``inheritedacl`` attribute name."""
        tm.that(acl_server.can_handle_acl(acl_line) is expected, eq=True)

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
        self, acl_line: str, expected_name: str, expected_payload: str
    ) -> None:
        """Splitting an ACL line yields the trimmed attribute name and payload."""
        attr_name, payload = FlextLdifServersNovell.Acl.splitacl_line(acl_line)
        tm.that(attr_name == expected_name, eq=True)
        tm.that(payload == expected_payload, eq=True)

    # ── Entry detection ─────────────────────────────────────────────────

    @pytest.mark.parametrize("test_case", m.Tests.NOVELL_ENTRY_TEST_CASES)
    def test_can_handle_entry_matches_expected_verdict(
        self, test_case: p.Tests.EntryTestCase, entry_server: p.Tests.ProcessEntryServer
    ) -> None:
        """Novell entries (by DN marker, attribute, or objectClass) are detected."""
        result = entry_server.can_handle(test_case.entry_dn, test_case.attributes)
        tm.that(result is test_case.expected_can_handle, eq=True)

    def test_can_handle_entry_rejects_empty_dn(
        self, entry_server: p.Tests.ProcessEntryServer
    ) -> None:
        """An empty DN is never treated as an eDirectory entry."""
        tm.that(
            entry_server.can_handle("", {"objectClass": ["ndsperson"]}) is False,
            eq=True,
        )

    # ── Entry normalisation ─────────────────────────────────────────────

    def test_process_entry_stamps_server_type_and_preserves_attributes(
        self, entry_server: p.Tests.ProcessEntryServer
    ) -> None:
        """Processing an entry preserves attributes and stamps the server type."""
        entry = m.Ldif.Entry.model_validate({
            "dn": "cn=user,o=Example",
            "attributes": {"cn": ["user"], "objectClass": ["ndsperson"]},
        })
        process_result = entry_server.process_entry(entry)
        tm.ok(process_result)
        # mro-0ftd.3.6.1: unwrap the canonical Entry without matcher type erasure.
        processed = process_result.unwrap()
        tm.that(processed, is_=m.Ldif.Entry)
        processed_attributes = processed.attributes
        if processed_attributes is None:
            msg = "Processed Novell entry is missing attributes"
            raise AssertionError(msg)
        attributes = processed_attributes.attributes
        tm.that(attributes["cn"] == ["user"], eq=True)
        tm.that(attributes["objectClass"] == ["ndsperson"], eq=True)
        tm.that(
            attributes[c.Ldif.ServerMetadataKeys.SERVER_TYPE]
            == [FlextLdifServersNovell.Constants.SERVER_TYPE],
            eq=True,
        )

    def test_process_entry_without_attributes_is_identity(
        self, entry_server: p.Tests.ProcessEntryServer
    ) -> None:
        """An entry with no attributes is returned unchanged and successfully."""
        entry = m.Ldif.Entry.model_validate({
            "dn": "cn=user,o=Example",
            "attributes": {},
        })
        process_result = entry_server.process_entry(entry)
        tm.ok(process_result)
        processed = process_result.unwrap()
        tm.that(processed, is_=m.Ldif.Entry)
        processed_attributes = processed.attributes
        if processed_attributes is None:
            msg = "Processed Novell entry is missing attributes"
            raise AssertionError(msg)
        tm.that(dict(processed_attributes.attributes) == {}, eq=True)
