"""Tests for Apache Directory Server (ApacheDS) LDIF quirks handling.

This module tests the FlextLdifServersApache implementation for handling Apache
Directory Server-specific attributes, object classes, entries, and ACLs in LDIF format.
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from flext_ldif import FlextLdifServersApache
from tests import c, m, t, u


class TestsTestFlextLdifApacheQuirks:
    """Test Apache Directory Server quirks implementation."""

    def test_server_initialization(self) -> None:
        """Test Apache Directory Server initialization."""
        server = FlextLdifServersApache()
        tm.that(server.server_type, eq="apache")
        tm.that(server.priority, eq=15)

    def test_schema_quirk_initialization(self) -> None:
        """Test schema quirk is initialized."""
        server = FlextLdifServersApache()
        tm.that(server.schema_quirk, none=False)

    def test_acl_quirk_initialization(self) -> None:
        """Test ACL quirk is initialized."""
        server = FlextLdifServersApache()
        tm.that(server.acl_quirk, none=False)

    def test_entry_quirk_initialization(self) -> None:
        """Test entry quirk is initialized."""
        server = FlextLdifServersApache()
        tm.that(server.entry_quirk, none=False)

    @pytest.mark.parametrize("test_case", c.Ldif.Tests.APACHE_ATTRIBUTE_TEST_CASES)
    def test_schema_attribute_can_handle(
        self, test_case: m.Ldif.Tests.AttributeTestCase
    ) -> None:
        """Test attribute detection for various scenarios."""
        server = FlextLdifServersApache()
        schema_quirk = server.schema_quirk
        tm.that(schema_quirk, is_=FlextLdifServersApache.Schema)
        result = schema_quirk.can_handle_attribute(test_case.attr_definition)
        tm.that(result is test_case.expected_can_handle, eq=True)

    def test_schema_attribute_parse_success(self) -> None:
        """Test parsing Apache DS attribute definition."""
        server = FlextLdifServersApache()
        schema = server.schema_quirk
        attr_def = "( 1.3.6.1.4.1.18060.0.4.1.2.100 NAME 'ads-enabled' DESC 'Enable flag' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )"
        attr_data = u.Ldif.Tests.quirk_parse_and_unwrap(
            schema,
            attr_def,
            parse_method="parse_attribute",
            expected_type=m.Ldif.SchemaAttribute,
        )
        assert attr_data is not None
        assert isinstance(attr_data, m.Ldif.SchemaAttribute)
        tm.that(attr_data.oid, eq="1.3.6.1.4.1.18060.0.4.1.2.100")
        tm.that(attr_data.name, eq="ads-enabled")
        tm.that(attr_data.desc, eq="Enable flag")
        tm.that(attr_data.syntax, eq="1.3.6.1.4.1.1466.115.121.1.7")
        tm.that(attr_data.single_value is True, eq=True)

    def test_schema_attribute_parse_with_syntax_length(self) -> None:
        """Test parsing attribute with syntax length specification."""
        server = FlextLdifServersApache()
        schema = server.schema_quirk
        attr_def = "( 1.3.6.1.4.1.18060.0.4.1.2.1 NAME 'ads-directoryServiceId' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )"
        attr_data = u.Ldif.Tests.quirk_parse_and_unwrap(
            schema,
            attr_def,
            parse_method="parse_attribute",
            expected_type=m.Ldif.SchemaAttribute,
        )
        assert attr_data is not None
        assert isinstance(attr_data, m.Ldif.SchemaAttribute)
        tm.that(attr_data.syntax, eq="1.3.6.1.4.1.1466.115.121.1.15")
        tm.that(attr_data.length, eq=256)

    def test_schema_attribute_parse_missing_oid(self) -> None:
        """Test parsing attribute without OID fails."""
        server = FlextLdifServersApache()
        schema = server.schema_quirk
        attr_def = "NAME 'ads-enabled' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7"
        u.Ldif.Tests.quirk_parse_and_unwrap(
            schema,
            attr_def,
            parse_method="parse_attribute",
            should_succeed=False,
        )

    @pytest.mark.parametrize("test_case", c.Ldif.Tests.APACHE_OBJECTCLASS_TEST_CASES)
    def test_schema_objectclass_can_handle(
        self,
        test_case: m.Ldif.Tests.ObjectClassTestCase,
    ) -> None:
        """Test objectClass detection for various scenarios."""
        server = FlextLdifServersApache()
        schema_quirk = server.schema_quirk
        tm.that(schema_quirk, is_=FlextLdifServersApache.Schema)
        result = schema_quirk.can_handle_objectclass(test_case.oc_definition)
        tm.that(result is test_case.expected_can_handle, eq=True)

    def test_schema_objectclass_parse_structural(self) -> None:
        """Test parsing STRUCTURAL objectClass."""
        server = FlextLdifServersApache()
        schema = server.schema_quirk
        oc_def = "( 1.3.6.1.4.1.18060.0.4.1.3.100 NAME 'ads-directoryService' DESC 'Directory service' SUP top STRUCTURAL MUST ( cn $ ads-directoryServiceId ) MAY ( ads-enabled ) )"
        oc_data = u.Ldif.Tests.quirk_parse_and_unwrap(
            schema,
            oc_def,
            parse_method="parse_objectclass",
            expected_type=m.Ldif.SchemaObjectClass,
        )
        assert oc_data is not None
        assert isinstance(oc_data, m.Ldif.SchemaObjectClass)
        tm.that(oc_data.oid, eq="1.3.6.1.4.1.18060.0.4.1.3.100")
        tm.that(oc_data.name, eq="ads-directoryService")
        tm.that(oc_data.kind, eq="STRUCTURAL")
        tm.that(oc_data.sup, eq="top")
        must_attrs = oc_data.must
        tm.that(must_attrs, is_=list)
        tm.that(must_attrs, has="cn")
        tm.that(must_attrs, has="ads-directoryServiceId")
        may_attrs = oc_data.may
        tm.that(may_attrs, is_=list)
        tm.that(may_attrs, has="ads-enabled")

    def test_schema_objectclass_parse_auxiliary(self) -> None:
        """Test parsing AUXILIARY objectClass."""
        server = FlextLdifServersApache()
        schema = server.schema_quirk
        oc_def = "( 1.3.6.1.4.1.18060.0.4.1.3.200 NAME 'ads-partition' AUXILIARY MAY ( ads-partitionSuffix $ ads-contextEntry ) )"
        oc_data = u.Ldif.Tests.quirk_parse_and_unwrap(
            schema,
            oc_def,
            parse_method="parse_objectclass",
            expected_type=m.Ldif.SchemaObjectClass,
        )
        assert oc_data is not None
        assert isinstance(oc_data, m.Ldif.SchemaObjectClass)
        tm.that(oc_data.kind, eq="AUXILIARY")

    def test_schema_objectclass_parse_abstract(self) -> None:
        """Test parsing ABSTRACT objectClass."""
        server = FlextLdifServersApache()
        schema = server.schema_quirk
        oc_def = "( 1.3.6.1.4.1.18060.0.4.1.3.1 NAME 'ads-base' ABSTRACT )"
        oc_data = u.Ldif.Tests.quirk_parse_and_unwrap(
            schema,
            oc_def,
            parse_method="parse_objectclass",
            expected_type=m.Ldif.SchemaObjectClass,
        )
        assert oc_data is not None
        assert isinstance(oc_data, m.Ldif.SchemaObjectClass)
        tm.that(oc_data.kind, eq="ABSTRACT")

    def test_schema_objectclass_parse_missing_oid(self) -> None:
        """Test parsing objectClass without OID fails."""
        server = FlextLdifServersApache()
        schema = server.schema_quirk
        oc_def = "NAME 'ads-directoryService' SUP top STRUCTURAL"
        u.Ldif.Tests.quirk_parse_and_unwrap(
            schema,
            oc_def,
            parse_method="parse_objectclass",
            should_succeed=False,
        )

    def test_schema_write_attribute_to_rfc(self) -> None:
        """Test writing attribute to RFC string format."""
        server = FlextLdifServersApache()
        schema = server.schema_quirk
        attr_data = m.Ldif.SchemaAttribute(
            oid="1.3.6.1.4.1.18060.0.4.1.2.100",
            name="ads-enabled",
            desc="Enable flag",
            syntax="1.3.6.1.4.1.1466.115.121.1.7",
            single_value=True,
        )
        u.Ldif.Tests.quirk_write_and_unwrap(
            schema,
            attr_data,
            write_method="_write_attribute",
            must_contain=[
                "1.3.6.1.4.1.18060.0.4.1.2.100",
                "ads-enabled",
                "SINGLE-VALUE",
            ],
        )

    def test_schema_write_objectclass_to_rfc(self) -> None:
        """Test writing objectClass to RFC string format."""
        server = FlextLdifServersApache()
        schema = server.schema_quirk
        oc_data = m.Ldif.SchemaObjectClass(
            oid="1.3.6.1.4.1.18060.0.4.1.3.100",
            name="ads-directoryService",
            kind="STRUCTURAL",
            sup="top",
            must=["cn", "ads-directoryServiceId"],
            may=["ads-enabled"],
        )
        u.Ldif.Tests.quirk_write_and_unwrap(
            schema,
            oc_data,
            write_method="_write_objectclass",
            must_contain=[
                "1.3.6.1.4.1.18060.0.4.1.3.100",
                "ads-directoryService",
                "STRUCTURAL",
            ],
        )

    def test_acl_can_handle_with_ads_aci(self) -> None:
        """Test ACL detection with ads-aci attribute."""
        server = FlextLdifServersApache()
        acl_quirk = server.acl_quirk
        acl_line = "ads-aci: ( version 3.0 ) ( deny grantAdd ) ( grantRemove )"
        acl_model = u.Ldif.Tests.acl_parse_and_unwrap(
            acl_quirk,
            acl_line,
            expected_type=m.Ldif.Acl,
        )
        assert acl_model is not None
        assert isinstance(acl_model, m.Ldif.Acl)
        roundtrip_result = u.Ldif.Tests.acl_parse_and_unwrap(
            acl_quirk,
            acl_model.raw_acl or str(acl_model),
        )
        assert roundtrip_result is not None

    def test_acl_can_handle_with_aci(self) -> None:
        """Test ACL detection with aci attribute."""
        server = FlextLdifServersApache()
        acl_quirk = server.acl_quirk
        acl_line = "aci: ( version 3.0 ) ( deny grantAdd ) ( grantRemove )"
        acl_model = u.Ldif.Tests.acl_parse_and_unwrap(
            acl_quirk,
            acl_line,
            expected_type=m.Ldif.Acl,
        )
        assert acl_model is not None
        assert isinstance(acl_model, m.Ldif.Acl)
        roundtrip_result = u.Ldif.Tests.acl_parse_and_unwrap(
            acl_quirk,
            acl_model.raw_acl or str(acl_model),
        )
        assert roundtrip_result is not None

    def test_acl_can_handle_with_version_prefix(self) -> None:
        """Test ACL detection with version prefix."""
        server = FlextLdifServersApache()
        acl_quirk = server.acl_quirk
        acl_line = "(version 3.0) (deny grantAdd) (grantRemove)"
        acl_model = u.Ldif.Tests.acl_parse_and_unwrap(
            acl_quirk,
            acl_line,
            expected_type=m.Ldif.Acl,
        )
        assert acl_model is not None
        assert isinstance(acl_model, m.Ldif.Acl)
        roundtrip_result = u.Ldif.Tests.acl_parse_and_unwrap(
            acl_quirk,
            acl_model.raw_acl or str(acl_model),
        )
        assert roundtrip_result is not None

    def test_acl_can_handle_negative(self) -> None:
        """Test ACL detection rejects non-ApacheDS ACLs."""
        server = FlextLdifServersApache()
        acl_quirk = server.acl_quirk
        tm.that(acl_quirk, is_=FlextLdifServersApache.Acl)
        acl_line = "access to * by * read"
        tm.that(acl_quirk.can_handle_acl(acl_line) is False, eq=True)

    def test_acl_can_handle_empty_line(self) -> None:
        """Test ACL detection rejects empty lines."""
        server = FlextLdifServersApache()
        acl_quirk = server.acl_quirk
        tm.that(acl_quirk, is_=FlextLdifServersApache.Acl)
        tm.that(acl_quirk.can_handle_acl("") is False, eq=True)

    def test_acl_parse_success(self) -> None:
        """Test parsing Apache DS ACI definition."""
        server = FlextLdifServersApache()
        acl_quirk = server.acl_quirk
        acl_line = "ads-aci: ( version 3.0 ) ( deny grantAdd ) ( grantRemove )"
        acl_data = u.Ldif.Tests.acl_parse_and_unwrap(
            acl_quirk,
            acl_line,
            expected_type=m.Ldif.Acl,
        )
        assert acl_data is not None
        assert isinstance(acl_data, m.Ldif.Acl)
        tm.that(acl_data.resolve_acl_format(), eq=c.Ldif.DEFAULT_ACL_FORMAT)
        tm.that(acl_data.server_type, eq=c.Ldif.ServerTypes.APACHE)

    def test_acl_parse_with_aci_attribute(self) -> None:
        """Test parsing ACI with aci attribute."""
        server = FlextLdifServersApache()
        acl_quirk = server.acl_quirk
        acl_line = "aci: ( deny grantAdd )"
        acl_data = u.Ldif.Tests.acl_parse_and_unwrap(
            acl_quirk,
            acl_line,
            expected_type=m.Ldif.Acl,
        )
        assert acl_data is not None
        assert isinstance(acl_data, m.Ldif.Acl)

    def test_acl_write_with_content(self) -> None:
        """Test writing ACL with content to RFC string format."""
        server = FlextLdifServersApache()
        acl_quirk = server.acl_quirk
        acl_model = m.Ldif.Acl(
            name="ads-aci",
            target=m.Ldif.AclTarget(target_dn="", attributes=[]),
            subject=m.Ldif.AclSubject(
                subject_type=c.Ldif.AclSubjectType.ALL, subject_value=""
            ),
            permissions=m.Ldif.AclPermissions(),
            server_type=c.Ldif.ServerTypes.APACHE,
            raw_acl="( version 3.0 ) ( deny grantAdd )",
        )
        u.Ldif.Tests.quirk_write_and_unwrap(
            acl_quirk,
            acl_model,
            write_method="_write_acl",
            must_contain=["aci:"],
        )

    def test_acl_write_with_clauses_only(self) -> None:
        """Test writing ACL with clauses only to RFC string format."""
        server = FlextLdifServersApache()
        acl_quirk = server.acl_quirk
        acl_model = m.Ldif.Acl(
            name="aci",
            target=m.Ldif.AclTarget(target_dn="", attributes=[]),
            subject=m.Ldif.AclSubject(
                subject_type=c.Ldif.AclSubjectType.ALL, subject_value=""
            ),
            permissions=m.Ldif.AclPermissions(),
            server_type=c.Ldif.ServerTypes.APACHE,
            raw_acl="( version 3.0 ) ( deny grantAdd )",
        )
        u.Ldif.Tests.acl_write_and_unwrap(
            acl_quirk,
            acl_model,
            must_contain=["aci:"],
        )

    def test_acl_write_empty(self) -> None:
        """Test writing empty ACL to RFC string format."""
        server = FlextLdifServersApache()
        acl_quirk = server.acl_quirk
        acl_model = m.Ldif.Acl(
            name="ads-aci",
            target=m.Ldif.AclTarget(target_dn="", attributes=[]),
            subject=m.Ldif.AclSubject(
                subject_type=c.Ldif.AclSubjectType.ALL, subject_value=""
            ),
            permissions=m.Ldif.AclPermissions(),
            server_type=c.Ldif.ServerTypes.APACHE,
            raw_acl="",
        )
        u.Ldif.Tests.acl_write_and_unwrap(
            acl_quirk,
            acl_model,
            must_contain=["ads-aci", "aci:"],
        )

    @pytest.mark.parametrize("test_case", c.Ldif.Tests.APACHE_ENTRY_TEST_CASES)
    def test_entry_can_handle(self, test_case: m.Ldif.Tests.EntryTestCase) -> None:
        """Test entry detection for various scenarios."""
        server = FlextLdifServersApache()
        entry_quirk = server.entry_quirk
        tm.that(entry_quirk, is_=FlextLdifServersApache.Entry)
        result = entry_quirk.can_handle(test_case.entry_dn, test_case.attributes)
        tm.that(result is test_case.expected_can_handle, eq=True)

    @staticmethod
    def _build_ldif(entry_dn: str, attributes: t.StrSequenceMapping) -> str:
        """Build LDIF string from DN and attributes."""
        ldif = f"dn: {entry_dn}\n"
        for attr, values in attributes.items():
            if isinstance(values, list):
                for val in values:
                    ldif += f"{attr}: {val}\n"
            else:
                ldif += f"{attr}: {values}\n"
        return ldif

    @pytest.mark.parametrize(
        "test_case",
        [tc for tc in c.Ldif.Tests.APACHE_ENTRY_TEST_CASES if tc.expected_can_handle],
    )
    def test_entry_parse_ldif(self, test_case: m.Ldif.Tests.EntryTestCase) -> None:
        """Test entry parsing via LDIF for Apache-detectable entries."""
        server = FlextLdifServersApache()
        entry_quirk = server.entry_quirk
        ldif = self._build_ldif(test_case.entry_dn, test_case.attributes)
        result = entry_quirk.parse_input(ldif)
        tm.that(result is not None, eq=True)
