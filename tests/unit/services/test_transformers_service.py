"""Behavior tests for service transformers."""

from __future__ import annotations

from flext_tests import tm

from flext_ldif import FlextLdifTransformer
from tests import c, m, p, u


class TestsFlextLdifTransformerService:
    """Cover public model conversion through the ldif facade."""

    def test_convert_model_with_entry_returns_success(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        entry = u.Tests.create_real_entry(
            dn=c.Tests.ANALYSIS_DN_VALID,
            attributes={"cn": ["valid"]},
        )

        result = api.convert_model(c.Tests.RFC, c.Tests.RFC, entry)
        converted = u.Tests.assert_success(result)

        tm.that(isinstance(converted, m.Ldif.Entry), eq=True)
        if not isinstance(converted, m.Ldif.Entry):
            msg = "Expected convert_model to return an Entry"
            raise AssertionError(msg)

        tm.that(converted.dn, is_=m.Ldif.DN)
        tm.that(
            (converted.dn.value if converted.dn is not None else ""),
            eq=c.Tests.ANALYSIS_DN_VALID,
        )

    def test_oid_to_oud_transformer_converts_orclaci_to_aci(self) -> None:
        # FlextLdifTransformer.apply is the migration hot path (used by the
        # processing pipeline); it must convert OID ACL attributes to OUD aci.
        entry = u.Tests.create_real_entry(
            dn="cn=users,dc=ctbc",
            attributes={
                "objectClass": ["top"],
                "orclaci": [
                    'access to entry by group="cn=admins,dc=ctbc" (browse,add)',
                ],
            },
        )
        transformer = FlextLdifTransformer(
            source_server=c.Ldif.ServerTypes.OID,
            target_server=c.Ldif.ServerTypes.OUD,
        )

        converted = u.Tests.assert_success(transformer.apply(entry))
        if not isinstance(converted, m.Ldif.Entry) or converted.attributes is None:
            msg = "Expected transformer to return an Entry with attributes"
            raise AssertionError(msg)
        attrs = converted.attributes.attributes

        tm.that("orclaci" not in attrs, eq=True)
        tm.that(
            attrs["aci"],
            eq=[
                ('(targetattr="*")(version 3.0; acl "users Entry by admins"; '
                'allow (read, search, add) groupdn="ldap:///cn=admins,dc=ctbc";)'),
            ],
        )
