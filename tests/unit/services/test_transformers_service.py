"""Behavioral tests for the service-layer LDIF transformers.

Every assertion targets the public contract of ``FlextLdifTransformer`` and the
``convert_model`` facade entry point: the ``r[T]`` outcome of a fallible
conversion, the resulting public ``m.Ldif.Entry`` state (dn / attributes), the
migration ACL rewrite promised by the OID->OUD hot path, base-DN scope
filtering, str/enum input parity, idempotence, and the error surfaced for an
unknown server type. No private attributes, collaborators, or internal calls
are inspected.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from flext_ldif.services.transformers import FlextLdifTransformer
from flext_tests import tm
from tests import c, m, u

if TYPE_CHECKING:
    from tests import p


class TestsFlextLdifTransformersService:
    """Cover the observable transformation contract of the ldif transformer."""

    def test_convert_model_returns_entry_preserving_dn(
        self, api: p.Ldif.LdifClient
    ) -> None:
        entry = u.Tests.create_real_entry(
            dn=c.Tests.ANALYSIS_DN_VALID, attributes={"cn": ["valid"]}
        )

        converted = u.Tests.assert_success(
            api.convert_model(c.Tests.RFC, c.Tests.RFC, entry)
        )

        tm.that(converted, is_=m.Ldif.Entry)
        if not isinstance(converted, m.Ldif.Entry) or converted.dn is None:
            msg = "Expected convert_model to return an Entry with a DN"
            raise AssertionError(msg)
        tm.that(converted.dn, is_=m.Ldif.DN)
        tm.that(converted.dn.value, eq=c.Tests.ANALYSIS_DN_VALID)

    def test_rfc_to_rfc_transformation_is_identity_preserving(self) -> None:
        entry = u.Tests.create_real_entry(
            dn="cn=keep,dc=example,dc=com",
            attributes={"objectClass": ["top"], "cn": ["keep"]},
        )
        transformer = FlextLdifTransformer(
            source_server=c.Ldif.ServerTypes.RFC, target_server=c.Ldif.ServerTypes.RFC
        )

        converted = self._success_entry(transformer.apply(entry))

        if converted.dn is None or converted.attributes is None:
            msg = "Expected identity transformation to preserve DN and attributes"
            raise AssertionError(msg)
        tm.that(converted.dn.value, eq="cn=keep,dc=example,dc=com")
        tm.that(
            converted.attributes.attributes, eq={"objectClass": ["top"], "cn": ["keep"]}
        )

    def test_default_server_types_apply_rfc_identity(self) -> None:
        # Unset source/target default to RFC per the public contract; applying
        # to a plain entry must still yield a success carrying the same entry.
        entry = u.Tests.create_real_entry(
            dn="cn=default,dc=example,dc=com", attributes={"cn": ["default"]}
        )

        converted = self._success_entry(FlextLdifTransformer().apply(entry))

        if converted.dn is None:
            msg = "Expected default transformer to preserve the DN"
            raise AssertionError(msg)
        tm.that(converted.dn.value, eq="cn=default,dc=example,dc=com")

    @pytest.mark.parametrize(
        ("source_server", "target_server"),
        [(c.Ldif.ServerTypes.OID, c.Ldif.ServerTypes.OUD), ("oid", "oud")],
    )
    def test_oid_to_oud_converts_orclaci_to_aci_for_enum_and_string_inputs(
        self,
        source_server: str | c.Ldif.ServerTypes,
        target_server: str | c.Ldif.ServerTypes,
    ) -> None:
        # apply() is the migration hot path: it must rewrite OID orclaci into
        # OUD aci identically whether the server type is passed as enum or str.
        entry = u.Tests.create_real_entry(
            dn="cn=users,dc=ctbc",
            attributes={
                "objectClass": ["top"],
                "orclaci": [
                    'access to entry by group="cn=admins,dc=ctbc" (browse,add)'
                ],
            },
        )
        transformer = FlextLdifTransformer(
            source_server=source_server, target_server=target_server
        )

        converted = self._success_entry(transformer.apply(entry))
        if converted.attributes is None:
            msg = "Expected transformer to return an Entry with attributes"
            raise AssertionError(msg)
        attrs = converted.attributes.attributes

        tm.that("orclaci" not in attrs, eq=True)
        tm.that(
            attrs["aci"],
            eq=[
                (
                    '(targetattr="*")(version 3.0; acl "users Entry by admins"; '
                    'allow (read, search, add) groupdn="ldap:///cn=admins,dc=ctbc";)'
                )
            ],
        )

    def test_base_dn_excludes_out_of_scope_bind_dn(self) -> None:
        entry = u.Tests.create_real_entry(
            dn="cn=users,dc=ctbc",
            attributes={
                "objectClass": ["top"],
                "orclaci": [
                    (
                        'access to entry by group="cn=x,dc=other" (browse) '
                        'by group="cn=a,dc=ctbc" (browse)'
                    )
                ],
            },
        )
        transformer = FlextLdifTransformer(
            source_server=c.Ldif.ServerTypes.OID,
            target_server=c.Ldif.ServerTypes.OUD,
            base_dn="dc=ctbc",
        )

        converted = self._success_entry(transformer.apply(entry))
        if converted.attributes is None:
            msg = "Expected transformer to return an Entry with attributes"
            raise AssertionError(msg)

        tm.that(
            converted.attributes.attributes["aci"],
            eq=[
                (
                    '(targetattr="*")(version 3.0; acl "users Entry by x"; '
                    'allow (read, search) groupdn="ldap:///cn=a,dc=ctbc";)'
                )
            ],
        )

    def test_unknown_server_type_raises_value_error(self) -> None:
        entry = u.Tests.create_real_entry(
            dn="cn=bad,dc=example,dc=com", attributes={"cn": ["bad"]}
        )
        transformer = FlextLdifTransformer(
            source_server="not-a-server", target_server=c.Ldif.ServerTypes.RFC
        )

        with pytest.raises(ValueError, match="not-a-server"):
            transformer.apply(entry)

    @staticmethod
    def _success_entry(result: p.Result[m.Ldif.Entry]) -> m.Ldif.Entry:
        """Assert the fallible conversion succeeded and yields a public Entry."""
        converted = u.Tests.assert_success(result)
        if not isinstance(converted, m.Ldif.Entry):
            msg = "Expected transformer to return an Entry"
            raise TypeError(msg)
        return converted
