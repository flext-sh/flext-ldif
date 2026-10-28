"""Behavioral tests for the service-layer LDIF transformers.

Every assertion targets the public contract of ``FlextLdifTransformer`` and the
``convert_model`` facade entry point: the ``r[T]`` outcome of a fallible
conversion, the resulting public ``m.Ldif.Entry`` state (dn / attributes), the
migration ACL rewrite promised by the OID->OUD hot path, base-DN scope
filtering, str/enum input parity, idempotence, and the error surfaced for an
unknown server type. No private attributes, collaborators, or internal calls
are inspected.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

import pytest

from flext_ldif import services
from tests import c, m, p, tm, u


class TestsFlextLdifTransformersService:
    """Cover the observable transformation contract of the ldif transformer."""

    @staticmethod
    def test_convert_model_returns_entry_preserving_dn(
        api: p.Ldif.LdifClient,
    ) -> None:
        """Conversion preserves the public entry's DN."""
        entry = u.Tests.create_real_entry(
            dn=c.Tests.ANALYSIS_DN_VALID,
            attributes={"cn": ["valid"]},
        )

        converted = tm.ok(
            api.convert_model(c.Tests.RFC, c.Tests.RFC, entry),
        )

        tm.that(
            converted,
            is_=m.Ldif.Entry,
            attrs_match={"dn.value": c.Tests.ANALYSIS_DN_VALID},
        )

    @staticmethod
    def test_rfc_to_rfc_transformation_is_identity_preserving(
        server: p.Ldif.ServerRegistry,
    ) -> None:
        """Identity transformation preserves the entry's DN and attributes."""
        entry = u.Tests.create_real_entry(
            dn="cn=keep,dc=example,dc=com",
            attributes={"objectClass": ["top"], "cn": ["keep"]},
        )
        transformer = services.FlextLdifTransformer(
            registry=server.registry,
            source_server=c.Ldif.ServerTypes.RFC,
            target_server=c.Ldif.ServerTypes.RFC,
        )

        converted = tm.ok(transformer.apply(entry))
        tm.that(tm.not_none(converted.dn).value, eq="cn=keep,dc=example,dc=com")
        tm.that(
            tm.not_none(converted.attributes).attributes,
            eq={"objectClass": ["top"], "cn": ["keep"]},
        )

    @staticmethod
    def test_default_server_types_apply_rfc_identity(
        server: p.Ldif.ServerRegistry,
    ) -> None:
        """Omitted selectors preserve a standard entry's DN."""
        entry = u.Tests.create_real_entry(
            dn="cn=default,dc=example,dc=com",
            attributes={"cn": ["default"]},
        )

        converted = tm.ok(
            services.FlextLdifTransformer(registry=server.registry).apply(entry)
        )
        tm.that(tm.not_none(converted.dn).value, eq="cn=default,dc=example,dc=com")

    @staticmethod
    @pytest.mark.parametrize(
        ("source_server", "target_server"),
        [(c.Ldif.ServerTypes.OID, c.Ldif.ServerTypes.OUD), ("oid", "oud")],
    )
    def test_oid_to_oud_converts_orclaci_to_aci_for_enum_and_string_inputs(
        server: p.Ldif.ServerRegistry,
        source_server: str | c.Ldif.ServerTypes,
        target_server: str | c.Ldif.ServerTypes,
    ) -> None:
        """OID ACL conversion agrees for string and enum selectors."""
        entry = u.Tests.create_real_entry(
            dn="cn=users,dc=ctbc",
            attributes={
                "objectClass": ["top"],
                "orclaci": [
                    'access to entry by group="cn=admins,dc=ctbc" (browse,add)',
                ],
            },
        )
        transformer = services.FlextLdifTransformer(
            registry=server.registry,
            source_server=source_server,
            target_server=target_server,
        )

        converted = tm.ok(transformer.apply(entry))
        attrs = tm.not_none(converted.attributes).attributes

        tm.that(attrs, lacks="orclaci")
        tm.that(
            attrs["aci"],
            eq=[
                (
                    '(targetattr="*")    (version 3.0; acl "users Entry by admins";'
                    '     allow (read, search, add)    groupdn="ldap:///cn=admins,dc=ctbc";)'
                ),
            ],
        )

    @staticmethod
    def test_base_dn_excludes_out_of_scope_bind_dn(
        server: p.Ldif.ServerRegistry,
    ) -> None:
        """The public base-DN option filters out-of-scope ACL bind DNs."""
        entry = u.Tests.orclaci_base_dn_entry(dn="cn=users,dc=ctbc")
        transformer = services.FlextLdifTransformer(
            registry=server.registry,
            source_server=c.Ldif.ServerTypes.OID,
            target_server=c.Ldif.ServerTypes.OUD,
            base_dn="dc=ctbc",
        )

        converted = tm.ok(transformer.apply(entry))

        tm.that(
            tm.not_none(converted.attributes).attributes["aci"],
            eq=[
                (
                    '(targetattr="*")    (version 3.0; acl "users Entry by x";'
                    '     allow (read, search)    groupdn="ldap:///cn=a,dc=ctbc";)'
                ),
            ],
        )

    @staticmethod
    def test_unknown_server_type_raises_value_error(
        server: p.Ldif.ServerRegistry,
    ) -> None:
        """Test unknown server type raises value error."""
        entry = u.Tests.create_real_entry(
            dn="cn=bad,dc=example,dc=com",
            attributes={"cn": ["bad"]},
        )
        transformer = services.FlextLdifTransformer(
            registry=server.registry,
            source_server="not-a-server",
            target_server=c.Ldif.ServerTypes.RFC,
        )

        with pytest.raises(ValueError, match="not-a-server"):
            transformer.apply(entry)
