"""Unit tests for the model-backed LDIF value protocols.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif import ldif
from tests import c, m, p, tm, u


class TestsFlextLdifProtocolsValues:
    """Value protocols resolve through the public facade and accept their models."""

    @staticmethod
    @pytest.mark.parametrize("server_type", [c.Tests.RFC, c.Tests.OID])
    def test_registered_schema_fields_support_oid_filtering(
        server: p.Ldif.ServerRegistry,
        server_type: str,
    ) -> None:
        """Registered schema fields retain only whitelisted OIDs through the facade."""
        constants: type[p.Ldif.ServerConstants] = tm.ok(
            server.resolve_server_constants(server_type),
        )
        attributes = {
            field: [c.Tests.FILTERS_ATTR_OID_VALID, c.Tests.FILTERS_UNWANTED_ATTR_OID]
            for field in constants.SCHEMA_FILTERABLE_FIELDS
        }
        entry = u.Tests.create_real_entry(
            dn=c.Tests.FILTERS_DN_SCHEMA,
            attributes=attributes,
        )
        filtered = ldif.filter_schema_attribute_values(
            entry,
            {
                field.lower(): frozenset({c.Tests.FILTERS_ATTR_OID_ALLOWED})
                for field in constants.SCHEMA_FILTERABLE_FIELDS
            },
        )
        tm.that(
            filtered.attributes_dict,
            eq={
                field: [c.Tests.FILTERS_ATTR_OID_VALID]
                for field in constants.SCHEMA_FILTERABLE_FIELDS
            },
        )
        tm.that(entry.attributes_dict, eq=attributes)

    @staticmethod
    def _assert_protocols(value: m.Value, *, transform: bool, process: bool) -> None:
        tm.that(isinstance(value, p.Ldif.TransformConfig), eq=transform)
        tm.that(isinstance(value, p.Ldif.ProcessConfig), eq=process)
        tm.fail(isinstance(value, p.Ldif.AciAllow))

    def test_models_satisfy_only_their_value_protocols(self) -> None:
        """Test server-to-server config models satisfy only their own protocols."""
        self._assert_protocols(
            m.Ldif.TransformConfig.servers(
                source_server=c.Ldif.ServerTypes.OID,
                target_server=c.Ldif.ServerTypes.OUD,
            ),
            transform=True,
            process=False,
        )
        self._assert_protocols(
            m.Ldif.ProcessConfig.servers(
                source_server=c.Ldif.ServerTypes.OID,
                target_server=c.Ldif.ServerTypes.OUD,
            ),
            transform=False,
            process=True,
        )
