"""Unit tests for the model-backed LDIF value protocols.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import tm

from tests import c, m, p


class TestsFlextLdifProtocolsValues:
    """Value protocols resolve through the public facade and accept their models."""

    @staticmethod
    def _assert_protocols(value: m.Value, *, transform: bool, process: bool) -> None:
        tm.that(isinstance(value, p.Ldif.TransformConfig), eq=transform)
        tm.that(isinstance(value, p.Ldif.ProcessConfig), eq=process)
        tm.that(isinstance(value, p.Ldif.AciAllow), eq=False)

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
