"""Base Constants for Server Servers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations


class FlextLdifConstantsServersBase:
    """Thin namespace: declarations live in _constants parts.

    Nao herda do facade de constants (flext_cli_c): a heranca puxava os
    type-sets do nucleo (PRIMITIVES_TYPES e demais) para dentro do
    namespace Ldif, e o codemod de type-set os redescobria em
    c.Ldif.* como duplicados de c.* ("type set declared twice").
    """
