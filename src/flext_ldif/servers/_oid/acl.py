"""Oracle Internet Directory (OID) Servers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_ldif import p, u
from flext_ldif.servers._oid import (
    FlextLdifServersOidAclFormat,
    FlextLdifServersOidAclParse,
    FlextLdifServersOidAclSubject,
    FlextLdifServersOidAclWrite,
)
from flext_ldif.servers._rfc import FlextLdifServersRfcAcl


class FlextLdifServersOidAcl(
    FlextLdifServersOidAclWrite,
    FlextLdifServersOidAclParse,
    FlextLdifServersOidAclSubject,
    FlextLdifServersOidAclFormat,
    FlextLdifServersRfcAcl,
):
    """Oracle Internet Directory (OID) ACL implementation."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)


__all__: list[str] = ["FlextLdifServersOidAcl"]
