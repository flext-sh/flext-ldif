"""Oracle Internet Directory (OID) Servers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import ClassVar, override

from flext_ldif import p, u
from flext_ldif.servers._oid import (
    FlextLdifServersOidAclFormat,
    FlextLdifServersOidAclParse,
    FlextLdifServersOidAclPipeline,
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

    @staticmethod
    @override
    def access_group_dns(entries: Sequence[p.Ldif.Entry]) -> frozenset[str]:
        """Return the DN keys of the exact OID security groups among ``entries``.

        Returns:
            The group DN keys of
            :meth:`FlextLdifServersOidAclPipeline.security_group_dns`.

        """
        return FlextLdifServersOidAclPipeline.security_group_dns(entries)


__all__: list[str] = ["FlextLdifServersOidAcl"]
