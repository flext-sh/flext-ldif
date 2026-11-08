"""Oracle Internet Directory (OID) Servers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import ClassVar, override

from flext_ldif import c, m, p, r, u
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
    def convert_directory_acls(
        entries: Sequence[p.Ldif.Entry],
        *,
        target_server_type: str,
        suffix: str,
    ) -> p.Result[p.Ldif.AclDirectoryConversion]:
        """Convert the directory's OID ACLs when the target is OUD.

        Returns:
            :meth:`FlextLdifServersOidAclPipeline.convert_directory` for an OUD
            target; the empty conversion for any other target.

        """
        if target_server_type != c.Ldif.ServerTypes.OUD:
            return r[p.Ldif.AclDirectoryConversion].ok(m.Ldif.AclDirectoryConversion())
        return FlextLdifServersOidAclPipeline.convert_directory(entries, suffix=suffix)


__all__: list[str] = ["FlextLdifServersOidAcl"]
