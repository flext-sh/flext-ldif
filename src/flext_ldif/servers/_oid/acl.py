"""Oracle Internet Directory (OID) Servers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_ldif import p, u
from flext_ldif.servers._oid.acl_format import FlextLdifServersOidAclFormatMixin
from flext_ldif.servers._oid.acl_parse import FlextLdifServersOidAclParseMixin
from flext_ldif.servers._oid.acl_subjects import FlextLdifServersOidAclSubjectMixin
from flext_ldif.servers._oid.acl_write import FlextLdifServersOidAclWriteMixin
from flext_ldif.servers._rfc.acl import FlextLdifServersRfcAcl


class FlextLdifServersOidAcl(
    FlextLdifServersOidAclWriteMixin,
    FlextLdifServersOidAclParseMixin,
    FlextLdifServersOidAclSubjectMixin,
    FlextLdifServersOidAclFormatMixin,
    FlextLdifServersRfcAcl,
):
    """Oracle Internet Directory (OID) ACL implementation."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)
