"""OID (Oracle Internet Directory) Server Classes.

This module exports the OID server quirk classes used by oid.py.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.servers._oid.acl import FlextLdifServersOidAcl
from flext_ldif.servers._oid.constants import FlextLdifServersOidConstants
from flext_ldif.servers._oid.entry import FlextLdifServersOidEntry
from flext_ldif.servers._oid.schema import FlextLdifServersOidSchema

__all__ = [
    "FlextLdifServersOidAcl",
    "FlextLdifServersOidConstants",
    "FlextLdifServersOidEntry",
    "FlextLdifServersOidSchema",
]
