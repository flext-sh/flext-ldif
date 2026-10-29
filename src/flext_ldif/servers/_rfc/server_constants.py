"""RFC 4512 Compliant Server Servers - Base LDAP Schema/ACL/Entry Implementation.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._constants import FlextLdifConstantsServersRfc


class FlextLdifConstantsServersRfc(
    FlextLdifConstantsServersRfc,
):
    """Thin inheritor: declarations live in _constants parts."""


__all__: list[str] = ["FlextLdifConstantsServersRfc"]
