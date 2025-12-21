"""Shared models for LDIF processing.

This module contains models that are shared between domain and settings
modules to avoid circular imports.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core._models.base import FlextModelsBase
from flext_ldif._models.domain import FlextLdifModelsDomains


class SchemaObjectClass(FlextModelsBase):
    """Represents an LDAP schema objectClass definition."""


# Use the real Acl class from domain module
# This ensures consistency between _models.shared.Acl and
# domain.FlextLdifModelsDomains.Acl without circular imports
Acl = FlextLdifModelsDomains.Acl
