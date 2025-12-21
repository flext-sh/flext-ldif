"""Shared models for LDIF processing.

This module contains models that are shared between domain and settings
modules to avoid circular imports.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core._models.base import FlextModelsBase


class SchemaObjectClass(FlextModelsBase):
    """Represents an LDAP schema objectClass definition."""


class Acl(FlextModelsBase):
    """Represents an LDAP ACL."""
