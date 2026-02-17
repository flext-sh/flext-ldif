"""Shared models for LDIF processing."""

from __future__ import annotations

from flext_core._models.base import FlextModelsBase


class SchemaObjectClass(FlextModelsBase):
    """Represents an LDAP schema objectClass definition."""


class Acl(FlextModelsBase):
    """Represents an LDAP ACL."""
