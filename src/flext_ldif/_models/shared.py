"""Shared models for LDIF processing."""

from __future__ import annotations

from flext_core import m


class SchemaObjectClass(m):
    """Represents an LDAP schema objectClass definition."""


class Acl(m):
    """Represents an LDAP ACL."""
