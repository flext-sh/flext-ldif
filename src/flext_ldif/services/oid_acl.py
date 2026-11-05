"""Public OID-to-OUD ACL conversion capability.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import p, t
from flext_ldif.servers import (
    FlextLdifServersOidAclAssemble,
    FlextLdifServersOidAclConvert,
    FlextLdifServersOidAclRender,
    FlextLdifServersOidAclToOud,
)


class FlextLdifOidAcl:
    """Expose OID ACL conversion through the public LDIF facade."""

    @staticmethod
    def parse_oid_acl_line(dn: str, line: str) -> p.Result[p.Ldif.OidAclRule]:
        """Parse one OID ACL attribute line into its typed rule.

        Returns:
            The parsed rule or the grammar failure.

        """
        return FlextLdifServersOidAclConvert.parse_oid_acl_line(dn, line)

    @staticmethod
    def convert_subject_to_oud(
        subject: p.Ldif.OidAclSubject,
    ) -> p.Result[p.Ldif.AciAllow]:
        """Convert one OID subject into an OUD ACI allow clause.

        Returns:
            The converted allow clause or the unsupported-subject failure.

        """
        return FlextLdifServersOidAclToOud.convert_subject_to_oud(subject)

    @staticmethod
    def convert_permissions(
        permissions: t.StrSequence,
        *,
        is_entry: bool,
    ) -> p.Result[p.Ldif.AclPermissionResolution]:
        """Resolve OID permissions into typed OUD grant and deny sets.

        Changed contract: the result is the typed ``allow``/``deny`` resolution
        (previously the bare allow sequence, which granted the complement of a
        pure-negation list). ``by * (nobrowse,noadd)`` now denies exactly
        those rights and grants nothing (OID 12.2.1.3 §30.1.4.3); the consumer
        renders ``deny`` as an OUD ``deny`` clause.

        Returns:
            The typed resolution or the conversion failure.

        """
        return FlextLdifServersOidAclToOud.convert_permissions(
            permissions,
            is_entry=is_entry,
        )

    @staticmethod
    def regex_to_wildcard(value: str) -> p.Result[str]:
        """Convert an OID regular-expression DN to an OUD wildcard DN.

        Changed contract: a DN with no exact OUD wildcard (anything beyond
        ``.*``/``.+``) is now an ``r.fail`` instead of being returned raw.

        Returns:
            The converted wildcard DN or the typed failure.

        """
        return FlextLdifServersOidAclToOud.regex_to_wildcard(value)

    @staticmethod
    def in_scope(dn: str, base_dn: str) -> bool:
        """Return whether a DN is in the supplied OUD scope."""
        return FlextLdifServersOidAclToOud.in_scope(dn, base_dn)

    @staticmethod
    def build_aci_rule(
        rule: p.Ldif.OidAclRule,
        *,
        base_dn: str = "",
    ) -> p.Result[p.Ldif.AciRule]:
        """Build one OUD ACI rule from a parsed OID ACL rule.

        Returns:
            The assembled ACI rule or the first conversion failure.

        """
        return FlextLdifServersOidAclAssemble.build_aci_rule(rule, base_dn=base_dn)

    @staticmethod
    def render_aci_string(aci: p.Ldif.AciRule) -> str:
        """Render a typed OUD ACI rule as an ``aci:`` attribute line.

        Returns:
            The compact LDAP attribute line.

        """
        return FlextLdifServersOidAclRender.render_aci_string(aci)


__all__: list[str] = ["FlextLdifOidAcl"]
