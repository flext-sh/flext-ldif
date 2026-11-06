"""Public OID-to-OUD ACL conversion capability.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from warnings import deprecated

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
    def resolve_permissions(
        permissions: t.StrSequence,
        *,
        is_entry: bool,
    ) -> p.Result[p.Ldif.AclPermissionResolution]:
        """Resolve OID permissions into typed OUD grant and deny sets.

        ``by * (nobrowse,noadd)`` denies exactly those rights and grants
        nothing (OID 12.2.1.3 §30.1.4.3); the deny set renders as an OUD
        ``deny`` clause.

        Returns:
            The typed resolution or the conversion failure.

        """
        return FlextLdifServersOidAclToOud.resolve_permissions(
            permissions,
            is_entry=is_entry,
        )

    @staticmethod
    @deprecated(
        "compat: convert_permissions -> resolve_permissions; "
        "fix: render the typed deny set",
    )
    def convert_permissions(
        permissions: t.StrSequence,
        *,
        is_entry: bool,
    ) -> p.Result[t.StrSequence]:
        """Return only the granted rights of :meth:`resolve_permissions`.

        Returns:
            The granted OUD permissions or the conversion failure.

        """
        return FlextLdifServersOidAclToOud.resolve_permissions(
            permissions,
            is_entry=is_entry,
        ).map(lambda resolved: tuple(resolved.allow))

    @staticmethod
    def regex_dn_to_wildcard(value: str) -> p.Result[str]:
        """Convert an OID regular-expression DN to its exact OUD wildcard DN.

        A DN beyond a plain DN or a leading ``.*,`` subtree wildcard surfaces
        as ``r.fail``.

        Returns:
            The converted wildcard DN or the typed failure.

        """
        return FlextLdifServersOidAclToOud.regex_dn_to_wildcard(value)

    @staticmethod
    @deprecated(
        "compat: regex_to_wildcard -> regex_dn_to_wildcard; "
        "fix: consume the typed result",
    )
    def regex_to_wildcard(value: str) -> str:
        """Return :meth:`regex_dn_to_wildcard`, raising on its failure.

        Returns:
            The converted wildcard DN.

        """
        return FlextLdifServersOidAclToOud.regex_dn_to_wildcard(value).unwrap()

    @staticmethod
    def in_scope(dn: str, base_dn: str) -> bool:
        """Return whether a DN is in the supplied OUD scope."""
        return FlextLdifServersOidAclToOud.in_scope(dn, base_dn)

    @staticmethod
    @deprecated(
        "compat: high_level_containers -> removed (no OID semantics); "
        "fix: drop the high-level container filter",
    )
    def high_level_containers(base_dn: str) -> frozenset[str]:
        """Return the base DN plus the deprecated container suffix DNs."""
        return FlextLdifServersOidAclToOud.container_dns(base_dn)

    @staticmethod
    def build_aci_rule(
        rule: p.Ldif.OidAclRule,
        *,
        base_dn: str = "",
        access_groups: frozenset[str] = frozenset(),
        sibling_attrs: t.StrSequence = (),
    ) -> p.Result[p.Ldif.AciRule]:
        """Build one OUD ACI rule from a parsed OID ACL rule.

        A group subject outside ``access_groups`` (the source dialect's
        ``access_group_dns``) fails; ``sibling_attrs`` holds the attributes
        other ACIs of the same ACP name explicitly.

        Returns:
            The assembled ACI rule or the first conversion failure.

        """
        return FlextLdifServersOidAclAssemble.build_aci_rule(
            rule,
            base_dn=base_dn,
            access_groups=access_groups,
            sibling_attrs=sibling_attrs,
        )

    @staticmethod
    @deprecated(
        "compat: render_aci_string -> render_aci_strings; "
        "fix: render every aci line of the rule",
    )
    def render_aci_string(aci: p.Ldif.AciRule) -> str:
        """Render a rule that needs exactly one ``aci:`` line.

        Returns:
            The single :meth:`render_aci_strings` line.

        Raises:
            ValueError: The rule renders no line or more than one line.

        """
        lines = FlextLdifServersOidAclRender.render_aci_strings(aci)
        if len(lines) != 1:
            msg = (
                f"ACI rule {aci.acl_name!r} renders {len(lines)} aci lines; "
                "render_aci_string returns exactly one (use render_aci_strings)"
            )
            raise ValueError(msg)
        return lines[0]

    @staticmethod
    def render_aci_strings(aci: p.Ldif.AciRule) -> t.StrSequence:
        """Render a typed OUD ACI rule as its ``aci:`` lines.

        Returns:
            One ``aci:`` line per clause targetattr/targetscope pair.

        """
        return FlextLdifServersOidAclRender.render_aci_strings(aci)


__all__: list[str] = ["FlextLdifOidAcl"]
