"""OUD aci rendering — AciRule value object → canonical aci string.

Renders the aligned OUD form: ``aci: (targetattr=…)`` then the indented
``(targetfilter=…)``/``(targetscope=…)``/``(version 3.0; acl "name";`` parts
and one indented ``allow (perms) bindrule;`` clause per permission set.
Same-permission subjects collapse into one ``allow`` clause with ``or``-joined
bind-rules. Pure string assembly — total function, no failure channel. Format
literals and layout widths are the ``c.Ldif`` SSOT.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence

from flext_ldif import c, m


class FlextLdifServersOidAclRender:
    """Render an assembled OUD :class:`m.Ldif.AciRule` to its string form."""

    @staticmethod
    def render_bind(allow: m.Ldif.AciAllow) -> str:
        """Render one allow clause's bind-rule in canonical OUD form.

        Returns:
            The bind-rule string (subject plus optional authmethod/ip).

        """
        if allow.subject_type == c.Ldif.OudSubjectType.USERATTR:
            keyword = c.Ldif.OudSubjectType.USERATTR.value
            bind = f'{keyword}="{allow.subject_value}"'
        else:
            bind = f'{allow.subject_type}="{c.Ldif.LDAP_PREFIX}{allow.subject_value}"'
        if allow.authmethod:
            bind += f' and authmethod="{allow.authmethod}"'
        if allow.ip:
            bind += f' and ip="{allow.ip}"'
        return bind

    @staticmethod
    def target_parts(aci: m.Ldif.AciRule) -> Sequence[str]:
        """Assemble the ACI target clauses (attr/filter/scope) in OUD order.

        Returns:
            Target clause strings; the first is the unprefixed
            ``(targetattr=…`` head, ready for layout composition.

        """
        if aci.targetattr.startswith(c.Ldif.OUD_ATTR_NEGATION):
            body = aci.targetattr[len(c.Ldif.OUD_ATTR_NEGATION) :]
            parts = [f'(targetattr{c.Ldif.OUD_ATTR_NEGATION}"{body}")']
        else:
            parts = [f'(targetattr="{aci.targetattr}")']
        if aci.targetfilter:
            value = (
                aci.targetfilter
                if aci.targetfilter.startswith("(")
                else f"({aci.targetfilter})"
            )
            parts.append(f'(targetfilter="{value}")')
        if aci.targetscope:
            parts.append(f'(targetscope="{aci.targetscope}")')
        return tuple(parts)

    @classmethod
    def render_aci_string(cls, aci: m.Ldif.AciRule) -> str:
        """Render an :class:`m.Ldif.AciRule` to its OUD ``aci:`` line.

        Allows are grouped by identical permission set (first-seen order); each
        group becomes one ``allow (perms) bind1 or bind2;`` clause. The value
        carries the aligned layout: target parts and ``(version`` follow
        ``c.Ldif.ACI_PART_INDENT``, each clause follows
        ``c.Ldif.ACI_CLAUSE_INDENT``, bind-rules start in one column after the
        longest ``allow (perms)``, and each further bind-rule's ``or`` keyword
        ends in that column. The LDIF writer folds the value at these
        boundaries.

        Returns:
            The resulting ``str``.

        """
        grouped = m.Ldif.AciAllowGroups()
        for allow in aci.allows:
            grouped = grouped.with_allow(allow, cls.render_bind(allow))
        heads = tuple(
            f"{c.Ldif.ACI_ALLOW} ({', '.join(group.permissions)})"
            for group in grouped.groups
        )
        head_width = max((len(head) for head in heads), default=0)
        bind_column = len(c.Ldif.ACI_CLAUSE_INDENT) + head_width + c.Ldif.ACI_BIND_GAP
        or_joint = " " * (bind_column - len(c.Ldif.BIND_OR)) + c.Ldif.BIND_OR
        clauses = "".join(
            f"{c.Ldif.ACI_CLAUSE_INDENT}{head.ljust(head_width + c.Ldif.ACI_BIND_GAP)}"
            f"{or_joint.join(group.binds)};"
            for head, group in zip(heads, grouped.groups, strict=True)
        )
        first, *rest = cls.target_parts(aci)
        parts = "".join(
            f"{c.Ldif.ACI_PART_INDENT}{part}"
            for part in (*rest, f'({c.Ldif.ACI_VERSION}; acl "{aci.acl_name}";')
        )
        return f"{c.Ldif.ACI_PREFIX}{first}{parts}{clauses})"


__all__: list[str] = ["FlextLdifServersOidAclRender"]
