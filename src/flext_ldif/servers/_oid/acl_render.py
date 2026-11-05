"""OUD aci rendering — AciRule value object → canonical aci string.

Renders the aligned OUD form: ``aci: (targetattr=…)`` then the indented
``(targetfilter=…)``/``(targetscope=…)``/``(version 3.0; acl "name";`` parts
and one indented ``allow (perms) bindrule;`` / ``deny (perms) bindrule;``
clause per permission set. Same-permission subjects collapse into one clause
with ``or``-joined bind-rules. A rule whose clauses need different
targetscopes renders one ``aci`` value per scope. Pure string assembly —
total function, no failure channel.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence

from flext_ldif import c, m, p
from flext_ldif.servers._oid import FlextLdifConstantsServersOid


class FlextLdifServersOidAclRender:
    """Render an assembled OUD :class:`m.Ldif.AciRule` to its string form."""

    @staticmethod
    def render_bind(allow: p.Ldif.AciBindClause) -> str:
        """Render one allow or deny clause's bind-rule in canonical OUD form.

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
    def target_parts(aci: p.Ldif.AciRule) -> Sequence[str]:
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

    @staticmethod
    def _scope_key(clause: p.Ldif.AciBindClause, aci: p.Ldif.AciRule) -> str | None:
        """Return the rendered targetscope of a clause (subtree renders as None)."""
        scope = clause.targetscope or aci.targetscope
        return (
            None if scope == FlextLdifConstantsServersOid.ACL_SCOPE_SUBTREE else scope
        )

    @classmethod
    def _render_scope(
        cls,
        aci: p.Ldif.AciRule,
        allows: Sequence[p.Ldif.AciBindClause],
        denies: Sequence[p.Ldif.AciBindClause],
    ) -> str:
        """Render the clauses of one targetscope as one ``aci:`` line.

        Returns:
            The aligned ``aci:`` line.

        """
        sections: list[tuple[str, p.Ldif.AciAllowGroups]] = []
        for keyword, clauses in (
            (c.Ldif.ACI_ALLOW, allows),
            (c.Ldif.ACI_DENY, denies),
        ):
            grouped = m.Ldif.AciAllowGroups()
            for clause in clauses:
                grouped = grouped.with_allow(clause, cls.render_bind(clause))
            sections.append((keyword, grouped))
        heads = tuple(
            (f"{keyword} ({', '.join(group.permissions)})", group)
            for keyword, grouped in sections
            for group in grouped.groups
        )
        head_width = max((len(head) for head, _ in heads), default=0)
        bind_column = len(c.Ldif.ACI_CLAUSE_INDENT) + head_width + c.Ldif.ACI_BIND_GAP
        or_joint = " " * (bind_column - len(c.Ldif.BIND_OR)) + c.Ldif.BIND_OR
        rendered = "".join(
            f"{c.Ldif.ACI_CLAUSE_INDENT}{head.ljust(head_width + c.Ldif.ACI_BIND_GAP)}"
            f"{or_joint.join(group.binds)};"
            for head, group in heads
        )
        first, *rest = cls.target_parts(aci)
        parts = "".join(
            f"{c.Ldif.ACI_PART_INDENT}{part}"
            for part in (*rest, f'({c.Ldif.ACI_VERSION}; acl "{aci.acl_name}";')
        )
        return f"{c.Ldif.ACI_PREFIX}{first}{parts}{rendered})"

    @classmethod
    def render_aci_strings(cls, aci: p.Ldif.AciRule) -> Sequence[str]:
        """Render an :class:`m.Ldif.AciRule` to its OUD ``aci:`` lines.

        Clauses group by targetscope (first-seen order, allows before
        denies); each scope renders one ``aci:`` line. Within a line, clauses
        with an identical permission set become one ``allow (perms) bind1 or
        bind2;`` / ``deny (perms) …;`` clause. Target parts and ``(version``
        follow ``c.Ldif.ACI_PART_INDENT``, each clause follows
        ``c.Ldif.ACI_CLAUSE_INDENT``, bind-rules start in one column after the
        longest clause head, and each further bind-rule's ``or`` keyword ends
        in that column. A rule without clauses renders nothing.

        Returns:
            One ``aci:`` line per targetscope.

        """
        scopes: list[str | None] = []
        for clause in (*aci.allows, *aci.denies):
            key = cls._scope_key(clause, aci)
            if key not in scopes:
                scopes.append(key)
        return tuple(
            cls._render_scope(
                aci.model_copy(update={"targetscope": scope}),
                [
                    clause
                    for clause in aci.allows
                    if cls._scope_key(clause, aci) == scope
                ],
                [
                    clause
                    for clause in aci.denies
                    if cls._scope_key(clause, aci) == scope
                ],
            )
            for scope in scopes
        )

    @classmethod
    def render_aci_string(cls, aci: p.Ldif.AciRule) -> str:
        """Render an :class:`m.Ldif.AciRule` to its newline-joined ``aci:`` lines.

        Returns:
            The :meth:`render_aci_strings` lines joined by a newline.

        """
        return "\n".join(cls.render_aci_strings(aci))


__all__: list[str] = ["FlextLdifServersOidAclRender"]
