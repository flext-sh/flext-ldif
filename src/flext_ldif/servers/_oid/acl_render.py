"""OUD aci rendering — AciRule value object → canonical aci string.

Renders the aligned OUD form: ``aci: (targetattr=…)`` then the indented
``(targetfilter=…)``/``(targetscope=…)``/``(version 3.0; acl "name";`` parts
and one indented ``allow (perms) bindrule;`` / ``deny (perms) bindrule;``
clause per permission set. Same-permission subjects collapse into one clause
with ``or``-joined bind-rules. A rule whose clauses need different
targetattrs or targetscopes renders one ``aci`` value per pair. Values are
validated at assembly; rendering is pure string assembly.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence
from warnings import deprecated

from flext_ldif import c, m, p


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
    def _target_key(
        clause: p.Ldif.AciBindClause,
        aci: p.Ldif.AciRule,
    ) -> tuple[str, str | None]:
        """Return the rendered ``(targetattr, targetscope)`` of a clause."""
        return (
            clause.targetattr or aci.targetattr,
            clause.targetscope or aci.targetscope,
        )

    @staticmethod
    def group_clauses(
        clauses: Sequence[p.Ldif.AciBindClause],
        binds: Sequence[str],
    ) -> Sequence[p.Ldif.AciAllowGroup]:
        """Group rendered bind rules by permission set and bind modifiers.

        Returns:
            The groups in first-seen order.

        """
        groups: list[p.Ldif.AciAllowGroup] = []
        for clause, bind in zip(clauses, binds, strict=True):
            key = (tuple(clause.permissions), clause.authmethod, clause.ip)
            index = next(
                (
                    position
                    for position, group in enumerate(groups)
                    if (tuple(group.permissions), group.authmethod, group.ip) == key
                ),
                None,
            )
            if index is None:
                groups.append(
                    m.Ldif.AciAllowGroup(
                        permissions=key[0],
                        binds=(bind,),
                        authmethod=clause.authmethod,
                        ip=clause.ip,
                    ),
                )
                continue
            group = groups[index]
            groups[index] = group.model_copy(update={"binds": (*group.binds, bind)})
        return tuple(groups)

    @classmethod
    def _render_target(
        cls,
        aci: p.Ldif.AciRule,
        allows: Sequence[p.Ldif.AciBindClause],
        denies: Sequence[p.Ldif.AciBindClause],
    ) -> str:
        """Render the clauses of one targetattr/targetscope as one ``aci:`` line.

        Returns:
            The aligned ``aci:`` line.

        """
        heads = tuple(
            (f"{keyword} ({', '.join(group.permissions)})", group)
            for keyword, clauses in (
                (c.Ldif.ACI_ALLOW, allows),
                (c.Ldif.ACI_DENY, denies),
            )
            for group in cls.group_clauses(
                clauses,
                [cls.render_bind(clause) for clause in clauses],
            )
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

        Clauses group by targetattr and targetscope (first-seen order, allows
        before denies); each pair renders one ``aci:`` line. Within a line,
        clauses with an identical permission set become one ``allow (perms)
        bind1 or bind2;`` / ``deny (perms) …;`` clause. Target parts and
        ``(version`` follow ``c.Ldif.ACI_PART_INDENT``, each clause follows
        ``c.Ldif.ACI_CLAUSE_INDENT``, bind-rules start in one column after the
        longest clause head, and each further bind-rule's ``or`` keyword ends
        in that column. A rule without clauses renders nothing.

        Returns:
            One ``aci:`` line per targetattr/targetscope pair.

        """
        keys: list[tuple[str, str | None]] = []
        for clause in (*aci.allows, *aci.denies):
            key = cls._target_key(clause, aci)
            if key not in keys:
                keys.append(key)
        return tuple(
            cls._render_target(
                aci.model_copy(update={"targetattr": attr, "targetscope": scope}),
                [
                    item
                    for item in aci.allows
                    if cls._target_key(item, aci) == (attr, scope)
                ],
                [
                    item
                    for item in aci.denies
                    if cls._target_key(item, aci) == (attr, scope)
                ],
            )
            for attr, scope in keys
        )

    @classmethod
    @deprecated(
        "compat: render_aci_string -> render_aci_strings; "
        "fix: render every aci line of the rule",
    )
    def render_aci_string(cls, aci: p.Ldif.AciRule) -> str:
        """Render a rule that needs exactly one ``aci:`` line.

        Returns:
            The single :meth:`render_aci_strings` line.

        Raises:
            ValueError: The rule renders no line or more than one line.

        """
        lines = cls.render_aci_strings(aci)
        if len(lines) != 1:
            msg = (
                f"ACI rule {aci.acl_name!r} renders {len(lines)} aci lines; "
                "render_aci_string returns exactly one (use render_aci_strings)"
            )
            raise ValueError(msg)
        return lines[0]


__all__: list[str] = ["FlextLdifServersOidAclRender"]
