"""OID ACL policy — typed evaluation levels and the per-ACI resolution.

Reads every OID ACL value with its origin attribute (``orclaci`` or
``orclentrylevelaci``) and carrier DN and builds what the OID evaluation
model needs (OID-30 §30.1.6; Algar conversion spec v4.1 section 2):

- R8: each by-clause subject becomes one OUD bind-rule leaf, or matches no
  session (a group without a security class, ``SuperUser`` E8,
  ``guidattr`` E4); anything else without a rule fails.
- R7: an ``AppendToAll`` clause joins every other ACI of its ACP.
- R6a: inside one ACI a grant from any matching clause wins over a matching
  denial (OID-30 §30.1.6.2; examples §30.3.6 and §30.3.9).
- R6b: ACIs of one level with an identical object string are one ACI.

Emission of the OUD ACIs lives in ``acl_render.py``.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence

from flext_ldif import c, m, p, r
from flext_ldif.servers._oid import (
    FlextLdifConstantsServersOid,
    FlextLdifServersOidAclConvert,
    FlextLdifServersOidAclToOud,
)


class FlextLdifServersOidAclAssemble:
    """Build the typed OID policy levels the OUD ACI emitter consumes."""

    @staticmethod
    def _event(rule: str, dn: str, detail: str) -> p.Ldif.AclConversionEvent:
        """Return one operator-review event."""
        return m.Ldif.AclConversionEvent(rule=rule, dn=dn, detail=detail)

    @classmethod
    def _clause(
        cls,
        dn: str,
        position: int,
        subject: p.Ldif.OidAclSubject,
        directory: p.Ldif.AclDirectory,
        *,
        is_entry: bool,
    ) -> p.Result[tuple[p.Ldif.AclClause, tuple[p.Ldif.AclConversionEvent, ...]]]:
        """Convert one by-clause: its OUD subject and its OID rights.

        A subject that matches no OUD session (E4 ``guidattr``) cannot keep a
        denial, so a ``guidattr`` clause that denies fails; a ``SuperUser``
        clause is the inherent exception E8 (the OUD account bypasses ACIs).
        An added-object constraint narrows an add grant only (R4d).

        Returns:
            The clause and its events, or the first failure.

        """
        constants = FlextLdifConstantsServersOid
        result = r[tuple[m.Ldif.AclClause, tuple[m.Ldif.AclConversionEvent, ...]]]
        where = dn or "<root DSE>"
        leaf = FlextLdifServersOidAclToOud.subject_leaf(subject, directory)
        if leaf.failure:
            return result.fail(f"{where}: {leaf.error}")
        rights = FlextLdifServersOidAclToOud.resolve_permissions(
            subject.permissions,
            is_entry=is_entry,
        )
        if rights.failure:
            return result.fail(f"{where}: {rights.error}")
        bind_leaf, outcome = leaf.value
        allow, deny = rights.value.allow, rights.value.deny
        if bind_leaf is None and outcome == constants.AclRule.E4 and deny:
            return result.fail(
                f"{where}: E4: guidattr=({subject.value}) denies {sorted(deny)}; "
                "OUD cannot compare orclGUID with the bind identity, so the "
                "denial would be lost",
            )
        constraint = subject.added_object_constraint
        if constraint and constants.ACL_RIGHT_ADD not in allow:
            return result.fail(
                f"{where}: R4d: added_object_constraint={constraint!r} on a "
                "clause that does not grant add has no conversion rule",
            )
        if constraint:
            checked = FlextLdifServersOidAclToOud.validate_ldap_filter(constraint)
            if checked.failure:
                return result.fail(f"{where}: {checked.error}")
        events: tuple[p.Ldif.AclConversionEvent, ...] = ()
        if bind_leaf is None:
            events = (
                cls._event(
                    outcome,
                    dn,
                    f"clause {position} {subject.subject_type} "
                    f"{subject.value!r} matches no OUD session",
                ),
            )
        return result.ok((
            m.Ldif.AclClause(
                index=position,
                subject=subject,
                leaf=bind_leaf,
                outcome="" if bind_leaf is not None else outcome,
                allow=allow,
                deny=deny,
            ),
            events,
        ))

    @classmethod
    def build_rule(
        cls,
        level: str,
        dn: str,
        value: str,
        index: int,
        directory: p.Ldif.AclDirectory,
    ) -> p.Result[tuple[p.Ldif.AclLevelRule, tuple[p.Ldif.AclConversionEvent, ...]]]:
        """Parse one OID ACL value and resolve its subjects and rights.

        Returns:
            The level rule with its events, or the first failure with its DN.

        """
        result = r[tuple[m.Ldif.AclLevelRule, tuple[m.Ldif.AclConversionEvent, ...]]]
        where = dn or "<root DSE>"
        parsed = FlextLdifServersOidAclConvert.parse_oid_acl_line(
            dn,
            f"{level}: {value}",
        )
        if parsed.failure:
            return result.fail(f"{where}: {parsed.error}")
        rule = parsed.value
        checked = FlextLdifServersOidAclToOud.check_attr_target(rule)
        if checked.failure:
            return result.fail(f"{where}: {checked.error}")
        target_filter: str | None = None
        if rule.target_filter is not None:
            validated = FlextLdifServersOidAclToOud.validate_ldap_filter(
                rule.target_filter,
            )
            if validated.failure:
                return result.fail(f"{where}: {validated.error}")
            target_filter = validated.value
        events: list[p.Ldif.AclConversionEvent] = []
        if rule.deny_group_override:
            events.append(
                cls._event(
                    FlextLdifConstantsServersOid.AclRule.E3,
                    dn,
                    "DenyGroupOverride also blocks the OID superuser; OUD "
                    "bypass-acl holders skip every ACI",
                ),
            )
        is_entry = rule.target_type == c.Ldif.AclTargetType.ENTRY
        clauses: list[p.Ldif.AclClause] = []
        for position, subject in enumerate(rule.subjects, 1):
            clause = cls._clause(dn, position, subject, directory, is_entry=is_entry)
            if clause.failure:
                return result.fail(clause.error or where)
            clauses.append(clause.value[0])
            events.extend(clause.value[1])
        return result.ok((
            m.Ldif.AclLevelRule(
                level=level,
                dn=dn,
                key=FlextLdifServersOidAclToOud.dn_key(dn),
                index=index,
                rule=rule,
                attrs=FlextLdifServersOidAclToOud.attr_set(rule),
                target_filter=target_filter,
                clauses=tuple(clauses),
            ),
            tuple(events),
        ))

    @staticmethod
    def append_to_all(
        rules: Sequence[p.Ldif.AclLevelRule],
    ) -> tuple[p.Ldif.AclLevelRule, ...]:
        """R7: append each ``AppendToAll`` clause to every other ACI of the level.

        Rights that do not exist for the host object kind are dropped from
        the appended clause; the ``AppendToAll`` ACI itself stays as written
        (OID-30 §30.1.4.1). Under R6a the append position decides nothing.

        Returns:
            The level's rules with the appended clauses.

        """
        appended = [
            (rule.index, clause)
            for rule in rules
            if rule.rule.append_to_all
            for clause in rule.clauses
        ]
        if not appended:
            return tuple(rules)
        extended: list[p.Ldif.AclLevelRule] = []
        for rule in rules:
            universe = (
                c.Ldif.ALL_ENTRY_PERMS if rule.attrs is None else c.Ldif.ALL_ATTR_PERMS
            )
            extra = [
                clause.model_copy(
                    update={
                        "index": len(rule.clauses) + offset,
                        "allow": clause.allow & universe,
                        "deny": clause.deny & universe,
                    },
                )
                for offset, (_, clause) in enumerate(
                    (item for item in appended if item[0] != rule.index),
                    1,
                )
                if (clause.allow | clause.deny) & universe
            ]
            extended.append(
                rule.model_copy(update={"clauses": (*rule.clauses, *extra)})
                if extra
                else rule,
            )
        return tuple(extended)

    @staticmethod
    def merge_identical_objects(
        rules: Sequence[p.Ldif.AclLevelRule],
    ) -> tuple[p.Ldif.AclLevelRule, ...]:
        """R6b: ACIs of one level with an identical object string are one ACI.

        The object is the target, the filter and the object keywords (OID-30
        §30.1.6.3). The merged clauses keep source order; under R6a the order
        decides nothing, so the merge has a single result.

        Returns:
            The merged rules in source order.

        """
        groups: dict[tuple[str, str | None], list[p.Ldif.AclLevelRule]] = {}
        for rule in rules:
            attrs = (
                c.Ldif.AclTargetType.ENTRY.value
                if rule.attrs is None
                else f"{rule.attrs.negated}:{sorted(rule.attrs.names)}"
            )
            identity = (
                f"{attrs} {rule.rule.deny_group_override} {rule.rule.append_to_all}"
            )
            groups.setdefault((identity, rule.target_filter), []).append(rule)
        merged: list[p.Ldif.AclLevelRule] = []
        for members in groups.values():
            if len(members) == 1:
                merged.append(members[0])
                continue
            clauses = [clause for member in members for clause in member.clauses]
            merged.append(
                members[0].model_copy(
                    update={
                        "index": min(member.index for member in members),
                        "clauses": tuple(
                            clause.model_copy(update={"index": position})
                            for position, clause in enumerate(clauses, 1)
                        ),
                    },
                ),
            )
        return tuple(sorted(merged, key=lambda item: item.index))

    @staticmethod
    def resolve(
        rule: p.Ldif.AclLevelRule,
    ) -> tuple[tuple[p.Ldif.AclResolution, ...], tuple[tuple[int, str], ...]]:
        """R6a: a grant from any matching clause wins over a matching denial.

        Within one ACI the effective access is the union of the granted
        rights of every matching clause (OID-30 §30.1.6.2; examples §30.3.6,
        §30.3.9; spec Q1 ``GRANT_WINS``). Clause order decides nothing, so a
        clause after ``by * (none)`` stays live. A denial keeps the subjects
        the ACI grants the right to as exclusions; a denial whose subject one
        of them covers is dead.

        Returns:
            The resolutions and the dead ``(clause, right)`` pairs.

        """
        constants = FlextLdifConstantsServersOid
        to_oud = FlextLdifServersOidAclToOud
        grantors: dict[str, list[p.Ldif.AclBindLeaf]] = {}
        for clause in rule.clauses:
            if clause.leaf is not None:
                for right in clause.allow:
                    grantors.setdefault(right, []).append(clause.leaf)
        resolutions: list[p.Ldif.AclResolution] = []
        dead: list[tuple[int, str]] = []
        for clause in rule.clauses:
            leaf = clause.leaf
            if leaf is None:
                continue
            for right in sorted(clause.allow | clause.deny):
                denied = right not in clause.allow
                others = [item for item in grantors.get(right, []) if item is not leaf]
                if denied and any(to_oud.covers(item, leaf) for item in others):
                    dead.append((clause.index, right))
                    continue
                resolutions.append(
                    m.Ldif.AclResolution(
                        clause=clause.index,
                        right=right,
                        effect=(
                            constants.AclEffect.DENY
                            if denied
                            else constants.AclEffect.ALLOW
                        ),
                        leaf=leaf,
                        grantors=tuple(others) if denied else (),
                        added_object_constraint=clause.subject.added_object_constraint,
                    ),
                )
        return tuple(resolutions), tuple(dead)


__all__: list[str] = ["FlextLdifServersOidAclAssemble"]
