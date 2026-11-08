"""OID ACL policy index and the R5 denial region placement.

Indexes the typed OID policy by evaluation level (OID-30 §30.1.6: the
entry's ``orclEntryLevelACI``, then each ACP up to the root DSE) and places
each OUD ``deny`` so that the levels OID evaluates first still decide inside
their region (Algar conversion spec v4.1, R5 "Região"):

- a nearer grant whose subject no farther ACP grants is excluded from the
  whole denial (global exclusion);
- the anchor's own entry-level ACI splits the scope (``base`` and
  ``subordinate``; for add, ``onelevel`` and ``target="*,*,P"``);
- an entry-level ACI below leaves through ``(!(entryDN=V))`` and gets its
  own ``base`` denial; an ACP below leaves through ``target!=`` and the
  denial is placed again inside it;
- two or more sibling ACP subtrees split the denial over the current
  children of the anchor read from the injected directory (E11, operator
  decision "Split by child").

The forms were measured on OUD 14.1.2.1 (phase D); any other overlap fails.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import override

from flext_ldif import c, m, p, r
from flext_ldif.servers._oid import (
    FlextLdifConstantsServersOid,
    FlextLdifServersOidAclAssemble,
    FlextLdifServersOidAclScope,
    FlextLdifServersOidAclToOud,
)


class FlextLdifServersOidAclRegion(FlextLdifServersOidAclScope):
    """The indexed OID policy and the placement of its OUD denials."""

    def __init__(
        self,
        rules: Sequence[p.Ldif.AclLevelRule],
        *,
        suffix: str,
        directory: p.Ldif.AclDirectory,
    ) -> None:
        """Index the policy by level and resolve every ACI once (R6a)."""
        constants = FlextLdifConstantsServersOid
        self._suffix = suffix
        self._directory = directory
        self._levels: dict[tuple[str, str], tuple[p.Ldif.AclLevelRule, ...]] = {}
        self._dns: dict[str, str] = {}
        self._resolutions: dict[
            tuple[str, str, int],
            tuple[p.Ldif.AclResolution, ...],
        ] = {}
        self.events: list[p.Ldif.AclConversionEvent] = []
        for rule in rules:
            index = (rule.key, rule.level)
            self._levels[index] = (*self._levels.get(index, ()), rule)
            self._dns.setdefault(rule.key, rule.dn)
            resolutions, dead = FlextLdifServersOidAclAssemble.resolve(rule)
            self._resolutions[rule.key, rule.level, rule.index] = resolutions
            self.events.extend(
                m.Ldif.AclConversionEvent(
                    rule=constants.AclRule.R6A,
                    dn=rule.dn,
                    detail=(
                        f"{rule.level} {rule.index}.{clause}: denial of {right} "
                        "is covered by a grant of the same ACI"
                    ),
                )
                for clause, right in dead
            )
        self._keys = sorted(
            {rule.key for rule in rules},
            key=lambda key: (key.count(","), key),
        )

    @staticmethod
    @override
    def every_attribute() -> p.Ldif.AclAttrSet:
        """Return ``targetattr="*"`` as the negated empty set."""
        return m.Ldif.AclAttrSet(names=frozenset(), negated=True)

    @staticmethod
    @override
    def intersect(
        left: p.Ldif.AclAttrSet, right: p.Ldif.AclAttrSet
    ) -> p.Ldif.AclAttrSet:
        """Return the intersection of two attribute sets."""
        if left.negated and right.negated:
            return m.Ldif.AclAttrSet(names=left.names | right.names, negated=True)
        if left.negated:
            return m.Ldif.AclAttrSet(names=right.names - left.names)
        if right.negated:
            return m.Ldif.AclAttrSet(names=left.names - right.names)
        return m.Ldif.AclAttrSet(names=left.names & right.names)

    @classmethod
    @override
    def overlaps(cls, left: p.Ldif.AclAttrSet, right: p.Ldif.AclAttrSet) -> bool:
        """Return whether two attribute sets share an attribute."""
        both = cls.intersect(left, right)
        return both.negated or bool(both.names)

    @classmethod
    @override
    def contains(cls, outer: p.Ldif.AclAttrSet, inner: p.Ldif.AclAttrSet) -> bool:
        """Return whether ``outer`` holds every attribute of ``inner``."""
        return cls.intersect(outer, inner) == inner

    def rules_at(self, key: str, level: str) -> tuple[p.Ldif.AclLevelRule, ...]:
        """Return the rules of one evaluation level in source order."""
        return self._levels.get((key, level), ())

    def resolutions(
        self,
        rule: p.Ldif.AclLevelRule,
    ) -> tuple[p.Ldif.AclResolution, ...]:
        """Return the R6a decisions of one rule."""
        return self._resolutions[rule.key, rule.level, rule.index]

    def grants(self, rule: p.Ldif.AclLevelRule, right: str) -> list[p.Ldif.AclBindLeaf]:
        """Return the subjects one rule grants one OID right to."""
        allow = FlextLdifConstantsServersOid.AclEffect.ALLOW
        return [
            item.leaf
            for item in self.resolutions(rule)
            if item.right == right and item.effect == allow
        ]

    def effective_attrs(self, rule: p.Ldif.AclLevelRule) -> p.Result[p.Ldif.AclAttrSet]:
        """R6b: ``attr=(*)`` loses the attributes another ACI of the level names.

        Inside one ACP ``attr=(*)`` means every attribute except those another
        ACI of the ACP names (OID-30 §30.1.6.3). ``attr!=`` beside ``attr=(*)``
        at one level has no OUD form. Entry rules answer every attribute.

        Returns:
            The targetattr set, or the R6b failure.

        """
        every = self.every_attribute()
        if rule.attrs is None:
            return r[p.Ldif.AclAttrSet].ok(every)
        if rule.attrs != every:
            return r[p.Ldif.AclAttrSet].ok(rule.attrs)
        others = [
            other.attrs
            for other in self.rules_at(rule.key, rule.level)
            if other.attrs is not None and other.attrs != every
        ]
        if any(attrs.negated for attrs in others):
            return r[p.Ldif.AclAttrSet].fail(
                f"R6b: {rule.dn} has attr!= and attr=(*) at one level; their "
                "precedence has no OUD form (OID-30 §30.1.6.3)",
            )
        named = frozenset().union(*(attrs.names for attrs in others))
        return r[p.Ldif.AclAttrSet].ok(m.Ldif.AclAttrSet(names=named, negated=True))

    def farther_acp_keys(self, rule: p.Ldif.AclLevelRule) -> list[str]:
        """Return the ACP keys evaluated after the rule's level, nearest first."""
        acp = c.Ldif.AclConvertType.ORCLACI.value
        own = [rule.key] if rule.level != acp else []
        ancestors = [
            key
            for key in reversed(self._keys)
            if key != rule.key
            and FlextLdifServersOidAclToOud.is_ancestor_or_self(key, rule.key)
            and self.rules_at(key, acp)
        ]
        return [*own, *ancestors]

    def farther_rules(self, rule: p.Ldif.AclLevelRule) -> list[p.Ldif.AclLevelRule]:
        """Return the farther ACP rules of the same object kind, nearest first."""
        acp = c.Ldif.AclConvertType.ORCLACI.value
        return [
            higher
            for key in self.farther_acp_keys(rule)
            for higher in self.rules_at(key, acp)
            if (higher.attrs is None) == (rule.attrs is None)
        ]

    @staticmethod
    @override
    def scope_depths(scope: str | None) -> tuple[int, int | None]:
        """Return the depth interval below the anchor a region scope covers."""
        scopes = FlextLdifConstantsServersOid.AclScope
        depths: dict[str | None, tuple[int, int | None]] = {
            scopes.DEPTH_TWO: (2, None),
            scopes.BASE: (0, 0),
            scopes.ONELEVEL: (1, 1),
            scopes.SUBORDINATE: (1, None),
        }
        return depths.get(scope, (0, None))

    @override
    @staticmethod
    def add_scope(level: str) -> str:
        """R4a: the OUD scope of add decided on the new entry, by level.

        Returns:
            The resulting ``str``.

        """
        constants = FlextLdifConstantsServersOid
        if level == c.Ldif.AclConvertType.ORCLACI:
            return constants.ACL_ACP_ADD_SCOPE
        return constants.ACL_ENTRYLEVEL_ADD_SCOPE

    @classmethod
    @override
    def level_region(cls, level: str, right: str) -> str | None:
        """Return the OUD region one level decides for one OID right."""
        constants = FlextLdifConstantsServersOid
        if right == constants.ACL_RIGHT_ADD:
            return cls.add_scope(level)
        if level == c.Ldif.AclConvertType.ORCLENTRYLEVELACI:
            return constants.AclScope.BASE
        return None

    @classmethod
    @override
    def intersects(
        cls,
        region: tuple[int, int | None],
        level_scope: str | None,
        depth: int,
    ) -> bool:
        """Return whether a level's region at ``depth`` meets the anchor's region."""
        low, high = region
        level_low, level_high = cls.scope_depths(level_scope)
        start = depth + level_low
        end = None if level_high is None else depth + level_high
        return (high is None or start <= high) and (end is None or end >= low)

    @staticmethod
    @override
    def simplify(bind: p.Ldif.AclBindRule) -> p.Ldif.AclBindRule | None:
        """Drop exclusions that cannot match; None when one covers the subject.

        Returns:
            The resulting ``m.Ldif.AclBindRule | None``.

        """
        to_oud = FlextLdifServersOidAclToOud
        if any(to_oud.covers(leaf, bind.include) for leaf in bind.exclude):
            return None
        kept: list[p.Ldif.AclBindLeaf] = []
        for leaf in bind.exclude:
            if to_oud.disjoint(leaf, bind.include) or any(
                to_oud.covers(other, leaf) for other in kept
            ):
                continue
            kept = [other for other in kept if not to_oud.covers(leaf, other)]
            kept.append(leaf)
        return m.Ldif.AclBindRule(include=bind.include, exclude=tuple(kept))

    @override
    def widen(
        self,
        decision: p.Ldif.AclDecision,
        extra: Sequence[p.Ldif.AclBindLeaf],
    ) -> p.Ldif.AclDecision | None:
        """Add exclusions to a decision; None when nothing is left.

        Returns:
            The resulting ``m.Ldif.AclDecision | None``.

        """
        bind = self.simplify(
            decision.bind.model_copy(
                update={"exclude": (*decision.bind.exclude, *extra)},
            ),
        )
        return None if bind is None else decision.model_copy(update={"bind": bind})

    def dn_of(self, key: str) -> str:
        """Return the DN as read for a key (directory first, then carriers)."""
        return self._directory.entries.get(key) or self._dns.get(key, key)

    def statement(
        self,
        decision: p.Ldif.AclDecision,
        region: p.Ldif.AclRegion,
    ) -> p.Ldif.AciStatement:
        """Assemble one OUD ACI statement for a decision at a placement.

        Returns:
            The resulting ``m.Ldif.AciStatement``.

        """
        constants = FlextLdifConstantsServersOid
        rule, form = decision.rule, decision.form
        scope, target = region.scope, region.target
        if scope == constants.AclScope.DEPTH_TWO:
            scope = None
            target = (
                f"{constants.OUD_TARGET_DEPTH_TWO_PREFIX}{self.dn_of(region.anchor)}"
            )
        return m.Ldif.AciStatement(
            dn=self.dn_of(region.anchor) if region.anchor else self._suffix,
            effect=decision.resolution.effect,
            rights=form.rights,
            attrs=form.attrs,
            targetfilter=form.targetfilter,
            targetscope=scope,
            target=target,
            target_negated=region.target_negated and target == region.target,
            bind=decision.bind,
            rule=form.rule,
            name=(
                f"{rule.level} {rule.index}.{decision.resolution.clause} {form.rule}"
            ),
            origin_dn=rule.dn,
            origin_index=rule.index,
            origin_level=rule.level,
        )

    def nearer_grants(
        self,
        decision: p.Ldif.AclDecision,
        region: p.Ldif.AclRegion,
    ) -> p.Result[list[p.Ldif.AclNearerGrant]]:
        """Return the nearer levels' grants of the right inside the region.

        An entry-level denial decides first, so nothing is nearer to it.

        Returns:
            The conflicting grants, or the failure of a filtered or partial one.

        """
        result = r[list[p.Ldif.AclNearerGrant]]
        found: list[p.Ldif.AclNearerGrant] = []
        if decision.rule.level == c.Ldif.AclConvertType.ORCLENTRYLEVELACI:
            return result.ok(found)
        for key, level in self.nearer_levels(decision, region):
            for nearer in self.rules_at(key, level):
                grant = self.conflicting(decision, nearer)
                if grant.failure:
                    return result.from_failure(grant)
                found.extend(
                    m.Ldif.AclNearerGrant(key=key, level=level, leaf=leaf)
                    for leaf in grant.value
                )
        return result.ok(found)

    def nearer_levels(
        self,
        decision: p.Ldif.AclDecision,
        region: p.Ldif.AclRegion,
    ) -> list[tuple[str, str]]:
        """Return the levels nearer than the denial whose region meets the region."""
        to_oud = FlextLdifServersOidAclToOud
        acp = c.Ldif.AclConvertType.ORCLACI.value
        entry = c.Ldif.AclConvertType.ORCLENTRYLEVELACI.value
        rule, right = decision.rule, decision.resolution.right
        bounds = self.scope_depths(region.scope)
        return [
            (key, level)
            for key in self._keys
            if to_oud.is_ancestor_or_self(region.anchor, key)
            and to_oud.is_ancestor_or_self(rule.key, key)
            for level in (entry, acp)
            if not (key == rule.key and level == acp)
            and self.intersects(
                bounds,
                self.level_region(level, right),
                to_oud.depth_below(region.anchor, key),
            )
        ]

    def conflicting(
        self,
        decision: p.Ldif.AclDecision,
        nearer: p.Ldif.AclLevelRule,
    ) -> p.Result[list[p.Ldif.AclBindLeaf]]:
        """Return the grant leaves of one nearer rule the denial would override.

        Returns:
            The leaves, or the failure for a filtered or partial grant.

        """
        to_oud = FlextLdifServersOidAclToOud
        rule, bind = decision.rule, decision.bind
        result = r[list[p.Ldif.AclBindLeaf]]
        nearer_attrs = self.effective_attrs(nearer)
        if nearer_attrs.failure:
            return result.from_failure(nearer_attrs)
        leaves = [
            leaf
            for leaf in self.grants(nearer, decision.resolution.right)
            if not to_oud.disjoint(leaf, bind.include)
            and not any(to_oud.covers(excluded, leaf) for excluded in bind.exclude)
        ]
        same_kind = (nearer.attrs is None) == (rule.attrs is None)
        if (
            not leaves
            or not same_kind
            or not self.overlaps(nearer_attrs.value, decision.form.attrs)
        ):
            return result.ok([])
        if not self.contains(nearer_attrs.value, decision.form.attrs):
            return result.fail(
                f"R5: {nearer.dn} grants {decision.resolution.right} on part of "
                f"the attributes {rule.dn} denies; the attribute split has no rule",
            )
        if nearer.target_filter is not None:
            return result.fail(
                f"R5: filtered grant of {decision.resolution.right} at "
                f"{nearer.dn} inside the denial of {rule.dn}; no rule covers it",
            )
        return result.ok(leaves)

    def safe_globally(
        self,
        decision: p.Ldif.AclDecision,
        leaf: p.Ldif.AclBindLeaf,
    ) -> bool:
        """Return whether excluding the leaf from the whole denial region is exact.

        Outside the nearer regions the excluded sessions fall through to
        farther levels; that is exact only when no farther ACP grants the
        right to a subject that may share a session with the leaf. A browse
        denial is never excluded globally: it removes read and compare, which
        attribute grants of any level give back (OID-30 Table 30-2).
        """
        to_oud = FlextLdifServersOidAclToOud
        if decision.resolution.right == FlextLdifConstantsServersOid.ACL_RIGHT_BROWSE:
            return False
        for farther in self.farther_rules(decision.rule):
            farther_attrs = self.effective_attrs(farther)
            if farther_attrs.failure:
                return False
            if not self.overlaps(farther_attrs.value, decision.form.attrs):
                continue
            for granted in self.grants(farther, decision.resolution.right):
                if any(to_oud.covers(item, granted) for item in decision.bind.exclude):
                    continue
                if not to_oud.disjoint(granted, leaf):
                    return False
        return True

    def place(
        self,
        decision: p.Ldif.AclDecision,
        region: p.Ldif.AclRegion,
    ) -> p.Result[list[p.Ldif.AciStatement]]:
        """R5 region: place a denial so that nearer grants still decide.

        Returns:
            The placed statements, or the region failure naming the levels.

        """
        result = r[list[p.Ldif.AciStatement]]
        conflicts = self.nearer_grants(decision, region)
        if conflicts.failure:
            return result.from_failure(conflicts)
        if not conflicts.value:
            return result.ok([self.statement(decision, region)])
        widened = self.widen(
            decision,
            [
                grant.leaf
                for grant in conflicts.value
                if self.safe_globally(decision, grant.leaf)
            ],
        )
        if widened is None:
            return result.ok([])
        remaining = self.nearer_grants(widened, region)
        if remaining.failure:
            return result.from_failure(remaining)
        if not remaining.value:
            return result.ok([self.statement(widened, region)])
        return self.split_region(widened, region, remaining.value)

    def split_region(
        self,
        decision: p.Ldif.AclDecision,
        region: p.Ldif.AclRegion,
        conflicts: list[p.Ldif.AclNearerGrant],
    ) -> p.Result[list[p.Ldif.AciStatement]]:
        """R5 region split with the measured OUD forms.

        Returns:
            The split statements, or the failure naming the levels.

        """
        to_oud = FlextLdifServersOidAclToOud
        constants = FlextLdifConstantsServersOid
        acp = c.Ldif.AclConvertType.ORCLACI.value
        keys = sorted({grant.key for grant in conflicts})
        if region.anchor in keys:
            at_anchor = [grant for grant in conflicts if grant.key == region.anchor]
            return self.split_at_anchor(decision, region, at_anchor)
        subtrees = [
            key
            for key in keys
            if any(grant.key == key and grant.level == acp for grant in conflicts)
        ]
        maximal = [
            key
            for key in subtrees
            if not any(
                other != key and to_oud.is_ancestor_or_self(other, key)
                for other in subtrees
            )
        ]
        points = [
            key
            for key in keys
            if key not in subtrees
            and not any(to_oud.is_ancestor_or_self(node, key) for node in maximal)
        ]
        is_add = decision.resolution.right == constants.ACL_RIGHT_ADD
        targeted = bool(region.target) or region.scope == constants.AclScope.DEPTH_TWO
        if len(maximal) > 1 and not targeted and not is_add:
            return self.split_by_child(decision, region, keys)
        if len(maximal) > 1 or (maximal and targeted) or (points and is_add):
            return r[list[p.Ldif.AciStatement]].fail(
                f"R5: denial of {decision.resolution.right} at {decision.rule.dn} "
                f"(clause {decision.resolution.clause}) overlaps grants of nearer "
                f"levels at {[self.dn_of(key) for key in keys]}; the region "
                "exclusion has no single measured OUD form (E11)",
            )
        outside = self.without_entries(decision, points)
        statements: list[p.Ldif.AciStatement] = []
        for key in points:
            near = self.widen(
                decision,
                [grant.leaf for grant in conflicts if grant.key == key],
            )
            if near is not None:
                statements.append(
                    self.statement(
                        near,
                        m.Ldif.AclRegion(anchor=key, scope=constants.AclScope.BASE),
                    ),
                )
        if not maximal:
            return r[list[p.Ldif.AciStatement]].ok([
                self.statement(outside, region),
                *statements,
            ])
        at_node = [grant for grant in conflicts if grant.key == maximal[0]]
        below = self.split_below(outside, region, at_node)
        if below.failure:
            return below
        return r[list[p.Ldif.AciStatement]].ok([*below.value, *statements])

    def split_by_child(
        self,
        decision: p.Ldif.AclDecision,
        region: p.Ldif.AclRegion,
        keys: Sequence[str],
    ) -> p.Result[list[p.Ldif.AciStatement]]:
        """E11 (operator decision "Split by child"): one denial per current child.

        Two or more sibling ACP subtrees have no single OUD exclusion form.
        The denial lands on the anchor itself (``base``) and on each current
        child of the anchor read from the injected directory; a child on a
        path to a nearer level is placed again, so the split descends only
        along those paths. Identical to OID for the directory as converted;
        an entry created later directly under the anchor gets no denial. The
        split statements carry rule E11 in their name, so the anchors whose
        new children go uncovered stay visible.

        Returns:
            The per-child statements, or the failure.

        """
        constants = FlextLdifConstantsServersOid
        to_oud = FlextLdifServersOidAclToOud
        result = r[list[p.Ldif.AciStatement]]
        anchor = region.anchor
        split = decision.model_copy(
            update={
                "form": decision.form.model_copy(
                    update={"rule": constants.AclRule.E11},
                ),
            },
        )
        children = sorted(
            key
            for key in self._directory.entries
            if key != anchor
            and to_oud.is_ancestor_or_self(anchor, key)
            and to_oud.depth_below(anchor, key) == 1
        )
        statements: list[p.Ldif.AciStatement] = []
        if region.scope is None:
            statements.append(
                self.statement(
                    split,
                    region.model_copy(update={"scope": constants.AclScope.BASE}),
                ),
            )
        placed: list[str] = []
        for child in children:
            on_path = any(to_oud.is_ancestor_or_self(child, key) for key in keys)
            child_region = m.Ldif.AclRegion(anchor=child)
            if not on_path:
                statements.append(self.statement(split, child_region))
                placed.append(child)
                continue
            grants = self.acp_grants_at(decision, child)
            if grants.failure:
                return result.from_failure(grants)
            pushed = self.widen(decision, grants.value)
            if pushed is None:
                continue
            inner = self.place(pushed, child_region)
            if inner.failure:
                return inner
            statements.extend(inner.value)
        self.events.append(
            m.Ldif.AclConversionEvent(
                rule=constants.AclRule.E11,
                dn=decision.rule.dn,
                detail=(
                    f"denial of {decision.resolution.right} split over "
                    f"{len(placed)} current child(ren) beside "
                    f"{[self.dn_of(key) for key in keys]}; a child created later "
                    "gets no denial"
                ),
            ),
        )
        return result.ok(statements)

    def acp_grants_at(
        self,
        decision: p.Ldif.AclDecision,
        key: str,
    ) -> p.Result[list[p.Ldif.AclBindLeaf]]:
        """Return the subjects the ACP at ``key`` grants the decision's right to."""
        leaves: list[p.Ldif.AclBindLeaf] = []
        for nearer in self.rules_at(key, c.Ldif.AclConvertType.ORCLACI.value):
            granted = self.conflicting(decision, nearer)
            if granted.failure:
                return r[list[p.Ldif.AclBindLeaf]].from_failure(granted)
            leaves.extend(granted.value)
        return r[list[p.Ldif.AclBindLeaf]].ok(leaves)

    def without_entries(
        self,
        decision: p.Ldif.AclDecision,
        keys: Sequence[str],
    ) -> p.Ldif.AclDecision:
        """Leave single entries out of a denial with an ``entryDN`` filter.

        Measured on OUD 14.1.2.1 (phase D): ``(!(entryDN=<dn>))`` in
        targetfilter excludes exactly that entry.

        Returns:
            The resulting ``m.Ldif.AclDecision``.

        """
        if not keys:
            return decision
        attr = FlextLdifConstantsServersOid.OUD_ENTRYDN_ATTR
        terms = "".join(f"({attr}={self.dn_of(key)})" for key in keys)
        excluded = f"(!{terms})" if len(keys) == 1 else f"(!(|{terms}))"
        current = decision.form.targetfilter
        combined = excluded if current is None else f"(&{current}{excluded})"
        return decision.model_copy(
            update={
                "form": decision.form.model_copy(update={"targetfilter": combined}),
            },
        )

    def split_at_anchor(
        self,
        decision: p.Ldif.AclDecision,
        region: p.Ldif.AclRegion,
        at_node: list[p.Ldif.AclNearerGrant],
    ) -> p.Result[list[p.Ldif.AciStatement]]:
        """The anchor's own entry-level ACI decides first (base or onelevel).

        Returns:
            The inner placement plus the narrowed near statement.

        """
        constants = FlextLdifConstantsServersOid
        result = r[list[p.Ldif.AciStatement]]
        is_add = decision.resolution.right == constants.ACL_RIGHT_ADD
        expected = constants.AclScope.SUBORDINATE if is_add else None
        if region.scope != expected:
            return result.fail(
                f"R5: denial of {decision.resolution.right} at {decision.rule.dn} "
                f"meets the entry-level ACI of {self.dn_of(region.anchor)} in "
                f"scope {region.scope}; no rule covers it",
            )
        inner_scope, near_scope = (
            (constants.AclScope.DEPTH_TWO, constants.AclScope.ONELEVEL)
            if is_add
            else (constants.AclScope.SUBORDINATE, constants.AclScope.BASE)
        )
        inner = self.place(decision, region.model_copy(update={"scope": inner_scope}))
        if inner.failure:
            return inner
        entry = c.Ldif.AclConvertType.ORCLENTRYLEVELACI.value
        near = self.widen(
            decision,
            [grant.leaf for grant in at_node if grant.level == entry],
        )
        if near is None:
            return inner
        return result.ok([
            *inner.value,
            self.statement(near, region.model_copy(update={"scope": near_scope})),
        ])

    def split_below(
        self,
        decision: p.Ldif.AclDecision,
        region: p.Ldif.AclRegion,
        at_node: list[p.Ldif.AclNearerGrant],
    ) -> p.Result[list[p.Ldif.AciStatement]]:
        """A nearer ACP below the anchor: exclude its region, then push down.

        The anchor statement excludes the node with ``target!=`` (its
        subtree, or its descendants for add); the denial is placed again at
        the node without the subjects the node's ACP grants.

        Returns:
            The anchor statement plus the pushed placement.

        """
        constants = FlextLdifConstantsServersOid
        acp = c.Ldif.AclConvertType.ORCLACI.value
        node = at_node[0].key
        is_add = decision.resolution.right == constants.ACL_RIGHT_ADD
        prefix = constants.OUD_TARGET_SUBTREE_EXCLUSION_PREFIX if is_add else ""
        anchor_statement = self.statement(
            decision,
            region.model_copy(
                update={
                    "target": f"{prefix}{self.dn_of(node)}",
                    "target_negated": True,
                },
            ),
        )
        pushed = self.widen(
            decision,
            [grant.leaf for grant in at_node if grant.level == acp],
        )
        if pushed is None:
            return r[list[p.Ldif.AciStatement]].ok([anchor_statement])
        inner = self.place(
            pushed,
            m.Ldif.AclRegion(
                anchor=node,
                scope=constants.AclScope.SUBORDINATE if is_add else None,
            ),
        )
        if inner.failure:
            return inner
        return r[list[p.Ldif.AciStatement]].ok([anchor_statement, *inner.value])


__all__: list[str] = ["FlextLdifServersOidAclRegion"]
