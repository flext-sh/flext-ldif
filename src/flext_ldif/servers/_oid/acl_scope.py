"""OID ACL attribute-set and scope algebra shared by region placement.

Stateless operations over OUD ``targetattr`` sets, ``targetscope`` depths
and bind rules; :class:`FlextLdifServersOidAclRegion` composes them.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence

from flext_ldif import c, m, p
from flext_ldif.servers._oid import (
    FlextLdifConstantsServersOid,
    FlextLdifServersOidAclToOud,
)


class FlextLdifServersOidAclScope:
    """Attribute-set, scope and bind-rule algebra of the OUD ACI region."""

    @staticmethod
    def every_attribute() -> p.Ldif.AclAttrSet:
        """Return ``targetattr="*"`` as the negated empty set."""
        return m.Ldif.AclAttrSet(names=frozenset(), negated=True)

    @staticmethod
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
    def overlaps(cls, left: p.Ldif.AclAttrSet, right: p.Ldif.AclAttrSet) -> bool:
        """Return whether two attribute sets share an attribute."""
        both = cls.intersect(left, right)
        return both.negated or bool(both.names)

    @classmethod
    def contains(cls, outer: p.Ldif.AclAttrSet, inner: p.Ldif.AclAttrSet) -> bool:
        """Return whether ``outer`` holds every attribute of ``inner``."""
        return cls.intersect(outer, inner) == inner

    @staticmethod
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
    def level_region(cls, level: str, right: str) -> str | None:
        """Return the OUD region one level decides for one OID right."""
        constants = FlextLdifConstantsServersOid
        if right == constants.ACL_RIGHT_ADD:
            return cls.add_scope(level)
        if level == c.Ldif.AclConvertType.ORCLENTRYLEVELACI:
            return constants.AclScope.BASE
        return None

    @classmethod
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
        return m.Ldif.AclBindRule.model_validate({
            "include": bind.include,
            "exclude": tuple(kept),
        })

    @classmethod
    def widen(
        cls,
        decision: p.Ldif.AclDecision,
        extra: Sequence[p.Ldif.AclBindLeaf],
    ) -> p.Ldif.AclDecision | None:
        """Add exclusions to a decision; None when nothing is left.

        Returns:
            The resulting ``m.Ldif.AclDecision | None``.

        """
        bind = cls.simplify(
            decision.bind.model_copy(
                update={"exclude": (*decision.bind.exclude, *extra)},
            ),
        )
        return None if bind is None else decision.model_copy(update={"bind": bind})


__all__: list[str] = ["FlextLdifServersOidAclScope"]
