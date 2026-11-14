"""OUD ACI emission and rendering of the conversion rules R1-R9.

Consumes the indexed OID policy (:class:`FlextLdifServersOidAclRegion`) and
emits OUD ACI statements per ``docs/specs/oid-oud-acl-conversion.md`` §4:

- R1/R2/R3: attribute grants keep the origin scope (``orclaci`` subtree,
  ``orclentrylevelaci`` base) and the filter as ``targetfilter``; read and
  compare are granted only where OID decides browse for the subject.
- R4: entry rights are separate ACIs: add ``subordinate``/``onelevel``
  (``dnattr`` reads the parent of the new entry, ``parent[1]``), delete
  with the origin scope, browse as ``objectClass`` read and search
  (operator decision "Emulate minimum"), the added-object constraint as the
  add ``targetfilter``. A proxy grant fails: its OID target is unmeasured.
- R5: every denial below the root DSE becomes a ``deny`` that excludes the
  subjects its ACI grants (R6a) and the privilege groups a farther ACP
  grants by group subject, placed by region (``acl_region.py``).
- R6b: a named attribute leaves the ACP's ``*`` ACI; a filtered ACI decides
  before the unfiltered one where its filter matches.
- R8: a grant to OID ``*`` goes to ``ldap:///all`` and a denial to
  ``ldap:///anyone`` (operator decision "Grant all, deny anyone").
- R9: root DSE ``orclaci`` grants land on the suffix root; its denials emit
  nothing.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, m, p, r, t
from flext_ldif.servers._oid import (
    FlextLdifConstantsServersOid,
    FlextLdifServersOidAclRegion,
    FlextLdifServersOidAclToOud,
)


class FlextLdifServersOidAclRender(FlextLdifServersOidAclRegion):
    """Emit and render the OUD ACI statements of an indexed OID policy."""

    def _event(self, rule: str, dn: str, detail: str) -> None:
        """Record one operator-review event."""
        self.events.append(m.Ldif.AclConversionEvent(rule=rule, dn=dn, detail=detail))

    def is_privilege(self, leaf: p.Ldif.AclBindLeaf) -> bool:
        """Return whether a group leaf is a source privilege group (Q5)."""
        constants = FlextLdifConstantsServersOid
        if leaf.kind != constants.AclLeafKind.GROUP:
            return False
        group = self._directory.groups.get(leaf.key)
        return group is not None and bool(
            group.classes & constants.OID_PRIVILEGE_GROUP_CLASSES,
        )

    def privilege_override(
        self,
        decision: p.Ldif.AclDecision,
    ) -> p.Result[list[p.Ldif.AclBindLeaf]]:
        """R5: the privilege groups a farther ACP grants the right by group subject.

        A denial at a lower ACP stays unresolved for a privilege group member
        when a higher ACP grants the right by a group subject (OID-30
        §30.1.6.5, §30.1.3.4.2). No override happens when the denying level's
        ACP carries ``DenyGroupOverride`` (Q4). A higher grant covering only
        part of the denied attributes or carrying a filter has no exact form.

        Returns:
            Group leaves to exclude from the denial, or the failure.

        """
        rule = decision.rule
        result = r[list[p.Ldif.AclBindLeaf]]
        own_acp = self.rules_at(rule.key, c.Ldif.AclConvertType.ORCLACI.value)
        if any(item.rule.deny_group_override for item in (*own_acp, rule)):
            return result.ok([])
        excluded: list[p.Ldif.AclBindLeaf] = []
        for higher in self.farther_rules(rule):
            leaves = [
                leaf
                for leaf in self.grants(higher, decision.resolution.right)
                if self.is_privilege(leaf)
            ]
            higher_attrs = self.effective_attrs(higher)
            if not leaves or higher_attrs.failure:
                continue
            attrs = decision.form.attrs
            covered = rule.attrs is None or self.contains(higher_attrs.value, attrs)
            if covered and higher.target_filter is None:
                excluded.extend(leaves)
            elif covered or self.overlaps(higher_attrs.value, attrs):
                return result.fail(
                    f"R5: privilege group(s) granted {decision.resolution.right} at "
                    f"{higher.dn or '<root DSE>'} cover only part of the denial at "
                    f"{rule.dn} (filter or attributes)",
                )
        return result.ok(excluded)

    def browse_resolved(
        self,
        rule: p.Ldif.AclLevelRule,
        leaf: p.Ldif.AclBindLeaf,
    ) -> tuple[bool, list[t.Ldif.AclBrowsePlacement]]:
        """R1: whether the subject has browse decided, and where a session browses.

        OID returns attribute values only with browse on the entry (OID-30
        Table 30-2, Table 30-3), and it decides browse and the attribute right
        per session, from all of its groups. A level whose entry ACI names
        browse for a subject covering this one decides browse for all of its
        sessions; denials are R5's. A grant of browse holds only for its own
        subject and on the entries its ACI filter matches. Every browse grant
        meeting the grant's region counts: on the rule's own level and the
        farther ACPs (placed at the rule's anchor; the anchor's entry level on
        the anchor alone) and, for an ACP rule, on the nearer levels below it
        (placed at that entry, or its subtree for an ACP). A grant to a subject
        covering this one needs nothing more, to a narrower one that subject,
        and to any other subject a session holding both, unless no session can
        (measured on OUD 14.1.2.1).

        Returns:
            Whether some level decides browse for the subject, and the
            placements: subject, required subject, filter, anchor, scope.

        """
        constants = FlextLdifConstantsServersOid
        to_oud = FlextLdifServersOidAclToOud
        acp = c.Ldif.AclConvertType.ORCLACI.value
        entry = c.Ldif.AclConvertType.ORCLENTRYLEVELACI.value
        base = constants.AclScope.BASE.value
        own_scope = base if rule.level == entry else None
        chain = [(key, acp) for key in self.farther_acp_keys(rule)]
        sources: list[tuple[tuple[str, str], bool, str, str | None]] = [
            (place, True, rule.key, own_scope)
            for place in ((rule.key, rule.level), *chain)
        ]
        if rule.level == acp:
            sources.append(((rule.key, entry), False, rule.key, base))
            sources.extend(
                ((key, level), False, key, base if level == entry else None)
                for key in self._keys
                if key != rule.key and to_oud.is_ancestor_or_self(rule.key, key)
                for level in (entry, acp)
            )
        decided = False
        placements: list[t.Ldif.AclBrowsePlacement] = []
        for (key, level), deciding, anchor, scope in sources:
            for item in self.rules_at(key, level):
                if item.attrs is not None:
                    continue
                for clause in item.clauses:
                    permissions = {
                        token.casefold() for token in clause.subject.permissions
                    }
                    if clause.leaf is None or not (
                        {"browse", "nobrowse"} & permissions
                    ):
                        continue
                    granted = bool({"read", "search"} & clause.allow)
                    wider = to_oud.covers(clause.leaf, leaf)
                    decided = decided or (wider and deciding)
                    if not granted or to_oud.disjoint(
                        clause.leaf,
                        leaf,
                    ):
                        continue
                    subject, also = (
                        (leaf, None)
                        if wider
                        else (clause.leaf, None)
                        if to_oud.covers(leaf, clause.leaf)
                        else (leaf, clause.leaf)
                    )
                    placements.append((
                        subject,
                        also,
                        item.target_filter,
                        anchor,
                        scope,
                    ))
        return decided, placements

    @staticmethod
    def browse_coupled(
        leaf: p.Ldif.AclBindLeaf,
        targetfilter: str | None,
        home: tuple[str, str | None],
        grants: list[t.Ldif.AclBrowsePlacement],
    ) -> list[t.Ldif.AclBrowsePlacement]:
        """R1: the placements of a read or compare grant under its browse.

        Each placement is a subject (the grant's own, or a narrower one that
        browses), the subject a session must also hold (a browse holder
        unrelated to the grant's subject), the grant's filter narrowed to the
        entries browsed, and where it lands. A placement the grant's own
        unfiltered placement already covers is dropped.

        Returns:
            The placements; the grant unchanged at ``home`` when its subject
            browses all of it or browse is granted nowhere (R5 decides that).

        """

        def narrowed(filters: set[str | None]) -> str | None:
            if None in filters:
                return targetfilter
            named = sorted(item for item in filters if item is not None)
            browse = named[0] if len(named) == 1 else f"(|{''.join(named)})"
            return browse if targetfilter is None else f"(&{targetfilter}{browse})"

        anchor, scope = home
        by_place: dict[
            tuple[str, str, str, str],
            tuple[t.Ldif.AclBrowsePlacement, set[str | None]],
        ] = {}
        for subject, also, item_filter, place, place_scope in grants:
            found = by_place.setdefault(
                (
                    subject.key,
                    "" if also is None else also.key,
                    place,
                    place_scope or "",
                ),
                ((subject, also, None, place, place_scope), set()),
            )
            found[1].add(item_filter)
        own_key = (leaf.key, "", anchor, scope or "")
        own_whole = by_place.get(own_key, ((leaf, None, None, anchor, scope), set()))[1]
        if not grants or None in own_whole:
            return [(leaf, None, targetfilter, anchor, scope)]
        placements: list[t.Ldif.AclBrowsePlacement] = []
        for key, ((subject, also, _, place, place_scope), filters) in sorted(
            by_place.items(),
            key=lambda pair: (
                pair[0][2] != anchor,
                pair[0][2],
                pair[0][3] != scope or "",
                pair[0][0] != leaf.key,
                pair[0][0],
                pair[0][1],
            ),
        ):
            reached = filters if key == own_key else filters - own_whole
            if reached:
                placements.append((
                    subject,
                    also,
                    narrowed(reached),
                    place,
                    place_scope,
                ))
        return placements

    def form(
        self,
        rule: p.Ldif.AclLevelRule,
        resolution: p.Ldif.AclResolution,
    ) -> p.Result[list[p.Ldif.AclForm]]:
        """Return the OUD rights, attributes, filter, scope and rule of a decision.

        Returns:
            Zero or one form (E7 emits none), or the failure.

        """
        constants = FlextLdifConstantsServersOid
        result = r[list[p.Ldif.AclForm]]
        entry_level = rule.level == c.Ldif.AclConvertType.ORCLENTRYLEVELACI
        scope = constants.AclScope.BASE.value if entry_level else None
        deny = resolution.effect == constants.AclEffect.DENY
        if rule.attrs is not None:
            attrs = self.effective_attrs(rule)
            if attrs.failure:
                return result.from_failure(attrs)
            identity = constants.AclRule.R2 if entry_level else constants.AclRule.R1
            return result.ok([
                m.Ldif.AclForm.model_validate({
                    "rights": (resolution.right,),
                    "attrs": attrs.value,
                    "targetfilter": rule.target_filter,
                    "targetscope": scope,
                    "rule": constants.AclRule.R5 if deny else identity,
                }),
            ])
        if resolution.right == constants.ACL_RIGHT_ADD:
            return self.add_form(rule, resolution)
        if resolution.right == constants.ACL_RIGHT_PROXY and not deny:
            self._event(
                constants.AclRule.R4C,
                rule.dn,
                f"{rule.level} {rule.index}.{resolution.clause}: proxy kept with "
                "the source scope, evaluated on the impersonated identity's entry "
                "(conversion rules R4, pending runtime measurement); the "
                "bind user still needs the proxied-auth privilege (E2)",
            )
        return result.ok([self.entry_form(rule, resolution, scope)])

    def add_form(
        self,
        rule: p.Ldif.AclLevelRule,
        resolution: p.Ldif.AclResolution,
    ) -> p.Result[list[p.Ldif.AclForm]]:
        """R4a/R4d: add is decided on the new entry (OUD-9 §9.2.3.3).

        An OID filter matches the parent while the OUD add ``targetfilter``
        matches the new entry (E7): a filtered add grant emits nothing and a
        filtered add denial fails, since dropping it would grant in OUD what
        OID denies.

        Returns:
            The add form, none under E7, or the E7 denial failure.

        """
        constants = FlextLdifConstantsServersOid
        result = r[list[p.Ldif.AclForm]]
        deny = resolution.effect == constants.AclEffect.DENY
        if rule.target_filter is not None:
            if deny:
                return result.fail(
                    f"{rule.dn}: E7: noadd under filter {rule.target_filter} "
                    "matches the parent in OID and the new entry in OUD; the "
                    "denial has no OUD form",
                )
            self._event(
                constants.AclRule.E7,
                rule.dn,
                f"{rule.level} {rule.index}.{resolution.clause}: add grant under "
                f"filter {rule.target_filter} emits nothing (stricter)",
            )
            return result.ok([])
        constraint = (
            None
            if deny or not resolution.added_object_constraint
            else FlextLdifServersOidAclToOud.validate_ldap_filter(
                resolution.added_object_constraint,
            ).value
        )
        return result.ok([
            m.Ldif.AclForm.model_validate({
                "rights": (constants.ACL_RIGHT_ADD,),
                "attrs": self.every_attribute(),
                "targetfilter": constraint,
                "targetscope": self.add_scope(rule.level),
                "rule": constants.AclRule.R5
                if deny
                else constants.AclRule.R4D
                if constraint
                else constants.AclRule.R4A,
            }),
        ])

    def entry_form(
        self,
        rule: p.Ldif.AclLevelRule,
        resolution: p.Ldif.AclResolution,
        scope: str | None,
    ) -> p.Ldif.AclForm:
        """R4b/R4c/R4e and the R5 browse and proxy denials for one entry right.

        Returns:
            The resulting ``m.Ldif.AclForm``.

        """
        constants = FlextLdifConstantsServersOid
        right = resolution.right
        deny = resolution.effect == constants.AclEffect.DENY
        rights: tuple[str, ...] = (right,)
        attrs = self.every_attribute()
        identity = (
            constants.AclRule.R4C
            if right == constants.ACL_RIGHT_PROXY
            else constants.AclRule.R4B
        )
        browse_rights = {
            constants.ACL_RIGHT_BROWSE,
            constants.ACL_RIGHT_READ,
            constants.ACL_RIGHT_SEARCH,
        }
        if right in browse_rights:
            rights = (
                constants.ACL_BROWSE_DENIAL_RIGHTS
                if deny
                else constants.ACL_BROWSE_GRANT_RIGHTS
            )
            if not deny:
                attrs = m.Ldif.AclAttrSet(
                    names=frozenset({constants.ACL_BROWSE_GRANT_ATTRIBUTE}),
                )
            identity = constants.AclRule.R4E
        return m.Ldif.AclForm.model_validate({
            "rights": rights,
            "attrs": attrs,
            "targetfilter": rule.target_filter,
            "targetscope": scope,
            "rule": constants.AclRule.R5 if deny else identity,
        })

    @staticmethod
    def granted_leaf(leaf: p.Ldif.AclBindLeaf) -> p.Ldif.AclBindLeaf:
        """R8 (operator decision "Grant all, deny anyone"): ``*`` grants go to all.

        Returns:
            The resulting ``m.Ldif.AclBindLeaf``.

        """
        constants = FlextLdifConstantsServersOid
        if leaf.kind != constants.AclLeafKind.ANYONE:
            return leaf
        return m.Ldif.AclBindLeaf(
            kind=constants.AclLeafKind.ALL,
            value=constants.OUD_BIND_ALL,
            key=constants.OUD_BIND_ALL,
        )

    def allow_statements(
        self,
        rule: p.Ldif.AclLevelRule,
        resolution: p.Ldif.AclResolution,
    ) -> p.Result[list[p.Ldif.AciStatement]]:
        """R1-R4 and R9 for one grant; a grant wins in its ACI (R6a).

        Returns:
            The grant's statements, or the failure.

        """
        constants = FlextLdifConstantsServersOid
        forms = self.form(rule, resolution)
        if forms.failure:
            return r[list[p.Ldif.AciStatement]].from_failure(forms)
        no_grants: list[t.Ldif.AclBrowsePlacement] = []
        browse, grants = (
            (True, no_grants)
            if rule.attrs is None
            else self.browse_resolved(rule, resolution.leaf)
        )
        statements: list[p.Ldif.AciStatement] = []
        for form in forms.value:
            rights = tuple(
                item
                for item in form.rights
                if browse or item not in constants.ACL_BROWSE_DENIAL_RIGHTS
            )
            if rights != form.rights:
                self._event(
                    constants.AclRule.R1,
                    rule.dn,
                    f"{rule.level} {rule.index}.{resolution.clause}: "
                    f"{resolution.right} needs browse, which no level decides "
                    "for the subject; nothing granted",
                )
            if not rights:
                continue
            home = (rule.key, form.targetscope)
            placements: list[t.Ldif.AclBrowsePlacement] = (
                self.browse_coupled(
                    resolution.leaf,
                    form.targetfilter,
                    home,
                    grants,
                )
                if set(rights) & set(constants.ACL_BROWSE_DENIAL_RIGHTS)
                else [(resolution.leaf, None, form.targetfilter, *home)]
            )
            for subject, also, targetfilter, anchor, scope in placements:
                kept = form.model_copy(
                    update={
                        "rights": rights,
                        "targetfilter": targetfilter,
                        "targetscope": scope,
                        "rule": form.rule if rule.key else constants.AclRule.R9,
                    },
                )
                statements.append(
                    self.statement(
                        m.Ldif.AclDecision.model_validate({
                            "rule": rule,
                            "resolution": resolution,
                            "form": kept,
                            "bind": m.Ldif.AclBindRule.model_validate({
                                "include": self.granted_leaf(subject),
                                "require": () if also is None else (also,),
                            }),
                        }),
                        m.Ldif.AclRegion(anchor=anchor, scope=scope),
                    ),
                )
        return r[list[p.Ldif.AciStatement]].ok(statements)

    def deny_statements(
        self,
        rule: p.Ldif.AclLevelRule,
        resolution: p.Ldif.AclResolution,
    ) -> p.Result[list[p.Ldif.AciStatement]]:
        """R5 for one denial, with R6b filter precedence and region placement.

        A root DSE denial emits nothing (R9): above it only the OUD default
        denial exists.

        Returns:
            The denial's statements, or the failure.

        """
        constants = FlextLdifConstantsServersOid
        result = r[list[p.Ldif.AciStatement]]
        if not rule.key:
            self._event(
                constants.AclRule.R9,
                rule.dn,
                f"root DSE denial {rule.index}.{resolution.clause} of "
                f"{resolution.right} emits nothing",
            )
            return result.ok([])
        forms = self.form(rule, resolution)
        if forms.failure:
            return result.from_failure(forms)
        statements: list[p.Ldif.AciStatement] = []
        for form in forms.value:
            decision = m.Ldif.AclDecision.model_validate({
                "rule": rule,
                "resolution": resolution,
                "form": form,
                "bind": m.Ldif.AclBindRule.model_validate({
                    "include": resolution.leaf,
                    "exclude": resolution.grantors,
                }),
            })
            override = self.privilege_override(decision)
            if override.failure:
                return result.from_failure(override)
            widened = self.widen(decision, override.value)
            for split in [] if widened is None else self.filter_precedence(widened):
                placed = self.place(
                    split,
                    m.Ldif.AclRegion(anchor=rule.key, scope=form.targetscope),
                )
                if placed.failure:
                    return placed
                statements.extend(placed.value)
        return result.ok(statements)

    def filter_precedence(
        self,
        decision: p.Ldif.AclDecision,
    ) -> list[p.Ldif.AclDecision]:
        """R6b: a filtered ACI of the level decides before the unfiltered one.

        Where a filter matches, the unfiltered denial excludes the subjects
        the filtered ACI grants; elsewhere it stays whole (OID-30
        §30.1.6.2.1-2). More than one overlapping filter is reported as E6.

        Returns:
            The denial split by filter, or the denial itself.

        """
        rule = decision.rule
        if rule.target_filter is not None:
            return [decision]
        grants: dict[str, list[p.Ldif.AclBindLeaf]] = {}
        for other in self.rules_at(rule.key, rule.level):
            other_attrs = self.effective_attrs(other)
            if (
                other.target_filter is None
                or (other.attrs is None) != (rule.attrs is None)
                or other_attrs.failure
                or not self.overlaps(other_attrs.value, decision.form.attrs)
            ):
                continue
            leaves = self.grants(other, decision.resolution.right)
            if leaves:
                grants.setdefault(other.target_filter, []).extend(leaves)
        if not grants:
            return [decision]
        if len(grants) > 1:
            self._event(
                FlextLdifConstantsServersOid.AclRule.E6,
                rule.dn,
                f"overlapping filters {sorted(grants)} decide in OID in a "
                "non-deterministic order",
            )
        negations = [f"(!{item})" for item in sorted(grants)]
        outside_filter = (
            negations[0] if len(negations) == 1 else f"(&{''.join(negations)})"
        )
        outside = decision.model_copy(
            update={
                "form": decision.form.model_copy(
                    update={"targetfilter": outside_filter},
                ),
            },
        )
        inside = [
            narrowed.model_copy(
                update={
                    "form": narrowed.form.model_copy(update={"targetfilter": item}),
                },
            )
            for item, leaves in sorted(grants.items())
            if (narrowed := self.widen(decision, leaves)) is not None
        ]
        return [outside, *inside]

    @staticmethod
    def _add_leaf(leaf: p.Ldif.AclBindLeaf) -> p.Result[p.Ldif.AclBindLeaf]:
        """R4a: rebind an add subject to the parent of the new entry.

        OID add on X authorizes children of X while OUD evaluates add on the
        new entry (OUD-9 §9.2.3.3). ``dnattr`` reads X's attribute, which is
        ``userattr="parent[1].<a>#USERDN"`` (OUD-9 §9.4.4.7, §9.4.4.9).
        ``self`` (the bind DN equals X) has no OUD parent form.

        Returns:
            The parent-bound leaf, or the failure for ``self``.

        """
        constants = FlextLdifConstantsServersOid
        kinds = constants.AclLeafKind
        if leaf.kind == kinds.SELF:
            return r[p.Ldif.AclBindLeaf].fail(
                "R4a: OID 'self' on add names the parent entry, while OUD "
                "ldap:///self names the entry being added; no OUD form",
            )
        if leaf.kind != kinds.USERATTR:
            return r[p.Ldif.AclBindLeaf].ok(leaf)
        value = f"{constants.OUD_USERATTR_PARENT}{leaf.value}"
        return r[p.Ldif.AclBindLeaf].ok(
            leaf.model_copy(update={"value": value, "key": value.lower()}),
        )

    @classmethod
    def finalize(cls, statement: p.Ldif.AciStatement) -> p.Result[p.Ldif.AciStatement]:
        """Bind every subject of an add statement to the parent entry (R4a).

        Returns:
            The statement ready to render, or the add-subject failure.

        """
        if FlextLdifConstantsServersOid.ACL_RIGHT_ADD not in statement.rights:
            return r[p.Ldif.AciStatement].ok(statement)
        bind = statement.bind
        leaves = r.traverse((bind.include, *bind.exclude), cls._add_leaf)
        if leaves.failure:
            return r[p.Ldif.AciStatement].fail(
                f"{statement.origin_dn}: {leaves.error}",
            )
        include, *exclude = leaves.value
        return r[p.Ldif.AciStatement].ok(
            statement.model_copy(
                update={
                    "bind": m.Ldif.AclBindRule.model_validate({
                        "include": include,
                        "exclude": tuple(exclude),
                    }),
                },
            ),
        )

    def emit(self) -> p.Result[list[p.Ldif.AciStatement]]:
        """Emit every statement of the policy in level order.

        Returns:
            All statements, or the first failure.

        """
        constants = FlextLdifConstantsServersOid
        entry = c.Ldif.AclConvertType.ORCLENTRYLEVELACI.value
        acp = c.Ldif.AclConvertType.ORCLACI.value
        statements: list[p.Ldif.AciStatement] = []
        for rule in self.rules_at("", entry):
            self._event(
                constants.AclRule.R9,
                rule.dn,
                f"root DSE orclentrylevelaci {rule.index} governs the root DSE "
                "only; OUD global ACIs own it (not relocated)",
            )
        for key in self._keys:
            for level in (entry, acp):
                if not key and level == entry:
                    continue
                for rule in self.rules_at(key, level):
                    for resolution in self.resolutions(rule):
                        produced = (
                            self.deny_statements(rule, resolution)
                            if resolution.effect == constants.AclEffect.DENY
                            else self.allow_statements(rule, resolution)
                        )
                        if produced.failure:
                            return produced
                        finalized = r.traverse(produced.value, self.finalize)
                        if finalized.failure:
                            return r[list[p.Ldif.AciStatement]].from_failure(finalized)
                        statements.extend(finalized.value)
        return r[list[p.Ldif.AciStatement]].ok(statements)

    @staticmethod
    def render_leaf(leaf: p.Ldif.AclBindLeaf) -> str:
        """Render one bind-rule subject (R8 table).

        Returns:
            The resulting ``str``.

        """
        constants = FlextLdifConstantsServersOid
        kinds = constants.AclLeafKind
        prefix = c.Ldif.LDAP_PREFIX
        userdn = c.Ldif.OudSubjectType.USERDN.value
        match leaf.kind:
            case kinds.GROUP:
                return f'{c.Ldif.OudSubjectType.GROUPDN.value}="{prefix}{leaf.value}"'
            case kinds.USERATTR:
                keyword = c.Ldif.OudSubjectType.USERATTR.value
                return f'{keyword}="{leaf.value}{c.Ldif.UserAttrSuffix.USERDN.value}"'
            case kinds.GROUPATTR:
                keyword = c.Ldif.OudSubjectType.USERATTR.value
                return f'{keyword}="{leaf.value}{c.Ldif.UserAttrSuffix.GROUPDN.value}"'
            case kinds.USER_SUBTREE:
                url = f"{prefix}{leaf.value}{constants.OUD_USERDN_SUBTREE_URL_SUFFIX}"
                return f'({userdn}="{url}" and {userdn}!="{prefix}{leaf.value}")'
            case _:
                return f'{userdn}="{prefix}{leaf.value}"'

    @classmethod
    def render_bind(cls, bind: p.Ldif.AclBindRule) -> str:
        """Render a subject with its R1 requirements and R5 exclusions.

        ``(S and R1 and not (E1 or E2))``: the session matches the subject,
        every required subject, and none of the exclusions.

        Returns:
            The OUD bind rule.

        """
        matched = " and ".join(
            cls.render_leaf(leaf) for leaf in (bind.include, *bind.require)
        )
        if not bind.exclude:
            return f"({matched})" if bind.require else matched
        excluded = " or ".join(cls.render_leaf(leaf) for leaf in bind.exclude)
        if len(bind.exclude) > 1:
            excluded = f"({excluded})"
        return f"({matched} and not {excluded})"

    @staticmethod
    def target_parts(statement: p.Ldif.AciStatement) -> list[str]:
        """Render the target keywords in OUD order (target, attr, filter, scope).

        Returns:
            The resulting ``list[str]``.

        """
        parts: list[str] = []
        if statement.target:
            operator = c.Ldif.OUD_ATTR_NEGATION if statement.target_negated else "="
            parts.append(
                f'(target{operator}"{c.Ldif.LDAP_PREFIX}{statement.target}")',
            )
        names = c.Ldif.OUD_ATTR_OR.join(sorted(statement.attrs.names))
        if statement.attrs.negated and names:
            parts.append(f'(targetattr{c.Ldif.OUD_ATTR_NEGATION}"{names}")')
        else:
            everything = FlextLdifConstantsServersOid.OUD_TARGETATTR_ALL
            parts.append(f'(targetattr="{names or everything}")')
        if statement.targetfilter:
            parts.append(f'(targetfilter="{statement.targetfilter}")')
        if statement.targetscope is not None:
            parts.append(f'(targetscope="{statement.targetscope}")')
        return parts

    @classmethod
    def render_statement(cls, statement: p.Ldif.AciStatement) -> str:
        """Render one statement as a single-line OUD ``aci`` value (no prefix).

        Returns:
            The resulting ``str``.

        """
        rights = ",".join(statement.rights)
        clause = f"{statement.effect} ({rights}) {cls.render_bind(statement.bind)};)"
        head = f'({c.Ldif.ACI_VERSION}; acl "{statement.name}";'
        return f"{''.join(cls.target_parts(statement))}{head} {clause}"


__all__: list[str] = ["FlextLdifServersOidAclRender"]
