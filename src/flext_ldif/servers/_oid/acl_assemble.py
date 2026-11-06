"""OID→OUD aci building — one parsed OID rule → one OUD AciRule.

``build_aci_rule`` converts subjects and permissions into typed allow and
deny clauses, checks base_dn scope and access groups, and derives the acl
name. Line/entry-level orchestration lives in ``acl_pipeline.py``; rendering
in ``acl_render.py``.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence

from flext_ldif import c, m, p, r
from flext_ldif.servers._oid import (
    FlextLdifConstantsServersOid,
    FlextLdifServersOidAclToOud,
)


class FlextLdifServersOidAclAssemble:
    """Build OUD aci value objects from parsed OID rules and orchestrate entries."""

    class _RuleAssembler:
        """Assemble one parsed OID rule into one OUD :class:`m.Ldif.AciRule`.

        Inside one OID ACI the effective access of a session is the union of
        the grants of every matching by-clause minus the union of their
        denials (OID-30 §30.1.6.2). Every subject keeps its own grant as an
        ``allow`` and its own denial as a ``deny`` with the same bind rule, so
        OUD deny precedence (OUD §9.1.4) reproduces that union. Every session
        matches a ``*`` subject without bind modifiers, so rights such a
        subject denies are removed from every grant of the rule. OID ``*``
        matches any entry and its coverage of anonymous sessions is not
        documented (OID-30 §30.1.4.2.1), so its grants render for
        authenticated sessions (``ldap:///all``) and its denials for every
        session (``ldap:///anyone``); neither direction grants more than OID.
        With ``base_dn``, an out-of-scope bind DN that only grants is
        excluded; one that denies fails, because its members may still bind
        inside the base. OID evaluates group membership only for security
        groups (OID-30 §30.1.3.4.6) while OUD honours every group, so a group
        subject must name one of ``access_groups``. An ACL on the root DSE
        governs the whole DIT (OID-30 §30.3.2) while an OUD ``aci`` there
        governs that entry only (OUD §9.1.2), so it fails. An entry ``browse``
        grant exposes the DN only (OID-30 Table 30-2) and OUD has no such
        right (OUD §9.2.3.3), so it fails. OUD ``*`` and ``!=`` targets do not
        cover operational attributes (OUD11-COMPAT) while OID ``attr=(*)``
        coverage of them is not documented, so a denial on such a target
        fails. Unsupported subjects, modifiers, tokens, regex DNs, filters and
        values outside the ACI quoting grammar surface as ``r.fail``.
        """

        def __init__(
            self,
            rule: p.Ldif.OidAclRule,
            base_dn: str,
            access_groups: frozenset[str],
            sibling_attrs: Sequence[str],
        ) -> None:
            """Bind the rule, scope, access groups and per-subject accumulators."""
            self._rule = rule
            self._base_dn = base_dn
            self._access_groups = access_groups
            self._sibling_attrs = sibling_attrs
            self._targetattr = c.Ldif.ACL_WILDCARD
            self._targetfilter: str | None = None
            self._is_entry = rule.target_type == c.Ldif.AclTargetType.ENTRY
            self._dn_binds = {
                c.Ldif.OudSubjectType.GROUPDN,
                c.Ldif.OudSubjectType.USERDN,
            }
            self._literal_binds = {
                c.Ldif.SUBJECT_SELF,
                c.Ldif.SUBJECT_ANYONE,
            }
            self._resolved: dict[
                int,
                tuple[p.Ldif.AciAllow, p.Ldif.AclPermissionResolution, bool],
            ] = {}
            self._excluded: dict[int, p.Ldif.AclSubjectOutcome] = {}

        def assemble(self) -> p.Result[p.Ldif.AciRule]:
            """Resolve every subject, then build the clauses and outcomes.

            Returns:
                The assembled rule, or the first target or subject failure.

            """
            target = self._resolve_target()
            if target.failure:
                return r[p.Ldif.AciRule].from_failure(target)
            for index, subject in enumerate(self._rule.subjects):
                step = self._resolve_subject(index, subject)
                if step.failure:
                    return r[p.Ldif.AciRule].from_failure(step)
            return self._quoted_values_check(self._build_rule())

        def _resolve_target(self) -> p.Result[bool]:
            """Reject a root DSE ACL, then convert the targetattr and filter.

            Returns:
                Success once the target is converted, or the typed failure.

            """
            constants = FlextLdifConstantsServersOid
            to_oud = FlextLdifServersOidAclToOud
            if to_oud.dn_key(self._rule.dn) == constants.OID_ROOT_DSE_DN:
                return r[bool].fail(
                    "OID ACL on the root DSE governs the whole DIT (OID-30 "
                    "§30.3.2) while an OUD aci there governs that entry only "
                    "(OUD §9.1.2); it needs an OUD global ACI (manual review "
                    "required)",
                )
            targetattr = to_oud.convert_targetattr(
                self._rule,
                sibling_attrs=self._sibling_attrs,
            )
            if targetattr.failure:
                return r[bool].from_failure(targetattr)
            self._targetattr = targetattr.value
            if self._rule.target_filter is not None:
                targetfilter = to_oud.validate_ldap_filter(self._rule.target_filter)
                if targetfilter.failure:
                    return r[bool].from_failure(targetfilter)
                self._targetfilter = targetfilter.value
            return r[bool].ok(value=True)

        def _rights_check(
            self,
            subject: p.Ldif.OidAclSubject,
            resolution: p.Ldif.AclPermissionResolution,
        ) -> p.Result[bool]:
            """Fail rights that have no exact OUD form on this target.

            Returns:
                Success, or the typed failure naming the right.

            """
            constants = FlextLdifConstantsServersOid
            if self._is_entry and any(
                perm in constants.OUD_VISIBILITY_PERMS for perm in resolution.allow
            ):
                return r[bool].fail(
                    f"OID entry browse granted to {subject.subject_type} "
                    f"{subject.value!r} exposes the DN only (OID-30 Table 30-2); "
                    "OUD returns an entry only with read on one of its "
                    "attributes (OUD §9.2.3.3), so no OUD right is exact "
                    "(manual review required)",
                )
            wildcard = self._targetattr == c.Ldif.ACL_WILDCARD or (
                self._targetattr.startswith(c.Ldif.OUD_ATTR_NEGATION)
            )
            if not self._is_entry and wildcard and resolution.deny:
                return r[bool].fail(
                    f"OID denial {tuple(resolution.deny)} on attribute target "
                    f"{self._rule.target_attrs!r} renders on OUD targetattr "
                    f"{self._targetattr!r}, which excludes operational attributes "
                    "(OUD11-COMPAT), while OID coverage of them is not "
                    "documented (manual review required)",
                )
            return r[bool].ok(value=True)

        @staticmethod
        def _quoted_values_check(aci: p.Ldif.AciRule) -> p.Result[p.Ldif.AciRule]:
            """Fail when a value rendered inside ACI quotes carries a quote.

            Returns:
                The rule, or the typed failure naming the value.

            """
            quote = FlextLdifConstantsServersOid.OUD_ACI_QUOTE
            values = (
                ("targetfilter", aci.targetfilter or ""),
                ("targetattr", aci.targetattr),
                ("acl name", aci.acl_name),
                *(
                    ("bind value", clause.subject_value)
                    for clause in (*aci.allows, *aci.denies)
                ),
            )
            for label, value in values:
                if quote in value:
                    return r[p.Ldif.AciRule].fail(
                        f"OUD ACI {label} {value!r} carries a quote the ACI "
                        "syntax cannot hold (manual review required)",
                    )
            return r[p.Ldif.AciRule].ok(aci)

        def _resolve_subject(
            self,
            index: int,
            subject: p.Ldif.OidAclSubject,
        ) -> p.Result[bool]:
            """Convert one subject's bind rule, modifiers and permissions.

            Returns:
                Success once the subject is resolved or excluded, or the
                first conversion failure.

            """
            bind = FlextLdifServersOidAclToOud.convert_subject_to_oud(subject)
            if bind.failure:
                return r[bool].from_failure(bind)
            ip = FlextLdifServersOidAclToOud.convert_bind_modifiers(subject)
            if ip.failure:
                return r[bool].from_failure(ip)
            resolved = FlextLdifServersOidAclToOud.resolve_permissions(
                subject.permissions,
                is_entry=self._is_entry,
            )
            if resolved.failure:
                return r[bool].from_failure(resolved)
            rights = self._rights_check(subject, resolved.value)
            if rights.failure:
                return r[bool].from_failure(rights)
            return self._place_subject(
                index,
                subject,
                bind.value.model_copy(update={"ip": ip.value}),
                resolved.value,
            )

        def _place_subject(
            self,
            index: int,
            subject: p.Ldif.OidAclSubject,
            bind: p.Ldif.AciAllow,
            resolution: p.Ldif.AclPermissionResolution,
        ) -> p.Result[bool]:
            """Apply the bind-DN wildcard, scope and access-group checks.

            Returns:
                Success once the subject is resolved or excluded, or the
                first check failure.

            """
            converted = bind.subject_value
            bind_value = converted
            if (
                bind.subject_type in self._dn_binds
                and converted not in self._literal_binds
            ):
                wildcard = FlextLdifServersOidAclToOud.convert_bind_dn(
                    bind.subject_type,
                    converted,
                )
                if wildcard.failure:
                    return r[bool].from_failure(wildcard)
                bind_value = wildcard.value
                if not FlextLdifServersOidAclToOud.in_scope(bind_value, self._base_dn):
                    return self._exclude_out_of_scope(
                        index,
                        subject,
                        bind_value,
                        resolution,
                    )
            if bind.subject_type == c.Ldif.OudSubjectType.GROUPDN and (
                FlextLdifServersOidAclToOud.dn_key(bind_value)
                not in self._access_groups
            ):
                return r[bool].fail(
                    f"OID group {bind_value!r} is not a verified security group "
                    "(orclACPgroup/orclPrivilegeGroup without nested or dynamic "
                    "members); OID ignores other groups for access while OUD "
                    "honours them (manual review required)",
                )
            self._resolved[index] = (
                bind.model_copy(update={"subject_value": bind_value}),
                resolution,
                bind_value != converted,
            )
            return r[bool].ok(value=True)

        def _exclude_out_of_scope(
            self,
            index: int,
            subject: p.Ldif.OidAclSubject,
            bind_value: str,
            resolution: p.Ldif.AclPermissionResolution,
        ) -> p.Result[bool]:
            """Exclude a grant-only subject bound outside base_dn; fail a denial.

            Returns:
                Success once excluded, or the failure of a denying subject.

            """
            if resolution.deny:
                return r[bool].fail(
                    f"OID subject {bind_value!r} outside base_dn "
                    f"{self._base_dn!r} denies {tuple(resolution.deny)}; its "
                    "members may bind inside the base, so the denial cannot be "
                    "dropped (manual review required)",
                )
            self._excluded[index] = m.Ldif.AclSubjectOutcome(
                subject=subject,
                kind=c.Ldif.AclSubjectOutcomeKind.OUT_OF_SCOPE,
                display_value=bind_value,
            )
            return r[bool].ok(value=True)

        def _catch_all_denials(self) -> frozenset[str]:
            """Return the rights a ``*`` subject without bind modifiers denies."""
            return frozenset(
                perm
                for index, (bind, resolution, _) in self._resolved.items()
                if self._rule.subjects[index].subject_type
                == c.Ldif.OidSubjectKind.ANYONE
                and not bind.ip
                for perm in resolution.deny
            )

        @staticmethod
        def _outcome(
            subject: p.Ldif.OidAclSubject,
            resolved: tuple[p.Ldif.AciAllow, p.Ldif.AclPermissionResolution, bool],
            catch_all: frozenset[str],
        ) -> p.Ldif.AclSubjectOutcome:
            """Type one resolved subject's effective allow, deny and kind.

            Returns:
                The subject outcome.

            """
            kind = c.Ldif.AclSubjectOutcomeKind
            bind, resolution, rewritten = resolved
            effective = tuple(
                perm for perm in resolution.allow if perm not in catch_all
            )
            deny = (
                m.Ldif.AciDeny(
                    subject_type=bind.subject_type,
                    subject_value=bind.subject_value,
                    permissions=resolution.deny,
                    ip=bind.ip,
                )
                if resolution.deny
                else None
            )
            grant_value = (
                FlextLdifConstantsServersOid.OUD_SUBJECT_AUTHENTICATED
                if subject.subject_type == c.Ldif.OidSubjectKind.ANYONE
                else bind.subject_value
            )
            if effective:
                outcome_kind = kind.GRANTED
            elif resolution.allow:
                outcome_kind = kind.CANCELLED
            elif resolution.total_denial:
                outcome_kind = kind.DENIED_ALL
            else:
                outcome_kind = kind.DENIED
            return m.Ldif.AclSubjectOutcome(
                subject=subject,
                kind=outcome_kind,
                allow=(
                    bind.model_copy(
                        update={"permissions": effective, "subject_value": grant_value},
                    )
                    if effective
                    else None
                ),
                deny=deny,
                wildcard_rewritten=rewritten,
            )

        def _build_rule(self) -> p.Ldif.AciRule:
            """Derive outcomes, scoped clauses and the acl name of the rule.

            Returns:
                The resulting ``m.Ldif.AciRule``.

            """
            catch_all = self._catch_all_denials()
            outcomes = tuple(
                self._excluded[index]
                if index in self._excluded
                else self._outcome(subject, self._resolved[index], catch_all)
                for index, subject in enumerate(self._rule.subjects)
            )
            rule_scope = FlextLdifServersOidAclToOud.rule_targetscope(self._rule)
            to_oud = FlextLdifServersOidAclToOud
            allows: list[p.Ldif.AciAllow] = []
            denies: list[p.Ldif.AciDeny] = []
            for outcome in outcomes:
                if outcome.allow is not None:
                    allows.extend(
                        outcome.allow.model_copy(
                            update={
                                "permissions": perms,
                                "targetattr": attr,
                                "targetscope": scope,
                            },
                        )
                        for attr, scope, perms in to_oud.clause_parts(
                            self._rule,
                            outcome.allow.permissions,
                            deny=False,
                        )
                    )
                if outcome.deny is not None:
                    denies.extend(
                        outcome.deny.model_copy(
                            update={
                                "permissions": perms,
                                "targetattr": attr,
                                "targetscope": scope,
                            },
                        )
                        for attr, scope, perms in to_oud.clause_parts(
                            self._rule,
                            outcome.deny.permissions,
                            deny=True,
                        )
                    )
            first_value = self._rule.subjects[0].value if self._rule.subjects else ""
            acl_name = FlextLdifServersOidAclAssemble.generate_acl_name(
                self._rule.dn,
                self._rule.target_type,
                first_value,
            )
            group_count = len({
                tuple(outcome.allow.permissions)
                for outcome in outcomes
                if outcome.allow is not None
            })
            if group_count > 1:
                acl_name += f" (+{group_count - 1})"
            return m.Ldif.AciRule(
                dn=self._rule.dn,
                targetattr=self._targetattr,
                targetfilter=self._targetfilter,
                targetscope=rule_scope,
                acl_name=acl_name,
                allows=tuple(allows),
                denies=tuple(denies),
                target_type=self._rule.target_type,
                outcomes=outcomes,
            )

    @staticmethod
    def generate_acl_name(dn: str, target_type: str, subject_value: str) -> str:
        """Build the human-readable acl name ``{container} {Entry|Attrs} by {subj}``.

        Returns:
            The resulting ``str``.

        """
        container_match = c.Ldif.CN_EXTRACT_RE.match(dn)
        container = (
            container_match.group(1) if container_match else c.Ldif.UNKNOWN_CONTAINER
        )
        subject_match = c.Ldif.CN_EXTRACT_RE.match(subject_value)
        subject_name = subject_match.group(1) if subject_match else subject_value
        perm_type = (
            c.Ldif.ACL_NAME_ENTRY
            if target_type == c.Ldif.AclTargetType.ENTRY
            else c.Ldif.ACL_NAME_ATTRS
        )
        return f"{container} {perm_type} by {subject_name}"

    @classmethod
    def build_aci_rule(
        cls,
        rule: p.Ldif.OidAclRule,
        *,
        base_dn: str = "",
        access_groups: frozenset[str] = frozenset(),
        sibling_attrs: Sequence[str] = (),
    ) -> p.Result[p.Ldif.AciRule]:
        """Assemble a parsed OID rule into one OUD :class:`m.Ldif.AciRule`.

        ``access_groups`` holds the DN keys
        (:meth:`FlextLdifServersOidAclToOud.dn_key`) of the groups verified as
        OID security groups; a group subject outside it fails.
        ``sibling_attrs`` holds the attributes other ACIs of the same ACP name
        explicitly (:meth:`FlextLdifServersOidAclToOud.convert_targetattr`).
        Subject conversion into allow/deny clauses, scope and group checks and
        acl-name derivation live in the nested ``_RuleAssembler``.

        Returns:
            The resulting ``p.Result[p.Ldif.AciRule]``.

        """
        return cls._RuleAssembler(
            rule,
            base_dn,
            access_groups,
            sibling_attrs,
        ).assemble()


__all__: list[str] = ["FlextLdifServersOidAclAssemble"]
