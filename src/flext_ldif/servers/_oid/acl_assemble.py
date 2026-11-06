"""OID→OUD aci building — one parsed OID rule → one OUD AciRule.

``build_aci_rule`` performs subject/permission conversion into typed allow and
deny clauses, base_dn scope filtering and acl-name derivation. Line/entry-level
orchestration lives in ``acl_pipeline.py``; rendering in ``acl_render.py``.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, m, p, r
from flext_ldif.servers._oid import FlextLdifServersOidAclToOud


class FlextLdifServersOidAclAssemble:
    """Build OUD aci value objects from parsed OID rules and orchestrate entries."""

    class _RuleAssembler:
        """Assemble one parsed OID rule into one OUD :class:`m.Ldif.AciRule`.

        Inside one OID ACI the effective access of a session is the union of
        the grants of every matching by-clause minus the union of their
        denials (OID-30 §30.1.6.2). Every subject keeps its own grant as an
        ``allow`` and its own denial as a ``deny`` with the same bind rule, so
        OUD deny precedence (OUD §9.1.4) reproduces that union. Because every
        session matches ``*``, rights a ``*`` subject denies are removed from
        every grant of the rule. With ``base_dn``, out-of-scope bind DNs are
        excluded. Unsupported subjects, modifiers, tokens and regex DNs
        surface as ``r.fail``.
        """

        def __init__(self, rule: p.Ldif.OidAclRule, base_dn: str) -> None:
            """Bind the rule, scope, and per-subject accumulators."""
            self._rule = rule
            self._base_dn = base_dn
            self._is_entry = rule.target_type == c.Ldif.AclTargetType.ENTRY
            self._dn_binds = {
                c.Ldif.OudSubjectType.GROUPDN,
                c.Ldif.OudSubjectType.USERDN,
            }
            self._literal_binds = {
                c.Ldif.SUBJECT_SELF,
                c.Ldif.SUBJECT_ANYONE,
                c.Ldif.DIRECTORY_MANAGER_DN,
            }
            self._resolved: dict[
                int,
                tuple[p.Ldif.AciAllow, p.Ldif.AclPermissionResolution, bool],
            ] = {}
            self._excluded: dict[int, p.Ldif.AclSubjectOutcome] = {}

        def assemble(self) -> p.Result[p.Ldif.AciRule]:
            """Resolve every subject, then build the clauses and outcomes.

            Returns:
                The assembled rule, or the first subject failure.

            """
            for index, subject in enumerate(self._rule.subjects):
                step = self._resolve_subject(index, subject)
                if step.failure:
                    return r[p.Ldif.AciRule].from_failure(step)
            return r[p.Ldif.AciRule].ok(self._build_rule())

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
            converted = bind.value.subject_value
            bind_value = converted
            dn_bind = bind.value.subject_type in self._dn_binds
            if dn_bind and converted not in self._literal_binds:
                wildcard = FlextLdifServersOidAclToOud.convert_bind_dn(
                    bind.value.subject_type,
                    converted,
                )
                if wildcard.failure:
                    return r[bool].from_failure(wildcard)
                bind_value = wildcard.value
                if not FlextLdifServersOidAclToOud.in_scope(bind_value, self._base_dn):
                    self._excluded[index] = m.Ldif.AclSubjectOutcome(
                        subject=subject,
                        kind=c.Ldif.AclSubjectOutcomeKind.OUT_OF_SCOPE,
                        display_value=bind_value,
                    )
                    return r[bool].ok(value=True)
            self._resolved[index] = (
                m.Ldif.AciAllow(
                    subject_type=bind.value.subject_type,
                    subject_value=bind_value,
                    ip=ip.value,
                ),
                resolved.value,
                bind_value != converted,
            )
            return r[bool].ok(value=True)

        def _catch_all_denials(self) -> frozenset[str]:
            """Return the rights any ``*`` subject of the rule denies."""
            return frozenset(
                perm
                for index, (_, resolution, _) in self._resolved.items()
                if self._rule.subjects[index].subject_type
                == c.Ldif.OidSubjectKind.ANYONE
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
                    bind.model_copy(update={"permissions": effective})
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
            has_anyone = any(
                outcome.allow is not None
                and outcome.subject.subject_type == c.Ldif.OidSubjectKind.ANYONE
                for outcome in outcomes
            )
            rule_scope = FlextLdifServersOidAclToOud.calculate_targetscope(
                self._rule,
                has_anyone_subject=has_anyone,
            )
            allows: list[p.Ldif.AciAllow] = []
            denies: list[p.Ldif.AciDeny] = []
            for outcome in outcomes:
                if outcome.allow is not None:
                    allows.extend(
                        outcome.allow.model_copy(
                            update={"permissions": perms, "targetscope": scope},
                        )
                        for scope, perms in FlextLdifServersOidAclToOud.clause_scopes(
                            self._rule,
                            outcome.allow.permissions,
                            deny=False,
                            rule_scope=rule_scope,
                        )
                    )
                if outcome.deny is not None:
                    denies.extend(
                        outcome.deny.model_copy(
                            update={"permissions": perms, "targetscope": scope},
                        )
                        for scope, perms in FlextLdifServersOidAclToOud.clause_scopes(
                            self._rule,
                            outcome.deny.permissions,
                            deny=True,
                            rule_scope=rule_scope,
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
                targetattr=FlextLdifServersOidAclToOud.resolve_targetattr(self._rule),
                targetfilter=self._rule.target_filter,
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
    ) -> p.Result[p.Ldif.AciRule]:
        """Assemble a parsed OID rule into one OUD :class:`m.Ldif.AciRule`.

        Subject conversion into allow/deny clauses, scope filtering and
        acl-name derivation live in the nested ``_RuleAssembler``.

        Returns:
            The resulting ``p.Result[p.Ldif.AciRule]``.

        """
        return cls._RuleAssembler(rule, base_dn).assemble()


__all__: list[str] = ["FlextLdifServersOidAclAssemble"]
