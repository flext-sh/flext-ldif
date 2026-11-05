"""OID→OUD aci building — one parsed OID rule → one OUD AciRule.

``build_aci_rule`` performs subject/permission conversion into typed allow and
deny clauses, base_dn scope filtering and acl-name derivation. Line/entry-level
orchestration lives in ``acl_pipeline.py``; rendering in ``acl_render.py``.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence

from flext_ldif import c, m, p, r
from flext_ldif.servers._oid import FlextLdifServersOidAclToOud


class FlextLdifServersOidAclAssemble:
    """Build OUD aci value objects from parsed OID rules and orchestrate entries."""

    class _RuleAssembler:
        """Assemble one parsed OID rule into one OUD :class:`m.Ldif.AciRule`.

        Every subject records one typed :class:`m.Ldif.AclSubjectOutcome`.
        Grants become ``allows``; explicit denials (``no*`` tokens and
        ``(none)``, OID-30 §30.1.4.3 / Table 30-2) become typed ``denies`` the
        consumer renders as OUD ``deny`` — never a complement grant. ``by *
        (none)`` is ``DENIED_ALL`` and dead-codes every later subject; with
        ``base_dn``, out-of-scope bind DNs are excluded. Object keywords,
        modifiers and regex DNs without an exact OUD form surface as
        ``r.fail``.
        """

        def __init__(self, rule: p.Ldif.OidAclRule, base_dn: str) -> None:
            """Bind the rule, scope, and converted-subject accumulators."""
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
            self._allows: list[p.Ldif.AciAllow] = []
            self._denies: list[p.Ldif.AciDeny] = []
            self._outcomes: list[p.Ldif.AclSubjectOutcome] = []
            self._has_anyone = False
            self._found_deny_all = False

        def assemble(self) -> p.Result[p.Ldif.AciRule]:
            """Run the subject conversion pass and build the final AciRule.

            ``DenyGroupOverride`` (OID-30 §30.1.3.4.2: blocks superuser and
            DirectoryAdminGroup overrides, which OUD decides by privileges, not
            ACIs) and ``AppendToAll`` (§30.1.4.1: appends the subject to every
            ACI of the ACP) have no per-rule OUD form and surface as
            ``r.fail``, as does an unknown permission token or an
            untranslatable modifier / regex DN (never a silent partial result).

            Returns:
                The resulting ``p.Result[p.Ldif.AciRule]``.

            """
            if self._rule.deny_group_override:
                return r[p.Ldif.AciRule].fail(
                    "OID DenyGroupOverride has no exact OUD ACI equivalent "
                    f"(manual review required): {self._rule.raw_line!r}",
                )
            if self._rule.append_to_all:
                return r[p.Ldif.AciRule].fail(
                    "OID AppendToAll has no per-rule OUD ACI equivalent "
                    f"(manual review required): {self._rule.raw_line!r}",
                )
            kind = c.Ldif.AclSubjectOutcomeKind
            for subject in self._rule.subjects:
                if self._found_deny_all:
                    self._record(
                        m.Ldif.AclSubjectOutcome(
                            subject=subject,
                            kind=kind.EXCLUDED_DEAD_CODE,
                        ),
                    )
                    continue
                step_result = self._process_subject(subject)
                if step_result.failure:
                    return r[p.Ldif.AciRule].from_failure(step_result)
            return r[p.Ldif.AciRule].ok(self._build_rule())

        def _record(self, outcome: p.Ldif.AclSubjectOutcome) -> p.Result[bool]:
            """Record the typed outcome of one subject.

            Returns:
                The resulting ``p.Result[bool]``.

            """
            self._outcomes.append(outcome)
            return r[bool].ok(value=True)

        def _process_subject(self, subject: p.Ldif.OidAclSubject) -> p.Result[bool]:
            """Convert one subject clause, appending its clauses and outcome.

            Returns:
                The resulting ``p.Result[bool]``.

            """
            kind = c.Ldif.AclSubjectOutcomeKind
            bind = FlextLdifServersOidAclToOud.convert_subject_to_oud(subject)
            if bind.failure:
                return self._record(
                    m.Ldif.AclSubjectOutcome(subject=subject, kind=kind.UNSUPPORTED),
                )
            ip = FlextLdifServersOidAclToOud.convert_bind_modifiers(subject)
            if ip.failure:
                return r[bool].from_failure(ip)
            bind_type = bind.value.subject_type
            converted = bind.value.subject_value
            bind_value = converted
            if bind_type in self._dn_binds and converted not in self._literal_binds:
                wildcard = FlextLdifServersOidAclToOud.regex_to_wildcard(converted)
                if wildcard.failure:
                    return r[bool].from_failure(wildcard)
                bind_value = wildcard.value
                if not FlextLdifServersOidAclToOud.in_scope(bind_value, self._base_dn):
                    return self._record(
                        m.Ldif.AclSubjectOutcome(
                            subject=subject,
                            kind=kind.OUT_OF_SCOPE,
                            display_value=bind_value,
                        ),
                    )
            dn_kinds = {c.Ldif.OidSubjectKind.GROUP, c.Ldif.OidSubjectKind.USER}
            return self._append_clauses(
                subject,
                m.Ldif.AciAllow(
                    subject_type=bind_type,
                    subject_value=bind_value,
                    ip=ip.value,
                ),
                wildcard_rewritten=bind_value != converted,
                display_value=(
                    converted if subject.subject_type in dn_kinds else subject.value
                ),
            )

        def _append_clauses(
            self,
            subject: p.Ldif.OidAclSubject,
            bind: p.Ldif.AciAllow,
            *,
            wildcard_rewritten: bool,
            display_value: str,
        ) -> p.Result[bool]:
            """Resolve permissions and append the allow/deny clauses + outcome.

            Returns:
                The resulting ``p.Result[bool]``.

            """
            resolved = FlextLdifServersOidAclToOud.convert_permissions(
                subject.permissions,
                is_entry=self._is_entry,
            )
            if resolved.failure:
                return r[bool].from_failure(resolved)
            kind = c.Ldif.AclSubjectOutcomeKind
            deny = (
                m.Ldif.AciDeny(
                    subject_type=bind.subject_type,
                    subject_value=bind.subject_value,
                    permissions=resolved.value.deny,
                    ip=bind.ip,
                )
                if resolved.value.deny
                else None
            )
            if deny is not None:
                self._denies.append(deny)
            if not resolved.value.allow:
                total = FlextLdifServersOidAclAssemble.deny_none(subject.permissions)
                self._found_deny_all = total and (
                    subject.subject_type == c.Ldif.OidSubjectKind.ANYONE
                )
                return self._record(
                    m.Ldif.AclSubjectOutcome(
                        subject=subject,
                        kind=(kind.DENIED_ALL if total else kind.DENIED)
                        if deny is not None
                        else kind.UNGRANTED,
                        deny=deny,
                        display_value=display_value,
                    ),
                )
            allow = bind.model_copy(update={"permissions": resolved.value.allow})
            self._allows.append(allow)
            self._has_anyone = self._has_anyone or (
                subject.subject_type == c.Ldif.OidSubjectKind.ANYONE
            )
            return self._record(
                m.Ldif.AclSubjectOutcome(
                    subject=subject,
                    kind=kind.GRANTED,
                    allow=allow,
                    deny=deny,
                    wildcard_rewritten=wildcard_rewritten,
                ),
            )

        def _build_rule(self) -> p.Ldif.AciRule:
            """Derive the acl name and assemble the final OUD AciRule.

            Returns:
                The resulting ``m.Ldif.AciRule``.

            """
            first_value = self._rule.subjects[0].value if self._rule.subjects else ""
            acl_name = FlextLdifServersOidAclAssemble.generate_acl_name(
                self._rule.dn,
                self._rule.target_type,
                first_value,
            )
            group_count = len({tuple(allow.permissions) for allow in self._allows})
            if group_count > 1:
                acl_name += f" (+{group_count - 1})"
            return m.Ldif.AciRule(
                dn=self._rule.dn,
                targetattr=FlextLdifServersOidAclToOud.resolve_targetattr(self._rule),
                targetfilter=self._rule.target_filter,
                targetscope=FlextLdifServersOidAclToOud.calculate_targetscope(
                    self._rule,
                    has_anyone_subject=self._has_anyone,
                ),
                acl_name=acl_name,
                allows=tuple(self._allows),
                denies=tuple(self._denies),
                target_type=self._rule.target_type,
                outcomes=tuple(self._outcomes),
            )

    @staticmethod
    def deny_none(permissions: Sequence[str]) -> bool:
        """Report whether the permission list is exactly the ``none`` deny token.

        Returns:
            The resulting ``bool``.

        """
        return [perm.lower() for perm in permissions] == [c.Ldif.PERM_NONE]

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
