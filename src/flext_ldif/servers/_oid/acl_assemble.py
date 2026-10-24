"""OID→OUD aci building — one parsed OID rule → one OUD AciRule.

``build_aci_rule`` performs subject/permission conversion, the deny-fallback,
base_dn scope filtering and acl-name derivation. Line/entry-level
orchestration lives in ``acl_pipeline.py``; rendering in ``acl_render.py``.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, m, p, r, t
from flext_ldif.servers._oid import FlextLdifServersOidAclToOud


class FlextLdifServersOidAclAssemble:
    """Build OUD aci value objects from parsed OID rules and orchestrate entries."""

    class _RuleAssembler:
        """Assemble one parsed OID rule into one OUD :class:`m.Ldif.AciRule`.

        ``by * (none)`` deny-fallback removes that clause + dead-codes every
        later subject; with ``base_dn``, an ``anyone`` rule at a high-level
        container is dropped and out-of-scope bind DNs are excluded (regex DNs →
        wildcards) — every subject records one typed
        :class:`m.Ldif.AclSubjectOutcome`. A deny-only rule yields a valid
        AciRule with empty ``allows`` + outcomes (caller skips emitting).
        """

        def __init__(self, rule: m.Ldif.OidAclRule, base_dn: str) -> None:
            """Bind the rule, scope, and converted-subject accumulators."""
            self._rule = rule
            self._base_dn = base_dn
            self._is_entry = rule.target_type == c.Ldif.AclTargetType.ENTRY
            self._containers: frozenset[str] = (
                FlextLdifServersOidAclToOud.high_level_containers(base_dn)
                if base_dn
                else frozenset()
            )
            self._dn_normalized = rule.dn.lower().replace(", ", ",").replace(" ,", ",")
            self._dn_binds = {
                c.Ldif.OudSubjectType.GROUPDN,
                c.Ldif.OudSubjectType.USERDN,
            }
            self._literal_binds = {
                c.Ldif.SUBJECT_SELF,
                c.Ldif.SUBJECT_ANYONE,
                c.Ldif.DIRECTORY_MANAGER_DN,
            }
            self._allows: list[m.Ldif.AciAllow] = []
            self._outcomes: list[m.Ldif.AclSubjectOutcome] = []
            self._has_anyone = False
            self._found_deny_all = False

        def assemble(self) -> p.Result[m.Ldif.AciRule]:
            """Run the subject conversion pass and build the final AciRule.

            An unknown permission token surfaces as ``r.fail`` (never a silent
            partial result).

            Returns:
                The resulting ``p.Result[m.Ldif.AciRule]``.

            """
            kind = c.Ldif.AclSubjectOutcomeKind
            for subject in self._rule.subjects:
                if self._found_deny_all:
                    self._record(subject, kind.EXCLUDED_DEAD_CODE)
                    continue
                step_result = self._process_subject(subject)
                if step_result.failure:
                    return r[m.Ldif.AciRule].from_failure(step_result)
            return r[m.Ldif.AciRule].ok(self._build_rule())

        def _record(
            self,
            subject: m.Ldif.OidAclSubject,
            kind: c.Ldif.AclSubjectOutcomeKind,
            *,
            allow: m.Ldif.AciAllow | None = None,
            wildcard_rewritten: bool = False,
            display_value: str = "",
        ) -> p.Result[bool]:
            """Record the typed outcome of one subject.

            Returns:
                The resulting ``p.Result[bool]``.

            """
            self._outcomes.append(
                m.Ldif.AclSubjectOutcome(
                    subject=subject,
                    kind=kind,
                    allow=allow,
                    wildcard_rewritten=wildcard_rewritten,
                    complement_calculated=allow is not None
                    and all(
                        perm.strip().lower() in c.Ldif.NEGATION_TO_BASE
                        for perm in subject.permissions
                    ),
                    display_value=display_value,
                ),
            )
            return r[bool].ok(value=True)

        def _process_subject(self, subject: m.Ldif.OidAclSubject) -> p.Result[bool]:
            """Convert one subject clause, appending its allow and outcome.

            Returns:
                The resulting ``p.Result[None]``.

            """
            kind = c.Ldif.AclSubjectOutcomeKind
            is_anyone = subject.subject_type == c.Ldif.OidSubjectKind.ANYONE
            if is_anyone and FlextLdifServersOidAclAssemble.deny_none(
                subject.permissions,
            ):
                self._found_deny_all = True
                return self._record(subject, kind.EXCLUDED_DENY_NONE)
            if is_anyone and self._dn_normalized in self._containers:
                return self._record(subject, kind.EXCLUDED_CONTAINER)
            bind = FlextLdifServersOidAclToOud.convert_subject_to_oud(subject)
            if bind.failure:
                return self._record(subject, kind.UNSUPPORTED)
            bind_type = bind.value.subject_type
            converted = bind.value.subject_value
            bind_value = converted
            if bind_type in self._dn_binds and converted not in self._literal_binds:
                bind_value = FlextLdifServersOidAclToOud.regex_to_wildcard(converted)
                if not FlextLdifServersOidAclToOud.in_scope(bind_value, self._base_dn):
                    return self._record(
                        subject,
                        kind.OUT_OF_SCOPE,
                        display_value=bind_value,
                    )
            dn_kinds = {c.Ldif.OidSubjectKind.GROUP, c.Ldif.OidSubjectKind.USER}
            return self._append_allow(
                subject,
                m.Ldif.AciAllow(
                    subject_type=bind_type,
                    subject_value=bind_value,
                    authmethod=subject.bindmode,
                    ip=subject.bindipfilter,
                ),
                wildcard_rewritten=bind_value != converted,
                display_value=(
                    converted if subject.subject_type in dn_kinds else subject.value
                ),
            )

        def _append_allow(
            self,
            subject: m.Ldif.OidAclSubject,
            bind: m.Ldif.AciAllow,
            *,
            wildcard_rewritten: bool,
            display_value: str,
        ) -> p.Result[bool]:
            """Convert permissions and append one allow clause with its outcome.

            Returns:
                The resulting ``p.Result[None]``.

            """
            perms = FlextLdifServersOidAclToOud.convert_permissions(
                subject.permissions,
                is_entry=self._is_entry,
            )
            if perms.failure:
                return r[bool].from_failure(perms)
            if not perms.value:
                return self._record(
                    subject,
                    c.Ldif.AclSubjectOutcomeKind.UNGRANTED,
                    display_value=display_value,
                )
            allow = bind.model_copy(update={"permissions": perms.value})
            self._allows.append(allow)
            self._has_anyone = self._has_anyone or (
                subject.subject_type == c.Ldif.OidSubjectKind.ANYONE
            )
            return self._record(
                subject,
                c.Ldif.AclSubjectOutcomeKind.GRANTED,
                allow=allow,
                wildcard_rewritten=wildcard_rewritten,
            )

        def _build_rule(self) -> m.Ldif.AciRule:
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
                target_type=self._rule.target_type,
                outcomes=tuple(self._outcomes),
            )

    @staticmethod
    def deny_none(permissions: t.StrSequence) -> bool:
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
        rule: m.Ldif.OidAclRule,
        *,
        base_dn: str = "",
    ) -> p.Result[m.Ldif.AciRule]:
        """Assemble a parsed OID rule into one OUD :class:`m.Ldif.AciRule`.

        Subject conversion, deny-fallback, scope filtering and acl-name
        derivation live in the nested ``_RuleAssembler``.

        Returns:
            The resulting ``p.Result[m.Ldif.AciRule]``.

        """
        return cls._RuleAssembler(rule, base_dn).assemble()


__all__: list[str] = ["FlextLdifServersOidAclAssemble"]
