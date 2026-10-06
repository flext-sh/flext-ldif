"""OID→OUD aci building — one parsed OID rule → one OUD AciRule.

``build_aci_rule`` performs subject/permission conversion, the deny-fallback,
base_dn scope filtering and acl-name derivation. Line/entry-level
orchestration lives in ``acl_pipeline.py``; rendering in ``acl_render.py``.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, m, p, r, t
from flext_ldif.servers._oid.acl_convert_oud import FlextLdifServersOidAclToOud


class _AciRuleAssembler:
    """Assemble one parsed OID rule into one OUD :class:`m.Ldif.AciRule`.

    ``by * (none)`` deny-fallback removes that clause + dead-codes every
    later subject; with ``base_dn``, an ``anyone`` rule at a high-level
    container is dropped and out-of-scope bind DNs are excluded (regex DNs →
    wildcards) — all recorded as notes. A deny-only rule yields a valid
    AciRule with empty ``allows`` + notes (caller skips emitting).
    """

    def __init__(self, rule: m.Ldif.OidAclRule, base_dn: str) -> None:
        """Bind the rule, scope, and converted-subject accumulators."""
        self._rule = rule
        self._base_dn = base_dn
        self._is_entry = rule.target_type == c.Ldif.AclTargetType.ENTRY
        self._containers = (
            FlextLdifServersOidAclToOud.high_level_containers(base_dn)
            if base_dn
            else frozenset()
        )
        self._dn_normalized = rule.dn.lower().replace(", ", ",").replace(" ,", ",")
        self._dn_binds = {c.Ldif.OudSubjectType.GROUPDN, c.Ldif.OudSubjectType.USERDN}
        self._literal_binds = {
            c.Ldif.SUBJECT_SELF,
            c.Ldif.SUBJECT_ANYONE,
            c.Ldif.DIRECTORY_MANAGER_DN,
        }
        self._allows: list[m.Ldif.AciAllow] = []
        self._notes: list[str] = []
        self._has_anyone = False
        self._found_deny_all = False

    def assemble(self) -> p.Result[m.Ldif.AciRule]:
        """Run the subject conversion pass and build the final AciRule.

        An unknown permission token surfaces as ``r.fail`` (never a silent
        partial result).

        Returns:
            The resulting ``p.Result[m.Ldif.AciRule]``.
        """
        for subject in self._rule.subjects:
            if self._found_deny_all:
                self._note_dead_subject(subject)
                continue
            step_result = self._process_subject(subject)
            if step_result.failure:
                return r[m.Ldif.AciRule].from_failure(step_result)
        return r[m.Ldif.AciRule].ok(self._build_rule())

    def _note_dead_subject(self, subject: m.Ldif.OidAclSubject) -> None:
        """Record one subject dead-coded after the ``by * (none)`` fallback."""
        self._notes.append(
            f"dead code after 'by * (none)': "
            f"{subject.subject_type} {subject.value!r}",
        )

    def _process_subject(self, subject: m.Ldif.OidAclSubject) -> p.Result[bool]:
        """Convert one subject clause, appending allows and notes.

        Returns:
            The resulting ``p.Result[None]``.
        """
        is_anyone = subject.subject_type == c.Ldif.OidSubjectKind.ANYONE
        if is_anyone and FlextLdifServersOidAclAssemble._is_deny_none(
            subject.permissions,
        ):
            self._found_deny_all = True
            self._notes.append("'by * (none)' removed (OUD default-deny)")
            return r[bool].ok(True)
        if is_anyone and self._dn_normalized in self._containers:
            self._notes.append(
                "anyone skipped at high-level container (OUD inherits to subtree)",
            )
            return r[bool].ok(True)
        bind = FlextLdifServersOidAclToOud.convert_subject_to_oud(subject)
        if bind.failure:
            self._notes.append(bind.error or "subject has no OUD equivalent")
            return r[bool].ok(True)
        bind_type = bind.value.subject_type
        bind_value = bind.value.subject_value
        if bind_type in self._dn_binds and bind_value not in self._literal_binds:
            bind_value = FlextLdifServersOidAclToOud.regex_to_wildcard(bind_value)
            if not FlextLdifServersOidAclToOud.is_in_scope(bind_value, self._base_dn):
                self._notes.append(
                    f"{subject.subject_type} {bind_value!r} removed "
                    f"(DN out of scope {self._base_dn})",
                )
                return r[bool].ok(True)
        return self._append_allow(subject, bind_type, bind_value, is_anyone)

    def _append_allow(
        self,
        subject: m.Ldif.OidAclSubject,
        bind_type: str,
        bind_value: str,
        is_anyone: bool,
    ) -> p.Result[bool]:
        """Convert permissions and append one allow clause with its notes.

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
            self._notes.append(
                f"{subject.subject_type} {subject.value!r} removed "
                f"(no OUD allow permissions / default-deny)",
            )
            return r[bool].ok(True)
        self._allows.append(
            m.Ldif.AciAllow(
                subject_type=bind_type,
                subject_value=bind_value,
                permissions=perms.value,
                authmethod=subject.bindmode,
                ip=subject.bindipfilter,
            ),
        )
        if subject.added_object_constraint:
            self._notes.append(
                f"added_object_constraint=({subject.added_object_constraint}) "
                "on this subject needs manual OUD targetfilter review",
            )
        if is_anyone and (sensitive := c.Ldif.SENSITIVE_PERMS & set(perms.value)):
            self._notes.append(
                f"anyone granted sensitive perms {sorted(sensitive)} — "
                "verify this is intended",
            )
        self._has_anyone = self._has_anyone or is_anyone
        return r[bool].ok(True)

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
            targetattr=FlextLdifServersOidAclToOud.get_targetattr(self._rule),
            targetfilter=self._rule.target_filter,
            targetscope=FlextLdifServersOidAclToOud.calculate_targetscope(
                self._rule,
                has_anyone_subject=self._has_anyone,
            ),
            acl_name=acl_name,
            allows=tuple(self._allows),
            notes=tuple(self._notes),
        )


class FlextLdifServersOidAclAssemble:
    """Build OUD aci value objects from parsed OID rules and orchestrate entries."""

    @staticmethod
    def _is_deny_none(permissions: t.StrSequence) -> bool:
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
        derivation live in :class:`_AciRuleAssembler`.

        Returns:
            The resulting ``p.Result[m.Ldif.AciRule]``.
        """
        return _AciRuleAssembler(rule, base_dn).assemble()


__all__: list[str] = ["FlextLdifServersOidAclAssemble"]
