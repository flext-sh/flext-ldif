"""OUD aci assembly — render an AciRule value object to its aci string.

Faithful port of the oracle ``AciRule.to_aci_string`` (non-formatted form):
``aci: (targetattr=…)(targetfilter=…)?(targetscope=…)?(version 3.0; acl
"name"; allow (perms) bindrule; …)``. Same-permission subjects collapse into
one ``allow`` clause with ``or``-joined bind-rules. Pure string assembly —
total function, no failure channel. Format literals are the ``c.Ldif`` SSOT.
"""

from __future__ import annotations

from flext_ldif import c, m, r, t
from flext_ldif.servers._oid.acl_convert_oud import FlextLdifServersOidAclToOud as Conv


class FlextLdifServersOidAclAssemble:
    """Render assembled OUD aci value objects to their canonical string form."""

    @staticmethod
    def _is_deny_none(permissions: t.StrSequence) -> bool:
        return [perm.lower() for perm in permissions] == [c.Ldif.PERM_NONE]

    @staticmethod
    def generate_acl_name(dn: str, target_type: str, subject_value: str) -> str:
        """Build the human-readable acl name ``{container} {Entry|Attrs} by {subj}``."""
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
    ) -> r[m.Ldif.AciRule]:
        """Assemble a parsed OID rule into one OUD :class:`m.Ldif.AciRule`.

        Subjects convert via :class:`FlextLdifServersOidAclToOud`; an ``anyone
        (none)`` deny-fallback removes that clause and turns every subsequent
        subject into dead code (recorded as notes). When ``base_dn`` is given, an
        ``anyone`` rule at a high-level container is dropped (OUD inherits to the
        subtree) and a bind DN outside ``base_dn`` is excluded — both with notes;
        OID regex bind DNs are converted to OUD wildcards. Subjects with no OUD
        equivalent or no resulting allow perms are dropped with a note. A
        deny-only rule yields a valid AciRule with empty ``allows`` + notes (the
        caller skips emitting an aci line). An unrecognized permission token
        surfaces as ``r.fail`` (never a silent partial result).
        """
        is_entry = rule.target_type == c.Ldif.AclTargetType.ENTRY
        containers = Conv.high_level_containers(base_dn) if base_dn else frozenset()
        dn_normalized = rule.dn.lower().replace(", ", ",").replace(" ,", ",")
        dn_binds = {c.Ldif.OudSubjectType.GROUPDN, c.Ldif.OudSubjectType.USERDN}
        literal_binds = {
            c.Ldif.SUBJECT_SELF,
            c.Ldif.SUBJECT_ANYONE,
            c.Ldif.DIRECTORY_MANAGER_DN,
        }
        allows: list[m.Ldif.AciAllow] = []
        notes: list[str] = []
        has_anyone = False
        found_deny_all = False
        for subject in rule.subjects:
            if found_deny_all:
                notes.append(
                    f"dead code after 'by * (none)': "
                    f"{subject.subject_type} {subject.value!r}",
                )
                continue
            is_anyone = subject.subject_type == c.Ldif.OidSubjectKind.ANYONE
            if is_anyone and cls._is_deny_none(subject.permissions):
                found_deny_all = True
                notes.append("'by * (none)' removed (OUD default-deny)")
                continue
            if is_anyone and dn_normalized in containers:
                notes.append(
                    "anyone skipped at high-level container "
                    "(OUD inherits to subtree)",
                )
                continue
            bind = Conv.convert_subject_to_oud(subject)
            if bind.failure:
                notes.append(bind.error or "subject has no OUD equivalent")
                continue
            bind_type = bind.value.subject_type
            bind_value = bind.value.subject_value
            if bind_type in dn_binds and bind_value not in literal_binds:
                bind_value = Conv.regex_to_wildcard(bind_value)
                if not Conv.is_in_scope(bind_value, base_dn):
                    notes.append(
                        f"{subject.subject_type} {bind_value!r} removed "
                        f"(DN out of scope {base_dn})",
                    )
                    continue
            perms = Conv.convert_permissions(subject.permissions, is_entry=is_entry)
            if perms.failure:
                return r[m.Ldif.AciRule].fail(
                    perms.error or "invalid OID permission token",
                )
            if not perms.value:
                notes.append(
                    f"{subject.subject_type} {subject.value!r} removed "
                    f"(no OUD allow permissions / default-deny)",
                )
                continue
            allows.append(
                m.Ldif.AciAllow(
                    subject_type=bind_type,
                    subject_value=bind_value,
                    permissions=perms.value,
                ),
            )
            has_anyone = has_anyone or is_anyone
        first_value = rule.subjects[0].value if rule.subjects else ""
        acl_name = cls.generate_acl_name(rule.dn, rule.target_type, first_value)
        group_count = len({tuple(allow.permissions) for allow in allows})
        if group_count > 1:
            acl_name += f" (+{group_count - 1})"
        return r[m.Ldif.AciRule].ok(
            m.Ldif.AciRule(
                dn=rule.dn,
                targetattr=Conv.get_targetattr(rule),
                targetfilter=rule.target_filter,
                targetscope=Conv.calculate_targetscope(
                    rule,
                    has_anyone_subject=has_anyone,
                ),
                acl_name=acl_name,
                allows=tuple(allows),
                notes=tuple(notes),
            ),
        )

    @staticmethod
    def _render_bind(allow: m.Ldif.AciAllow) -> str:
        if allow.subject_type == c.Ldif.OudSubjectType.USERATTR:
            keyword = c.Ldif.OudSubjectType.USERATTR.value
            return f'{keyword}="{allow.subject_value}"'
        return f'{allow.subject_type}="{c.Ldif.LDAP_PREFIX}{allow.subject_value}"'

    @staticmethod
    def _target_parts(aci: m.Ldif.AciRule) -> t.StrSequence:
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

    @classmethod
    def render_aci_string(cls, aci: m.Ldif.AciRule) -> str:
        """Render an :class:`m.Ldif.AciRule` to its OUD ``aci:`` line.

        Allows are grouped by identical permission set (first-seen order); each
        group becomes one ``allow (perms) bind1 or bind2;`` clause.
        """
        grouped: dict[t.StrSequence, list[str]] = {}
        for allow in aci.allows:
            grouped.setdefault(tuple(allow.permissions), []).append(
                cls._render_bind(allow),
            )
        clauses = [
            f"{c.Ldif.ACI_ALLOW} ({', '.join(perms)}) {c.Ldif.BIND_OR.join(binds)};"
            for perms, binds in grouped.items()
        ]
        version_part = f'({c.Ldif.ACI_VERSION}; acl "{aci.acl_name}";'
        return (
            f"{c.Ldif.ACI_PREFIX}{''.join(cls._target_parts(aci))}"
            f"{version_part} {' '.join(clauses)})"
        )


__all__: list[str] = ["FlextLdifServersOidAclAssemble"]
