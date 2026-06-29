"""OUD aci rendering — AciRule value object → canonical aci string.

Faithful port of the oracle ``AciRule.to_aci_string`` (non-formatted form):
``aci: (targetattr=…)(targetfilter=…)?(targetscope=…)?(version 3.0; acl
"name"; allow (perms) bindrule; …)``. Same-permission subjects collapse into
one ``allow`` clause with ``or``-joined bind-rules. Pure string assembly —
total function, no failure channel. Format literals are the ``c.Ldif`` SSOT.
"""

from __future__ import annotations

from flext_ldif import c, m, t


class FlextLdifServersOidAclRender:
    """Render an assembled OUD :class:`m.Ldif.AciRule` to its string form."""

    @staticmethod
    def _render_bind(allow: m.Ldif.AciAllow) -> str:
        if allow.subject_type == c.Ldif.OudSubjectType.USERATTR:
            keyword = c.Ldif.OudSubjectType.USERATTR.value
            bind = f'{keyword}="{allow.subject_value}"'
        else:
            bind = f'{allow.subject_type}="{c.Ldif.LDAP_PREFIX}{allow.subject_value}"'
        if allow.authmethod:
            bind += f' and authmethod="{allow.authmethod}"'
        if allow.ip:
            bind += f' and ip="{allow.ip}"'
        return bind

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
        grouped = m.Ldif.AciAllowGroups()
        for allow in aci.allows:
            grouped = grouped.with_allow(allow, cls._render_bind(allow))
        clauses = tuple(
            f"{c.Ldif.ACI_ALLOW} ({', '.join(group.permissions)}) "
            f"{c.Ldif.BIND_OR.join(group.binds)};"
            for group in grouped.groups
        )
        version_part = f'({c.Ldif.ACI_VERSION}; acl "{aci.acl_name}";'
        return (
            f"{c.Ldif.ACI_PREFIX}{''.join(cls._target_parts(aci))}"
            f"{version_part} {' '.join(clauses)})"
        )


__all__: list[str] = ["FlextLdifServersOidAclRender"]
