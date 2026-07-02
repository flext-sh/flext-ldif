"""ACL-conversion models — OID rule / OUD aci typed value objects.

Cohesive home for the OID→OUD ACL conversion model layer (parsed OID rules,
assembled OUD aci rules, and the subject-matcher parse descriptor). Mirrors the
``_constants/acl_convert.py`` SSOT; composed into ``m.Ldif`` via MRO.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Annotated

from flext_core import m, u
from flext_ldif import t


class FlextLdifModelsAclConvert:
    """Namespace for OID→OUD ACL conversion models."""

    class OidAclSubject(m.FrozenModel):
        """One parsed by-clause subject of an OID ACL rule (typed; no raw dict).

        ``subject_type`` ∈ {group, dn, self, anyone, superuser, dnattr, groupattr,
        guidattr, unknown}; ``value`` is the DN / group DN / attribute name; and
        ``permissions`` holds the raw OID permission tokens for this by-clause.
        """

        subject_type: Annotated[
            str,
            u.Field(description="Parsed subject keyword (group/dn/self/anyone/...)"),
        ]
        value: Annotated[
            str,
            u.Field(description="Subject value: DN, group DN, or attribute name"),
        ] = ""
        permissions: Annotated[
            t.StrSequence,
            u.Field(description="Raw OID permission tokens for this by-clause"),
        ] = ()
        bindmode: Annotated[
            str,
            u.Field(description="OID bindmode modifier → OUD authmethod"),
        ] = ""
        bindipfilter: Annotated[
            str,
            u.Field(description="OID bindipfilter modifier → OUD ip"),
        ] = ""
        added_object_constraint: Annotated[
            str,
            u.Field(description="OID added_object_constraint modifier (note only)"),
        ] = ""

    class OidAclRule(m.FrozenModel):
        """A parsed OID ``orclaci``/``orclentrylevelaci`` rule (pre-conversion)."""

        dn: Annotated[str, u.Field(description="Entry DN that owns the ACL")]
        acl_type: Annotated[str, u.Field(description="orclaci | orclentrylevelaci")]
        target_type: Annotated[str, u.Field(description="entry | attr")]
        target_attrs: Annotated[
            str,
            u.Field(description="'*' | comma-list | '!=comma-list'"),
        ] = "*"
        target_filter: Annotated[
            str | None,
            u.Field(description="LDAP filter expression, if present"),
        ] = None
        subjects: Annotated[
            tuple[FlextLdifModelsAclConvert.OidAclSubject, ...],
            u.Field(description="Parsed by-clause subjects"),
        ] = ()
        raw_line: Annotated[
            str,
            u.Field(description="Original raw OID ACL line"),
        ] = ""

    class AciAllow(m.FrozenModel):
        """One OUD ``aci`` ``allow()`` clause: bind-rule subject + permission set."""

        subject_type: Annotated[
            str,
            u.Field(description="OUD bind-rule keyword: userdn | groupdn | userattr"),
        ]
        subject_value: Annotated[
            str,
            u.Field(description="Bind-rule value, e.g. ldap:///cn=Directory Manager"),
        ]
        permissions: Annotated[
            t.StrSequence,
            u.Field(description="OUD permission tokens in canonical order"),
        ] = ()
        authmethod: Annotated[
            str,
            u.Field(description="OUD authmethod bind-rule constraint (from bindmode)"),
        ] = ""
        ip: Annotated[
            str,
            u.Field(description="OUD ip bind-rule constraint (from bindipfilter)"),
        ] = ""

    class AciRule(m.FrozenModel):
        """An OUD ``aci`` rule assembled from one OID rule (one rule → one aci)."""

        dn: Annotated[str, u.Field(description="Entry DN that owns the aci")]
        targetattr: Annotated[
            str,
            u.Field(description="targetattr expression, e.g. '*' or 'cn||sn'"),
        ] = "*"
        targetfilter: Annotated[
            str | None,
            u.Field(description="targetfilter expression, if present"),
        ] = None
        targetscope: Annotated[
            str | None,
            u.Field(description="targetscope, e.g. 'base', if present"),
        ] = None
        acl_name: Annotated[str, u.Field(description="Human-readable acl name")] = ""
        allows: Annotated[
            tuple[FlextLdifModelsAclConvert.AciAllow, ...],
            u.Field(description="allow() clauses"),
        ] = ()
        notes: Annotated[
            t.StrSequence,
            u.Field(
                description="Conversion notes: subjects dropped/removed and why",
            ),
        ] = ()

    class AciAllowGroup(m.FrozenModel):
        """One render-time allow group keyed by identical OUD permission tokens."""

        permissions: Annotated[
            t.StrSequence,
            u.Field(description="Canonical permission tuple shared by this group"),
        ] = ()
        binds: Annotated[
            t.StrSequence,
            u.Field(description="Rendered bind rules joined with OUD 'or'"),
        ] = ()
        authmethod: Annotated[
            str,
            u.Field(description="Shared authmethod modifier for this group"),
        ] = ""
        ip: Annotated[
            str,
            u.Field(description="Shared ip modifier for this group"),
        ] = ""

        def with_bind(
            self,
            bind: str,
        ) -> FlextLdifModelsAclConvert.AciAllowGroup:
            """Return a copy with ``bind`` appended, preserving immutable flow."""
            return FlextLdifModelsAclConvert.AciAllowGroup(
                permissions=self.permissions,
                binds=(*self.binds, bind),
                authmethod=self.authmethod,
                ip=self.ip,
            )

    class AciAllowGroups(m.FrozenModel):
        """Pydantic render grouping model replacing ad-hoc dict/list state."""

        groups: Annotated[
            tuple[FlextLdifModelsAclConvert.AciAllowGroup, ...],
            u.Field(description="Allow groups in first-seen render order"),
        ] = ()

        def with_allow(
            self,
            allow: FlextLdifModelsAclConvert.AciAllow,
            bind: str,
        ) -> FlextLdifModelsAclConvert.AciAllowGroups:
            """Return grouped allow state with one rendered bind rule appended."""
            permissions = tuple(allow.permissions)
            updated: tuple[FlextLdifModelsAclConvert.AciAllowGroup, ...] = ()
            matched = False
            for group in self.groups:
                same_permissions = tuple(group.permissions) == permissions
                same_modifiers = (
                    group.authmethod == allow.authmethod and group.ip == allow.ip
                )
                if same_permissions and same_modifiers:
                    updated = (*updated, group.with_bind(bind))
                    matched = True
                    continue
                updated = (*updated, group)
            if not matched:
                updated = (
                    *updated,
                    FlextLdifModelsAclConvert.AciAllowGroup(
                        permissions=permissions,
                        binds=(bind,),
                        authmethod=allow.authmethod,
                        ip=allow.ip,
                    ),
                )
            return FlextLdifModelsAclConvert.AciAllowGroups(groups=updated)

    class AclSubjectMatcher(m.ArbitraryTypesModel):
        """Parse descriptor: a compiled by-clause regex + group extraction map.

        ``value_group`` is either a capture-group index (int) or a literal subject
        value (str, e.g. ``"self"``/``"anyone"``); ``perms_group`` is the capture
        index holding the permission token list.
        """

        pattern: Annotated[
            t.RegexPattern,
            u.Field(description="Compiled by-clause matcher from c.Ldif"),
        ]
        subj_type: Annotated[
            str,
            u.Field(description="Subject keyword this matcher yields"),
        ]
        value_group: Annotated[
            int | str,
            u.Field(description="Capture-group index OR literal subject value"),
        ]
        perms_group: Annotated[
            int,
            u.Field(description="Capture-group index of the permission tokens"),
        ]

    class AclSubjectMatcherCatalog(m.FrozenModel):
        """Typed matcher catalog used by the OID ACL parser."""

        matchers: Annotated[
            tuple[FlextLdifModelsAclConvert.AclSubjectMatcher, ...],
            u.Field(description="OID by-clause subject matchers in priority order"),
        ] = ()

    class OidAclSubjectModifiers(m.FrozenModel):
        """Parsed optional OID by-clause modifiers."""

        bindmode: Annotated[
            str,
            u.Field(description="OID bindmode modifier value"),
        ] = ""
        bindipfilter: Annotated[
            str,
            u.Field(description="OID bindipfilter modifier value"),
        ] = ""
        added_object_constraint: Annotated[
            str,
            u.Field(description="OID added_object_constraint modifier value"),
        ] = ""


__all__: list[str] = ["FlextLdifModelsAclConvert"]
