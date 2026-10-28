"""ACL-conversion models — OID rule / OUD aci typed value objects.

Cohesive home for the OID→OUD ACL conversion model layer (parsed OID rules,
assembled OUD aci rules, and the subject-matcher parse descriptor). Mirrors the
``_constants/acl_convert.py`` SSOT; composed into ``m.Ldif`` via MRO.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from collections.abc import Sequence
from typing import Annotated

from flext_core import m

from flext_ldif import c, t


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
            m.Field(description="Parsed subject keyword (group/dn/self/anyone/...)"),
        ]
        value: Annotated[
            str,
            m.Field(description="Subject value: DN, group DN, or attribute name"),
        ] = ""
        permissions: Annotated[
            Sequence[str],
            m.Field(description="Raw OID permission tokens for this by-clause"),
        ] = ()
        bindmode: Annotated[
            str,
            m.Field(description="OID bindmode modifier → OUD authmethod"),
        ] = ""
        bindipfilter: Annotated[
            str,
            m.Field(description="OID bindipfilter modifier → OUD ip"),
        ] = ""
        added_object_constraint: Annotated[
            str,
            m.Field(description="OID added_object_constraint modifier (note only)"),
        ] = ""

    class OidAclRule(m.FrozenModel):
        """A parsed OID ``orclaci``/``orclentrylevelaci`` rule (pre-conversion)."""

        dn: Annotated[str, m.Field(description="Entry DN that owns the ACL")]
        acl_type: Annotated[str, m.Field(description="orclaci | orclentrylevelaci")]
        target_type: Annotated[str, m.Field(description="entry | attr")]
        target_attrs: Annotated[
            str,
            m.Field(description="'*' | comma-list | '!=comma-list'"),
        ] = "*"
        target_filter: Annotated[
            str | None,
            m.Field(description="LDAP filter expression, if present"),
        ] = None
        subjects: Annotated[
            tuple[FlextLdifModelsAclConvert.OidAclSubject, ...],
            m.Field(description="Parsed by-clause subjects"),
        ] = ()
        raw_line: Annotated[str, m.Field(description="Original raw OID ACL line")] = ""

    class AciAllow(m.FrozenModel):
        """One OUD ``aci`` ``allow()`` clause: bind-rule subject + permission set."""

        subject_type: Annotated[
            str,
            m.Field(description="OUD bind-rule keyword: userdn | groupdn | userattr"),
        ]
        subject_value: Annotated[
            str,
            m.Field(description="Bind-rule value, e.g. ldap:///cn=Directory Manager"),
        ]
        permissions: Annotated[
            Sequence[str],
            m.Field(description="OUD permission tokens in canonical order"),
        ] = ()
        authmethod: Annotated[
            str,
            m.Field(description="OUD authmethod bind-rule constraint (from bindmode)"),
        ] = ""
        ip: Annotated[
            str,
            m.Field(description="OUD ip bind-rule constraint (from bindipfilter)"),
        ] = ""

    class AclSubjectOutcome(m.FrozenModel):
        """What conversion did with one OID by-clause subject, in input order.

        ``allow``, ``wildcard_rewritten`` and ``complement_calculated``
        describe a ``GRANTED`` subject.
        ``display_value`` is the converted bind DN after wildcarding for
        ``OUT_OF_SCOPE``, and for ``UNGRANTED`` the converted DN of a
        ``group``/``user`` subject or the raw value otherwise. An
        ``UNSUPPORTED`` subject's kind is its ``subject.subject_type``.
        """

        subject: Annotated[
            FlextLdifModelsAclConvert.OidAclSubject,
            m.Field(description="The OID subject exactly as parsed"),
        ]
        kind: Annotated[
            c.Ldif.AclSubjectOutcomeKind,
            m.Field(description="Conversion outcome for this subject"),
        ]
        allow: Annotated[
            FlextLdifModelsAclConvert.AciAllow | None,
            m.Field(description="Final allow clause of a GRANTED subject"),
        ] = None
        wildcard_rewritten: Annotated[
            bool,
            m.Field(description="Whether regex→wildcard rewrote the bind DN"),
        ] = False
        complement_calculated: Annotated[
            bool,
            m.Field(
                description="Whether the granted permissions are the complement "
                "of negation-only OID permissions",
            ),
        ] = False
        display_value: Annotated[
            str,
            m.Field(description="Bind value shown for OUT_OF_SCOPE / UNGRANTED"),
        ] = ""

    class AciRule(m.FrozenModel):
        """An OUD ``aci`` rule assembled from one OID rule (one rule → one aci)."""

        dn: Annotated[str, m.Field(description="Entry DN that owns the aci")]
        targetattr: Annotated[
            str,
            m.Field(description="targetattr expression, e.g. '*' or 'cn||sn'"),
        ] = "*"
        targetfilter: Annotated[
            str | None,
            m.Field(description="targetfilter expression, if present"),
        ] = None
        targetscope: Annotated[
            str | None,
            m.Field(description="targetscope, e.g. 'base', if present"),
        ] = None
        acl_name: Annotated[str, m.Field(description="Human-readable acl name")] = ""
        allows: Annotated[
            tuple[FlextLdifModelsAclConvert.AciAllow, ...],
            m.Field(description="allow() clauses"),
        ] = ()
        target_type: Annotated[
            str,
            m.Field(description="OID target kind of the source rule: entry | attr"),
        ] = ""
        outcomes: Annotated[
            tuple[FlextLdifModelsAclConvert.AclSubjectOutcome, ...],
            m.Field(description="Per-subject conversion outcomes in input order"),
        ] = ()

    class AclEntryConversion(m.FrozenModel):
        """OID→OUD ACL conversion of one entry: its rules or the Oracle skip."""

        rules: Annotated[
            tuple[FlextLdifModelsAclConvert.AciRule, ...],
            m.Field(description="Assembled aci rules in OID line order"),
        ] = ()
        oracle_internal_skip: Annotated[
            bool,
            m.Field(description="Whether the DN is Oracle-internal (not migrated)"),
        ] = False

    class AciAllowGroup(m.FrozenModel):
        """One render-time allow group keyed by identical OUD permission tokens."""

        permissions: Annotated[
            Sequence[str],
            m.Field(description="Canonical permission tuple shared by this group"),
        ] = ()
        binds: Annotated[
            Sequence[str],
            m.Field(description="Rendered bind rules joined with OUD 'or'"),
        ] = ()
        authmethod: Annotated[
            str,
            m.Field(description="Shared authmethod modifier for this group"),
        ] = ""
        ip: Annotated[str, m.Field(description="Shared ip modifier for this group")] = (
            ""
        )

    class AciAllowGroups(m.FrozenModel):
        """Pydantic render grouping model replacing ad-hoc dict/list state."""

        groups: Annotated[
            tuple[FlextLdifModelsAclConvert.AciAllowGroup, ...],
            m.Field(description="Allow groups in first-seen render order"),
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
                    updated = (
                        *updated,
                        FlextLdifModelsAclConvert.AciAllowGroup(
                            permissions=group.permissions,
                            binds=(*group.binds, bind),
                            authmethod=group.authmethod,
                            ip=group.ip,
                        ),
                    )
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
            m.Field(description="Compiled by-clause matcher from c.Ldif"),
        ]
        subj_type: Annotated[
            str,
            m.Field(description="Subject keyword this matcher yields"),
        ]
        value_group: Annotated[
            int | str,
            m.Field(description="Capture-group index OR literal subject value"),
        ]
        perms_group: Annotated[
            int,
            m.Field(description="Capture-group index of the permission tokens"),
        ]

    class AclSubjectMatcherCatalog(m.FrozenModel):
        """Typed matcher catalog used by the OID ACL parser."""

        matchers: Annotated[
            tuple[FlextLdifModelsAclConvert.AclSubjectMatcher, ...],
            m.Field(description="OID by-clause subject matchers in priority order"),
        ] = ()

    class OidAclSubjectModifiers(m.FrozenModel):
        """Parsed optional OID by-clause modifiers."""

        bindmode: Annotated[str, m.Field(description="OID bindmode modifier value")] = (
            ""
        )
        bindipfilter: Annotated[
            str,
            m.Field(description="OID bindipfilter modifier value"),
        ] = ""
        added_object_constraint: Annotated[
            str,
            m.Field(description="OID added_object_constraint modifier value"),
        ] = ""


__all__: list[str] = ["FlextLdifModelsAclConvert"]
