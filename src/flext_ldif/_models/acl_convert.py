"""ACL-conversion models — the typed OID policy and the OUD ACI statements.

Value objects of the OID→OUD ACL conversion: parsed OID rules, the injected
source directory, the evaluation levels and resolutions of the OID policy,
and the OUD ACI statements emitted from them. They carry data only; the
OID dialect (``servers/_oid``) owns the grammar and the conversion rules.
Composed into ``m.Ldif`` via MRO.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Annotated

from flext_core import m

from flext_ldif import p, t


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
            m.Field(description="OID bindmode modifier (no exact OUD authmethod)"),
        ] = ""
        bindipfilter: Annotated[
            str,
            m.Field(description="OID bindipfilter modifier (orclipaddress filter)"),
        ] = ""
        added_object_constraint: Annotated[
            str,
            m.Field(description="OID added_object_constraint modifier"),
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
            tuple[
                Annotated[
                    p.Ldif.OidAclSubject,
                    t.schema_for_model(FlextLdifModelsAclConvert.OidAclSubject),
                ],
                ...,
            ],
            m.Field(description="Parsed by-clause subjects"),
        ] = ()
        raw_line: Annotated[str, m.Field(description="Original raw OID ACL line")] = ""
        deny_group_override: Annotated[
            bool,
            m.Field(description="Whether the object carries DenyGroupOverride"),
        ] = False
        append_to_all: Annotated[
            bool,
            m.Field(description="Whether the object carries AppendToAll"),
        ] = False

    class AclPermissionResolution(m.FrozenModel):
        """OID rights one OID access list grants and denies (OID-30 §30.1.4.3).

        Each access level is granted or denied independently and ``noxxx``
        denies ``xxx``; ``none`` denies every right of the target kind (Table
        30-2). A right both granted and denied in one list is denied. Rights
        the list does not name stay unresolved and appear in neither set.
        """

        allow: Annotated[
            frozenset[str],
            m.Field(description="Granted OID rights of the target kind"),
        ] = frozenset()
        deny: Annotated[
            frozenset[str],
            m.Field(description="Denied OID rights of the target kind"),
        ] = frozenset()

    class AclSecurityGroup(m.FrozenModel):
        """One source group entry: its OID security classes and nesting."""

        classes: Annotated[
            frozenset[str],
            m.Field(description="Case-folded OID security group classes"),
        ] = frozenset()
        member_groups: Annotated[
            frozenset[str],
            m.Field(description="DN keys of the member entries that are groups"),
        ] = frozenset()
        dynamic: Annotated[
            bool,
            m.Field(description="Whether membership is computed (memberURL)"),
        ] = False

    class AclDirectory(m.FrozenModel):
        """The migrated source directory injected into ACL conversion.

        ``entries`` maps every migrated DN key to the DN as read; it is the
        child set of the per-child denial split. ``groups`` holds every group
        entry with its security classes (R8, OID-30 §30.1.3.4.6).
        """

        entries: Annotated[
            Mapping[str, str],
            m.Field(
                default_factory=lambda: MappingProxyType[str, str]({}),
                description="DN key to DN as read, for every migrated entry",
            ),
        ]
        groups: Annotated[
            Mapping[
                str,
                Annotated[
                    p.Ldif.AclSecurityGroup,
                    t.schema_for_model(FlextLdifModelsAclConvert.AclSecurityGroup),
                ],
            ],
            m.Field(
                default_factory=lambda: MappingProxyType[str, p.Ldif.AclSecurityGroup]({}),
                description="Group entries keyed by DN key",
            ),
        ]

    class AclBindLeaf(m.FrozenModel):
        """One OUD bind-rule subject converted from one OID subject (R8)."""

        kind: Annotated[str, m.Field(description="Bind leaf kind")]
        value: Annotated[str, m.Field(description="Bind value as rendered")]
        key: Annotated[str, m.Field(description="Comparison key of the value")]

    class AclBindRule(m.FrozenModel):
        """A subject with the subjects it excludes: ``S and not (E1 or E2)``."""

        include: Annotated[
            Annotated[
                p.Ldif.AclBindLeaf,
                t.schema_for_model(FlextLdifModelsAclConvert.AclBindLeaf),
            ],
            m.Field(description="Subject the rule matches"),
        ]
        exclude: Annotated[
            tuple[
                Annotated[
                    p.Ldif.AclBindLeaf,
                    t.schema_for_model(FlextLdifModelsAclConvert.AclBindLeaf),
                ],
                ...,
            ],
            m.Field(description="Subjects excluded from the match"),
        ] = ()

    class AclAttrSet(m.FrozenModel):
        """An attribute set: listed names, or every attribute but ``names``."""

        names: Annotated[
            frozenset[str],
            m.Field(description="Case-folded attribute names"),
        ] = frozenset()
        negated: Annotated[
            bool,
            m.Field(description="Every attribute except ``names``"),
        ] = False

    class AclClause(m.FrozenModel):
        """One OID by-clause with its converted subject and OID rights."""

        index: Annotated[int, m.Field(description="1-based clause position")]
        subject: Annotated[
            Annotated[
                p.Ldif.OidAclSubject,
                t.schema_for_model(FlextLdifModelsAclConvert.OidAclSubject),
            ],
            m.Field(description="The OID subject as parsed"),
        ]
        leaf: Annotated[
            Annotated[
                p.Ldif.AclBindLeaf,
                t.schema_for_model(FlextLdifModelsAclConvert.AclBindLeaf),
            ]
            | None,
            m.Field(description="OUD subject, or None when no session matches"),
        ] = None
        outcome: Annotated[
            str,
            m.Field(description="Rule that decided a subject without session"),
        ] = ""
        allow: Annotated[
            frozenset[str],
            m.Field(description="Granted OID rights"),
        ] = frozenset()
        deny: Annotated[
            frozenset[str],
            m.Field(description="Denied OID rights"),
        ] = frozenset()

    class AclLevelRule(m.FrozenModel):
        """One OID ACI at its evaluation level (OID-30 §30.1.6)."""

        level: Annotated[
            str,
            m.Field(description="Origin attribute: orclaci or orclentrylevelaci"),
        ]
        dn: Annotated[str, m.Field(description="Carrier DN as read")]
        key: Annotated[str, m.Field(description="Carrier DN key")]
        index: Annotated[int, m.Field(description="1-based position at the level")]
        rule: Annotated[
            Annotated[
                p.Ldif.OidAclRule,
                t.schema_for_model(FlextLdifModelsAclConvert.OidAclRule),
            ],
            m.Field(description="The parsed OID ACI"),
        ]
        attrs: Annotated[
            Annotated[
                p.Ldif.AclAttrSet,
                t.schema_for_model(FlextLdifModelsAclConvert.AclAttrSet),
            ]
            | None,
            m.Field(description="Attribute target; None for an entry target"),
        ] = None
        target_filter: Annotated[
            str | None,
            m.Field(description="Parenthesized OID filter, if present"),
        ] = None
        clauses: Annotated[
            tuple[
                Annotated[
                    p.Ldif.AclClause,
                    t.schema_for_model(FlextLdifModelsAclConvert.AclClause),
                ],
                ...,
            ],
            m.Field(description="By-clauses in source order"),
        ] = ()

    class AclResolution(m.FrozenModel):
        """One OID right decided by one clause of one ACI (R6a)."""

        clause: Annotated[int, m.Field(description="Deciding clause position")]
        right: Annotated[str, m.Field(description="OID right")]
        effect: Annotated[str, m.Field(description="allow or deny")]
        leaf: Annotated[
            Annotated[
                p.Ldif.AclBindLeaf,
                t.schema_for_model(FlextLdifModelsAclConvert.AclBindLeaf),
            ],
            m.Field(description="Subject of the clause"),
        ]
        grantors: Annotated[
            tuple[
                Annotated[
                    p.Ldif.AclBindLeaf,
                    t.schema_for_model(FlextLdifModelsAclConvert.AclBindLeaf),
                ],
                ...,
            ],
            m.Field(description="Subjects the same ACI grants the right to"),
        ] = ()
        added_object_constraint: Annotated[
            str,
            m.Field(description="OID added-object constraint of the clause"),
        ] = ""

    class AclForm(m.FrozenModel):
        """OUD rights, attributes, filter and scope of one decision."""

        rights: Annotated[tuple[str, ...], m.Field(description="OUD rights")]
        attrs: Annotated[
            Annotated[
                p.Ldif.AclAttrSet,
                t.schema_for_model(FlextLdifModelsAclConvert.AclAttrSet),
            ],
            m.Field(description="OUD targetattr set"),
        ]
        targetfilter: Annotated[
            str | None,
            m.Field(description="OUD targetfilter"),
        ] = None
        targetscope: Annotated[
            str | None,
            m.Field(description="OUD targetscope; None is the subtree default"),
        ] = None
        rule: Annotated[str, m.Field(description="Conversion rule applied")]

    class AclDecision(m.FrozenModel):
        """One resolution with its OUD form and bind rule."""

        rule: Annotated[
            Annotated[
                p.Ldif.AclLevelRule,
                t.schema_for_model(FlextLdifModelsAclConvert.AclLevelRule),
            ],
            m.Field(description="Source ACI"),
        ]
        resolution: Annotated[
            Annotated[
                p.Ldif.AclResolution,
                t.schema_for_model(FlextLdifModelsAclConvert.AclResolution),
            ],
            m.Field(description="Decided right"),
        ]
        form: Annotated[
            Annotated[
                p.Ldif.AclForm, t.schema_for_model(FlextLdifModelsAclConvert.AclForm)
            ],
            m.Field(description="OUD form"),
        ]
        bind: Annotated[
            Annotated[
                p.Ldif.AclBindRule,
                t.schema_for_model(FlextLdifModelsAclConvert.AclBindRule),
            ],
            m.Field(description="OUD bind rule"),
        ]

    class AclRegion(m.FrozenModel):
        """Where a statement lands and the part of the subtree it covers."""

        anchor: Annotated[str, m.Field(description="Anchor DN key")]
        scope: Annotated[
            str | None,
            m.Field(description="Region scope; None is the whole subtree"),
        ] = None
        target: Annotated[
            str | None,
            m.Field(description="OUD target pattern without the URL prefix"),
        ] = None
        target_negated: Annotated[
            bool,
            m.Field(description="Whether the target is an exclusion"),
        ] = False

    class AclNearerGrant(m.FrozenModel):
        """A grant of a nearer evaluation level inside a denial's region."""

        key: Annotated[str, m.Field(description="Level DN key")]
        level: Annotated[str, m.Field(description="Level attribute")]
        leaf: Annotated[
            Annotated[
                p.Ldif.AclBindLeaf,
                t.schema_for_model(FlextLdifModelsAclConvert.AclBindLeaf),
            ],
            m.Field(description="Granted subject"),
        ]

    class AciStatement(m.FrozenModel):
        """One OUD ACI value placed on one entry."""

        dn: Annotated[str, m.Field(description="Entry that carries the ACI")]
        effect: Annotated[str, m.Field(description="allow or deny")]
        rights: Annotated[tuple[str, ...], m.Field(description="OUD rights")]
        attrs: Annotated[
            Annotated[
                p.Ldif.AclAttrSet,
                t.schema_for_model(FlextLdifModelsAclConvert.AclAttrSet),
            ],
            m.Field(description="OUD targetattr set"),
        ]
        targetfilter: Annotated[
            str | None,
            m.Field(description="OUD targetfilter"),
        ] = None
        targetscope: Annotated[
            str | None,
            m.Field(description="OUD targetscope"),
        ] = None
        target: Annotated[
            str | None,
            m.Field(description="OUD target pattern without the URL prefix"),
        ] = None
        target_negated: Annotated[
            bool,
            m.Field(description="Whether the target is ``target!=``"),
        ] = False
        bind: Annotated[
            Annotated[
                p.Ldif.AclBindRule,
                t.schema_for_model(FlextLdifModelsAclConvert.AclBindRule),
            ],
            m.Field(description="OUD bind rule"),
        ]
        rule: Annotated[str, m.Field(description="Conversion rule applied")]
        name: Annotated[str, m.Field(description="acl name: the origin")]
        origin_dn: Annotated[str, m.Field(description="Source ACL carrier DN")]
        origin_index: Annotated[
            int,
            m.Field(description="Source ACI position at its level"),
        ]
        origin_level: Annotated[
            str,
            m.Field(description="Source ACL attribute"),
        ]

    class AclConversionEvent(m.FrozenModel):
        """One conversion fact the operator reviews (rule and source)."""

        rule: Annotated[str, m.Field(description="Rule or exception identifier")]
        dn: Annotated[str, m.Field(description="Source ACL carrier DN")]
        detail: Annotated[str, m.Field(description="What the rule decided")]

    class AclDirectoryConversion(m.FrozenModel):
        """OID→OUD ACL conversion of a whole directory.

        ``values`` maps the DN key of each entry that receives OUD ``aci``
        values to those values; ``consumed`` holds the DN keys whose OID ACL
        attributes the conversion consumed.
        """

        statements: Annotated[
            tuple[
                Annotated[
                    p.Ldif.AciStatement,
                    t.schema_for_model(FlextLdifModelsAclConvert.AciStatement),
                ],
                ...,
            ],
            m.Field(description="Emitted ACI statements in emission order"),
        ] = ()
        values: Annotated[
            Mapping[str, tuple[str, ...]],
            m.Field(
                default_factory=lambda: MappingProxyType[str, tuple[str, ...]]({}),
                description="Rendered aci values by receiving DN key",
            ),
        ]
        events: Annotated[
            tuple[
                Annotated[
                    p.Ldif.AclConversionEvent,
                    t.schema_for_model(FlextLdifModelsAclConvert.AclConversionEvent),
                ],
                ...,
            ],
            m.Field(description="Operator-review events in order"),
        ] = ()
        consumed: Annotated[
            frozenset[str],
            m.Field(description="DN keys whose OID ACLs were consumed"),
        ] = frozenset()

    class AclEntryConversion(m.FrozenModel):
        """OID→OUD ACL conversion recorded on one entry."""

        statements: Annotated[
            tuple[
                Annotated[
                    p.Ldif.AciStatement,
                    t.schema_for_model(FlextLdifModelsAclConvert.AciStatement),
                ],
                ...,
            ],
            m.Field(description="ACI statements placed on this entry"),
        ] = ()
        events: Annotated[
            tuple[
                Annotated[
                    p.Ldif.AclConversionEvent,
                    t.schema_for_model(FlextLdifModelsAclConvert.AclConversionEvent),
                ],
                ...,
            ],
            m.Field(description="Events of the ACLs this entry carried"),
        ] = ()
        oracle_internal_skip: Annotated[
            bool,
            m.Field(description="Whether the DN is Oracle-internal (not migrated)"),
        ] = False

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
            tuple[
                Annotated[
                    p.Ldif.AclSubjectMatcher,
                    t.schema_for_model(FlextLdifModelsAclConvert.AclSubjectMatcher),
                ],
                ...,
            ],
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
