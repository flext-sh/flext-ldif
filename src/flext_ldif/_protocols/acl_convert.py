# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/acl_convert
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_cli import FlextCliProtocols

if TYPE_CHECKING:
    from flext_ldif import t


class FlextLdifProtocolsAclConvert:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class OidAclSubject(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def subject_type(self) -> str:
            """Parsed subject keyword (group/dn/self/anyone/...)."""
            ...

        @property
        def value(self) -> str:
            """Subject value: DN, group DN, or attribute name."""
            ...

        @property
        def permissions(self) -> Sequence[str]:
            """Raw OID permission tokens for this by-clause."""
            ...

        @property
        def bindmode(self) -> str:
            """OID bindmode modifier (no exact OUD authmethod)."""
            ...

        @property
        def bindipfilter(self) -> str:
            """OID bindipfilter modifier (orclipaddress filter)."""
            ...

        @property
        def added_object_constraint(self) -> str:
            """OID added_object_constraint modifier."""
            ...

    @runtime_checkable
    class OidAclRule(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def dn(self) -> str:
            """Entry DN that owns the ACL."""
            ...

        @property
        def acl_type(self) -> str:
            """Orclaci | orclentrylevelaci."""
            ...

        @property
        def target_type(self) -> str:
            """Entry | attr."""
            ...

        @property
        def target_attrs(self) -> str:
            """'*' | comma-list | '!=comma-list'."""
            ...

        @property
        def target_filter(self) -> str | None:
            """LDAP filter expression, if present."""
            ...

        @property
        def subjects(self) -> tuple[FlextLdifProtocolsAclConvert.OidAclSubject, ...]:
            """Parsed by-clause subjects."""
            ...

        @property
        def raw_line(self) -> str:
            """Original raw OID ACL line."""
            ...

        @property
        def deny_group_override(self) -> bool:
            """Whether the object carries DenyGroupOverride."""
            ...

        @property
        def append_to_all(self) -> bool:
            """Whether the object carries AppendToAll."""
            ...

    @runtime_checkable
    class AclPermissionResolution(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def allow(self) -> frozenset[str]:
            """Granted OID rights of the target kind."""
            ...

        @property
        def deny(self) -> frozenset[str]:
            """Denied OID rights of the target kind."""
            ...

    @runtime_checkable
    class AclSecurityGroup(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def classes(self) -> frozenset[str]:
            """Case-folded OID security group classes."""
            ...

        @property
        def member_groups(self) -> frozenset[str]:
            """DN keys of the member entries that are groups."""
            ...

        @property
        def dynamic(self) -> bool:
            """Whether membership is computed (memberURL)."""
            ...

    @runtime_checkable
    class AclDirectory(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def entries(self) -> Mapping[str, str]:
            """DN key to DN as read, for every migrated entry."""
            ...

        @property
        def groups(self) -> Mapping[str, FlextLdifProtocolsAclConvert.AclSecurityGroup]:
            """Group entries keyed by DN key."""
            ...

    @runtime_checkable
    class AclBindLeaf(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def kind(self) -> str:
            """Bind leaf kind."""
            ...

        @property
        def value(self) -> str:
            """Bind value as rendered."""
            ...

        @property
        def key(self) -> str:
            """Comparison key of the value."""
            ...

    @runtime_checkable
    class AclBindRule(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def include(self) -> FlextLdifProtocolsAclConvert.AclBindLeaf:
            """Subject the rule matches."""
            ...

        @property
        def exclude(self) -> tuple[FlextLdifProtocolsAclConvert.AclBindLeaf, ...]:
            """Subjects excluded from the match."""
            ...

    @runtime_checkable
    class AclAttrSet(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def names(self) -> frozenset[str]:
            """Case-folded attribute names."""
            ...

        @property
        def negated(self) -> bool:
            """Every attribute except ``names``."""
            ...

    @runtime_checkable
    class AclClause(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def index(self) -> int:
            """1-based clause position."""
            ...

        @property
        def subject(self) -> FlextLdifProtocolsAclConvert.OidAclSubject:
            """The OID subject as parsed."""
            ...

        @property
        def leaf(self) -> FlextLdifProtocolsAclConvert.AclBindLeaf | None:
            """OUD subject, or None when no session matches."""
            ...

        @property
        def outcome(self) -> str:
            """Rule that decided a subject without session."""
            ...

        @property
        def allow(self) -> frozenset[str]:
            """Granted OID rights."""
            ...

        @property
        def deny(self) -> frozenset[str]:
            """Denied OID rights."""
            ...

    @runtime_checkable
    class AclLevelRule(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def level(self) -> str:
            """Origin attribute: orclaci or orclentrylevelaci."""
            ...

        @property
        def dn(self) -> str:
            """Carrier DN as read."""
            ...

        @property
        def key(self) -> str:
            """Carrier DN key."""
            ...

        @property
        def index(self) -> int:
            """1-based position at the level."""
            ...

        @property
        def rule(self) -> FlextLdifProtocolsAclConvert.OidAclRule:
            """The parsed OID ACI."""
            ...

        @property
        def attrs(self) -> FlextLdifProtocolsAclConvert.AclAttrSet | None:
            """Attribute target; None for an entry target."""
            ...

        @property
        def target_filter(self) -> str | None:
            """Parenthesized OID filter, if present."""
            ...

        @property
        def clauses(self) -> tuple[FlextLdifProtocolsAclConvert.AclClause, ...]:
            """By-clauses in source order."""
            ...

    @runtime_checkable
    class AclResolution(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def clause(self) -> int:
            """Deciding clause position."""
            ...

        @property
        def right(self) -> str:
            """OID right."""
            ...

        @property
        def effect(self) -> str:
            """Allow or deny."""
            ...

        @property
        def leaf(self) -> FlextLdifProtocolsAclConvert.AclBindLeaf:
            """Subject of the clause."""
            ...

        @property
        def grantors(self) -> tuple[FlextLdifProtocolsAclConvert.AclBindLeaf, ...]:
            """Subjects the same ACI grants the right to."""
            ...

        @property
        def added_object_constraint(self) -> str:
            """OID added-object constraint of the clause."""
            ...

    @runtime_checkable
    class AclForm(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def rights(self) -> tuple[str, ...]:
            """OUD rights."""
            ...

        @property
        def attrs(self) -> FlextLdifProtocolsAclConvert.AclAttrSet:
            """OUD targetattr set."""
            ...

        @property
        def targetfilter(self) -> str | None:
            """OUD targetfilter."""
            ...

        @property
        def targetscope(self) -> str | None:
            """OUD targetscope; None is the subtree default."""
            ...

        @property
        def rule(self) -> str:
            """Conversion rule applied."""
            ...

    @runtime_checkable
    class AclDecision(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def rule(self) -> FlextLdifProtocolsAclConvert.AclLevelRule:
            """Source ACI."""
            ...

        @property
        def resolution(self) -> FlextLdifProtocolsAclConvert.AclResolution:
            """Decided right."""
            ...

        @property
        def form(self) -> FlextLdifProtocolsAclConvert.AclForm:
            """OUD form."""
            ...

        @property
        def bind(self) -> FlextLdifProtocolsAclConvert.AclBindRule:
            """OUD bind rule."""
            ...

    @runtime_checkable
    class AclRegion(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def anchor(self) -> str:
            """Anchor DN key."""
            ...

        @property
        def scope(self) -> str | None:
            """Region scope; None is the whole subtree."""
            ...

        @property
        def target(self) -> str | None:
            """OUD target pattern without the URL prefix."""
            ...

        @property
        def target_negated(self) -> bool:
            """Whether the target is an exclusion."""
            ...

    @runtime_checkable
    class AclNearerGrant(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def key(self) -> str:
            """Level DN key."""
            ...

        @property
        def level(self) -> str:
            """Level attribute."""
            ...

        @property
        def leaf(self) -> FlextLdifProtocolsAclConvert.AclBindLeaf:
            """Granted subject."""
            ...

    @runtime_checkable
    class AciStatement(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def dn(self) -> str:
            """Entry that carries the ACI."""
            ...

        @property
        def effect(self) -> str:
            """Allow or deny."""
            ...

        @property
        def rights(self) -> tuple[str, ...]:
            """OUD rights."""
            ...

        @property
        def attrs(self) -> FlextLdifProtocolsAclConvert.AclAttrSet:
            """OUD targetattr set."""
            ...

        @property
        def targetfilter(self) -> str | None:
            """OUD targetfilter."""
            ...

        @property
        def targetscope(self) -> str | None:
            """OUD targetscope."""
            ...

        @property
        def target(self) -> str | None:
            """OUD target pattern without the URL prefix."""
            ...

        @property
        def target_negated(self) -> bool:
            """Whether the target is ``target!=``."""
            ...

        @property
        def bind(self) -> FlextLdifProtocolsAclConvert.AclBindRule:
            """OUD bind rule."""
            ...

        @property
        def rule(self) -> str:
            """Conversion rule applied."""
            ...

        @property
        def name(self) -> str:
            """Acl name: the origin."""
            ...

        @property
        def origin_dn(self) -> str:
            """Source ACL carrier DN."""
            ...

        @property
        def origin_index(self) -> int:
            """Source ACI position at its level."""
            ...

        @property
        def origin_level(self) -> str:
            """Source ACL attribute."""
            ...

    @runtime_checkable
    class AclConversionEvent(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def rule(self) -> str:
            """Rule or exception identifier."""
            ...

        @property
        def dn(self) -> str:
            """Source ACL carrier DN."""
            ...

        @property
        def detail(self) -> str:
            """What the rule decided."""
            ...

    @runtime_checkable
    class AclDirectoryConversion(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def statements(self) -> tuple[FlextLdifProtocolsAclConvert.AciStatement, ...]:
            """Emitted ACI statements in emission order."""
            ...

        @property
        def values(self) -> Mapping[str, tuple[str, ...]]:
            """Rendered aci values by receiving DN key."""
            ...

        @property
        def events(self) -> tuple[FlextLdifProtocolsAclConvert.AclConversionEvent, ...]:
            """Operator-review events in order."""
            ...

        @property
        def consumed(self) -> frozenset[str]:
            """DN keys whose OID ACLs were consumed."""
            ...

    @runtime_checkable
    class AclEntryConversion(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def statements(self) -> tuple[FlextLdifProtocolsAclConvert.AciStatement, ...]:
            """ACI statements placed on this entry."""
            ...

        @property
        def events(self) -> tuple[FlextLdifProtocolsAclConvert.AclConversionEvent, ...]:
            """Events of the ACLs this entry carried."""
            ...

        @property
        def oracle_internal_skip(self) -> bool:
            """Whether the DN is Oracle-internal (not migrated)."""
            ...

    @runtime_checkable
    class AclSubjectMatcher(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        pattern: t.RegexPattern
        subj_type: str
        value_group: int | str
        perms_group: int

    @runtime_checkable
    class AclSubjectMatcherCatalog(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def matchers(
            self,
        ) -> tuple[FlextLdifProtocolsAclConvert.AclSubjectMatcher, ...]:
            """OID by-clause subject matchers in priority order."""
            ...

    @runtime_checkable
    class OidAclSubjectModifiers(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def bindmode(self) -> str:
            """OID bindmode modifier value."""
            ...

        @property
        def bindipfilter(self) -> str:
            """OID bindipfilter modifier value."""
            ...

        @property
        def added_object_constraint(self) -> str:
            """OID added_object_constraint modifier value."""
            ...


__all__: list[str] = [
    "FlextLdifProtocolsAclConvert",
]
