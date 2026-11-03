# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/acl_convert
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_cli import FlextCliProtocols

if TYPE_CHECKING:
    from flext_ldif import t
    from flext_ldif._constants import FlextLdifConstantsAclConvert


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
            """OID bindmode modifier → OUD authmethod."""
            ...

        @property
        def bindipfilter(self) -> str:
            """OID bindipfilter modifier → OUD ip."""
            ...

        @property
        def added_object_constraint(self) -> str:
            """OID added_object_constraint modifier (note only)."""
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

    @runtime_checkable
    class AciAllow(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def subject_type(self) -> str:
            """OUD bind-rule keyword: userdn | groupdn | userattr."""
            ...

        @property
        def subject_value(self) -> str:
            """Bind-rule value, e.g. ldap:///cn=Directory Manager."""
            ...

        @property
        def permissions(self) -> Sequence[str]:
            """OUD permission tokens in canonical order."""
            ...

        @property
        def authmethod(self) -> str:
            """OUD authmethod bind-rule constraint (from bindmode)."""
            ...

        @property
        def ip(self) -> str:
            """OUD ip bind-rule constraint (from bindipfilter)."""
            ...

    @runtime_checkable
    class AclSubjectOutcome(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def subject(self) -> FlextLdifProtocolsAclConvert.OidAclSubject:
            """The OID subject exactly as parsed."""
            ...

        @property
        def kind(self) -> FlextLdifConstantsAclConvert.AclSubjectOutcomeKind:
            """Conversion outcome for this subject."""
            ...

        @property
        def allow(self) -> FlextLdifProtocolsAclConvert.AciAllow | None:
            """Final allow clause of a GRANTED subject."""
            ...

        @property
        def wildcard_rewritten(self) -> bool:
            """Whether regex→wildcard rewrote the bind DN."""
            ...

        @property
        def complement_calculated(self) -> bool:
            """Structural member projected from the owning model.

            Whether the granted permissions are the complement of negation-only OID
            permissions.
            """
            ...

        @property
        def display_value(self) -> str:
            """Bind value shown for OUT_OF_SCOPE / UNGRANTED."""
            ...

    @runtime_checkable
    class AciRule(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def dn(self) -> str:
            """Entry DN that owns the aci."""
            ...

        @property
        def targetattr(self) -> str:
            """Targetattr expression, e.g. '*' or 'cn||sn'."""
            ...

        @property
        def targetfilter(self) -> str | None:
            """Targetfilter expression, if present."""
            ...

        @property
        def targetscope(self) -> str | None:
            """targetscope, e.g. 'base', if present."""
            ...

        @property
        def acl_name(self) -> str:
            """Human-readable acl name."""
            ...

        @property
        def allows(self) -> tuple[FlextLdifProtocolsAclConvert.AciAllow, ...]:
            """allow() clauses."""
            ...

        @property
        def target_type(self) -> str:
            """OID target kind of the source rule: entry | attr."""
            ...

        @property
        def outcomes(
            self,
        ) -> tuple[FlextLdifProtocolsAclConvert.AclSubjectOutcome, ...]:
            """Per-subject conversion outcomes in input order."""
            ...

    @runtime_checkable
    class AclEntryConversion(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def rules(self) -> tuple[FlextLdifProtocolsAclConvert.AciRule, ...]:
            """Assembled aci rules in OID line order."""
            ...

        @property
        def oracle_internal_skip(self) -> bool:
            """Whether the DN is Oracle-internal (not migrated)."""
            ...

    @runtime_checkable
    class AciAllowGroup(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def permissions(self) -> Sequence[str]:
            """Canonical permission tuple shared by this group."""
            ...

        @property
        def binds(self) -> Sequence[str]:
            """Rendered bind rules joined with OUD 'or'."""
            ...

        @property
        def authmethod(self) -> str:
            """Shared authmethod modifier for this group."""
            ...

        @property
        def ip(self) -> str:
            """Shared ip modifier for this group."""
            ...

    @runtime_checkable
    class AciAllowGroups(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def groups(self) -> tuple[FlextLdifProtocolsAclConvert.AciAllowGroup, ...]:
            """Allow groups in first-seen render order."""
            ...

        def with_allow(
            self, allow: FlextLdifProtocolsAclConvert.AciAllow, bind: str
        ) -> FlextLdifProtocolsAclConvert.AciAllowGroups:
            """Return grouped allow state with one rendered bind rule appended."""
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
