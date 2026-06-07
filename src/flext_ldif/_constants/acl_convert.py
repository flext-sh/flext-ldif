"""FlextLdifConstantsAclConvert - OID→OUD ACL conversion constants (SSOT).

Faithful port of the proven oracle ``algar-oud-mig/scripts/_constants/acl_converter.py``
into flext-ldif as the single source of truth for OID orclaci/orclentrylevelaci →
OUD aci conversion (parse patterns, permission maps, subject/target taxonomy, scope
rules). Owns every compiled ``re.Pattern`` it needs; consumers import the ``*_RE``
authorities — ``import re`` outside this module is forbidden (AGENTS.md §3.1).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from enum import StrEnum, unique
from types import MappingProxyType
from typing import ClassVar, Final

from flext_ldif._typings.base import FlextLdifTypesBase as t


class FlextLdifConstantsAclConvert:
    """OID→OUD ACL conversion constants (one flat namespace; composed into c.Ldif)."""

    @unique
    class AclConvertType(StrEnum):
        """OID ACL attribute kinds carrying access rules."""

        ORCLACI = "orclaci"
        ORCLENTRYLEVELACI = "orclentrylevelaci"

    @unique
    class AclTargetType(StrEnum):
        """OID ACL target kinds."""

        ENTRY = "entry"
        ATTR = "attr"

    @unique
    class OudSubjectType(StrEnum):
        """OUD aci bind-rule keywords."""

        GROUPDN = "groupdn"
        USERDN = "userdn"
        USERATTR = "userattr"

    @unique
    class UserAttrSuffix(StrEnum):
        """OUD ``userattr`` value suffixes."""

        USERDN = "#USERDN"
        GROUPDN = "#GROUPDN"

    ACL_ACCESS_TO: Final[str] = "access to"
    "Literal prefix after the ACL attribute name in an OID rule."
    ACL_WILDCARD: Final[str] = "*"
    "OID wildcard for 'all attributes' / 'anyone' targets."
    ACL_SCOPE_BASE: Final[str] = "base"
    "OUD targetscope value for entry-level / anyone-scoped rules."

    ATTR_PATTERN_RE: ClassVar[t.RegexPattern] = re.compile(
        r"attr\s*(!?=)\s*\(([^)]*)\)",
        re.IGNORECASE,
    )
    "Matches ``attr=(a,b)`` / ``attr!=(a,b)`` — group(1)=operator, group(2)=attrs."
    FILTER_PREFIX_RE: ClassVar[t.RegexPattern] = re.compile(
        r"filter\s*=\s*\(",
        re.IGNORECASE,
    )
    "Matches the start of a ``filter=(...)`` clause (balanced-paren scan follows)."
    CN_EXTRACT_RE: ClassVar[t.RegexPattern] = re.compile(r"cn=([^,]+)", re.IGNORECASE)
    "Extracts the first ``cn=`` RDN value (for acl-name derivation)."
    WHITESPACE_RE: ClassVar[t.RegexPattern] = re.compile(r"\s+")
    DN_NORMALIZE_COMMA_RE: ClassVar[t.RegexPattern] = re.compile(r"\s*,\s*")
    DN_NORMALIZE_EQUALS_RE: ClassVar[t.RegexPattern] = re.compile(r"\s*=\s*")

    ENTRY_PERM_MAP: ClassVar[Mapping[str, str | None]] = MappingProxyType({
        "browse": "read, search",
        "add": "add",
        "delete": "delete",
        "proxy": "proxy",
        "noadd": None,
        "nodelete": None,
        "noproxy": None,
        "nobrowse": None,
        "none": None,
    })
    "OID entry-level permission → OUD permission(s); None = negation/deny (dropped)."
    ATTR_PERM_MAP: ClassVar[Mapping[str, str | None]] = MappingProxyType({
        "read": "read",
        "search": "search",
        "write": "write",
        "selfwrite": "selfwrite",
        "compare": "compare",
        "noread": None,
        "nosearch": None,
        "nowrite": None,
        "noselfwrite": None,
        "nocompare": None,
        "none": None,
    })
    "OID attribute-level permission → OUD permission; None = negation/deny (dropped)."
    NEGATION_TO_BASE: ClassVar[Mapping[str, str]] = MappingProxyType({
        "noread": "read",
        "nosearch": "search",
        "nowrite": "write",
        "noselfwrite": "selfwrite",
        "nocompare": "compare",
        "noadd": "add",
        "nodelete": "delete",
        "noproxy": "proxy",
        "nobrowse": "browse",
    })
    "OID ``noX`` negation token → its base permission (for complement computation)."
    ALL_ENTRY_PERMS: Final[frozenset[str]] = frozenset({
        "browse",
        "add",
        "delete",
        "proxy",
    })
    ALL_ATTR_PERMS: Final[frozenset[str]] = frozenset({
        "read",
        "search",
        "write",
        "selfwrite",
        "compare",
    })
    PERM_ORDERED: Final[tuple[str, ...]] = (
        "read",
        "search",
        "write",
        "selfwrite",
        "compare",
        "add",
        "delete",
        "proxy",
    )
    "Canonical OUD permission ordering for deterministic aci assembly."

    HIGH_LEVEL_CONTAINER_SUFFIXES: Final[tuple[str, ...]] = (
        "",
        "dc=network,",
        "cn=users,dc=network,",
        "cn=groups,dc=network,",
        "cn=perfis,dc=network,",
    )
    "DN suffixes (relative to base) treated as high-level containers (filter anyone)."


__all__: list[str] = ["FlextLdifConstantsAclConvert"]
