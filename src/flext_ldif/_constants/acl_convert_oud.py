"""FlextLdifConstantsAclConvertOud - OUD-output ACL taxonomy (SSOT).

The OUD side of the OID→OUD ACL conversion: bind-rule keywords, ``userattr``
suffixes, permission maps, the canonical permission ordering, and the
high-level-container scope rules. Split from ``_constants/acl_convert.py``
(parse patterns) per the 200-LOC SUPREME LAW (AGENTS.md §3.1); composed into
``c.Ldif`` alongside it.
"""

from __future__ import annotations

from enum import StrEnum, unique
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar, Final

if TYPE_CHECKING:
    from collections.abc import Mapping


class FlextLdifConstantsAclConvertOud:
    """OUD-output ACL conversion constants (one flat namespace; into c.Ldif)."""

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

    ACL_SCOPE_BASE: Final[str] = "base"
    "OUD targetscope value for entry-level / anyone-scoped rules."
    DIRECTORY_MANAGER_DN: Final[str] = "cn=Directory Manager"
    "OUD root account that OID ``SuperUser`` maps to."
    LDAP_PREFIX: Final[str] = "ldap:///"
    "URL prefix wrapping a DN inside a ``groupdn``/``userdn`` bind-rule."
    SUBJECT_SELF: Final[str] = "self"
    SUBJECT_ANYONE: Final[str] = "anyone"
    OUD_ATTR_OR: Final[str] = "||"
    "OUD ``targetattr`` multi-attribute OR separator (``cn||sn||mail``)."
    OUD_ATTR_NEGATION: Final[str] = "!="
    "OUD ``targetattr`` negation operator (``targetattr!=...``)."
    ACI_PREFIX: Final[str] = "aci: "
    ACI_ATTR_NAME: Final[str] = "aci"
    "OUD ACL attribute name (replaces OID orclaci/orclentrylevelaci)."
    ACI_VERSION: Final[str] = "version 3.0"
    ACI_ALLOW: Final[str] = "allow"
    BIND_OR: Final[str] = " or "
    "Separator joining same-permission bind-rules inside one ``allow`` clause."
    UNKNOWN_CONTAINER: Final[str] = "Unknown"
    "acl-name container fallback when the DN has no ``cn=`` RDN."
    ACL_NAME_ENTRY: Final[str] = "Entry"
    ACL_NAME_ATTRS: Final[str] = "Attrs"
    PERM_NONE: Final[str] = "none"
    "OID permission token denying all access (``by X (none)``)."
    PERM_ALL: Final[str] = "all"
    "OID/OUD permission token granting all rights."

    # OID permission → OUD permission(s); None = negation/deny (dropped).
    ENTRY_PERM_MAP: ClassVar[Mapping[str, str | None]] = MappingProxyType({
        "all": "all",
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
    ATTR_PERM_MAP: ClassVar[Mapping[str, str | None]] = MappingProxyType({
        "all": "all",
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
    # OID ``noX`` negation token → its base permission (for complement computation).
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
    # OUD perms that are security-sensitive when granted to anyone (review flag).
    SENSITIVE_PERMS: Final[frozenset[str]] = frozenset(
        {"proxy", "write", "delete", "add", "selfwrite"},
    )
    # Canonical OUD permission ordering for deterministic aci assembly.
    PERM_ORDERED: Final[tuple[str, ...]] = (
        "all",
        "read",
        "search",
        "write",
        "selfwrite",
        "compare",
        "add",
        "delete",
        "proxy",
    )
    # DN suffixes (relative to base) treated as high-level containers (filter anyone).
    HIGH_LEVEL_CONTAINER_SUFFIXES: Final[tuple[str, ...]] = (
        "",
        "dc=network,",
        "cn=users,dc=network,",
        "cn=groups,dc=network,",
        "cn=perfis,dc=network,",
    )


__all__: list[str] = ["FlextLdifConstantsAclConvertOud"]
