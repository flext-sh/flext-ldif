"""Oracle Internet Directory (OID) Servers.

The shared OID profile constants live in the ``_constants`` parts and are
composed here by MRO. The OID→OUD ACL conversion declarations below belong to
this dialect implementation only and are not part of the shared ``c.Ldif``
facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from enum import StrEnum, unique
from typing import TYPE_CHECKING, ClassVar

from flext_ldif._constants import (
    FlextLdifConstantsBase,
    FlextLdifConstantsServersOid as _OidConstants,
)
from flext_ldif.servers._rfc import FlextLdifConstantsServersRfc as _RfcConstants

if TYPE_CHECKING:
    from flext_ldif import t


class FlextLdifConstantsServersOid(
    _OidConstants,
    _RfcConstants,
):
    """OID server constants plus the OID→OUD ACL conversion declarations."""

    OID_ACL_OBJECT_KEYWORDS_RE: ClassVar[t.RegexPattern] = re.compile(
        r"^(?:(?P<dgo>DenyGroupOverride)\s*)?(?:(?P<ata>AppendToAll)\s*)?",
        re.IGNORECASE,
    )
    "Object keywords ``[DenyGroupOverride] [AppendToAll]`` after the filter (OID-A7)."
    OID_ACL_OBJECT_KEYWORD_RE: ClassVar[t.RegexPattern] = re.compile(
        r"\b(DenyGroupOverride|AppendToAll)\b",
        re.IGNORECASE,
    )
    "An object keyword found outside its BNF position (OID-A7 §A.7.1)."
    OID_ATTR_TARGET_RE: ClassVar[t.RegexPattern] = re.compile(
        r"attr\s*(!?=)\s*(?:\(([^)]*)\)|(\*)(?![^\s(]))",
        re.IGNORECASE,
    )
    "``attr=(list)``, ``attr!=(list)`` or ``attr=*`` (OID-A7 §A.7.1 ``<object>``)."

    OID_PREFIX_WILDCARD_RE: ClassVar[t.RegexPattern] = re.compile(
        r"^(?:\.\*|\*)\s*,\s*(?P<base>[^*]+)$",
    )
    "The only OID DN expression: ``*,<dn>`` (OID-A7 §A.7.1; ``.*,`` in OID-30 text)."
    OID_DN_EXPRESSION_RE: ClassVar[t.RegexPattern] = re.compile(
        r'[\[\]{}|^$?()*]|(?<!\\)\+|\\(?![,+"\\<>;=# ]|[0-9A-Fa-f]{2})',
    )
    "A regex construct or non-RFC 4514 escape inside an OID subject DN."
    _OID_SUBJ_MODIFIER: ClassVar[str] = (
        r"(?:\s+(?:added_object_constraint|constraintonaddedobject|bindmode"
        r"|bindipfilter)\s*=\s*"
        rf'(?:\({FlextLdifConstantsBase.LDAP_FILTER_BODY_PATTERN}\)|"[^"]*"))'
    )
    _OID_SUBJ_MODIFIERS: ClassVar[str] = rf"(?:{_OID_SUBJ_MODIFIER})*"
    _OID_SUBJ_PERMS: ClassVar[str] = rf"{_OID_SUBJ_MODIFIERS}\s*\(([^)]*)\)"
    _OID_SUBJ_END: ClassVar[str] = rf"{_OID_SUBJ_MODIFIERS}\s*$"

    OID_SUBJ_SUPERUSER_RE: ClassVar[t.RegexPattern] = re.compile(
        rf"by\s+SuperUser{_OID_SUBJ_PERMS}{_OID_SUBJ_END}",
        re.IGNORECASE,
    )
    "``by SuperUser [modifiers] (perms) [modifiers]`` (OID-A7 §A.7.1)."
    OID_SUBJ_GROUP_RE: ClassVar[t.RegexPattern] = re.compile(
        rf'by\s+group\s*=\s*"([^"]+)"{_OID_SUBJ_PERMS}{_OID_SUBJ_END}',
        re.IGNORECASE,
    )
    '``by group="<dn>" [modifiers] (perms) [modifiers]``.'
    OID_SUBJ_DN_RE: ClassVar[t.RegexPattern] = re.compile(
        rf'by\s+dn\s*=\s*"([^"]+)"{_OID_SUBJ_PERMS}{_OID_SUBJ_END}',
        re.IGNORECASE,
    )
    '``by dn="<regex>" [modifiers] (perms) [modifiers]``.'
    OID_SUBJ_QUOTED_DN_RE: ClassVar[t.RegexPattern] = re.compile(
        rf'by\s+"([^"]+)"{_OID_SUBJ_PERMS}{_OID_SUBJ_END}',
        re.IGNORECASE,
    )
    '``by "<dn>" [modifiers] (perms) [modifiers]``.'
    OID_SUBJ_SELF_RE: ClassVar[t.RegexPattern] = re.compile(
        rf"by\s+self{_OID_SUBJ_PERMS}{_OID_SUBJ_END}",
        re.IGNORECASE,
    )
    "``by self [modifiers] (perms) [modifiers]``."
    OID_SUBJ_ANYONE_RE: ClassVar[t.RegexPattern] = re.compile(
        rf"by\s+\*{_OID_SUBJ_PERMS}{_OID_SUBJ_END}",
        re.IGNORECASE,
    )
    "``by * [modifiers] (perms) [modifiers]``."
    OID_SUBJ_DNATTR_RE: ClassVar[t.RegexPattern] = re.compile(
        rf"by\s+dnattr\s*=\s*\(([^)]*)\){_OID_SUBJ_PERMS}{_OID_SUBJ_END}",
        re.IGNORECASE,
    )
    "``by dnattr=(<attr>) [modifiers] (perms) [modifiers]``."
    OID_SUBJ_GROUPATTR_RE: ClassVar[t.RegexPattern] = re.compile(
        rf"by\s+groupattr\s*=\s*\(([^)]*)\){_OID_SUBJ_PERMS}{_OID_SUBJ_END}",
        re.IGNORECASE,
    )
    "``by groupattr=(<attr>) [modifiers] (perms) [modifiers]``."
    OID_SUBJ_GUIDATTR_RE: ClassVar[t.RegexPattern] = re.compile(
        rf"by\s+guidattr\s*=\s*\(([^)]*)\){_OID_SUBJ_PERMS}{_OID_SUBJ_END}",
        re.IGNORECASE,
    )
    "``by guidattr=(<attr>) [modifiers] (perms) [modifiers]``."
    OID_BY_CLAUSE_RE: ClassVar[t.RegexPattern] = re.compile(
        r"by\s+(?:"
        r'(?:group|dn)\s*=\s*"[^"]+"'
        r'|"[^"]+"'
        r"|SuperUser|self|\*"
        r"|(?:dnattr|groupattr|guidattr)\s*=\s*\([^)]*\)"
        rf"){_OID_SUBJ_MODIFIERS}\s*\([^)]*\){_OID_SUBJ_MODIFIERS}",
        re.IGNORECASE,
    )
    "Each ``by <subject> [modifiers] (perms) [modifiers]`` clause of an OID ACL."
    OID_SUBJ_MODIFIER_RE: ClassVar[t.RegexPattern] = re.compile(
        r"(bindmode|bindipfilter|added_object_constraint|constraintonaddedobject)"
        r"\s*=\s*"
        rf'(?:\(({FlextLdifConstantsBase.LDAP_FILTER_BODY_PATTERN})\)|"([^"]*)")',
        re.IGNORECASE,
    )
    "One by-clause modifier: g1=kind, g2=paren-value, g3=quoted-value."
    OID_ADDED_OBJECT_MODIFIERS: ClassVar[frozenset[str]] = frozenset({
        "added_object_constraint",
        "constraintonaddedobject",
    })
    "Spellings of the added-object constraint modifier (OID-30 §30.1.4.2.4)."
    OID_ATTR_DESCRIPTOR_RE: ClassVar[t.RegexPattern] = re.compile(
        r"^(?:[A-Za-z][A-Za-z0-9-]*|\d+(?:\.\d+)+)(?:;[A-Za-z0-9-]+)*$",
    )
    "One attribute description: name or numeric OID plus options (RFC 4512)."

    OID_SECURITY_GROUP_CLASSES: ClassVar[frozenset[str]] = frozenset({
        "orclacpgroup",
        "orclprivilegegroup",
    })
    "Group classes whose membership OID evaluates for access (OID-30 §30.1.3.4.6)."
    OID_GROUP_CLASSES: ClassVar[frozenset[str]] = frozenset({
        "groupofnames",
        "groupofuniquenames",
        "groupofurls",
        "orclgroup",
        "orcldynamicgroup",
        "orclacpgroup",
        "orclprivilegegroup",
    })
    "Object classes that make an entry a group."
    OID_GROUP_MEMBER_ATTRS: ClassVar[frozenset[str]] = frozenset({
        "member",
        "uniquemember",
    })
    "Static membership attributes of a group entry."
    OID_DYNAMIC_MEMBER_ATTRS: ClassVar[frozenset[str]] = frozenset({
        "labeleduri",
        "memberurl",
    })
    "Attributes that compute group membership dynamically."

    OID_ATTR_OPTION_SEPARATOR: ClassVar[str] = ";"
    "Separator of an attribute description's options (RFC 4512 §2.5)."
    OID_ROOT_DSE_DN: ClassVar[str] = ""
    "DN of the root DSE, whose ``orclACI`` governs the whole DIT (OID-30 §30.3.2)."
    OID_LDAP_FILTER_ITEM_RE: ClassVar[t.RegexPattern] = re.compile(
        r"^(?:[A-Za-z][A-Za-z0-9-]*|\d+(?:\.\d+)+)(?:;[A-Za-z0-9-]+)*"
        r"(?:(?:~=|>=|<=)(?:[^()*\\\x00]|\\[0-9A-Fa-f]{2})*"
        r"|=(?:[^()\\\x00]|\\[0-9A-Fa-f]{2})*)$",
    )
    "One RFC 4515 simple, present or substring filter item, without parentheses."
    OID_LDAP_FILTER_EXTENSIBLE_RE: ClassVar[t.RegexPattern] = re.compile(
        r"^(?:(?:[A-Za-z][A-Za-z0-9-]*|\d+(?:\.\d+)+)(?:;[A-Za-z0-9-]+)*"
        r"(?::dn)?(?::(?:[A-Za-z][A-Za-z0-9-]*|\d+(?:\.\d+)+))?"
        r"|(?::dn)?:(?:[A-Za-z][A-Za-z0-9-]*|\d+(?:\.\d+)+))"
        r":=(?:[^()*\\\x00]|\\[0-9A-Fa-f]{2})*$",
        re.IGNORECASE,
    )
    "One RFC 4515 extensible-match filter item, without parentheses."
    OID_LDAP_FILTER_OPERATORS: ClassVar[frozenset[str]] = frozenset({"&", "|", "!"})
    "RFC 4515 filter composition operators."

    OID_PRIVILEGE_GROUP_CLASSES: ClassVar[frozenset[str]] = frozenset({
        "orclprivilegegroup",
    })
    "Group class whose members a higher group grant lifts a denial for (§30.1.3.4.2)."

    @unique
    class AclLeafKind(StrEnum):
        """OUD bind-rule subject kinds of the conversion (R8)."""

        ANYONE = "anyone"
        ALL = "all"
        SELF = "self"
        USER = "user"
        USER_SUBTREE = "user_subtree"
        GROUP = "group"
        USERATTR = "userattr"

    @unique
    class AclRule(StrEnum):
        """Conversion rules R1-R9, inherent exceptions E1-E11, Oracle DNs S11."""

        R1 = "R1"
        R2 = "R2"
        R3 = "R3"
        R4A = "R4a"
        R4B = "R4b"
        R4C = "R4c"
        R4D = "R4d"
        R4E = "R4e"
        R5 = "R5"
        R6A = "R6a"
        R6B = "R6b"
        R7 = "R7"
        R8 = "R8"
        R9 = "R9"
        E2 = "E2"
        E3 = "E3"
        E4 = "E4"
        E6 = "E6"
        E7 = "E7"
        E8 = "E8"
        E11 = "E11"
        ORACLE_INTERNAL = "S11"

    @unique
    class AclEffect(StrEnum):
        """Effect of one OUD permission/bind-rule pair (OUD-9 §9.2.3.4)."""

        ALLOW = "allow"
        DENY = "deny"

    @unique
    class AclScope(StrEnum):
        """OUD targetscope values (OUD-9 §9.2.2.8) and the depth-two region."""

        BASE = "base"
        ONELEVEL = "onelevel"
        SUBORDINATE = "subordinate"
        DEPTH_TWO = "depth2"

    ACL_RIGHT_ADD: ClassVar[str] = "add"
    ACL_RIGHT_BROWSE: ClassVar[str] = "browse"
    ACL_RIGHT_PROXY: ClassVar[str] = "proxy"
    # OUD aci rights in rendering order; statements that differ only in their
    # rights render as one aci listing them in this order.
    OUD_RIGHTS_ORDER: ClassVar[tuple[str, ...]] = (
        "read",
        "search",
        "write",
        "selfwrite",
        "compare",
        "add",
        "delete",
        "proxy",
    )
    ACL_BROWSE_GRANT_ATTRIBUTE: ClassVar[str] = "objectclass"
    "R4e (operator decision, emulate minimum): the attribute browse exposes."
    ACL_BROWSE_GRANT_RIGHTS: ClassVar[tuple[str, ...]] = ("read", "search")
    "R4e: OUD rights on objectClass that make the entry visible (OUD-9 §9.2.3.3)."
    ACL_BROWSE_DENIAL_RIGHTS: ClassVar[tuple[str, ...]] = ("read", "compare")
    "R5: a browse denial removes values and compare (OID-30 Table 30-2)."
    ACL_ENTRYLEVEL_ADD_SCOPE: ClassVar[str] = "onelevel"
    "R4a: entry-level add creates direct children only (OUD-9 §9.2.3.3)."
    ACL_ACP_ADD_SCOPE: ClassVar[str] = "subordinate"
    "R4a: an ACP's add creates entries anywhere below it."

    OUD_ACI_QUOTE: ClassVar[str] = '"'
    "Delimiter of every quoted OUD ACI value; a quoted value cannot carry it."
    OUD_BIND_ALL: ClassVar[str] = "all"
    "``userdn=ldap:///all``: every authenticated session (OUD-9 §9.4.2.1)."
    OUD_BIND_ANYONE: ClassVar[str] = "anyone"
    "``userdn=ldap:///anyone``: every session, anonymous included."
    OUD_BIND_SELF: ClassVar[str] = "self"
    "``userdn=ldap:///self``: the bind DN equals the target entry."
    OUD_USERDN_SUBTREE_URL_SUFFIX: ClassVar[str] = "??sub?(objectclass=*)"
    "R8: LDAP URL suffix of a subtree ``userdn`` (OUD-9 §9.4.2; measured, phase D)."
    OUD_USERATTR_PARENT: ClassVar[str] = "parent[1]."
    "R4a: ``userattr`` read on the parent of the added entry (OUD-9 §9.4.4.9)."
    OUD_TARGET_SUBTREE_EXCLUSION_PREFIX: ClassVar[str] = "*,"
    "R5: target prefix matching every descendant of a DN (measured, phase D)."
    OUD_TARGET_DEPTH_TWO_PREFIX: ClassVar[str] = "*,*,"
    "R5: target prefix matching descendants two or more levels down."
    OUD_ENTRYDN_ATTR: ClassVar[str] = "entryDN"
    "R5: ``(entryDN=<dn>)`` in targetfilter matches exactly one entry (measured)."
    OUD_TARGETATTR_ALL: ClassVar[str] = "*"
    "OUD targetattr of every attribute (measured: includes operational, phase B)."


__all__: list[str] = ["FlextLdifConstantsServersOid"]
