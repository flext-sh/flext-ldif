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
from typing import TYPE_CHECKING, Annotated, ClassVar
from warnings import deprecated

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

    OID_ACL_OBJECT_KEYWORD_RE: ClassVar[t.RegexPattern] = re.compile(
        r"\b(DenyGroupOverride|AppendToAll)\b",
        re.IGNORECASE,
    )
    "OID object keywords ``DenyGroupOverride``/``AppendToAll`` (OID-30 §30.1.4.1)."

    OID_DN_SUBTREE_REGEX_RE: ClassVar[t.RegexPattern] = re.compile(
        r"^(?:\.\*|\.\+|\*)\s*,\s*(.+)$",
    )
    "Leading OID subtree wildcard ``.*,<dn>`` / ``*,<dn>`` (OID-A7 §A.7.1)."
    OID_DN_ESCAPED_DOT_RE: ClassVar[t.RegexPattern] = re.compile(r"(?<!\\)\\\.")
    "Regex-escaped literal dot ``\\.`` inside an OID DN."
    OID_DN_UNSUPPORTED_RE: ClassVar[t.RegexPattern] = re.compile(
        r'[\[\]{}|^$?()*]|(?<!\\)\+|\\(?![,+"\\<>;=# ]|[0-9A-Fa-f]{2})',
    )
    "Regex construct or non-DN escape with no exact OUD bind-DN form."
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

    OID_IP_FILTER_TERM_RE: ClassVar[t.RegexPattern] = re.compile(
        r"^\(?\s*orclipaddress\s*=\s*([^()\s]+)\s*\)?$",
        re.IGNORECASE,
    )
    "One ``orclipaddress=<value>`` equality term (OID-30 §30.1.4.2.3)."
    OID_IP_FILTER_OR_RE: ClassVar[t.RegexPattern] = re.compile(
        r"^\(?\s*\|\s*((?:\(\s*orclipaddress\s*=\s*[^()\s]+\s*\)\s*)+)\)?$",
        re.IGNORECASE,
    )
    "An OR of ``orclipaddress=<value>`` equality terms (OID-30 §30.1.4.2.3)."
    OID_IP_FILTER_OR_TERM_RE: ClassVar[t.RegexPattern] = re.compile(
        r"\(\s*orclipaddress\s*=\s*([^()\s]+)\s*\)",
        re.IGNORECASE,
    )
    "Each term of an ``orclipaddress`` OR filter."
    OID_IPV4_PREFIX_RE: ClassVar[t.RegexPattern] = re.compile(
        r"^(\d{1,3}(?:\.\d{1,3}){0,3})(\.\*)?$",
    )
    "IPv4 address, or dotted-octet prefix + trailing ``.*`` substring wildcard."
    IPV4_OCTET_COUNT: ClassVar[int] = 4
    IPV4_OCTET_MAX: ClassVar[int] = 255
    IPV4_OCTET_WILDCARD: ClassVar[str] = "*"

    OID_ATTR_OPTION_SEPARATOR: ClassVar[str] = ";"
    "Separator of an attribute description's options (RFC 4512 §2.5)."
    OID_ROOT_DSE_DN: ClassVar[str] = ""
    "DN of the root DSE, whose ``orclACI`` governs the whole DIT (OID-30 §30.3.2)."
    OID_ENTRY_VISIBILITY_PERMS: ClassVar[frozenset[str]] = frozenset({"browse"})
    "Entry rights that expose the DN only (OID-30 Table 30-2)."
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

    OUD_ACI_QUOTE: ClassVar[str] = '"'
    "Delimiter of every quoted OUD ACI value; a quoted value cannot carry it."
    OUD_DN_SUBTREE_WILDCARD: ClassVar[str] = "**,"
    "OUD bind-DN prefix matching one or more RDN components (OUD §9.5.2)."
    OUD_IP_LIST_SEPARATOR: ClassVar[str] = ","
    "Separator of an OUD ``ip`` bind-rule address list (OUD §9.4.5)."
    OUD_SUBJECT_AUTHENTICATED: ClassVar[str] = "all"
    "OUD userdn keyword of every authenticated session (OUD §9.4.2.3)."
    ACL_SCOPE_ONELEVEL: ClassVar[str] = "onelevel"
    "OUD targetscope of the first-generation children of the ACI entry."
    OUD_CHILD_ENTRY_PERMS: ClassVar[frozenset[str]] = frozenset({"add"})
    "OUD rights checked on the entry being added, not its parent (OUD §9.2.3.3)."
    OUD_VISIBILITY_PERMS: ClassVar[frozenset[str]] = frozenset({"read", "search"})
    "OUD rights that make an entry visible in a search result (OUD §9.2.3.3)."
    OUD_GLOBAL_OPERATIONAL_TARGETATTR: ClassVar[str] = (
        "createTimestamp||creatorsName||modifiersName||modifyTimestamp||entryDN"
        "||entryUUID||subschemaSubentry||orclguid||nsuniqueid"
    )
    "Operational attributes the OUD default global ACIs grant (OUD12-28 §28.1.2)."
    OUD_OPERATIONAL_ATTRS: ClassVar[frozenset[str]] = frozenset({
        *(name.lower() for name in OUD_GLOBAL_OPERATIONAL_TARGETATTR.split("||")),
        "aci",
    })
    "Known OUD operational attributes, case-folded (OUD11-COMPAT; OUD12-28)."
    OUD_GLOBAL_OPERATIONAL_PERMS: ClassVar[tuple[str, ...]] = (
        "read",
        "search",
        "compare",
    )
    "Rights the OUD default global ACIs grant on those operational attributes."

    HIGH_LEVEL_CONTAINER_SUFFIXES: ClassVar[
        Annotated[
            tuple[str, ...],
            deprecated(
                "compat: HIGH_LEVEL_CONTAINER_SUFFIXES -> removed (no OID "
                "semantics); fix: drop the high-level container filter",
            ),
        ]
    ] = (
        "",
        "dc=network,",
        "cn=users,dc=network,",
        "cn=groups,dc=network,",
        "cn=perfis,dc=network,",
    )
    "Deprecated consumer container suffixes (relative to base)."


__all__: list[str] = ["FlextLdifConstantsServersOid"]
