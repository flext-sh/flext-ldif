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

from flext_ldif._constants import FlextLdifConstantsServersOid as _OidConstants
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
    OUD_DN_SUBTREE_WILDCARD: ClassVar[str] = "**,"
    "OUD bind-DN prefix matching one or more RDN components (OUD §9.5.2)."

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
    OUD_IP_LIST_SEPARATOR: ClassVar[str] = ","

    ACL_SCOPE_ONELEVEL: ClassVar[str] = "onelevel"
    "OUD targetscope of the first-generation children of the ACI entry."
    ACL_SCOPE_SUBTREE: ClassVar[str] = "subtree"
    "OUD default targetscope (rendered by omission)."
    ENTRY_LEVEL_CHILD_PERMS: ClassVar[frozenset[str]] = frozenset({"add"})
    "OUD rights that OUD checks on a new child entry (OUD §9.2.3.3)."

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
