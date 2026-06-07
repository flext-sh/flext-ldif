"""FlextLdifConstantsAclConvert - OID ACL parse patterns (SSOT).

The OID/parse side of the OID→OUD ACL conversion: attribute-kind / target /
subject enums and every compiled ``re.Pattern`` used to parse an OID
orclaci/orclentrylevelaci line. The OUD-output taxonomy (permission maps,
bind-rule keywords, scope rules) lives in the sibling
``_constants/acl_convert_oud.py``. Consumers import the ``*_RE`` authorities —
``import re`` outside this module is forbidden (AGENTS.md §3.1).
"""

from __future__ import annotations

import re
from enum import StrEnum, unique
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
    class OidSubjectKind(StrEnum):
        """OID by-clause subject kinds emitted by the parser."""

        GROUP = "group"
        USER = "user"
        SELF = "self"
        ANYONE = "anyone"
        SUPERUSER = "superuser"
        DNATTR = "dnattr"
        GROUPATTR = "groupattr"
        GUIDATTR = "guidattr"
        UNKNOWN = "unknown"

    ACL_ACCESS_TO: Final[str] = "access to"
    ACL_WILDCARD: Final[str] = "*"

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

    # by-clause subject matchers; group→subject mapping is the SUBJECT_MATCHERS SSOT.
    SUBJ_SUPERUSER_RE: ClassVar[t.RegexPattern] = re.compile(
        r"by\s+SuperUser\s*\(([^)]+)\)",
        re.IGNORECASE,
    )
    SUBJ_GROUP_RE: ClassVar[t.RegexPattern] = re.compile(
        r'by\s+group\s*=\s*"([^"]+)".*?\(([^)]+)\)\s*$',
        re.IGNORECASE,
    )
    SUBJ_DN_RE: ClassVar[t.RegexPattern] = re.compile(
        r'by\s+dn\s*=\s*"([^"]+)".*?\(([^)]+)\)\s*$',
        re.IGNORECASE,
    )
    SUBJ_SELF_RE: ClassVar[t.RegexPattern] = re.compile(
        r"by\s+self.*?\(([^)]+)\)\s*$",
        re.IGNORECASE,
    )
    SUBJ_ANYONE_RE: ClassVar[t.RegexPattern] = re.compile(
        r"by\s+\*.*?\(([^)]+)\)\s*$",
        re.IGNORECASE,
    )
    SUBJ_DNATTR_RE: ClassVar[t.RegexPattern] = re.compile(
        r"by\s+dnattr\s*=\s*\(([^)]+)\)\s*\(([^)]+)\)",
        re.IGNORECASE,
    )
    SUBJ_GROUPATTR_RE: ClassVar[t.RegexPattern] = re.compile(
        r"by\s+groupattr\s*=\s*\(([^)]+)\)\s*\(([^)]+)\)",
        re.IGNORECASE,
    )
    SUBJ_GUIDATTR_RE: ClassVar[t.RegexPattern] = re.compile(
        r"by\s+guidattr\s*=\s*\(([^)]+)\)\s*\(([^)]+)\)",
        re.IGNORECASE,
    )

    _BY_MODS = (
        r"(?:\s+added_object_constraint\s*=\s*\([^)]+\))?"
        r"(?:\s+bindmode\s*=\s*\([^)]+\))?"
        r"(?:\s+bindipfilter\s*=\s*\([^)]+\))?"
    )
    BY_CLAUSE_RE: ClassVar[t.RegexPattern] = re.compile(
        r"by\s+(?:"
        rf'group\s*=\s*"[^"]+"{_BY_MODS}\s*\([^)]+\)'
        rf'|dn\s*=\s*"[^"]+"{_BY_MODS}\s*\([^)]+\)'
        r"|SuperUser\s*\([^)]+\)"
        rf"|self{_BY_MODS}\s*\([^)]+\)"
        rf"|\*{_BY_MODS}\s*\([^)]+\)"
        r"|dnattr\s*=\s*\([^)]+\)\s*\([^)]+\)"
        r"|groupattr\s*=\s*\([^)]+\)\s*\([^)]+\)"
        r"|guidattr\s*=\s*\([^)]+\)\s*\([^)]+\)"
        r")",
        re.IGNORECASE,
    )
    "Finds each ``by <subject> (perms)`` clause in an OID ACL (optional modifiers)."
    SUBJ_MODIFIER_RE: ClassVar[t.RegexPattern] = re.compile(
        r"(bindmode|bindipfilter|added_object_constraint)\s*=\s*"
        r'(?:\(([^)]+)\)|"([^"]+)")',
        re.IGNORECASE,
    )
    "by-clause modifier: g1=kind, g2=paren-value, g3=quoted-value."

    # Ordered OID-regex → OUD-wildcard replacements (applied to bind DNs).
    OID_REGEX_REPLACEMENTS: Final[tuple[tuple[str, str], ...]] = (
        (".*", "*"),
        (".+", "*"),
        (r"\.", "."),
        (r"\,", ","),
    )
    OID_REGEX_RESIDUAL_RE: ClassVar[t.RegexPattern] = re.compile(r"[\[\]{}|^$+?()]")
    "Residual regex metacharacters → DN too complex to wildcard (keep original)."


__all__: list[str] = ["FlextLdifConstantsAclConvert"]
