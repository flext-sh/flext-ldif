"""FlextLdifConstantsAclConvert - OID ACL parse patterns (SSOT).

The OID/parse side of the OID→OUD ACL conversion: attribute-kind / target /
subject enums and every compiled ``re.Pattern`` used to parse an OID
orclaci/orclentrylevelaci line. The OUD-output taxonomy (permission maps,
bind-rule keywords, scope rules) lives in the sibling
``_constants/_base.py``. Consumers import the ``*_RE`` authorities —
``import re`` outside this module is forbidden (AGENTS.md §3.1).

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from enum import StrEnum, unique
from typing import TYPE_CHECKING, Annotated, ClassVar
from warnings import deprecated

from flext_ldif._constants import FlextLdifConstantsBase

if TYPE_CHECKING:
    from flext_ldif import t


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

    @unique
    class AclSubjectOutcomeKind(StrEnum):
        """What ACL conversion did with one by-clause subject.

        ``GRANTED`` keeps an effective allow (plus a deny for its denied
        rights); ``DENIED`` denies some rights and grants nothing;
        ``DENIED_ALL`` denies every right of the target kind; ``CANCELLED``
        grants only rights that a catch-all subject of the same rule denies;
        ``OUT_OF_SCOPE`` binds a DN outside the migration base.
        """

        GRANTED = "granted"
        DENIED = "denied"
        DENIED_ALL = "denied_all"
        CANCELLED = "cancelled"
        OUT_OF_SCOPE = "out_of_scope"

    ACL_ACCESS_TO: ClassVar[str] = "access to"
    ACL_WILDCARD: ClassVar[str] = "*"

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
    ORACLE_INTERNAL_DN_RES: ClassVar[tuple[t.RegexPattern, ...]] = (
        re.compile(r"^orclownerguid=", re.IGNORECASE),
        re.compile(r"^cn=orclpwdverifierconfig,", re.IGNORECASE),
        re.compile(r"^cn=orclaci,", re.IGNORECASE),
        re.compile(r".*cn=OracleContext,", re.IGNORECASE),
    )
    "Oracle-internal DNs whose OID ACLs have no OUD counterpart (not migrated)."

    _SUBJ_MODIFIER_PATTERN = (
        r"(?:\s+(?:added_object_constraint|constraintonaddedobject|bindmode|bindipfilter)"
        rf'\s*=\s*(?:\({FlextLdifConstantsBase.LDAP_FILTER_BODY_PATTERN}\)|"[^"]+"))'
    )
    _SUBJ_MODIFIERS = rf"(?:{_SUBJ_MODIFIER_PATTERN})*"

    # Deprecated by-clause grammar; the OID dialect constants own the current one.
    SUBJ_SUPERUSER_RE: ClassVar[
        Annotated[
            t.RegexPattern,
            deprecated(
                "compat: c.Ldif.SUBJ_SUPERUSER_RE -> "
                "FlextLdifConstantsServersOid.OID_SUBJ_SUPERUSER_RE; "
                "fix: read the OID dialect grammar",
            ),
        ]
    ] = re.compile(
        r"by\s+SuperUser\s*\(([^)]+)\)",
        re.IGNORECASE,
    )
    SUBJ_GROUP_RE: ClassVar[
        Annotated[
            t.RegexPattern,
            deprecated(
                "compat: c.Ldif.SUBJ_GROUP_RE -> "
                "FlextLdifConstantsServersOid.OID_SUBJ_GROUP_RE; "
                "fix: read the OID dialect grammar",
            ),
        ]
    ] = re.compile(
        rf'by\s+group\s*=\s*"([^"]+)"{_SUBJ_MODIFIERS}\s*\(([^)]+)\)'
        rf"{_SUBJ_MODIFIERS}\s*$",
        re.IGNORECASE,
    )
    SUBJ_DN_RE: ClassVar[
        Annotated[
            t.RegexPattern,
            deprecated(
                "compat: c.Ldif.SUBJ_DN_RE -> "
                "FlextLdifConstantsServersOid.OID_SUBJ_DN_RE; "
                "fix: read the OID dialect grammar",
            ),
        ]
    ] = re.compile(
        rf'by\s+dn\s*=\s*"([^"]+)"{_SUBJ_MODIFIERS}\s*\(([^)]+)\)'
        rf"{_SUBJ_MODIFIERS}\s*$",
        re.IGNORECASE,
    )
    SUBJ_QUOTED_DN_RE: ClassVar[
        Annotated[
            t.RegexPattern,
            deprecated(
                "compat: c.Ldif.SUBJ_QUOTED_DN_RE -> "
                "FlextLdifConstantsServersOid.OID_SUBJ_QUOTED_DN_RE; "
                "fix: read the OID dialect grammar",
            ),
        ]
    ] = re.compile(
        rf'by\s+"([^"]+)"{_SUBJ_MODIFIERS}\s*\(([^)]+)\)'
        rf"{_SUBJ_MODIFIERS}\s*$",
        re.IGNORECASE,
    )
    SUBJ_SELF_RE: ClassVar[
        Annotated[
            t.RegexPattern,
            deprecated(
                "compat: c.Ldif.SUBJ_SELF_RE -> "
                "FlextLdifConstantsServersOid.OID_SUBJ_SELF_RE; "
                "fix: read the OID dialect grammar",
            ),
        ]
    ] = re.compile(
        rf"by\s+self{_SUBJ_MODIFIERS}\s*\(([^)]+)\){_SUBJ_MODIFIERS}\s*$",
        re.IGNORECASE,
    )
    SUBJ_ANYONE_RE: ClassVar[
        Annotated[
            t.RegexPattern,
            deprecated(
                "compat: c.Ldif.SUBJ_ANYONE_RE -> "
                "FlextLdifConstantsServersOid.OID_SUBJ_ANYONE_RE; "
                "fix: read the OID dialect grammar",
            ),
        ]
    ] = re.compile(
        rf"by\s+\*{_SUBJ_MODIFIERS}\s*\(([^)]+)\){_SUBJ_MODIFIERS}\s*$",
        re.IGNORECASE,
    )
    SUBJ_DNATTR_RE: ClassVar[
        Annotated[
            t.RegexPattern,
            deprecated(
                "compat: c.Ldif.SUBJ_DNATTR_RE -> "
                "FlextLdifConstantsServersOid.OID_SUBJ_DNATTR_RE; "
                "fix: read the OID dialect grammar",
            ),
        ]
    ] = re.compile(
        r"by\s+dnattr\s*=\s*\(([^)]+)\)\s*\(([^)]+)\)",
        re.IGNORECASE,
    )
    SUBJ_GROUPATTR_RE: ClassVar[
        Annotated[
            t.RegexPattern,
            deprecated(
                "compat: c.Ldif.SUBJ_GROUPATTR_RE -> "
                "FlextLdifConstantsServersOid.OID_SUBJ_GROUPATTR_RE; "
                "fix: read the OID dialect grammar",
            ),
        ]
    ] = re.compile(
        r"by\s+groupattr\s*=\s*\(([^)]+)\)\s*\(([^)]+)\)",
        re.IGNORECASE,
    )
    SUBJ_GUIDATTR_RE: ClassVar[
        Annotated[
            t.RegexPattern,
            deprecated(
                "compat: c.Ldif.SUBJ_GUIDATTR_RE -> "
                "FlextLdifConstantsServersOid.OID_SUBJ_GUIDATTR_RE; "
                "fix: read the OID dialect grammar",
            ),
        ]
    ] = re.compile(
        r"by\s+guidattr\s*=\s*\(([^)]+)\)\s*\(([^)]+)\)",
        re.IGNORECASE,
    )

    BY_CLAUSE_RE: ClassVar[
        Annotated[
            t.RegexPattern,
            deprecated(
                "compat: c.Ldif.BY_CLAUSE_RE -> "
                "FlextLdifConstantsServersOid.OID_BY_CLAUSE_RE; "
                "fix: read the OID dialect grammar",
            ),
        ]
    ] = re.compile(
        r"by\s+(?:"
        rf'group\s*=\s*"[^"]+"{_SUBJ_MODIFIERS}\s*\([^)]+\){_SUBJ_MODIFIERS}'
        rf'|dn\s*=\s*"[^"]+"{_SUBJ_MODIFIERS}\s*\([^)]+\){_SUBJ_MODIFIERS}'
        rf'|"[^"]+"{_SUBJ_MODIFIERS}\s*\([^)]+\){_SUBJ_MODIFIERS}'
        r"|SuperUser\s*\([^)]+\)"
        rf"|self{_SUBJ_MODIFIERS}\s*\([^)]+\){_SUBJ_MODIFIERS}"
        rf"|\*{_SUBJ_MODIFIERS}\s*\([^)]+\){_SUBJ_MODIFIERS}"
        r"|dnattr\s*=\s*\([^)]+\)\s*\([^)]+\)"
        r"|groupattr\s*=\s*\([^)]+\)\s*\([^)]+\)"
        r"|guidattr\s*=\s*\([^)]+\)\s*\([^)]+\)"
        r")",
        re.IGNORECASE,
    )
    "Finds each ``by <subject> (perms)`` clause in an OID ACL (optional modifiers)."
    SUBJ_MODIFIER_RE: ClassVar[
        Annotated[
            t.RegexPattern,
            deprecated(
                "compat: c.Ldif.SUBJ_MODIFIER_RE -> "
                "FlextLdifConstantsServersOid.OID_SUBJ_MODIFIER_RE; "
                "fix: read the OID dialect grammar",
            ),
        ]
    ] = re.compile(
        r"(bindmode|bindipfilter|added_object_constraint|constraintonaddedobject)\s*=\s*"
        rf'(?:\(({FlextLdifConstantsBase.LDAP_FILTER_BODY_PATTERN})\)|"([^"]+)")',
        re.IGNORECASE,
    )
    "by-clause modifier: g1=kind, g2=paren-value, g3=quoted-value."


__all__: list[str] = ["FlextLdifConstantsAclConvert"]
