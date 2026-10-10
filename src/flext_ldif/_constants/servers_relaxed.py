"""Relaxed (lenient) server-profile constants.

ENFORCE-079 part module: declarations live in the
_constants package; the server constants classes compose them via MRO.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from flext_ldif._constants import FlextLdifConstantsEnums

if TYPE_CHECKING:
    from flext_ldif import t


class FlextLdifConstantsServersRelaxed:
    """Relaxed (lenient) server-profile constants."""

    SERVER_TYPE: ClassVar[str] = FlextLdifConstantsEnums.ServerTypes.RELAXED.value
    PRIORITY: ClassVar[int] = 200
    CANONICAL_NAME: ClassVar[str] = "relaxed"
    ALIASES: ClassVar[frozenset[str]] = frozenset(["relaxed", "lenient"])
    CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["relaxed"])
    CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["relaxed", "rfc"])
    ACL_FORMAT: ClassVar[str] = "rfc_generic"
    ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"
    OID_PATTERN: ClassVar[t.Ldif.RegexPattern] = re.compile(
        r"\(\s*([0-9a-zA-Z._\-]+)",
    )
    OID_NUMERIC_WITH_PAREN: ClassVar[str] = "\\(\\s*([0-9]+(?:\\.[0-9]+)+)"
    OID_NUMERIC_WITH_PAREN_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
        OID_NUMERIC_WITH_PAREN,
    )
    OID_NUMERIC_ANYWHERE: ClassVar[str] = "([0-9]+\\.[0-9]+(?:\\.[0-9]+)*)"
    OID_NUMERIC_ANYWHERE_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
        OID_NUMERIC_ANYWHERE,
    )
    OID_ALPHANUMERIC_RELAXED: ClassVar[str] = "\\(\\s*([a-zA-Z0-9._-]+)"
    OID_ALPHANUMERIC_RELAXED_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
        OID_ALPHANUMERIC_RELAXED,
    )
    SCHEMA_MUST_SEPARATOR: ClassVar[str] = "$"
    SCHEMA_MAY_SEPARATOR: ClassVar[str] = "$"
    SCHEMA_NAME_PATTERN: ClassVar[str] = "NAME\\s+['\\\"]?([^'\\\" ]+)['\\\"]?"
    SCHEMA_NAME_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
        SCHEMA_NAME_PATTERN,
        re.IGNORECASE,
    )
    ACL_DEFAULT_NAME: ClassVar[str] = "relaxed_acl"
    ACL_DEFAULT_TARGET_DN: ClassVar[str] = "*"
    ACL_DEFAULT_SUBJECT_TYPE: ClassVar[str] = "all"
    ACL_DEFAULT_SUBJECT_VALUE: ClassVar[str] = "*"
    ACL_WRITE_PREFIX: ClassVar[str] = "acl: "
    LDIF_DN_PREFIX: ClassVar[str] = "dn: "
    LDIF_ATTR_SEPARATOR: ClassVar[str] = ": "
    ENCODING_UTF8: ClassVar[str] = "utf-8"
    ENCODING_ERROR_HANDLING: ClassVar[str] = "replace"
    LDIF_NEWLINE: ClassVar[str] = "\n"
    LDIF_JOIN_SEPARATOR: ClassVar[str] = "\n"


__all__: list[str] = ["FlextLdifConstantsServersRelaxed"]
