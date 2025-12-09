"""RFC 4512 Compliant Server Quirks - Base LDAP Schema/ACL/Entry Implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides RFC-compliant baseline implementations for LDAP directory operations.
All server-specific quirks (OID, OUD, OpenLDAP, etc.) extend this RFC base.

Architecture:
    - RFC baseline: Strict RFC 2849/4512 compliance
    - Server quirks: Extend RFC with server-specific enhancements
    - No cross-server dependencies: Each server is isolated
    - Generic conversions: All via RFC intermediate format

References:
    - RFC 2849: LDIF Format Specification
    - RFC 4512: LDAP Directory Information Models

"""

from __future__ import annotations

from flext_core import FlextLogger, FlextResult

from flext_ldif.models import FlextLdifModels as m
from flext_ldif.servers._rfc import (
    FlextLdifServersRfcAcl,
    FlextLdifServersRfcConstants,
    FlextLdifServersRfcEntry,
    FlextLdifServersRfcSchema,
)
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.typings import t

logger = FlextLogger(__name__)


# TypedDicts moved to typings.py - import from there


class FlextLdifServersRfc(FlextLdifServersBase):
    r"""RFC-Compliant LDAP Server Implementation - STRICT Baseline.

    Implements STRICT RFC-compliant LDIF processing based on:
    - RFC 2849: LDIF Data Interchange Format (entry/change records)
    - RFC 4512: LDAP Directory Information Models (schema)
    - RFC 4514: String Representation of Distinguished Names
    - RFC 4517: LDAP Syntaxes and Matching Rules
    - RFC 2820: Access Control Requirements (ACL concepts)

    RFC 4512 Schema ABNF Grammar:
    =============================
    AttributeTypeDescription = LPAREN WSP
        numericoid                         ; Rfc.SYNTAX_OID
        [ SP "NAME" SP qdescrs ]           ; Rfc.SCHEMA_KW_NAME
        [ SP "DESC" SP qdstring ]          ; Rfc.SCHEMA_KW_DESC
        [ SP "OBSOLETE" ]                  ; Rfc.SCHEMA_KW_OBSOLETE
        [ SP "SUP" SP oid ]                ; Rfc.SCHEMA_KW_SUP
        [ SP "EQUALITY" SP oid ]           ; Rfc.SCHEMA_KW_EQUALITY
        [ SP "ORDERING" SP oid ]           ; Rfc.SCHEMA_KW_ORDERING
        [ SP "SUBSTR" SP oid ]             ; Rfc.SCHEMA_KW_SUBSTR
        [ SP "SYNTAX" SP noidlen ]         ; Rfc.SCHEMA_KW_SYNTAX
        [ SP "SINGLE-VALUE" ]              ; Rfc.SCHEMA_KW_SINGLE_VALUE
        [ SP "COLLECTIVE" ]                ; Rfc.SCHEMA_KW_COLLECTIVE
        [ SP "NO-USER-MODIFICATION" ]      ; Rfc.SCHEMA_KW_NO_USER_MODIFICATION
        [ SP "USAGE" SP usage ]            ; Rfc.SCHEMA_KW_USAGE
        extensions WSP RPAREN              ; Rfc.SCHEMA_EXTENSION_PREFIX

    ObjectClassDescription = LPAREN WSP
        numericoid
        [ SP "NAME" SP qdescrs ]
        [ SP "DESC" SP qdstring ]
        [ SP "OBSOLETE" ]
        [ SP "SUP" SP oids ]
        [ SP kind ]                        ; Rfc.SCHEMA_KINDS
        [ SP "MUST" SP oids ]              ; Rfc.SCHEMA_KW_MUST
        [ SP "MAY" SP oids ]               ; Rfc.SCHEMA_KW_MAY
        extensions WSP RPAREN

    usage = "userApplications" /           ; Rfc.SCHEMA_USAGE_*
            "directoryOperation" /
            "distributedOperation" /
            "dSAOperation"

    kind = "ABSTRACT" / "STRUCTURAL" / "AUXILIARY"  ; Rfc.SCHEMA_KIND_*

    ABNF Syntax (c.Ldif.Rfc):
    =====================================
    WSP    = 0*SPACE                       ; Rfc.SCHEMA_WSP
    SP     = 1*SPACE
    LPAREN = %x28                          ; Rfc.SCHEMA_LPAREN
    RPAREN = %x29                          ; Rfc.SCHEMA_RPAREN
    SQUOTE = %x27                          ; Rfc.SCHEMA_SQUOTE
    DQUOTE = %x22                          ; Rfc.SCHEMA_DQUOTE
    DOLLAR = %x24                          ; Rfc.SCHEMA_DOLLAR

    Key RFC Standards Implemented:
    ==============================
    RFC 2849 - LDIF Format:
        - Line folding at 76 bytes (Rfc.LINE_FOLD_WIDTH)
        - Base64 encoding for non-safe characters (Rfc.BASE64_CHARS)
        - Change types: c.Ldif.ChangeType enum (add, delete, modify, modrdn, moddn)
        - Modify ops: c.Ldif.ModifyOperation enum (add, delete, replace)

    RFC 4512 - Schema:
        - Schema keywords: Rfc.SCHEMA_KW_*
        - Usage values: Rfc.SCHEMA_USAGE_VALUES
        - Kind values: Rfc.SCHEMA_KINDS

    RFC 4514 - Distinguished Names:
        - Escape chars: Rfc.DN_ESCAPE_CHARS, DN_ESCAPE_AT_START, DN_ESCAPE_AT_END
        - Character classes: Rfc.DN_LUTF1_EXCLUDE, DN_TUTF1_EXCLUDE, DN_SUTF1_EXCLUDE
        - Separators: Rfc.DN_RDN_SEPARATOR, DN_MULTIVALUE_SEPARATOR

    Metadata Keys (c.Ldif.Rfc):
    =======================================
    - META_RFC_*: Entry/LDIF metadata
    - META_SCHEMA_*: Schema parsing metadata
    - META_DN_*: DN transformation metadata
    - META_TRANSFORMATION_*: Cross-server conversion tracking

    Architecture:
    =============
    RFC Server provides complete RFC baseline. Server-specific quirks extend
    by overriding hook methods (see Entry.Acl classes for hook patterns).

    """

    def _handle_parse_operation(
        self,
        ldif_text: str,
    ) -> FlextResult[m.Ldif.Entry | str]:
        """Handle parse operation for main quirk.

        Delegates to base class implementation.
        """
        return super()._handle_parse_operation(ldif_text)

    def _handle_write_operation(
        self,
        entries: list[m.Ldif.Entry],
    ) -> FlextResult[m.Ldif.Entry | str]:
        """Handle write operation for main quirk.

        Delegates to base class implementation.
        """
        return super()._handle_write_operation(entries)

    def _route_model_to_write(
        self,
        model: t.Ldif.ConvertibleModel,
    ) -> FlextResult[str]:
        """Route a single model to appropriate write method.

        Delegates to base class implementation.
        """
        return super()._route_model_to_write(model)

    class Constants(FlextLdifServersRfcConstants):
        """RFC baseline constants (RFC 4512 compliant). Inherited by all servers."""

    class Acl(FlextLdifServersRfcAcl):
        """Aclbaseline constants (RFC 4512 compliant). Inherited by all Servers."""

    class Schema(FlextLdifServersRfcSchema):
        """RFC baseline constants (RFC 4512 compliant). Inherited by all servers."""

    class Entry(FlextLdifServersRfcEntry):
        """RFC baseline constants (RFC 4512 compliant). Inherited by all servers."""


__all__ = [
    "FlextLdifServersRfc",
]
