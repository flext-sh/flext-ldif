"""Schema definitions stay RFC 4512-valid through phase-aware OUD writes.

Bead flext-o1gan: OUD 14.1.2.1.0 rejects quoted SYNTAX OIDs in ``cn=schema``
modify values with ``invalidAttributeSyntax`` (21) — RFC 4512 § 2.5.1 defines
the SYNTAX property as an unquoted ``noidlen``. Phase-aware OUD writes must
re-serialize cross-server ``attributetypes``/``objectclasses`` definitions
through the canonical source-parse → OUD-write cycle, while same-server
round trips stay byte-stable. Live OUD 14.1.2.1.0 evidence: the quoted form
of ``OUD_QUOTED_OBJECTCLASS_DEFINITION`` fails with ``Result Code: 21`` and
the unquoted form of ``OUD_UNQUOTED_OBJECTCLASS_DEFINITION`` succeeds.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from tests import c, m, p, tm

_QUOTED_SCHEMA_SOURCE = (
    "dn: cn=schema\n"
    "objectClass: top\n"
    "objectClass: subschema\n"
    "cn: schema\n"
    "attributetypes: ( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch"
    " SYNTAX '1.3.6.1.4.1.1466.115.121.1.38' )\n"
    "attributetypes: ( 99.99.99.1 NAME 'cpf' DESC 'Synthetic schema definition'"
    " EQUALITY caseIgnoreMatch SYNTAX '1.3.6.1.4.1.1466.115.121.1.15'"
    " USAGE userApplications )\n"
    "objectclasses: ( 99.99.99.99.1 NAME 'customUser' DESC 'Synthetic schema"
    " definition' SUP top STRUCTURAL MAY ( cpf ) )\n"
)

_OUD_CANONICAL_SCHEMA_SOURCE = (
    "dn: cn=schema\n"
    "objectClass: top\n"
    "objectClass: subschema\n"
    "cn: schema\n"
    "attributetypes: ( 99.99.99.2 NAME 'matricula' DESC 'Synthetic schema"
    " definition' EQUALITY caseIgnoreMatch SYNTAX"
    " 1.3.6.1.4.1.1466.115.121.1.15 )\n"
)

_OUD_QUOTED_OBJECTCLASS_DEFINITION = (
    "attributetypes: ( 2.5.4.0 NAME 'objectClass' EQUALITY"
    " objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )"
)

_PHASE_MODIFY_FORMAT_OPTIONS = m.Ldif.WriteFormatOptions(
    ldif_changetype="modify",
    ldif_modify_operation="add",
)


def _active_logical_lines(ldif_text: str) -> list[str]:
    """Unfold RFC 2849 continuation lines and drop comment lines.

    Returns:
        The resulting ``list[str]``.

    """
    logical_lines: list[str] = []
    current: str | None = None
    for line in ldif_text.splitlines():
        if line.startswith("#"):
            continue
        if line.startswith(" "):
            current = (current or "") + line[1:]
        else:
            if current is not None:
                logical_lines.append(current)
            current = line or None
    if current is not None:
        logical_lines.append(current)
    return logical_lines


def _write_oud_phase(api: p.Ldif.LdifClient, parsed: m.Ldif.ParseResponse) -> str:
    """Write parsed entries through the OUD phase path and return the content.

    Returns:
        The resulting ``str``.

    """
    written = tm.ok(
        api.write(
            list(parsed.entries),
            server_type=c.Ldif.ServerTypes.OUD,
            format_options=_PHASE_MODIFY_FORMAT_OPTIONS,
        ),
    )
    return tm.not_none(written.content)


class TestsFlextLdifOudSchemaPhaseWrite:
    """Exercise the phase-aware OUD schema write path through the public API."""

    @staticmethod
    def test_oud_phase_write_emits_rfc4512_syntax_oids(
        api: p.Ldif.LdifClient,
    ) -> None:
        """Cross-server schema definitions must lose quoted SYNTAX OIDs."""
        parsed = tm.ok(
            api.parse_ldif(_QUOTED_SCHEMA_SOURCE, server_type=c.Ldif.ServerTypes.OID),
        )

        logical_lines = _active_logical_lines(_write_oud_phase(api, parsed))
        schema_lines = [
            line
            for line in logical_lines
            if line.startswith(("attributetypes:", "objectclasses:"))
        ]
        tm.ok(bool(schema_lines), msg="phase write must emit schema definitions")
        quoted = [line for line in schema_lines if "SYNTAX '" in line]
        if quoted:
            msg = (
                f"OUD rejects quoted SYNTAX OIDs (invalidAttributeSyntax); got {quoted}"
            )
            tm.reject(msg)
        tm.that(logical_lines, has=_OUD_QUOTED_OBJECTCLASS_DEFINITION)

    @staticmethod
    def test_oud_phase_write_roundtrip_keeps_definitions_stable(
        api: p.Ldif.LdifClient,
    ) -> None:
        """parse→write→parse→write must not drift or re-quote definitions."""
        parsed = tm.ok(
            api.parse_ldif(_QUOTED_SCHEMA_SOURCE, server_type=c.Ldif.ServerTypes.OID),
        )
        first = _write_oud_phase(api, parsed)
        reparsed = tm.ok(
            api.parse_ldif(first, server_type=c.Ldif.ServerTypes.OUD),
        )
        tm.that(len(reparsed.entries), eq=len(parsed.entries))

        second = _write_oud_phase(api, reparsed)

        first_values = [
            line
            for line in _active_logical_lines(first)
            if line.startswith(("attributetypes:", "objectclasses:"))
        ]
        second_values = [
            line
            for line in _active_logical_lines(second)
            if line.startswith(("attributetypes:", "objectclasses:"))
        ]
        tm.that(second_values, eq=first_values)
        tm.that([line for line in second_values if "SYNTAX '" in line], empty=True)

    @staticmethod
    def test_oud_phase_write_preserves_oud_canonical_definitions(
        api: p.Ldif.LdifClient,
    ) -> None:
        """Same-server writes keep OUD-canonical definitions unchanged."""
        parsed = tm.ok(
            api.parse_ldif(
                _OUD_CANONICAL_SCHEMA_SOURCE,
                server_type=c.Ldif.ServerTypes.OUD,
            ),
        )

        logical_lines = _active_logical_lines(_write_oud_phase(api, parsed))
        tm.ok(
            any(
                line.startswith("attributetypes: ( 99.99.99.2 NAME 'matricula'")
                and "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15" in line
                for line in logical_lines
            )
        )
        tm.that([line for line in logical_lines if "SYNTAX '" in line], empty=True)
