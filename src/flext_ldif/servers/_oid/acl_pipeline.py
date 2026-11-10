"""OID→OUD ACL conversion of a whole directory over the R1-R9 engine.

``convert_directory`` reads every entry's ``orclaci``/``orclentrylevelaci``
values, resolves them against the injected source directory and emits the
OUD ACI statements through :class:`FlextLdifServersOidAclRender`, which places
each statement on the entry its region decides. ``apply_to_entry`` replaces an
entry's OID ACL attributes with the ``aci`` values that conversion placed on
it. Malformed input surfaces as ``r.fail``.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence

from flext_ldif import c, m, p, r
from flext_ldif.servers._oid import (
    FlextLdifConstantsServersOid,
    FlextLdifServersOidAclAssemble,
    FlextLdifServersOidAclRender,
    FlextLdifServersOidAclToOud,
)


class FlextLdifServersOidAclPipeline:
    """Directory-level OID→OUD ACL conversion and its per-entry application."""

    @classmethod
    def convert_directory(  # ruff: ignore[too-many-locals] - ACL directory conversion is inherently complex
        cls,
        entries: Sequence[p.Ldif.Entry],
        *,
        suffix: str,
    ) -> p.Result[p.Ldif.AclDirectoryConversion]:
        """Convert the OID ACLs of every entry into placed OUD ACI values.

        Every OID ACL value becomes one level rule (positions start at 1);
        Oracle-internal names do not exclude retained entries' access policy.
        The render places every statement on its
        receiving entry; its values are deduplicated per entry in emission
        order.

        Returns:
            The directory conversion, or the first failure with its DN.

        """
        result = r[p.Ldif.AclDirectoryConversion]
        to_oud = FlextLdifServersOidAclToOud
        directory = to_oud.acl_directory(entries)
        rules: list[p.Ldif.AclLevelRule] = []
        events: list[p.Ldif.AclConversionEvent] = []
        consumed: set[str] = set()
        for entry in entries:
            attributes = entry.attributes.attributes if entry.attributes else {}
            dn = entry.dn.value if entry.dn else ""
            names = cls._acl_attribute_names(dn, tuple(attributes))
            if names.failure:
                return result.from_failure(names)
            if not names.value:
                continue
            consumed.add(to_oud.dn_key(dn))
            for name in names.value:
                level: list[p.Ldif.AclLevelRule] = []
                for index, value in enumerate(attributes[name], 1):
                    built = FlextLdifServersOidAclAssemble.build_rule(
                        name.lower(), dn, value, index, directory
                    )
                    if built.failure:
                        return result.from_failure(built)
                    level.append(built.value[0])
                    events.extend(built.value[1])
                rules.extend(
                    FlextLdifServersOidAclAssemble.merge_identical_objects(
                        FlextLdifServersOidAclAssemble.append_to_all(level),
                    ),
                )
        render = FlextLdifServersOidAclRender(rules, suffix=suffix, directory=directory)
        emitted = render.emit()
        if emitted.failure:
            return result.from_failure(emitted)
        statements = cls._merge_rights(emitted.value)
        values: dict[str, list[str]] = {}
        for statement in statements:
            rendered = FlextLdifServersOidAclRender.render_statement(statement)
            placed = values.setdefault(to_oud.dn_key(statement.dn), [])
            if rendered not in placed:
                placed.append(rendered)
        return result.ok(
            m.Ldif.AclDirectoryConversion(
                statements=tuple(statements),
                values={key: tuple(found) for key, found in values.items()},
                events=(*events, *render.events),
                consumed=frozenset(consumed),
            ),
        )

    @staticmethod
    def _merge_rights(
        statements: Sequence[p.Ldif.AciStatement],
    ) -> list[p.Ldif.AciStatement]:
        """Merge statements that differ only in their rights, in emission order.

        Returns:
            One statement per distinct remainder, rights in OUD order.

        """
        order = FlextLdifConstantsServersOid.OUD_RIGHTS_ORDER
        merged: dict[str, p.Ldif.AciStatement] = {}
        for statement in statements:
            key = statement.model_copy(update={"rights": ()}).model_dump_json()
            held = merged.get(key)
            if held is None:
                merged[key] = statement
                continue
            rights = {*held.rights, *statement.rights}
            merged[key] = held.model_copy(
                update={"rights": tuple(right for right in order if right in rights)},
            )
        return list(merged.values())

    @classmethod
    def apply_to_entry(
        cls,
        entry: p.Ldif.Entry,
        conversion: p.Ldif.AclDirectoryConversion,
        *,
        source_server_type: str,
        target_server_type: str,
    ) -> p.Result[p.Ldif.Entry]:
        """Replace one entry's OID ACL attributes with its converted ``aci``.

        The entry keeps every other attribute; it receives the ``aci`` values
        the directory conversion placed on it (also when it carried no OID
        ACL) and records them as :class:`m.Ldif.AclEntryConversion`.

        Only an OID→OUD conversion applies. An entry carrying OID ACLs that
        the directory conversion did not consume fails: converting it alone
        would leave OID access control unconverted.

        Returns:
            The converted entry, unchanged when the conversion touches nothing.

        """
        if not (
            source_server_type == c.Ldif.ServerTypes.OID
            and target_server_type == c.Ldif.ServerTypes.OUD
        ):
            return r[p.Ldif.Entry].ok(entry)
        to_oud = FlextLdifServersOidAclToOud
        dn = entry.dn.value if entry.dn else ""
        key = to_oud.dn_key(dn)
        placed = conversion.values.get(key, ())
        attrs_model = entry.attributes
        current = dict(attrs_model.attributes) if attrs_model else {}
        names = cls._acl_attribute_names(dn, tuple(current))
        if names.failure:
            return r[p.Ldif.Entry].from_failure(names)
        if names.value and key not in conversion.consumed:
            return r[p.Ldif.Entry].fail(
                f"OID entry {dn!r} carries {list(names.value)!r} outside the "
                "directory ACL conversion; convert the whole source directory "
                "(placement of OUD ACIs is directory-wide)",
            )
        if not names.value and not placed:
            return r[p.Ldif.Entry].ok(entry)
        for name in names.value:
            del current[name]
        if placed:
            existing = list(current.get(c.Ldif.ACI_ATTR_NAME, ()))
            current[c.Ldif.ACI_ATTR_NAME] = [
                *existing,
                *(value for value in placed if value not in existing),
            ]
        attributes = (
            attrs_model.model_copy(
                update={
                    "attributes": current,
                    "attribute_metadata": {
                        name: value
                        for name, value in attrs_model.attribute_metadata.items()
                        if name not in names.value
                    },
                },
            )
            if attrs_model
            else m.Ldif.Attributes(attributes=current)
        )
        recorded = m.Ldif.AclEntryConversion(
            statements=tuple(
                statement
                for statement in conversion.statements
                if to_oud.dn_key(statement.dn) == key
            ),
            events=tuple(
                event for event in conversion.events if to_oud.dn_key(event.dn) == key
            ),
        )
        metadata = (
            entry.metadata.model_copy(update={"acl_conversion": recorded})
            if entry.metadata is not None
            else m.Ldif.ServerMetadata(
                server_type=c.Ldif.ServerTypes.OID,
                acl_conversion=recorded,
            )
        )
        return r[p.Ldif.Entry].ok(
            entry.model_copy(update={"attributes": attributes, "metadata": metadata}),
        )

    @staticmethod
    def _acl_attribute_names(
        dn: str,
        names: Sequence[str],
    ) -> p.Result[Sequence[str]]:
        """Return the OID ACL attribute names of an entry, failing inexact ones.

        A source ``aci`` attribute is not enforced by OID but would be by
        OUD, and an OID ACL attribute with options has no documented OID
        semantics; both fail.

        Returns:
            The ``orclaci``/``orclentrylevelaci`` names, or the typed failure.

        """
        separator = FlextLdifConstantsServersOid.OID_ATTR_OPTION_SEPARATOR
        bases = {name: name.split(separator, 1)[0].lower() for name in names}
        optioned = [
            name
            for name, base in bases.items()
            if base in c.Ldif.AclConvertType and name.lower() != base
        ]
        if optioned:
            return r[Sequence[str]].fail(
                f"OID ACL attributes with options {optioned!r} on {dn!r} have no "
                "documented OID semantics (manual review required)",
            )
        return r[Sequence[str]].ok(
            tuple(name for name in names if name.lower() in c.Ldif.AclConvertType),
        )


__all__: list[str] = ["FlextLdifServersOidAclPipeline"]
