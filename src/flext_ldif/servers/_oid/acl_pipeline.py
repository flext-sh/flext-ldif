"""OID→OUD ACL pipeline — entry/line orchestration over the build+render stack.

``build_aci_rules`` parses and assembles an entry's OID ACL lines into typed
rules with per-subject outcomes; ``convert_acl_values`` renders them (with
dedup) into raw ``aci`` attribute values; ``convert_entry_acls``
rewrites a whole OID entry, replacing its ``orclaci``/``orclentrylevelaci``
attributes with one ``aci`` attribute. Malformed input surfaces as ``r.fail``.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence

from flext_ldif import c, m, p, r
from flext_ldif.servers._oid import (
    FlextLdifServersOidAclAssemble,
    FlextLdifServersOidAclConvert,
    FlextLdifServersOidAclRender,
)


class FlextLdifServersOidAclPipeline:
    """Top-level OID→OUD ACL conversion orchestration (lines and entries)."""

    @classmethod
    def build_aci_rules(
        cls,
        dn: str,
        oid_acl_lines: Sequence[str],
        *,
        base_dn: str = "",
    ) -> p.Result[tuple[m.Ldif.AciRule, ...]]:
        """Parse and assemble each OID ACL line into one typed OUD aci rule.

        Each rule carries its rendered-ready allows and the per-subject
        :class:`m.Ldif.AclSubjectOutcome` records. A malformed line or unknown
        perm token surfaces as ``r.fail``.

        Returns:
            The resulting ``p.Result[tuple[m.Ldif.AciRule, ...]]``.

        """
        rules: list[m.Ldif.AciRule] = []
        for line in oid_acl_lines:
            rule = FlextLdifServersOidAclConvert.parse_oid_acl_line(dn, line)
            if rule.failure:
                return r[tuple[m.Ldif.AciRule, ...]].from_failure(rule)
            aci = FlextLdifServersOidAclAssemble.build_aci_rule(
                rule.value,
                base_dn=base_dn,
            )
            if aci.failure:
                return r[tuple[m.Ldif.AciRule, ...]].from_failure(aci)
            rules.append(aci.value)
        return r[tuple[m.Ldif.AciRule, ...]].ok(tuple(rules))

    @staticmethod
    def render_aci_values(rules: tuple[m.Ldif.AciRule, ...]) -> Sequence[str]:
        """Render rules with allows to deduplicated raw ``aci`` attribute values.

        Duplicate values (whitespace- and case-normalized) keep first order.

        Returns:
            The resulting ``Sequence[str]``.

        """
        values: list[str] = []
        seen: set[str] = set()
        for aci in rules:
            if not aci.allows:
                continue
            rendered = FlextLdifServersOidAclRender.render_aci_string(
                aci,
            ).removeprefix(c.Ldif.ACI_PREFIX)
            normalized = c.Ldif.WHITESPACE_RE.sub(" ", rendered.strip().lower())
            if normalized in seen:
                continue
            seen.add(normalized)
            values.append(rendered)
        return tuple(values)

    @classmethod
    def convert_acl_values(
        cls,
        dn: str,
        oid_acl_lines: Sequence[str],
        *,
        base_dn: str = "",
    ) -> p.Result[Sequence[str]]:
        """Convert an entry's OID ACL lines to deduplicated OUD ``aci`` values.

        Each ``orclaci:``/``orclentrylevelaci:`` line is parsed → built →
        rendered; deny-only rules emit nothing; duplicate aci values (whitespace-
        and case-normalized) are merged keeping first order. A malformed line or
        unknown perm token surfaces as ``r.fail``. Returned values exclude the
        ``aci: `` prefix (they are raw ``aci`` attribute values).

        Returns:
            The resulting ``p.Result[Sequence[str]]``.

        """
        return cls.build_aci_rules(dn, oid_acl_lines, base_dn=base_dn).map(
            cls.render_aci_values,
        )

    @classmethod
    def convert_entry_acls(
        cls,
        entry: m.Ldif.Entry,
        source_type_norm: str,
        target_type_norm: str,
        base_dn: str = "",
    ) -> p.Result[m.Ldif.Entry]:
        """Rewrite an OID entry's ACL attributes to a single OUD ``aci`` attribute.

        Fires only for oid→oud entries carrying ``orclaci``/``orclentrylevelaci``;
        their values convert (via :meth:`convert_acl_values`) into ``aci`` values
        and the OID ACL attributes are removed. An Oracle-internal DN
        (``c.Ldif.ORACLE_INTERNAL_DN_RES``) loses its OID ACLs without any
        ``aci``. The typed :class:`m.Ldif.AclEntryConversion` (rules with their
        per-subject outcomes, or the Oracle-internal skip) is recorded on
        ``entry.metadata.acl_conversion``. A malformed ACL surfaces as
        ``r.fail``; non-matching entries pass through unchanged.

        Returns:
            The resulting ``p.Result[m.Ldif.Entry]``.

        """
        if not (
            source_type_norm == c.Ldif.ServerTypes.OID
            and target_type_norm == c.Ldif.ServerTypes.OUD
        ):
            return r[m.Ldif.Entry].ok(entry)
        attrs_model = entry.attributes
        if attrs_model is None or not attrs_model.attributes:
            return r[m.Ldif.Entry].ok(entry)
        current = dict(attrs_model.attributes)
        acl_names = [name for name in current if name.lower() in c.Ldif.AclConvertType]
        if not acl_names:
            return r[m.Ldif.Entry].ok(entry)
        dn_value = entry.dn.value if entry.dn else ""
        oid_lines = [
            f"{name}: {value}" for name in acl_names for value in current[name]
        ]
        skipped = any(rule.match(dn_value) for rule in c.Ldif.ORACLE_INTERNAL_DN_RES)
        rules = (
            r[tuple[m.Ldif.AciRule, ...]].ok(())
            if skipped
            else cls.build_aci_rules(dn_value, oid_lines, base_dn=base_dn)
        )
        if rules.failure:
            return r[m.Ldif.Entry].from_failure(rules)
        for name in acl_names:
            del current[name]
        if values := cls.render_aci_values(rules.value):
            current[c.Ldif.ACI_ATTR_NAME] = list(values)
        kept_meta = {
            key: value
            for key, value in attrs_model.attribute_metadata.items()
            if key not in acl_names
        }
        new_attrs = attrs_model.model_copy(
            update={"attributes": current, "attribute_metadata": kept_meta},
        )
        conversion = m.Ldif.AclEntryConversion(
            rules=rules.value,
            oracle_internal_skip=skipped,
        )
        metadata = (
            entry.metadata.model_copy(update={"acl_conversion": conversion})
            if entry.metadata is not None
            else m.Ldif.ServerMetadata(
                server_type=c.Ldif.ServerTypes.OID,
                acl_conversion=conversion,
            )
        )
        return r[m.Ldif.Entry].ok(
            entry.model_copy(update={"attributes": new_attrs, "metadata": metadata}),
        )


__all__: list[str] = ["FlextLdifServersOidAclPipeline"]
