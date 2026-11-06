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
    FlextLdifConstantsServersOid,
    FlextLdifServersOidAclAssemble,
    FlextLdifServersOidAclConvert,
    FlextLdifServersOidAclRender,
    FlextLdifServersOidAclToOud,
)


class FlextLdifServersOidAclPipeline:
    """Top-level OID→OUD ACL conversion orchestration (lines and entries)."""

    @staticmethod
    def _values(entry: p.Ldif.Entry, names: frozenset[str]) -> Sequence[str]:
        """Return the values of every attribute of ``entry`` named in ``names``."""
        attributes = entry.attributes.attributes if entry.attributes else {}
        return tuple(
            value
            for name, values in attributes.items()
            if name.lower() in names
            for value in values
        )

    @classmethod
    def security_group_dns(cls, entries: Sequence[p.Ldif.Entry]) -> frozenset[str]:
        """Return the DN keys of the entries that are exact OID security groups.

        OID evaluates group membership for access only for ``orclACPgroup``
        and ``orclPrivilegeGroup`` groups, through nesting chains of those
        classes only, and a group carrying both classes evaluates
        non-deterministically (OID-30 §30.1.3.4.4, §30.1.3.4.6). OUD nesting
        semantics are not documented. A group qualifies only when it carries
        exactly one security class, no dynamic membership attribute, and
        every static member is an entry of ``entries`` that is not a group.

        Returns:
            The qualifying group DN keys
            (:meth:`FlextLdifServersOidAclToOud.dn_key`).

        """
        constants = FlextLdifConstantsServersOid
        to_oud = FlextLdifServersOidAclToOud
        classes = frozenset({c.Ldif.DictKeys.OBJECTCLASS.lower()})
        known = {to_oud.dn_key(entry.dn_str) for entry in entries}
        groups = {
            to_oud.dn_key(entry.dn_str)
            for entry in entries
            if {value.lower() for value in cls._values(entry, classes)}
            & constants.OID_GROUP_CLASSES
            or cls._values(entry, constants.OID_GROUP_MEMBER_ATTRS)
            or cls._values(entry, constants.OID_DYNAMIC_MEMBER_ATTRS)
        }
        return frozenset(
            to_oud.dn_key(entry.dn_str)
            for entry in entries
            if len(
                {value.lower() for value in cls._values(entry, classes)}
                & constants.OID_SECURITY_GROUP_CLASSES,
            )
            == 1
            and not cls._values(entry, constants.OID_DYNAMIC_MEMBER_ATTRS)
            and all(
                to_oud.dn_key(member) in known and to_oud.dn_key(member) not in groups
                for member in cls._values(entry, constants.OID_GROUP_MEMBER_ATTRS)
            )
        )

    @classmethod
    def build_aci_rules(
        cls,
        dn: str,
        oid_acl_lines: Sequence[str],
        *,
        base_dn: str = "",
        access_groups: frozenset[str] = frozenset(),
    ) -> p.Result[tuple[p.Ldif.AciRule, ...]]:
        """Parse and assemble each OID ACL line into one typed OUD aci rule.

        Each rule carries its allow and deny clauses and the per-subject
        :class:`m.Ldif.AclSubjectOutcome` records. The ACIs of one ACL
        attribute form one ACP, so an ``attr=(*)`` ACI there excludes the
        attributes its siblings name (OID-30 §30.1.6.3). A malformed line, an
        unsupported construct or a group outside ``access_groups``
        (:meth:`security_group_dns`) surfaces as ``r.fail``.

        Returns:
            The resulting ``p.Result[tuple[p.Ldif.AciRule, ...]]``.

        """
        parsed = r.traverse(
            oid_acl_lines,
            lambda line: FlextLdifServersOidAclConvert.parse_oid_acl_line(dn, line),
        )
        if parsed.failure:
            return r[tuple[p.Ldif.AciRule, ...]].from_failure(parsed)
        named = {
            acl_type: tuple(
                dict.fromkeys(
                    attr
                    for rule in parsed.value
                    if rule.acl_type == acl_type
                    for attr in FlextLdifServersOidAclToOud.named_target_attrs(rule)
                ),
            )
            for acl_type in {rule.acl_type for rule in parsed.value}
        }
        return r.traverse(
            parsed.value,
            lambda rule: FlextLdifServersOidAclAssemble.build_aci_rule(
                rule,
                base_dn=base_dn,
                access_groups=access_groups,
                sibling_attrs=named[rule.acl_type],
            ),
        ).map(tuple)

    @staticmethod
    def render_aci_values(rules: tuple[p.Ldif.AciRule, ...]) -> Sequence[str]:
        """Render every allow and deny clause to deduplicated ``aci`` values.

        Each rule renders one value per clause targetscope; duplicate values
        (whitespace- and case-normalized) keep first order.

        Returns:
            The raw ``aci`` attribute values.

        """
        values: list[str] = []
        seen: set[str] = set()
        for aci in rules:
            for line in FlextLdifServersOidAclRender.render_aci_strings(aci):
                rendered = line.removeprefix(c.Ldif.ACI_PREFIX)
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
        access_groups: frozenset[str] = frozenset(),
    ) -> p.Result[Sequence[str]]:
        """Convert an entry's OID ACL lines to deduplicated OUD ``aci`` values.

        Each ``orclaci:``/``orclentrylevelaci:`` line is parsed → built →
        rendered with its allow and deny clauses; duplicate aci values
        (whitespace- and case-normalized) are merged keeping first order. A
        malformed line or unknown perm token surfaces as ``r.fail``. Returned
        values exclude the ``aci: `` prefix (they are raw ``aci`` attribute
        values).

        Returns:
            The resulting ``p.Result[Sequence[str]]``.

        """
        return cls.build_aci_rules(
            dn,
            oid_acl_lines,
            base_dn=base_dn,
            access_groups=access_groups,
        ).map(
            cls.render_aci_values,
        )

    @classmethod
    def _internal_denials(
        cls,
        dn: str,
        oid_acl_lines: Sequence[str],
    ) -> p.Result[bool]:
        """Fail when an Oracle-internal entry's OID ACLs deny any right.

        Dropping a denial would grant in OUD what OID denies; dropping a
        grant only narrows access.

        Returns:
            Success when every line only grants, or the typed failure.

        """
        for line in oid_acl_lines:
            rule = FlextLdifServersOidAclConvert.parse_oid_acl_line(dn, line)
            if rule.failure:
                return r[bool].from_failure(rule)
            is_entry = rule.value.target_type == c.Ldif.AclTargetType.ENTRY
            for subject in rule.value.subjects:
                resolved = FlextLdifServersOidAclToOud.resolve_permissions(
                    subject.permissions,
                    is_entry=is_entry,
                )
                if resolved.failure:
                    return r[bool].from_failure(resolved)
                if resolved.value.deny:
                    return r[bool].fail(
                        f"Oracle-internal entry {dn!r} carries an OID ACL that "
                        f"denies {tuple(resolved.value.deny)}; dropping it would "
                        "grant in OUD what OID denies (manual review required)",
                    )
        return r[bool].ok(value=True)

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
        if c.Ldif.ACI_ATTR_NAME.lower() in bases.values():
            return r[Sequence[str]].fail(
                f"OID entry {dn!r} carries an aci attribute, which OID does not "
                "enforce and OUD would enforce as access control (manual review "
                "required)",
            )
        if optioned:
            return r[Sequence[str]].fail(
                f"OID ACL attributes with options {optioned!r} on {dn!r} have no "
                "documented OID semantics (manual review required)",
            )
        return r[Sequence[str]].ok(
            tuple(name for name in names if name.lower() in c.Ldif.AclConvertType),
        )

    @classmethod
    def convert_entry_acls(
        cls,
        entry: p.Ldif.Entry,
        source_type_norm: str,
        target_type_norm: str,
        base_dn: str = "",
        access_groups: frozenset[str] = frozenset(),
    ) -> p.Result[p.Ldif.Entry]:
        """Rewrite an OID entry's ACL attributes to a single OUD ``aci`` attribute.

        Fires only for oid→oud entries carrying ``orclaci``/``orclentrylevelaci``;
        their values convert (via :meth:`convert_acl_values`) into ``aci`` values
        and the OID ACL attributes are removed. An Oracle-internal DN
        (``c.Ldif.ORACLE_INTERNAL_DN_RES``) loses its OID ACLs without any
        ``aci`` only when none of them denies a right. The typed
        :class:`m.Ldif.AclEntryConversion` (rules with their per-subject
        outcomes, or the Oracle-internal skip) is recorded on
        ``entry.metadata.acl_conversion``. A source ``aci`` attribute (OID does
        not enforce it, OUD would), an OID ACL attribute carrying options and a
        malformed ACL surface as ``r.fail``; entries without ACL attributes
        pass through unchanged.

        Returns:
            The resulting ``p.Result[p.Ldif.Entry]``.

        """
        if not (
            source_type_norm == c.Ldif.ServerTypes.OID
            and target_type_norm == c.Ldif.ServerTypes.OUD
        ):
            return r[p.Ldif.Entry].ok(entry)
        attrs_model = entry.attributes
        if attrs_model is None or not attrs_model.attributes:
            return r[p.Ldif.Entry].ok(entry)
        current = dict(attrs_model.attributes)
        dn_value = entry.dn.value if entry.dn else ""
        names = cls._acl_attribute_names(dn_value, tuple(current))
        if names.failure:
            return r[p.Ldif.Entry].from_failure(names)
        acl_names = names.value
        if not acl_names:
            return r[p.Ldif.Entry].ok(entry)
        oid_lines = [
            f"{name}: {value}" for name in acl_names for value in current[name]
        ]
        skipped = any(rule.match(dn_value) for rule in c.Ldif.ORACLE_INTERNAL_DN_RES)
        no_rules: tuple[p.Ldif.AciRule, ...] = ()
        rules = (
            cls._internal_denials(dn_value, oid_lines).map(lambda _: no_rules)
            if skipped
            else cls.build_aci_rules(
                dn_value,
                oid_lines,
                base_dn=base_dn,
                access_groups=access_groups,
            )
        )
        if rules.failure:
            return r[p.Ldif.Entry].from_failure(rules)
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
        return r[p.Ldif.Entry].ok(
            entry.model_copy(update={"attributes": new_attrs, "metadata": metadata}),
        )


__all__: list[str] = ["FlextLdifServersOidAclPipeline"]
