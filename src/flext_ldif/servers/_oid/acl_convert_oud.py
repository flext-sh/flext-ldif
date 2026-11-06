"""OID→OUD ACL primitives — rights, subjects, attribute sets and the directory.

The building blocks of the conversion rules R1-R9 (Algar conversion spec
v4.1, ``acl-conversion-guide.md``): OID access lists resolve to granted and
denied OID rights (OID-30 §30.1.4.3), each OID subject becomes one OUD
bind-rule leaf or matches no session (R8), attribute targets become OUD
``targetattr`` sets (R1) and the injected source directory gives the group
security classes (OID-30 §30.1.3.4.6). A form without a rule surfaces as
``r.fail``; nothing is approximated or dropped in silence.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence

from flext_ldif import c, m, p, r, u
from flext_ldif.servers._oid import FlextLdifConstantsServersOid


class FlextLdifServersOidAclToOud:
    """OID ACL conversion primitives shared by the policy and the emitter."""

    @staticmethod
    def normalize_dn(dn: str) -> str:
        """Return a DN without spaces around its ``,`` and ``=`` separators."""
        compact: str = c.Ldif.DN_NORMALIZE_COMMA_RE.sub(",", dn)
        return c.Ldif.DN_NORMALIZE_EQUALS_RE.sub("=", compact).strip()

    @classmethod
    def dn_key(cls, dn: str) -> str:
        """Return the comparison key of a DN: separators compacted, case folded."""
        return cls.normalize_dn(dn).lower()

    @staticmethod
    def in_scope(dn: str, base_dn: str) -> bool:
        """Return whether ``dn`` is ``base_dn`` or below it (an empty base is all)."""
        return not base_dn or u.Ldif.under_base(dn, base_dn)

    @staticmethod
    def is_ancestor_or_self(ancestor: str, key: str) -> bool:
        """Return whether DN key ``key`` equals or descends from ``ancestor``.

        The root DSE (empty key) is the ancestor of every DN.
        """
        return ancestor in {"", key} or key.endswith(f",{ancestor}")

    @staticmethod
    def depth_below(anchor: str, key: str) -> int:
        """Return the RDN count of ``key`` below its ancestor-or-self ``anchor``."""
        if anchor == key:
            return 0
        if not anchor:
            return key.count(",") + 1
        return key.count(",") - anchor.count(",")

    @staticmethod
    def resolve_permissions(
        permissions: Sequence[str],
        *,
        is_entry: bool,
    ) -> p.Result[m.Ldif.AclPermissionResolution]:
        """Resolve one OID access list into granted and denied OID rights.

        Only the tokens of the OID access grammar for the object kind are
        accepted (OID-A7 §A.7.1; OID-30 Table 30-2): ``none``, the entry
        rights ``browse``/``add``/``delete``/``proxy`` or the attribute rights
        ``read``/``search``/``write``/``selfwrite``/``compare``, and their
        ``no*`` forms. ``none`` denies every right of the kind; a right both
        granted and denied in one list is denied. ``all``, ``*``, an empty
        list or token and a right of the other kind surface as ``r.fail``.

        Returns:
            The OID rights resolution, or the typed failure.

        """
        scope = c.Ldif.ALL_ENTRY_PERMS if is_entry else c.Ldif.ALL_ATTR_PERMS
        other = c.Ldif.ALL_ATTR_PERMS if is_entry else c.Ldif.ALL_ENTRY_PERMS
        kind = c.Ldif.AclTargetType.ENTRY if is_entry else c.Ldif.AclTargetType.ATTR
        tokens = [raw.strip().lower() for raw in permissions]
        result = r[m.Ldif.AclPermissionResolution]
        if not tokens:
            return result.fail("Empty OID access list (manual review required)")
        if not all(tokens):
            return result.fail(
                f"Empty token in OID access list {tuple(permissions)!r} "
                "(OID-A7 §A.7.1; manual review required)",
            )
        granted: set[str] = set()
        denied: set[str] = set()
        for token in tokens:
            base = c.Ldif.NEGATION_TO_BASE.get(token, token)
            if token == c.Ldif.PERM_NONE:
                denied.update(scope)
            elif base in scope:
                (denied if base != token else granted).add(base)
            elif base in other:
                return result.fail(
                    f"OID permission {token!r} is not a right of an "
                    f"{kind.value!r} object (OID-30 Table 30-2; manual review "
                    "required)",
                )
            else:
                return result.fail(
                    f"Unknown OID permission token {token!r} (not in the OID "
                    "access grammar, OID-A7 §A.7.1; manual review required)",
                )
        return result.ok(
            m.Ldif.AclPermissionResolution(
                allow=frozenset(granted - denied),
                deny=frozenset(denied),
            ),
        )

    @classmethod
    def _filter_end(cls, text: str, start: int) -> int:
        """Return the index after the RFC 4515 filter at ``start``, or ``-1``."""
        constants = FlextLdifConstantsServersOid
        if start >= len(text) or text[start] != "(":
            return -1
        operator = text[start + 1 : start + 2]
        if operator in constants.OID_LDAP_FILTER_OPERATORS:
            return cls._compound_end(text, start + 2, single=operator == "!")
        close = text.find(")", start + 1)
        item = text[start + 1 : close] if close >= 0 else ""
        valid = constants.OID_LDAP_FILTER_ITEM_RE.match(
            item,
        ) or constants.OID_LDAP_FILTER_EXTENSIBLE_RE.match(item)
        return close + 1 if close >= 0 and valid else -1

    @classmethod
    def _compound_end(cls, text: str, position: int, *, single: bool) -> int:
        """Return the index after a compound filter's closing ``)``, or ``-1``."""
        count = 0
        while 0 <= position < len(text) and text[position] == "(":
            position = cls._filter_end(text, position)
            count += 1
        valid = position >= 0 and (count == 1 if single else count >= 1)
        if not valid or position >= len(text) or text[position] != ")":
            return -1
        return position + 1

    @classmethod
    def validate_ldap_filter(cls, value: str) -> p.Result[str]:
        """Validate an OID filter as exactly one RFC 4515 LDAP filter.

        The OID object filter and the added-object constraint are LDAP
        filters (OID-30 §30.1.4.1, §30.1.4.2.4) rendered as the OUD
        ``targetfilter`` (OUD-9 §9.2.2.5), whose value is a quoted string: a
        filter carrying ``"`` has no OUD form. The body is stored without its
        outer parentheses, which are restored.

        Returns:
            The parenthesized filter, or the typed failure.

        """
        stripped = value.strip()
        text = stripped if stripped.startswith("(") else f"({stripped})"
        if cls._filter_end(text, 0) != len(text):
            return r[str].fail(
                f"OID ACL filter {value!r} is not one RFC 4515 LDAP filter "
                "(manual review required)",
            )
        if FlextLdifConstantsServersOid.OUD_ACI_QUOTE in text:
            return r[str].fail(
                f"OID ACL filter {value!r} carries a quote, which an OUD "
                "targetfilter cannot hold (manual review required)",
            )
        return r[str].ok(text)

    @staticmethod
    def attr_set(rule: p.Ldif.OidAclRule) -> m.Ldif.AclAttrSet | None:
        """R1: return the attribute target as a case-folded attribute set.

        ``attr=(a,b)`` lists names, ``attr!=(a,b)`` excludes them and
        ``attr=(*)`` (or ``attr=*``) is every attribute. An entry target has
        no attribute set.

        Returns:
            The attribute set, or None for an entry target.

        """
        if rule.target_type == c.Ldif.AclTargetType.ENTRY:
            return None
        negated = rule.target_attrs.startswith(c.Ldif.OUD_ATTR_NEGATION)
        body = rule.target_attrs.removeprefix(c.Ldif.OUD_ATTR_NEGATION).strip()
        names = frozenset(
            name.strip().lower()
            for name in body.split(",")
            if name.strip() and name.strip() != c.Ldif.ACL_WILDCARD
        )
        return m.Ldif.AclAttrSet(
            names=names,
            negated=negated or body == c.Ldif.ACL_WILDCARD,
        )

    @staticmethod
    def check_attr_target(rule: p.Ldif.OidAclRule) -> p.Result[bool]:
        """Accept ``*`` or a list of attribute descriptions, optionally negated.

        An empty element, ``*`` inside a list, an attribute outside the
        description grammar, or a name of an OID ACL attribute (it does not
        exist after conversion) has no exact OUD ``targetattr``.

        Returns:
            Success, or the typed failure.

        """
        if rule.target_type == c.Ldif.AclTargetType.ENTRY:
            return r[bool].ok(value=True)
        body = rule.target_attrs.removeprefix(c.Ldif.OUD_ATTR_NEGATION).strip()
        if body == c.Ldif.ACL_WILDCARD:
            return r[bool].ok(value=True)
        names = [name.strip() for name in body.split(",")]
        descriptor = FlextLdifConstantsServersOid.OID_ATTR_DESCRIPTOR_RE
        if not all(descriptor.match(name) for name in names):
            return r[bool].fail(
                f"OID attribute target {rule.target_attrs!r} is not '*' or a "
                "list of attribute descriptions (manual review required)",
            )
        acl_attrs = {name.lower() for name in names} & {
            str(kind) for kind in c.Ldif.AclConvertType
        }
        if acl_attrs:
            return r[bool].fail(
                f"OID ACL target names the ACL attributes {sorted(acl_attrs)!r}, "
                "which do not exist after conversion to OUD aci (manual review "
                "required)",
            )
        return r[bool].ok(value=True)

    @classmethod
    def acl_directory(cls, entries: Sequence[p.Ldif.Entry]) -> m.Ldif.AclDirectory:
        """Read the injected source directory: every DN and every group entry.

        An entry is a group when it carries a group class, a static member or
        a computed-membership attribute (OID-30 §30.1.3.4). Its OID security
        classes are ``orclACPgroup`` and ``orclPrivilegeGroup``
        (§30.1.3.4.6); its member groups are resolved after every entry is
        read, so input order does not matter.

        Returns:
            The typed source directory.

        """
        constants = FlextLdifConstantsServersOid
        names: dict[str, str] = {}
        found: dict[str, tuple[frozenset[str], frozenset[str], bool]] = {}
        for entry in entries:
            key = cls.dn_key(entry.dn_str)
            names.setdefault(key, entry.dn_str)
            attributes = {
                name.lower(): values for name, values in entry.attributes_dict.items()
            }
            classes = frozenset(
                value.lower()
                for value in attributes.get(c.Ldif.DictKeys.OBJECTCLASS.lower(), ())
            )
            members = frozenset(
                cls.dn_key(value)
                for name in constants.OID_GROUP_MEMBER_ATTRS
                for value in attributes.get(name, ())
            )
            dynamic = any(
                attributes.get(name) for name in constants.OID_DYNAMIC_MEMBER_ATTRS
            )
            if classes & constants.OID_GROUP_CLASSES or members or dynamic:
                found[key] = (
                    classes & constants.OID_SECURITY_GROUP_CLASSES,
                    members,
                    dynamic,
                )
        return m.Ldif.AclDirectory(
            entries=names,
            groups={
                key: m.Ldif.AclSecurityGroup(
                    classes=classes,
                    member_groups=frozenset(item for item in members if item in found),
                    dynamic=dynamic,
                )
                for key, (classes, members, dynamic) in found.items()
            },
        )

    @classmethod
    def _group_defect(
        cls,
        directory: m.Ldif.AclDirectory,
        key: str,
        seen: frozenset[str],
    ) -> str:
        """Return why group ``key`` has no exact OUD ``groupdn``, or ``""``.

        OID evaluates a group for access only with exactly one security class
        (both classes evaluate non-deterministically, E6) and only through
        nesting chains of security groups (OID-30 §30.1.3.4.4-6); OUD
        ``groupdn`` follows every nested group and computed membership.
        """
        group = directory.groups[key]
        if group.dynamic:
            return f"group {key!r} has computed membership"
        if len(group.classes) > 1:
            return f"group {key!r} carries both OID security classes (E6)"
        for member in sorted(group.member_groups - seen):
            if not directory.groups[member].classes:
                return (
                    f"group {key!r} nests {member!r}, which OID does not "
                    "evaluate and OUD groupdn would"
                )
            nested = cls._group_defect(directory, member, seen | {key})
            if nested:
                return nested
        return ""

    @classmethod
    def _group_leaf(
        cls,
        value: str,
        directory: m.Ldif.AclDirectory,
    ) -> p.Result[tuple[m.Ldif.AclBindLeaf | None, str]]:
        """R8: a group grants only when it is an exact source security group.

        Returns:
            The group leaf; None (matches no session) for a group without a
            security class; or the failure for an inexact group.

        """
        constants = FlextLdifConstantsServersOid
        result = r[tuple[m.Ldif.AclBindLeaf | None, str]]
        dn = cls.normalize_dn(value)
        key = dn.lower()
        if c.Ldif.ACL_WILDCARD in dn:
            return result.fail(
                f"R8: OID group DN with a wildcard has no OUD groupdn: {value!r}",
            )
        group = directory.groups.get(key)
        if group is None or not group.classes:
            return result.ok((None, constants.AclRule.R8))
        defect = cls._group_defect(directory, key, frozenset())
        if defect:
            return result.fail(f"R8: {defect}; no exact OUD groupdn")
        return result.ok((
            m.Ldif.AclBindLeaf(kind=constants.AclLeafKind.GROUP, value=dn, key=key),
            constants.AclRule.R8,
        ))

    @classmethod
    def _user_leaf(cls, value: str) -> p.Result[tuple[m.Ldif.AclBindLeaf | None, str]]:
        """R8: a subject DN is literal; ``*,<dn>`` is the strict subtree of dn.

        The OID BNF admits a DN or ``*,<dn_of_any_subtree_root>`` and nothing
        else (OID-A7 §A.7.1 note); ``.*,`` is how OID-30 text writes the
        prefix. Any other regex construct or non-RFC 4514 escape fails.

        Returns:
            The user or strict-subtree leaf, or the failure.

        """
        constants = FlextLdifConstantsServersOid
        result = r[tuple[m.Ldif.AclBindLeaf | None, str]]
        dn = cls.normalize_dn(value)
        if match := constants.OID_PREFIX_WILDCARD_RE.match(dn):
            base = cls.normalize_dn(match.group("base"))
            if constants.OID_DN_EXPRESSION_RE.search(base):
                return result.fail(
                    f"R8: OID DN expression {value!r} is not '*,<dn>' over a "
                    "literal DN (OID-A7 §A.7.1)",
                )
            return result.ok((
                m.Ldif.AclBindLeaf(
                    kind=constants.AclLeafKind.USER_SUBTREE,
                    value=base,
                    key=base.lower(),
                ),
                constants.AclRule.R8,
            ))
        if constants.OID_DN_EXPRESSION_RE.search(dn):
            return result.fail(
                f"R8: OID DN expression {value!r} is not a literal DN or the "
                "prefix wildcard '*,<dn>'; the OID grammar admits no other form "
                "(OID-A7 §A.7.1)",
            )
        return result.ok((
            m.Ldif.AclBindLeaf(
                kind=constants.AclLeafKind.USER, value=dn, key=dn.lower()
            ),
            constants.AclRule.R8,
        ))

    @classmethod
    def subject_leaf(
        cls,
        subject: p.Ldif.OidAclSubject,
        directory: m.Ldif.AclDirectory,
    ) -> p.Result[tuple[m.Ldif.AclBindLeaf | None, str]]:
        """R8: convert one OID subject into its OUD bind-rule leaf.

        ``*`` is ``anyone`` (the emitter grants it to ``all``), ``self`` is
        ``self``, ``dnattr=(a)`` is ``userattr="a#USERDN"``, a DN is literal
        and a group is checked against the directory. ``SuperUser`` (E8) and
        ``guidattr`` (E4) match no OUD session. ``groupattr`` (OUD follows
        groups OID ignores), ``bindmode`` and ``bindipfilter`` (no measured
        OUD mapping) fail.

        Returns:
            The leaf (None for no session) and its rule, or the failure.

        """
        constants = FlextLdifConstantsServersOid
        kinds = c.Ldif.OidSubjectKind
        leaves = constants.AclLeafKind
        result = r[tuple[m.Ldif.AclBindLeaf | None, str]]
        if subject.bindmode or subject.bindipfilter:
            return result.fail(
                f"R8: bindmode={subject.bindmode!r} bindipfilter="
                f"{subject.bindipfilter!r} has no measured OUD mapping and is "
                "never copied raw",
            )
        match subject.subject_type:
            case kinds.SUPERUSER:
                return result.ok((None, constants.AclRule.E8))
            case kinds.GUIDATTR:
                return result.ok((None, constants.AclRule.E4))
            case kinds.ANYONE:
                leaf = m.Ldif.AclBindLeaf(
                    kind=leaves.ANYONE,
                    value=constants.OUD_BIND_ANYONE,
                    key=constants.OUD_BIND_ANYONE,
                )
            case kinds.SELF:
                leaf = m.Ldif.AclBindLeaf(
                    kind=leaves.SELF,
                    value=constants.OUD_BIND_SELF,
                    key=constants.OUD_BIND_SELF,
                )
            case kinds.GROUP:
                return cls._group_leaf(subject.value, directory)
            case kinds.USER:
                return cls._user_leaf(subject.value)
            case kinds.DNATTR if constants.OID_ATTR_DESCRIPTOR_RE.match(subject.value):
                value = subject.value.strip()
                leaf = m.Ldif.AclBindLeaf(
                    kind=leaves.USERATTR,
                    value=value,
                    key=value.lower(),
                )
            case kinds.GROUPATTR:
                return result.fail(
                    f"R8: OID groupattr=({subject.value}) honours only the "
                    "security groups the attribute names (OID-30 §30.1.3.4.6), "
                    "while OUD userattr GROUPDN honours every group",
                )
            case _:
                return result.fail(
                    f"R8: OID subject {subject.subject_type!r} "
                    f"{subject.value!r} has no conversion rule",
                )
        return result.ok((leaf, constants.AclRule.R8))

    @staticmethod
    def covers(outer: m.Ldif.AclBindLeaf, inner: m.Ldif.AclBindLeaf) -> bool:
        """Return whether every session matching ``inner`` also matches ``outer``.

        True for ``anyone``, the same subject, or a user inside a subtree.
        """
        kinds = FlextLdifConstantsServersOid.AclLeafKind
        if outer.kind == kinds.ANYONE or (outer.kind, outer.key) == (
            inner.kind,
            inner.key,
        ):
            return True
        if outer.kind == kinds.USER_SUBTREE and inner.kind in {
            kinds.USER,
            kinds.USER_SUBTREE,
        }:
            return inner.key.endswith(f",{outer.key}")
        return False

    @classmethod
    def disjoint(cls, left: m.Ldif.AclBindLeaf, right: m.Ldif.AclBindLeaf) -> bool:
        """Return whether no session can match both leaves (provable from DNs).

        Group membership, ``self`` and ``userattr`` are not decidable at
        conversion time, so they overlap every subject.
        """
        kinds = FlextLdifConstantsServersOid.AclLeafKind
        users = {kinds.USER, kinds.USER_SUBTREE}
        if left.kind not in users or right.kind not in users:
            return False
        return not (cls.covers(left, right) or cls.covers(right, left))


__all__: list[str] = ["FlextLdifServersOidAclToOud"]
