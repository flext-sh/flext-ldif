"""OID→OUD ACL primitives — rights, subjects, attribute sets and the directory.

The building blocks of the conversion rules R1-R9
(``docs/specs/oid-oud-acl-conversion.md``): OID access lists resolve to granted and
denied OID rights (OID-30 §30.1.4.3), each OID subject becomes one OUD
bind-rule leaf or matches no session (R8), attribute targets become OUD
``targetattr`` sets (R1) and the injected source directory gives the group
security classes (OID-30 §30.1.3.4.6). A form without a rule surfaces as
``r.fail``; nothing is approximated or dropped in silence.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from functools import lru_cache

from ldap3.core.exceptions import LDAPInvalidFilterError
from ldap3.operation.search import (
    AND,
    MATCH_EQUAL,
    MATCH_PRESENT,
    MATCH_SUBSTRING,
    NOT,
    OR,
    ROOT,
    FilterNode,
    parse_filter,
)

from flext_ldif import c, m, p, r, u
from flext_ldif.servers._oid import FlextLdifConstantsServersOid


class FlextLdifServersOidAclToOud:
    """OID ACL conversion primitives shared by the policy and the emitter."""

    @staticmethod
    def normalize_dn(dn: str) -> str:
        """Return a DN without spaces around its ``,`` and ``=`` separators."""
        compact: str = c.Ldif.DN_NORMALIZE_COMMA_RE.sub(",", dn)
        return c.Ldif.DN_NORMALIZE_EQUALS_RE.sub("=", compact).strip()

    @staticmethod
    @lru_cache(maxsize=1 << 17)
    def dn_key(dn: str) -> str:
        """Return the comparison key of a DN: separators compacted, case folded.

        Cached: the policy compares the same DNs for every entry it converts.
        """
        return FlextLdifServersOidAclToOud.normalize_dn(dn).lower()

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
    ) -> p.Result[p.Ldif.AclPermissionResolution]:
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
        result = r[p.Ldif.AclPermissionResolution]
        if not tokens:
            return result.fail("Empty OID access list (manual review required)")
        if not all(tokens):
            return result.fail(
                f"Empty token in OID access list {tuple(permissions)!r} "
                "(OID-A7 §A.7.1; manual review required)",
            )
        permission_map = c.Ldif.ENTRY_PERM_MAP if is_entry else c.Ldif.ATTR_PERM_MAP
        all_oud_rights = frozenset(
            right.strip()
            for mapped in permission_map.values()
            if mapped is not None
            for right in mapped.split(",")
        )
        granted: set[str] = set()
        denied: set[str] = set()
        for token in tokens:
            base = c.Ldif.NEGATION_TO_BASE.get(token, token)
            if token == c.Ldif.PERM_NONE:
                denied.update(all_oud_rights)
            elif base in scope:
                mapped = permission_map[base]
                if mapped is None:
                    return result.fail(
                        f"Unknown OID permission token {token!r} (not in the OID "
                        "access grammar, OID-A7 §A.7.1; manual review required)",
                    )
                rights = {right.strip() for right in mapped.split(",")}
                (denied if base != token else granted).update(rights)
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

    @classmethod
    def filter_matches(
        cls,
        value: str,
        attributes: Mapping[str, tuple[str, ...]],
    ) -> p.Result[bool]:
        """Evaluate one RFC 4515 filter against one entry's attributes (E7).

        OID decides an entry ACI's ``filter=`` on the entry the operation acts
        on; for add that is the parent (measured on OID 12.2.1.4). Equality,
        presence, substrings, ``&``, ``|`` and ``!`` are evaluated with
        case-insensitive string matching, the OID default for the directory
        string and object class syntaxes the policy filters name. Any other
        assertion (ordering, approximate, extensible) fails: its matching rule
        is not known here.

        Returns:
            Whether the entry matches, or the typed failure.

        """
        result = r[bool]
        try:
            root = parse_filter(
                search_filter=value,
                schema=None,
                auto_escape=False,
                auto_encode=False,
                validator=None,
                check_names=False,
            )
        except LDAPInvalidFilterError as error:
            return result.fail(f"OID ACL filter {value!r} does not parse: {error}")

        def evaluate(node: FilterNode) -> bool:
            if node.tag in {ROOT, AND}:
                return all(evaluate(item) for item in node.elements)
            if node.tag == OR:
                return any(evaluate(item) for item in node.elements)
            if node.tag == NOT:
                return not evaluate(node.elements[0])
            return cls._assertion_matches(value, node, attributes)

        try:
            return result.ok(evaluate(root))
        except ValueError as error:
            return result.fail(str(error))

    @classmethod
    def _assertion_matches(
        cls,
        value: str,
        node: FilterNode,
        attributes: Mapping[str, tuple[str, ...]],
    ) -> bool:
        """Return whether one filter assertion holds for the entry's values.

        Raises:
            ValueError: For an assertion with no known matching rule.

        """
        assertion = node.assertion
        held = [
            item.casefold()
            for item in attributes.get(str(assertion["attr"]).lower(), ())
        ]
        if node.tag == MATCH_PRESENT:
            return bool(held)
        if node.tag == MATCH_EQUAL:
            return cls._filter_text(assertion["value"]) in held
        if node.tag == MATCH_SUBSTRING:
            initial = cls._filter_text(assertion.get("initial") or b"")
            final = cls._filter_text(assertion.get("final") or b"")
            middles = [cls._filter_text(item) for item in assertion.get("any") or ()]
            return any(
                cls._substring_matches(item, initial, middles, final) for item in held
            )
        msg = f"OID ACL filter {value!r} uses an assertion with no known matching rule"
        raise ValueError(msg)

    @staticmethod
    def _filter_text(raw: bytes) -> str:
        """Decode an RFC 4515 assertion value and fold its case.

        Returns:
            The unescaped, case-folded value.

        """
        parts = FlextLdifConstantsServersOid.LDAP_FILTER_ESCAPE_RE.split(raw)
        decoded = b"".join(
            bytes.fromhex(part.decode()) if index % 2 else part
            for index, part in enumerate(parts)
        )
        return decoded.decode("utf-8", errors="strict").casefold()

    @staticmethod
    def _substring_matches(
        held: str,
        initial: str,
        middles: Sequence[str],
        final: str,
    ) -> bool:
        """Return whether one value matches an RFC 4515 substring assertion."""
        if not held.startswith(initial) or len(held) < len(initial) + len(final):
            return False
        position = len(initial)
        end = len(held) - len(final)
        for middle in middles:
            found = held.find(middle, position, end)
            if found < 0:
                return False
            position = found + len(middle)
        return held.endswith(final)

    @staticmethod
    def attr_set(rule: p.Ldif.OidAclRule) -> p.Ldif.AclAttrSet | None:
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

        An empty element, ``*`` inside a list or an attribute outside the
        description grammar has no exact OUD ``targetattr``. OID ACL attribute
        names already arrive as ``aci`` from the target parser.

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
        return r[bool].ok(value=True)

    @classmethod
    def acl_directory(cls, entries: Sequence[p.Ldif.Entry]) -> p.Ldif.AclDirectory:
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
        values_by_entry: dict[str, dict[str, tuple[str, ...]]] = {}
        found: dict[str, tuple[frozenset[str], frozenset[str], bool]] = {}
        for entry in entries:
            key = cls.dn_key(entry.dn_str)
            names.setdefault(key, entry.dn_str)
            attributes = {
                name.lower(): values for name, values in entry.attributes_dict.items()
            }
            merged = values_by_entry.setdefault(key, {})
            for name, values in attributes.items():
                base = name.partition(";")[0]
                merged[base] = (*merged.get(base, ()), *values)
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
            attributes=values_by_entry,
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
        directory: p.Ldif.AclDirectory,
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
        directory: p.Ldif.AclDirectory,
    ) -> p.Result[tuple[p.Ldif.AclBindLeaf | None, str]]:
        """R8: a group grants only when it is an exact source security group.

        ``group="G"`` names a literal DN, never a group search (OID-A7 §A.7.1):
        a group absent from the source has no members in this generation, also
        when its literal value carries ``*``, so it matches no session and the
        non-match is recorded. A present group whose DN carries ``*`` fails.

        Returns:
            The group leaf; None (matches no session) for an absent group or a
            group without a security class; or the failure for an inexact group.

        """
        constants = FlextLdifConstantsServersOid
        result = r[tuple[p.Ldif.AclBindLeaf | None, str]]
        dn = cls.normalize_dn(value)
        key = dn.lower()
        group = directory.groups.get(key)
        if group is None or not group.classes:
            return result.ok((None, constants.AclRule.R8))
        if c.Ldif.ACL_WILDCARD in dn:
            return result.fail(
                f"R8: OID group DN with a wildcard has no OUD groupdn: {value!r}",
            )
        defect = cls._group_defect(directory, key, frozenset())
        if defect:
            return result.fail(f"R8: {defect}; no exact OUD groupdn")
        return result.ok((
            m.Ldif.AclBindLeaf(kind=constants.AclLeafKind.GROUP, value=dn, key=key),
            constants.AclRule.R8,
        ))

    @classmethod
    def _user_leaf(cls, value: str) -> p.Result[tuple[p.Ldif.AclBindLeaf | None, str]]:
        """R8: a subject DN is literal; ``*,<dn>`` is the strict subtree of dn.

        ``.*<dn>`` (no comma) matches the DN itself and its subtree.

        The OID BNF admits a DN or ``*,<dn_of_any_subtree_root>`` and nothing
        else (OID-A7 §A.7.1 note); ``.*,`` is how OID-30 text writes the
        prefix. Any other regex construct or non-RFC 4514 escape fails.

        Returns:
            The user or strict-subtree leaf, or the failure.

        """
        constants = FlextLdifConstantsServersOid
        result = r[tuple[p.Ldif.AclBindLeaf | None, str]]
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
        if match := constants.OID_REGEX_TREE_RE.match(dn):
            base = cls.normalize_dn(match.group("base"))
            if constants.OID_DN_EXPRESSION_RE.search(base):
                return result.fail(
                    f"R8: OID DN expression {value!r} is not '.*<dn>' over a "
                    "literal DN",
                )
            return result.ok((
                m.Ldif.AclBindLeaf(
                    kind=constants.AclLeafKind.USER_TREE,
                    value=base,
                    key=base.lower(),
                ),
                constants.AclRule.R8,
            ))
        if constants.OID_DN_EXPRESSION_RE.search(dn):
            return result.fail(
                f"R8: OID DN expression {value!r} is not a literal DN, the "
                "subtree '.*<dn>' or the "
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
        directory: p.Ldif.AclDirectory,
    ) -> p.Result[tuple[p.Ldif.AclBindLeaf | None, str]]:
        """R8: convert one OID subject into its OUD bind-rule leaf.

        ``*`` is ``anyone`` (the emitter grants it to ``all``), ``self`` is
        ``self``, ``dnattr=(a)`` is ``userattr="a#USERDN"``, a DN is literal
        and a group is checked against the directory. ``SuperUser`` (E8) and
        ``guidattr`` (E4) match no OUD session; ``groupattr=(a)`` is
        ``userattr="a#GROUPDN"`` (conversion rules R8). ``bindmode`` and
        ``bindipfilter`` fail unless the exact supported form is ``*`` with
        ``bindmode=Proxy``: OID's authentication threshold excludes anonymous,
        represented by the existing OUD ``all`` leaf for grants and denials.

        Returns:
            The leaf (None for no session) and its rule, or the failure.

        """
        constants = FlextLdifConstantsServersOid
        kinds = c.Ldif.OidSubjectKind
        leaves = constants.AclLeafKind
        result = r[tuple[p.Ldif.AclBindLeaf | None, str]]
        authenticated_only = (
            subject.subject_type,
            subject.bindmode.casefold(),
            subject.bindipfilter,
        ) == (kinds.ANYONE, "proxy", "")
        if (subject.bindmode or subject.bindipfilter) and not authenticated_only:
            return result.fail(
                f"R8: bindmode={subject.bindmode!r} bindipfilter="
                f"{subject.bindipfilter!r} has no measured OUD mapping and is "
                "never copied raw",
            )
        match subject.subject_type:
            case kinds.SUPERUSER:
                outcome = result.ok((None, constants.AclRule.E8))
            case kinds.GUIDATTR:
                outcome = result.ok((None, constants.AclRule.E4))
            case kinds.ANYONE:
                binding = (
                    constants.OUD_BIND_ALL
                    if authenticated_only
                    else constants.OUD_BIND_ANYONE
                )
                leaf = m.Ldif.AclBindLeaf(
                    kind=leaves.ALL if authenticated_only else leaves.ANYONE,
                    value=binding,
                    key=binding,
                )
                outcome = result.ok((leaf, constants.AclRule.R8))
            case kinds.SELF:
                leaf = m.Ldif.AclBindLeaf(
                    kind=leaves.SELF,
                    value=constants.OUD_BIND_SELF,
                    key=constants.OUD_BIND_SELF,
                )
                outcome = result.ok((leaf, constants.AclRule.R8))
            case kinds.GROUP:
                outcome = cls._group_leaf(subject.value, directory)
            case kinds.USER:
                outcome = cls._user_leaf(subject.value)
            case kinds.DNATTR if constants.OID_ATTR_DESCRIPTOR_RE.match(subject.value):
                value = subject.value.strip()
                leaf = m.Ldif.AclBindLeaf(
                    kind=leaves.USERATTR,
                    value=value,
                    key=value.lower(),
                )
                outcome = result.ok((leaf, constants.AclRule.R8))
            case kinds.GROUPATTR if constants.OID_ATTR_DESCRIPTOR_RE.match(
                subject.value,
            ):
                value = subject.value.strip()
                leaf = m.Ldif.AclBindLeaf(
                    kind=leaves.GROUPATTR,
                    value=value,
                    key=value.lower(),
                )
                outcome = result.ok((leaf, constants.AclRule.R8))
            case _:
                outcome = result.fail(
                    f"R8: OID subject {subject.subject_type!r} "
                    f"{subject.value!r} has no conversion rule",
                )
        return outcome

    @staticmethod
    def covers(outer: p.Ldif.AclBindLeaf, inner: p.Ldif.AclBindLeaf) -> bool:
        """Return whether every session matching ``inner`` also matches ``outer``.

        True for ``anyone``, the same subject, or a user inside a subtree.
        """
        kinds = FlextLdifConstantsServersOid.AclLeafKind
        if outer.kind == kinds.ANYONE or (outer.kind, outer.key) == (
            inner.kind,
            inner.key,
        ):
            return True
        trees = {kinds.USER, kinds.USER_SUBTREE, kinds.USER_TREE}
        if outer.kind == kinds.USER_SUBTREE and inner.kind in trees:
            return inner.key.endswith(f",{outer.key}")
        if outer.kind == kinds.USER_TREE and inner.kind in trees:
            return inner.key == outer.key or inner.key.endswith(f",{outer.key}")
        return False

    @classmethod
    def disjoint(cls, left: p.Ldif.AclBindLeaf, right: p.Ldif.AclBindLeaf) -> bool:
        """Return whether no session can match both leaves (provable from DNs).

        Group membership, ``self`` and ``userattr`` are not decidable at
        conversion time, so they overlap every subject.
        """
        kinds = FlextLdifConstantsServersOid.AclLeafKind
        users = {kinds.USER, kinds.USER_SUBTREE, kinds.USER_TREE}
        if left.kind not in users or right.kind not in users:
            return False
        return not (cls.covers(left, right) or cls.covers(right, left))


__all__: list[str] = ["FlextLdifServersOidAclToOud"]
