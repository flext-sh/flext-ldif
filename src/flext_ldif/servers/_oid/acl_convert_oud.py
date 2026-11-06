"""OID→OUD ACL conversion — typed OidAclRule parts → OUD aci value objects.

Each by-clause subject maps to one OUD bind-rule (``m.Ldif.AciAllow``);
subjects with no exact OUD equivalent (``SuperUser``/``groupattr``/
``guidattr``/unknown) surface as ``r.fail`` carrying the manual review note.
Permission lists resolve to typed grant and deny sets (OID 12.2.1.3 ch. 30
§30.1.4.3: each access level is granted or denied independently and
``noxxx`` denies ``xxx``). Tokens outside the OID access grammar, modifiers,
regex DNs, filters and targets without an exact OUD form surface as
``r.fail``.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from warnings import deprecated

from flext_ldif import c, m, p, r, u
from flext_ldif.servers._oid import FlextLdifConstantsServersOid


class FlextLdifServersOidAclToOud:
    """Convert parsed OID ACL value objects into OUD aci value objects."""

    @staticmethod
    def _normalize_dn(dn: str) -> str:
        normalized: str = c.Ldif.DN_NORMALIZE_COMMA_RE.sub(",", dn)
        normalized = c.Ldif.DN_NORMALIZE_EQUALS_RE.sub("=", normalized)
        return normalized.strip()

    @classmethod
    def dn_key(cls, dn: str) -> str:
        """Return the comparison key of a DN: separator spaces removed, case folded."""
        return cls._normalize_dn(dn).lower()

    @staticmethod
    def container_dns(base_dn: str) -> frozenset[str]:
        """Return the base DN plus the deprecated container suffix DNs.

        Serves only the deprecated ``high_level_containers`` pass-throughs and
        is removed with them.
        """
        base = base_dn.lower().strip()
        return frozenset(
            f"{suffix}{base}" if suffix else base
            for suffix in FlextLdifConstantsServersOid.HIGH_LEVEL_CONTAINER_SUFFIXES
        )

    @classmethod
    @deprecated(
        "compat: high_level_containers -> removed (no OID semantics); "
        "fix: drop the high-level container filter",
    )
    def high_level_containers(cls, base_dn: str) -> frozenset[str]:
        """Return :meth:`container_dns` (deprecated consumer filter)."""
        return cls.container_dns(base_dn)

    @staticmethod
    def in_scope(dn: str, base_dn: str) -> bool:
        """Return True if ``dn`` is the base or a descendant of it (empty base =.

        all).
        """
        return not base_dn or u.Ldif.under_base(dn, base_dn)

    @staticmethod
    def regex_dn_to_wildcard(value: str) -> p.Result[str]:
        r"""Convert an OID DN regex to the exact OUD bind-DN wildcard.

        The OID grammar allows a DN or a leading wildcard over a subtree root
        (``.*,<dn>``; OID-A7 §A.7.1, written ``.*,`` or ``*,`` in Oracle
        text). That matches one or more RDNs below the root, which is OUD
        ``**,<dn>`` (OUD 12.2.1.4 §9.5.2). A regex-escaped dot ``\.`` is a
        literal dot. Any other wildcard, quantifier, regex construct or
        non-DN escape has no exact OUD form and surfaces as ``r.fail``.

        Returns:
            The OUD bind DN, or the typed failure.

        """
        constants = FlextLdifConstantsServersOid
        subtree = constants.OID_DN_SUBTREE_REGEX_RE.match(value)
        root = subtree.group(1) if subtree else value
        root = constants.OID_DN_ESCAPED_DOT_RE.sub(".", root)
        if constants.OID_DN_UNSUPPORTED_RE.search(root):
            return r[str].fail(
                f"OID regex DN has no exact OUD wildcard (only a leading '.*,' "
                f"subtree wildcard converts; manual review required): {value!r}",
            )
        prefix = constants.OUD_DN_SUBTREE_WILDCARD if subtree else ""
        return r[str].ok(f"{prefix}{root}")

    @classmethod
    def convert_bind_dn(cls, bind_type: str, value: str) -> p.Result[str]:
        """Convert the DN of a ``userdn``/``groupdn`` bind rule.

        A ``dn=`` subject is a DN regex (:meth:`regex_dn_to_wildcard`). A
        ``group=`` subject names one group DN (OID-A7 §A.7.1), so a wildcard
        in it has no exact OUD ``groupdn`` form and surfaces as ``r.fail``.

        Returns:
            The OUD bind DN, or the typed failure.

        """
        if bind_type != c.Ldif.OudSubjectType.GROUPDN:
            return cls.regex_dn_to_wildcard(value)
        if c.Ldif.ACL_WILDCARD in value:
            return r[str].fail(
                f"OID group DN with a wildcard has no exact OUD groupdn "
                f"(manual review required): {value!r}",
            )
        return r[str].ok(value)

    @classmethod
    @deprecated(
        "compat: regex_to_wildcard -> regex_dn_to_wildcard; "
        "fix: consume the typed result",
    )
    def regex_to_wildcard(cls, value: str) -> str:
        """Return :meth:`regex_dn_to_wildcard`, raising on its failure."""
        return cls.regex_dn_to_wildcard(value).unwrap()

    @staticmethod
    def _ipv4_pattern(term: str) -> p.Result[str]:
        """Translate one ``orclipaddress`` filter value into an OUD ip pattern.

        An exact IPv4 address stays as is; a dotted-octet prefix followed by
        ``.*`` (LDAP substring = address prefix) pads the missing octets with
        ``*``. Any other value has no exact OUD ip form.

        Returns:
            The OUD ip pattern, or the typed failure.

        """
        constants = FlextLdifConstantsServersOid
        match = constants.OID_IPV4_PREFIX_RE.match(term)
        octets = match.group(1).split(".") if match else []
        wildcard = bool(match and match.group(2))
        exact = len(octets) == constants.IPV4_OCTET_COUNT and not wildcard
        prefix = 0 < len(octets) < constants.IPV4_OCTET_COUNT and wildcard
        if not (exact or prefix) or any(
            int(octet) > constants.IPV4_OCTET_MAX for octet in octets
        ):
            return r[str].fail(
                f"OID bindipfilter value {term!r} has no exact OUD ip pattern "
                "(manual review required)",
            )
        padding = [constants.IPV4_OCTET_WILDCARD] * (
            constants.IPV4_OCTET_COUNT - len(octets)
        )
        return r[str].ok(".".join((*octets, *padding)))

    @classmethod
    def convert_bindipfilter(cls, value: str) -> p.Result[str]:
        """Translate an OID ``bindipfilter`` into the OUD ``ip`` bind-rule value.

        ``BindIPFilter`` is an LDAP filter on ``orclipaddress`` (OID-30
        §30.1.4.2.3); OUD ``ip`` takes an address list (OUD 12.2.1.4 §9.4.5).
        One equality term, or an OR of equality terms, translates exactly to a
        comma-separated list; ``&``, ``!``/``!=``, an empty filter and other
        shapes surface as ``r.fail``.

        Returns:
            The OUD ip value, or the typed failure.

        """
        constants = FlextLdifConstantsServersOid
        text = value.strip()
        term = constants.OID_IP_FILTER_TERM_RE.match(text)
        alternatives = constants.OID_IP_FILTER_OR_RE.match(text)
        if term is not None:
            raw_terms: Sequence[str] = (term.group(1),)
        elif alternatives is not None:
            raw_terms = tuple(
                item.group(1)
                for item in constants.OID_IP_FILTER_OR_TERM_RE.finditer(
                    alternatives.group(1),
                )
            )
        else:
            return r[str].fail(
                f"OID bindipfilter {value!r} has no exact OUD ip equivalent "
                "(only orclipaddress equality terms or their OR translate; "
                "manual review required)",
            )
        return r.traverse(raw_terms, cls._ipv4_pattern).map(
            constants.OUD_IP_LIST_SEPARATOR.join,
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
        """Validate an OID ``filter=(...)`` object qualifier as one LDAP filter.

        The OID object filter is an LDAP filter (OID-30 §30.1.4.1) and renders
        as the OUD ``targetfilter`` (OUD §9.2.2.5). The text must be exactly
        one RFC 4515 filter: ``&``/``|`` over one or more filters, ``!`` over
        one, or a simple, present, substring or extensible item. The qualifier
        body is stored without its outer parentheses, which are restored.

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
        return r[str].ok(text)

    @classmethod
    def convert_bind_modifiers(cls, subject: p.Ldif.OidAclSubject) -> p.Result[str]:
        """Translate a subject's OID modifiers into its OUD ``ip`` constraint.

        ``bindmode`` fails: OID authentication modes are ordered (Anonymous <
        Proxy < Simple < MD5Digest < PKCS12, each blocking the lower ones;
        OID-30 §30.1.4.2.2) while OUD ``authmethod`` is an equality on
        ``none``/``simple``/``ssl``/``sasl`` (OUD §9.4.8). The added-object
        constraint (OID-30 §30.1.4.2.4) narrows ``add`` and has no exact OUD
        form, so it fails too. ``bindipfilter`` translates through
        :meth:`convert_bindipfilter`; a subject without one yields ``""``.

        Returns:
            The OUD ip value, or the typed failure.

        """
        if subject.bindmode:
            return r[str].fail(
                f"OID bindmode {subject.bindmode!r} has no exact OUD authmethod "
                "(ordered OID modes vs OUD equality; manual review required)",
            )
        if subject.added_object_constraint:
            return r[str].fail(
                "OID added_object_constraint "
                f"{subject.added_object_constraint!r} has no exact OUD "
                "equivalent (manual review required)",
            )
        if not subject.bindipfilter:
            return r[str].ok("")
        return cls.convert_bindipfilter(subject.bindipfilter)

    @staticmethod
    def _order_perms(perms: set[str]) -> Sequence[str]:
        return tuple(perm for perm in c.Ldif.PERM_ORDERED if perm in perms)

    @staticmethod
    def _map_tokens(
        bases: frozenset[str],
        perm_map: Mapping[str, str | None],
    ) -> set[str]:
        granted: set[str] = set()
        for base in bases:
            mapped = perm_map.get(base)
            if mapped:
                granted.update(
                    part.strip() for part in mapped.split(",") if part.strip()
                )
        return granted

    @staticmethod
    def _collect_permission_bases(
        permissions: Sequence[str],
        *,
        is_entry: bool,
    ) -> p.Result[tuple[frozenset[str], frozenset[str]]]:
        """Split OID access tokens into granted and denied base rights.

        Only the tokens of the OID access grammar for the object kind are
        accepted (OID-A7 §A.7.1; OID-30 Table 30-2): ``none``, the entry
        rights ``browse``/``add``/``delete``/``proxy`` or the attribute rights
        ``read``/``search``/``write``/``selfwrite``/``compare``, and their
        ``no*`` forms. ``all``, ``*``, an empty list or token and a right of
        the other object kind surface as ``r.fail``. ``none`` denies every right of the
        kind; a right both granted and denied is denied.

        Returns:
            The ``(granted, denied)`` base rights, or the typed failure.

        """
        scope = c.Ldif.ALL_ENTRY_PERMS if is_entry else c.Ldif.ALL_ATTR_PERMS
        other = c.Ldif.ALL_ATTR_PERMS if is_entry else c.Ldif.ALL_ENTRY_PERMS
        kind = c.Ldif.AclTargetType.ENTRY if is_entry else c.Ldif.AclTargetType.ATTR
        tokens = [raw.strip().lower() for raw in permissions]
        result = r[tuple[frozenset[str], frozenset[str]]]
        if not tokens:
            return result.fail("Empty OID access list (manual review required)")
        if not all(tokens):
            return result.fail(
                f"Empty token in OID access list {tuple(permissions)!r} "
                "(OID-A7 §A.7.1; manual review required)",
            )
        granted: set[str] = set()
        denied: set[str] = set()
        for perm in tokens:
            base = c.Ldif.NEGATION_TO_BASE.get(perm, perm)
            if perm == c.Ldif.PERM_NONE:
                denied.update(scope)
            elif base in scope:
                (denied if base != perm else granted).add(base)
            elif base in other:
                return result.fail(
                    f"OID permission {perm!r} is not a right of an {kind.value!r} "
                    "object (OID-30 Table 30-2; manual review required)",
                )
            else:
                return result.fail(
                    f"Unknown OID permission token {perm!r} (not in the OID "
                    "access grammar, OID-A7 §A.7.1; manual review required)",
                )
        return result.ok((frozenset(granted - denied), frozenset(denied)))

    @classmethod
    def resolve_permissions(
        cls,
        permissions: Sequence[str],
        *,
        is_entry: bool,
    ) -> p.Result[p.Ldif.AclPermissionResolution]:
        """Resolve OID access tokens into ordered OUD grant and deny sets.

        Each access level is granted or denied independently and ``noxxx``
        denies ``xxx`` (OID 12.2.1.3 §30.1.4.3). A pure-negation list denies
        exactly the named rights and grants nothing; unnamed rights stay
        unresolved (Table 30-4). ``none`` denies every right of the target
        kind (Table 30-2) and sets ``total_denial``. A token outside the OID
        access grammar of the object kind surfaces as ``r.fail``.

        Returns:
            The typed grant/deny resolution, or the token failure.

        """
        perm_map = c.Ldif.ENTRY_PERM_MAP if is_entry else c.Ldif.ATTR_PERM_MAP
        scope = c.Ldif.ALL_ENTRY_PERMS if is_entry else c.Ldif.ALL_ATTR_PERMS

        def resolve(
            bases: tuple[frozenset[str], frozenset[str]],
        ) -> p.Ldif.AclPermissionResolution:
            granted, denied = bases
            deny = cls._map_tokens(denied, perm_map)
            allow = cls._map_tokens(granted, perm_map) - deny
            return m.Ldif.AclPermissionResolution(
                allow=cls._order_perms(allow),
                deny=cls._order_perms(deny),
                total_denial=denied == scope,
            )

        return cls._collect_permission_bases(permissions, is_entry=is_entry).map(
            resolve,
        )

    @classmethod
    @deprecated(
        "compat: convert_permissions -> resolve_permissions; "
        "fix: render the typed deny set",
    )
    def convert_permissions(
        cls,
        permissions: Sequence[str],
        *,
        is_entry: bool,
    ) -> p.Result[Sequence[str]]:
        """Return the granted rights of :meth:`resolve_permissions` only.

        Returns:
            The granted OUD tokens, or the token failure.

        """
        return cls.resolve_permissions(permissions, is_entry=is_entry).map(
            lambda resolved: tuple(resolved.allow),
        )

    @staticmethod
    def _target_attr_names(rule: p.Ldif.OidAclRule) -> Sequence[str]:
        """Return the attribute names of an ``attr=``/``attr!=`` target list."""
        body = rule.target_attrs.removeprefix(c.Ldif.OUD_ATTR_NEGATION)
        return tuple(name.strip() for name in body.split(",") if name.strip())

    @classmethod
    def named_target_attrs(cls, rule: p.Ldif.OidAclRule) -> Sequence[str]:
        """Return the attributes an ``attr=(list)`` rule names explicitly.

        Entry targets, ``attr=(*)`` and ``attr!=(list)`` name none.

        Returns:
            The named attributes in input order.

        """
        attrs = rule.target_attrs
        if (
            rule.target_type == c.Ldif.AclTargetType.ENTRY
            or attrs.startswith(c.Ldif.OUD_ATTR_NEGATION)
            or attrs in {c.Ldif.ACL_WILDCARD, ""}
        ):
            return ()
        return cls._target_attr_names(rule)

    @classmethod
    def convert_targetattr(
        cls,
        rule: p.Ldif.OidAclRule,
        *,
        sibling_attrs: Sequence[str] = (),
    ) -> p.Result[str]:
        """Compute the OUD ``targetattr`` of a rule, failing on inexact forms.

        An entry target renders ``*``; ``attr=(a,b)`` renders ``a||b`` and
        ``attr!=(a,b)`` renders ``!=a||b``. When another ACI of the same ACP
        names attributes explicitly, OID reads that ACP's ``attr=(*)`` as every
        attribute except those (OID-30 §30.1.6.3), so ``attr=(*)`` renders
        ``!=`` over ``sibling_attrs``; an ``attr!=`` rule next to such
        siblings is undefined in OID and fails. A target naming an OID ACL
        attribute (it does not exist after conversion), mixing OUD
        operational and user attributes, or negating an operational attribute
        has no exact OUD form (OUD11-COMPAT) and fails.

        Returns:
            The OUD targetattr, or the typed failure.

        """
        result = r[str]
        if rule.target_type == c.Ldif.AclTargetType.ENTRY:
            return result.ok(c.Ldif.ACL_WILDCARD)
        negated = rule.target_attrs.startswith(c.Ldif.OUD_ATTR_NEGATION)
        if negated and sibling_attrs:
            return result.fail(
                f"OID attr!= target {rule.target_attrs!r} shares its ACP with "
                f"named-attribute ACIs {tuple(sibling_attrs)!r}; OID leaves that "
                "combination undefined (OID-30 §30.1.6.3; manual review required)",
            )
        names = cls._target_attr_names(rule)
        if not negated and not cls.named_target_attrs(rule):
            names = tuple(dict.fromkeys(sibling_attrs))
            negated = bool(names)
        if not names:
            return result.ok(c.Ldif.ACL_WILDCARD)
        defect = cls._targetattr_defect(rule, names, negated=negated)
        if defect:
            return result.fail(defect)
        joined = c.Ldif.OUD_ATTR_OR.join(names)
        return result.ok(f"{c.Ldif.OUD_ATTR_NEGATION}{joined}" if negated else joined)

    @staticmethod
    def _targetattr_defect(
        rule: p.Ldif.OidAclRule,
        names: Sequence[str],
        *,
        negated: bool,
    ) -> str:
        """Return why ``names`` has no exact OUD targetattr, or ``""``."""
        folded = {name.lower() for name in names}
        acl_attrs = folded & {str(kind) for kind in c.Ldif.AclConvertType}
        operational = folded & FlextLdifConstantsServersOid.OUD_OPERATIONAL_ATTRS
        if c.Ldif.ACL_WILDCARD in names:
            return (
                f"OID ACL target {rule.target_attrs!r} mixes '*' with attribute "
                "names, which OUD rejects (OUD11-COMPAT; manual review required)"
            )
        if acl_attrs:
            return (
                f"OID ACL target names the ACL attributes {sorted(acl_attrs)!r}, "
                "which do not exist after conversion to OUD aci (manual review "
                "required)"
            )
        if operational and (negated or operational != folded):
            return (
                f"OID ACL target {rule.target_attrs!r} would render an OUD "
                "targetattr that negates or mixes the operational attributes "
                f"{sorted(operational)!r}, which OUD rejects (OUD11-COMPAT; "
                "manual review required)"
            )
        return ""

    @classmethod
    @deprecated(
        "compat: resolve_targetattr -> convert_targetattr; "
        "fix: consume the typed result",
    )
    def resolve_targetattr(cls, rule: p.Ldif.OidAclRule) -> str:
        """Return :meth:`convert_targetattr` without siblings, raising on failure."""
        return cls.convert_targetattr(rule).unwrap()

    @staticmethod
    def rule_targetscope(rule: p.Ldif.OidAclRule) -> str | None:
        """Compute the OUD ``targetscope`` of a rule.

        ``orclentrylevelaci`` governs only its entry (OID-30 §30.1.3.3) and
        renders ``base``. An ``orclaci`` is prescriptive over its whole
        subtree (OID-30 §30.1.3.2), the OUD default, so its targetscope is
        omitted (``None``).

        Returns:
            ``base`` or ``None``.

        """
        if rule.acl_type == c.Ldif.AclConvertType.ORCLENTRYLEVELACI:
            return c.Ldif.ACL_SCOPE_BASE
        return None

    @classmethod
    @deprecated(
        "compat: calculate_targetscope -> rule_targetscope; "
        "fix: drop has_anyone_subject (an orclaci is always subtree)",
    )
    def calculate_targetscope(
        cls,
        rule: p.Ldif.OidAclRule,
        *,
        has_anyone_subject: bool,
    ) -> str | None:
        """Return :meth:`rule_targetscope`; ``has_anyone_subject`` has no effect."""
        del has_anyone_subject
        return cls.rule_targetscope(rule)

    @staticmethod
    def _split_by(
        permissions: Sequence[str],
        selected: frozenset[str],
    ) -> tuple[Sequence[str], Sequence[str]]:
        """Return ``(rights in selected, other rights)`` in input order."""
        return (
            tuple(perm for perm in permissions if perm in selected),
            tuple(perm for perm in permissions if perm not in selected),
        )

    @classmethod
    def clause_parts(
        cls,
        rule: p.Ldif.OidAclRule,
        permissions: Sequence[str],
        *,
        deny: bool,
    ) -> Sequence[tuple[str | None, str | None, Sequence[str]]]:
        """Partition one clause's OUD rights by the targetattr and scope they need.

        OUD returns an entry only with read on one of its attributes (OUD
        §9.2.3.3) and its default global ACIs grant read, search and compare
        on named operational attributes (OUD12-28 §28.1.2), which ``*`` does
        not cover (OUD11-COMPAT). An entry denial of read or search therefore
        also denies those rights, in its own aci, on those operational
        attributes, so the entry stays hidden as in OID. ``orclentrylevelaci``
        governs only its entry (OID-30 §30.1.3.3), but OID ``add`` there
        authorizes adding children while OUD checks ``add`` on the new child
        (OUD §9.2.3.3), so ``add`` renders with ``onelevel``. ``None`` means
        the rule's targetattr or targetscope.

        Returns:
            ``(targetattr, targetscope, rights)`` triples with non-empty rights.

        """
        constants = FlextLdifConstantsServersOid
        attr_parts: list[tuple[str | None, Sequence[str]]] = [(None, permissions)]
        if (
            deny
            and rule.target_type == c.Ldif.AclTargetType.ENTRY
            and cls._split_by(permissions, constants.OUD_VISIBILITY_PERMS)[0]
        ):
            attr_parts.append((
                constants.OUD_GLOBAL_OPERATIONAL_TARGETATTR,
                constants.OUD_GLOBAL_OPERATIONAL_PERMS,
            ))
        parts: list[tuple[str | None, str | None, Sequence[str]]] = []
        for targetattr, perms in attr_parts:
            if rule.acl_type == c.Ldif.AclConvertType.ORCLENTRYLEVELACI:
                child, own = cls._split_by(perms, constants.OUD_CHILD_ENTRY_PERMS)
                parts.extend((
                    (targetattr, None, own),
                    (targetattr, constants.ACL_SCOPE_ONELEVEL, child),
                ))
            else:
                parts.append((targetattr, None, perms))
        return tuple(part for part in parts if part[2])

    @classmethod
    def convert_subject_to_oud(
        cls,
        subject: p.Ldif.OidAclSubject,
    ) -> p.Result[p.Ldif.AciAllow]:
        """Map one OID by-clause subject to an OUD bind-rule.

        Returns an :class:`m.Ldif.AciAllow` whose ``subject_value`` is the
        normalized bind value (``ldap:///`` is applied at aci assembly) and whose
        ``permissions`` are left empty — the assembler fills the resolved
        rights. ``*`` maps to ``anyone``; the assembler narrows its grants to
        authenticated sessions. ``SuperUser``, ``groupattr``, ``guidattr`` and
        unknown subjects have no exact OUD equivalent and surface as
        ``r.fail`` carrying the manual-review note.

        Returns:
            The resulting ``p.Result[p.Ldif.AciAllow]``.

        """
        kind = subject.subject_type
        value = subject.value
        oud = c.Ldif.OudSubjectType
        match kind:
            case c.Ldif.OidSubjectKind.GROUP:
                bind_type, bind_value = oud.GROUPDN.value, cls._normalize_dn(value)
            case c.Ldif.OidSubjectKind.USER:
                bind_type, bind_value = oud.USERDN.value, cls._normalize_dn(value)
            case c.Ldif.OidSubjectKind.SELF:
                bind_type, bind_value = oud.USERDN.value, c.Ldif.SUBJECT_SELF
            case c.Ldif.OidSubjectKind.ANYONE:
                bind_type, bind_value = oud.USERDN.value, c.Ldif.SUBJECT_ANYONE
            case c.Ldif.OidSubjectKind.SUPERUSER:
                return r[p.Ldif.AciAllow].fail(
                    "OID SuperUser is subject to access control and names the "
                    "configured superuser DN (OID-30 §30.1.4.2.1; R3.9), while "
                    "the OUD root user bypasses ACIs (OUD §9.1.4); no OUD bind "
                    "rule keeps its grants and denials (manual review required)",
                )
            case c.Ldif.OidSubjectKind.GROUPATTR:
                return r[p.Ldif.AciAllow].fail(
                    f"OID groupattr=({value}) honours only the security groups "
                    "the attribute names on each entry (OID-30 §30.1.3.4.6), "
                    "while OUD userattr GROUPDN honours every group; the "
                    "per-entry values cannot be verified from the ACI (manual "
                    "review required)",
                )
            case c.Ldif.OidSubjectKind.DNATTR if (
                not FlextLdifConstantsServersOid.OID_ATTR_DESCRIPTOR_RE.match(value)
            ):
                return r[p.Ldif.AciAllow].fail(
                    f"Subject '{kind}' value {value!r} is not one attribute "
                    "description (manual review required)",
                )
            case c.Ldif.OidSubjectKind.DNATTR:
                bind_type = oud.USERATTR.value
                bind_value = f"{value}{c.Ldif.UserAttrSuffix.USERDN.value}"
            case _:
                return r[p.Ldif.AciAllow].fail(
                    f"Subject '{kind}' has no OUD equivalent "
                    f"(manual review required): {value!r}",
                )
        return r[p.Ldif.AciAllow].ok(
            m.Ldif.AciAllow(subject_type=bind_type, subject_value=bind_value),
        )


__all__: list[str] = ["FlextLdifServersOidAclToOud"]
