"""OID→OUD ACL conversion — typed OidAclRule parts → OUD aci value objects.

Each by-clause subject maps to one OUD bind-rule (``m.Ldif.AciAllow``);
subjects with no OUD equivalent (``guidattr``/unknown) surface as ``r.fail``
carrying the manual review note. Permission lists resolve to typed grant and
deny sets (OID 12.2.1.3 ch. 30 §30.1.4.3: each access level is granted or
denied independently and ``noxxx`` denies ``xxx``). Tokens outside the OID
access grammar, modifiers and regex DNs without an exact OUD form surface as
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
        comma-separated list; ``&``, ``!``/``!=`` and other shapes surface as
        ``r.fail``. An empty value yields ``""``.

        Returns:
            The OUD ip value, or the typed failure.

        """
        constants = FlextLdifConstantsServersOid
        text = value.strip()
        if not text:
            return r[str].ok("")
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
    def convert_bind_modifiers(cls, subject: p.Ldif.OidAclSubject) -> p.Result[str]:
        """Translate a subject's OID modifiers into its OUD ``ip`` constraint.

        ``bindmode`` fails: OID authentication modes are ordered (Anonymous <
        Proxy < Simple < MD5Digest < PKCS12, each blocking the lower ones;
        OID-30 §30.1.4.2.2) while OUD ``authmethod`` is an equality on
        ``none``/``simple``/``ssl``/``sasl`` (OUD §9.4.8). The added-object
        constraint (OID-30 §30.1.4.2.4) narrows ``add`` and has no exact OUD
        form, so it fails too. ``bindipfilter`` translates through
        :meth:`convert_bindipfilter`.

        Returns:
            The OUD ip value (``""`` without a filter), or the typed failure.

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
        ``no*`` forms. ``all``, ``*``, an empty list and a right of the other
        object kind surface as ``r.fail``. ``none`` denies every right of the
        kind; a right both granted and denied is denied.

        Returns:
            The ``(granted, denied)`` base rights, or the typed failure.

        """
        scope = c.Ldif.ALL_ENTRY_PERMS if is_entry else c.Ldif.ALL_ATTR_PERMS
        other = c.Ldif.ALL_ATTR_PERMS if is_entry else c.Ldif.ALL_ENTRY_PERMS
        kind = c.Ldif.AclTargetType.ENTRY if is_entry else c.Ldif.AclTargetType.ATTR
        tokens = [raw.strip().lower() for raw in permissions if raw.strip()]
        result = r[tuple[frozenset[str], frozenset[str]]]
        if not tokens:
            return result.fail("Empty OID access list (manual review required)")
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
    def resolve_targetattr(rule: p.Ldif.OidAclRule) -> str:
        """Compute the OUD ``targetattr`` (entry→``*``, list→``a||b``,.

        # ``attr!=``→``!=a||b``).

        Returns:
            The resulting ``str``.

        """
        attr_negation: str = c.Ldif.OUD_ATTR_NEGATION
        attr_or: str = c.Ldif.OUD_ATTR_OR
        wildcard: str = c.Ldif.ACL_WILDCARD
        if rule.target_type == c.Ldif.AclTargetType.ENTRY:
            return wildcard
        attrs: str = rule.target_attrs
        if attrs.startswith(attr_negation):
            body = attrs[len(attr_negation) :]
            joined = body.replace(",", attr_or).replace(" ", "")
            return f"{attr_negation}{joined}"
        if attrs in {wildcard, ""}:
            return wildcard
        return attrs.replace(",", attr_or).replace(" ", "")

    @staticmethod
    def calculate_targetscope(
        rule: p.Ldif.OidAclRule,
        *,
        has_anyone_subject: bool,
    ) -> str | None:
        """Compute the OUD ``targetscope`` of the rule's allow clauses.

        ``orclentrylevelaci`` is non-inheritable → always ``base``. An ``orclaci``
        with a granting ``anyone`` subject is pinned to ``base`` to prevent
        inheritance to the subtree; otherwise the OUD default (subtree) applies
        and ``targetscope`` is omitted (``None``).

        Returns:
            The resulting ``str | None``.

        """
        acl_scope_base: str = c.Ldif.ACL_SCOPE_BASE
        if rule.acl_type == c.Ldif.AclConvertType.ORCLENTRYLEVELACI:
            return acl_scope_base
        if has_anyone_subject:
            return acl_scope_base
        return None

    @staticmethod
    def clause_scopes(
        rule: p.Ldif.OidAclRule,
        permissions: Sequence[str],
        *,
        deny: bool,
        rule_scope: str | None,
    ) -> Sequence[tuple[str | None, Sequence[str]]]:
        """Partition one clause's OUD rights by the targetscope they need.

        ``orclentrylevelaci`` governs only its entry (OID-30 §30.1.3.3), but
        OID ``add`` there authorizes adding children while OUD checks ``add``
        on the new child (OUD 12.2.1.4 §9.2.3.3), so ``add`` renders with
        ``onelevel`` and the other rights with the rule scope. An ``orclaci``
        is prescriptive over its whole subtree (OID-30 §30.1.3.2), so its
        denials render with ``subtree`` even when the rule's allows are
        pinned to ``base``. ``None`` means the rule's targetscope.

        Returns:
            ``(targetscope, rights)`` pairs with non-empty rights.

        """
        constants = FlextLdifConstantsServersOid
        if rule.acl_type == c.Ldif.AclConvertType.ORCLENTRYLEVELACI:
            child = constants.ENTRY_LEVEL_CHILD_PERMS
            parts: Sequence[tuple[str | None, Sequence[str]]] = (
                (None, tuple(perm for perm in permissions if perm not in child)),
                (
                    constants.ACL_SCOPE_ONELEVEL,
                    tuple(perm for perm in permissions if perm in child),
                ),
            )
        elif deny and rule_scope is not None:
            parts = ((constants.ACL_SCOPE_SUBTREE, tuple(permissions)),)
        else:
            parts = ((None, tuple(permissions)),)
        return tuple((scope, perms) for scope, perms in parts if perms)

    @classmethod
    def convert_subject_to_oud(
        cls,
        subject: p.Ldif.OidAclSubject,
    ) -> p.Result[p.Ldif.AciAllow]:
        """Map one OID by-clause subject to an OUD bind-rule.

        Returns an :class:`m.Ldif.AciAllow` whose ``subject_value`` is the
        normalized bind value (``ldap:///`` is applied at aci assembly) and whose
        ``permissions`` are left empty — the assembler fills the resolved
        rights. ``guidattr``/unknown subjects have no OUD equivalent and
        surface as ``r.fail`` carrying the manual-review note.

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
                bind_type, bind_value = oud.USERDN.value, c.Ldif.DIRECTORY_MANAGER_DN
            case c.Ldif.OidSubjectKind.DNATTR:
                bind_type = oud.USERATTR.value
                bind_value = f"{value}{c.Ldif.UserAttrSuffix.USERDN.value}"
            case c.Ldif.OidSubjectKind.GROUPATTR:
                bind_type = oud.USERATTR.value
                bind_value = f"{value}{c.Ldif.UserAttrSuffix.GROUPDN.value}"
            case _:
                return r[p.Ldif.AciAllow].fail(
                    f"Subject '{kind}' has no OUD equivalent "
                    f"(manual review required): {value!r}",
                )
        return r[p.Ldif.AciAllow].ok(
            m.Ldif.AciAllow(subject_type=bind_type, subject_value=bind_value),
        )


__all__: list[str] = ["FlextLdifServersOidAclToOud"]
