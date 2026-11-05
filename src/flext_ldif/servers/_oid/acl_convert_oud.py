"""OID→OUD ACL conversion — typed OidAclRule → OUD aci value objects.

Each by-clause subject maps to one OUD bind-rule (``m.Ldif.AciAllow``);
subjects with no OUD equivalent (``guidattr``/unknown) surface as ``r.fail``
carrying the manual review note — never a silent drop. Permission lists resolve
to typed grant and deny sets (OID 12.2.1.3 ch. 30 §30.1.4.3: each access level
is granted or denied independently and ``noxxx`` denies ``xxx``). Modifiers and
regex DNs without an exact OUD form surface as ``r.fail``. Taxonomy is the
``c.Ldif`` SSOT.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from flext_ldif import c, m, p, r, u


class FlextLdifServersOidAclToOud:
    """Convert parsed OID ACL value objects into OUD aci value objects."""

    @staticmethod
    def _normalize_dn(dn: str) -> str:
        normalized: str = c.Ldif.DN_NORMALIZE_COMMA_RE.sub(",", dn)
        normalized = c.Ldif.DN_NORMALIZE_EQUALS_RE.sub("=", normalized)
        return normalized.strip()

    @staticmethod
    def in_scope(dn: str, base_dn: str) -> bool:
        """Return True if ``dn`` is the base or a descendant of it (empty base =.

        all).
        """
        return not base_dn or u.Ldif.under_base(dn, base_dn)

    @staticmethod
    def regex_to_wildcard(value: str) -> p.Result[str]:
        r"""Convert an OID regex DN to an OUD wildcard (``.*``/``.+`` → ``*``).

        OID restricts the DN regex to a leading wildcard over a subtree root
        (OID-A7 §A.7.1); OUD bind DNs accept only ``*`` wildcards (OUD 12.2.1.4
        §9.5.2). ``\.``/``\,`` are unescaped. A residual regex metacharacter
        means the DN has no exact OUD form and surfaces as ``r.fail`` — the raw
        regex is never written as a bind DN.

        Returns:
            The OUD wildcard DN, or the typed failure.

        """
        converted = value
        for pattern, replacement in c.Ldif.OID_REGEX_REPLACEMENTS:
            converted = converted.replace(pattern, replacement)
        if c.Ldif.OID_REGEX_RESIDUAL_RE.search(converted):
            return r[str].fail(
                f"OID regex DN has no exact OUD wildcard (only '.*' and '.+' "
                f"convert; manual review required): {value!r}",
            )
        return r[str].ok(converted)

    @staticmethod
    def _ipv4_pattern(term: str) -> p.Result[str]:
        """Translate one ``orclipaddress`` filter value into an OUD ip pattern.

        An exact IPv4 address stays as is; a dotted-octet prefix followed by
        ``.*`` (LDAP substring = address prefix) pads the missing octets with
        ``*``. Any other value has no exact OUD ip form.

        Returns:
            The OUD ip pattern, or the typed failure.

        """
        match = c.Ldif.OID_IPV4_PREFIX_RE.match(term)
        octets = match.group(1).split(".") if match else []
        wildcard = bool(match and match.group(2))
        exact = len(octets) == c.Ldif.IPV4_OCTET_COUNT and not wildcard
        prefix = 0 < len(octets) < c.Ldif.IPV4_OCTET_COUNT and wildcard
        if not (exact or prefix) or any(
            int(octet) > c.Ldif.IPV4_OCTET_MAX for octet in octets
        ):
            return r[str].fail(
                f"OID bindipfilter value {term!r} has no exact OUD ip pattern "
                "(manual review required)",
            )
        padding = [c.Ldif.IPV4_OCTET_WILDCARD] * (c.Ldif.IPV4_OCTET_COUNT - len(octets))
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
        text = value.strip()
        if not text:
            return r[str].ok("")
        term = c.Ldif.OID_IP_FILTER_TERM_RE.match(text)
        alternatives = c.Ldif.OID_IP_FILTER_OR_RE.match(text)
        if term is not None:
            raw_terms: Sequence[str] = (term.group(1),)
        elif alternatives is not None:
            raw_terms = tuple(
                item.group(1)
                for item in c.Ldif.OID_IP_FILTER_OR_TERM_RE.finditer(
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
            c.Ldif.OUD_IP_LIST_SEPARATOR.join,
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
        ordered = tuple(p for p in c.Ldif.PERM_ORDERED if p in perms)
        extra = tuple(sorted(perms - set(c.Ldif.PERM_ORDERED)))
        return ordered + extra

    @classmethod
    def _map_tokens(
        cls,
        bases: set[str],
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

    @classmethod
    def _collect_permission_bases(
        cls,
        permissions: Sequence[str],
        perm_map: Mapping[str, str | None],
        all_perms: frozenset[str],
    ) -> p.Result[tuple[set[str], set[str], bool, bool]]:
        """Split OID permission tokens into positive/negated base sets.

        Returns:
            The resulting ``p.Result[tuple[set[str], set[str], bool, bool]]``.

        """
        positive_bases: set[str] = set()
        negated_bases: set[str] = set()
        deny_all = False
        explicit_all = False
        known_positive = c.Ldif.ALL_ENTRY_PERMS | c.Ldif.ALL_ATTR_PERMS
        for raw in permissions:
            perm = raw.strip().lower()
            if not perm:
                continue
            if perm == "none":
                deny_all = True
            elif perm.startswith(c.ParserBooleanToken.NO):
                base = c.Ldif.NEGATION_TO_BASE.get(perm)
                if base is None:
                    return r[tuple[set[str], set[str], bool, bool]].fail(
                        f"Unknown negation perm: {perm!r}",
                    )
                negated_bases.add(base)
            elif perm == c.Ldif.PERM_ALL:
                explicit_all = True
                positive_bases.update(all_perms)
            elif perm in perm_map:
                positive_bases.add(perm)
            elif perm not in known_positive:
                return r[tuple[set[str], set[str], bool, bool]].fail(
                    f"Unknown permission token: {perm!r}",
                )
        return r[tuple[set[str], set[str], bool, bool]].ok((
            positive_bases,
            negated_bases,
            deny_all,
            explicit_all,
        ))

    @classmethod
    def _resolve_permissions(
        cls,
        perm_map: Mapping[str, str | None],
        all_perms: frozenset[str],
        bases: tuple[set[str], set[str], bool, bool],
    ) -> p.Ldif.AclPermissionResolution:
        """Resolve collected positive/negated bases into grant and deny sets.

        Returns:
            The ordered OUD allow and deny tokens.

        """
        positive_bases, negated_bases, deny_all, explicit_all = bases
        if deny_all:
            return m.Ldif.AclPermissionResolution(
                deny=cls._order_perms(cls._map_tokens(set(all_perms), perm_map)),
            )
        if explicit_all and not negated_bases:
            return m.Ldif.AclPermissionResolution(allow=(c.Ldif.PERM_ALL,))
        deny = cls._map_tokens(negated_bases, perm_map)
        allow = cls._map_tokens(positive_bases - negated_bases, perm_map) - deny
        return m.Ldif.AclPermissionResolution(
            allow=cls._order_perms(allow),
            deny=cls._order_perms(deny),
        )

    @classmethod
    def convert_permissions(
        cls,
        permissions: Sequence[str],
        *,
        is_entry: bool,
    ) -> p.Result[p.Ldif.AclPermissionResolution]:
        """Resolve OID permission tokens into ordered OUD grant and deny sets.

        Each access level is granted or denied independently and ``noxxx``
        denies ``xxx`` (OID 12.2.1.3 §30.1.4.3). A pure-negation list therefore
        denies exactly the named rights and grants NOTHING; unnamed rights stay
        unresolved (Table 30-4). A mixed list keeps its positive grants and
        denies its ``no*`` rights. ``none`` denies every right of the target
        kind (Table 30-2). ``all`` expands to the scoped permission universe
        before ``no*`` negations apply. A perm valid only at the other scope
        (``read`` on an entry rule) resolves to nothing here; a token in
        neither scope → ``r.fail``.

        Returns:
            The typed grant/deny resolution, or the unknown-token failure.

        """
        perm_map = c.Ldif.ENTRY_PERM_MAP if is_entry else c.Ldif.ATTR_PERM_MAP
        all_perms = c.Ldif.ALL_ENTRY_PERMS if is_entry else c.Ldif.ALL_ATTR_PERMS
        return cls._collect_permission_bases(permissions, perm_map, all_perms).map(
            lambda bases: cls._resolve_permissions(perm_map, all_perms, bases),
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
        """Compute the OUD ``targetscope`` (``base`` or default subtree).

        ``orclentrylevelaci`` is non-inheritable → always ``base``. An ``orclaci``
        with a surviving ``anyone`` subject is pinned to ``base`` to prevent
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

    @classmethod
    def convert_subject_to_oud(
        cls,
        subject: p.Ldif.OidAclSubject,
    ) -> p.Result[p.Ldif.AciAllow]:
        """Map one OID by-clause subject to an OUD bind-rule.

        Returns an :class:`m.Ldif.AciAllow` whose ``subject_value`` is the
        normalized bind value (``ldap:///`` is applied at aci assembly) and whose
        ``permissions`` are left empty — Step 5 fills the converted permission
        set. ``guidattr``/unknown subjects have no OUD equivalent and surface as
        ``r.fail`` (the caller records the manual-review note).

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
