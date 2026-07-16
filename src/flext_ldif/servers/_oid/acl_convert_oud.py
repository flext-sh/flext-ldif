"""OID→OUD ACL conversion — typed OidAclRule → OUD aci value objects.

Faithful port of the OUD migration oracle converter
(``convert_subject_to_oud`` and downstream assembly). Each by-clause subject
maps to one OUD bind-rule (``m.Ldif.AciAllow``); subjects with no OUD
equivalent (``guidattr``/unknown) surface as ``r.fail`` carrying the manual
review note — never a silent drop. Taxonomy is the ``c.Ldif`` SSOT.
"""

from __future__ import annotations

from flext_ldif import c, m, p, r, t


class FlextLdifServersOidAclToOud:
    """Convert parsed OID ACL value objects into OUD aci value objects."""

    @staticmethod
    def _normalize_dn(dn: str) -> str:
        normalized: str = c.Ldif.DN_NORMALIZE_COMMA_RE.sub(",", dn)
        normalized = c.Ldif.DN_NORMALIZE_EQUALS_RE.sub("=", normalized)
        return normalized.strip()

    @staticmethod
    def high_level_containers(base_dn: str) -> frozenset[str]:
        """Return base + high-level-suffix DNs where ``anyone`` inherits to the subtree."""
        base = base_dn.lower().strip()
        return frozenset(
            f"{suffix}{base}" if suffix else base
            for suffix in c.Ldif.HIGH_LEVEL_CONTAINER_SUFFIXES
        )

    @staticmethod
    def is_in_scope(dn: str, base_dn: str) -> bool:
        """Return True if ``dn`` is the base or a descendant of it (empty base = all)."""
        if not base_dn:
            return True
        dn_lower = dn.lower().strip()
        base = base_dn.lower()
        return dn_lower == base or dn_lower.endswith(f",{base}")

    @staticmethod
    def regex_to_wildcard(value: str) -> str:
        r"""Convert an OID regex DN to an OUD wildcard (``.*``/``.+`` → ``*``).

        Unescapes ``\.``/``\,``; a residual regex metacharacter means the DN
        cannot be safely wildcarded — return it unchanged.
        """
        if not value:
            return value
        converted = value
        for pattern, replacement in c.Ldif.OID_REGEX_REPLACEMENTS:
            converted = converted.replace(pattern, replacement)
        if c.Ldif.OID_REGEX_RESIDUAL_RE.search(converted):
            return value
        return converted

    @staticmethod
    def _order_perms(perms: set[str]) -> t.StrSequence:
        ordered = tuple(p for p in c.Ldif.PERM_ORDERED if p in perms)
        extra = tuple(sorted(perms - set(c.Ldif.PERM_ORDERED)))
        return ordered + extra

    @classmethod
    def _map_tokens(
        cls,
        bases: set[str],
        perm_map: t.MappingKV[str, str | None],
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
    def convert_permissions(
        cls,
        permissions: t.StrSequence,
        *,
        is_entry: bool,
    ) -> p.Result[t.StrSequence]:
        """Convert OID permission tokens to the ordered OUD allow set.

        ``none``/pure negations → no allow (``()``); a pure-negation set expands
        to the COMPLEMENT. ``all`` expands to the scoped permission universe
        before applying any ``no*`` negation, avoiding OUD overgrant. A perm
        valid only at the other scope (``read`` on an entry rule) grants nothing
        here and is skipped; a token in neither scope → ``r.fail``.
        """
        perm_map = c.Ldif.ENTRY_PERM_MAP if is_entry else c.Ldif.ATTR_PERM_MAP
        all_perms = c.Ldif.ALL_ENTRY_PERMS if is_entry else c.Ldif.ALL_ATTR_PERMS
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
            elif perm.startswith("no"):
                base = c.Ldif.NEGATION_TO_BASE.get(perm)
                if base is None:
                    return r[t.StrSequence].fail(f"Unknown negation perm: {perm!r}")
                negated_bases.add(base)
            elif perm == c.Ldif.PERM_ALL:
                explicit_all = True
                positive_bases.update(all_perms)
            elif perm in perm_map:
                positive_bases.add(perm)
            elif perm not in known_positive:
                return r[t.StrSequence].fail(f"Unknown permission token: {perm!r}")
        if positive_bases:
            effective_bases = (
                positive_bases - negated_bases if explicit_all else positive_bases
            )
            if explicit_all and not negated_bases:
                return r[t.StrSequence].ok((c.Ldif.PERM_ALL,))
            allow = cls._map_tokens(effective_bases, perm_map)
            return r[t.StrSequence].ok(cls._order_perms(allow))
        if negated_bases and not deny_all:
            complement = cls._map_tokens(set(all_perms) - negated_bases, perm_map)
            return r[t.StrSequence].ok(cls._order_perms(complement))
        return r[t.StrSequence].ok(())

    @staticmethod
    def get_targetattr(rule: m.Ldif.OidAclRule) -> str:
        """Compute the OUD ``targetattr`` (entry→``*``, list→``a||b``, ``attr!=``→``!=a||b``)."""
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
        rule: m.Ldif.OidAclRule,
        *,
        has_anyone_subject: bool,
    ) -> str | None:
        """Compute the OUD ``targetscope`` (``base`` or default subtree).

        ``orclentrylevelaci`` is non-inheritable → always ``base``. An ``orclaci``
        with a surviving ``anyone`` subject is pinned to ``base`` to prevent
        inheritance to the subtree; otherwise the OUD default (subtree) applies
        and ``targetscope`` is omitted (``None``).
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
        subject: m.Ldif.OidAclSubject,
    ) -> p.Result[p.Ldif.AciAllow]:
        """Map one OID by-clause subject to an OUD bind-rule.

        Returns an :class:`m.Ldif.AciAllow` whose ``subject_value`` is the
        normalized bind value (``ldap:///`` is applied at aci assembly) and whose
        ``permissions`` are left empty — Step 5 fills the converted permission
        set. ``guidattr``/unknown subjects have no OUD equivalent and surface as
        ``r.fail`` (the caller records the manual-review note).
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
