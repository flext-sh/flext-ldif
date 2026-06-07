"""OID→OUD ACL conversion — typed OidAclRule → OUD aci value objects.

Faithful port of the oracle ``algar-oud-mig/scripts`` converter
(``convert_subject_to_oud`` and downstream assembly). Each by-clause subject
maps to one OUD bind-rule (``m.Ldif.AciAllow``); subjects with no OUD
equivalent (``guidattr``/unknown) surface as ``r.fail`` carrying the manual
review note — never a silent drop. Taxonomy is the ``c.Ldif`` SSOT.
"""

from __future__ import annotations

from flext_ldif import c, m, r, t


class FlextLdifServersOidAclToOud:
    """Convert parsed OID ACL value objects into OUD aci value objects."""

    @staticmethod
    def _normalize_dn(dn: str) -> str:
        normalized = c.Ldif.DN_NORMALIZE_COMMA_RE.sub(",", dn)
        normalized = c.Ldif.DN_NORMALIZE_EQUALS_RE.sub("=", normalized)
        return normalized.strip()

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
                granted.update(part.strip() for part in mapped.split(",") if part.strip())
        return granted

    @classmethod
    def convert_permissions(
        cls,
        permissions: t.StrSequence,
        *,
        is_entry: bool,
    ) -> r[t.StrSequence]:
        """Convert OID permission tokens to the ordered OUD allow set.

        Mirrors the oracle: ``none`` and pure negations yield no allow perms
        (``()``); a pure-negation set (``noX``) expands to the COMPLEMENT of the
        full permission set; positive tokens map through the entry/attr perm map.
        An unrecognized token surfaces as ``r.fail`` (never a silent drop).
        """
        perm_map = c.Ldif.ENTRY_PERM_MAP if is_entry else c.Ldif.ATTR_PERM_MAP
        allow: set[str] = set()
        negated_bases: set[str] = set()
        deny_all = False
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
            elif perm in perm_map:
                allow.update(cls._map_tokens({perm}, perm_map))
            else:
                return r[t.StrSequence].fail(f"Unknown permission token: {perm!r}")
        if allow:
            return r[t.StrSequence].ok(cls._order_perms(allow))
        if negated_bases and not deny_all:
            all_perms = c.Ldif.ALL_ENTRY_PERMS if is_entry else c.Ldif.ALL_ATTR_PERMS
            complement = cls._map_tokens(set(all_perms) - negated_bases, perm_map)
            return r[t.StrSequence].ok(cls._order_perms(complement))
        return r[t.StrSequence].ok(())

    @staticmethod
    def get_targetattr(rule: m.Ldif.OidAclRule) -> str:
        """Compute the OUD ``targetattr`` value for a rule.

        Entry-level ACLs have no OUD ``targetattr="entry"`` syntax — operations
        apply to the whole entry, so OUD uses ``*``. Attribute lists join with
        ``||``; an OID ``attr!=`` negation becomes ``!=a||b``.
        """
        if rule.target_type == c.Ldif.AclTargetType.ENTRY:
            return c.Ldif.ACL_WILDCARD
        attrs = rule.target_attrs
        if attrs.startswith(c.Ldif.OUD_ATTR_NEGATION):
            body = attrs[len(c.Ldif.OUD_ATTR_NEGATION) :]
            joined = body.replace(",", c.Ldif.OUD_ATTR_OR).replace(" ", "")
            return f"{c.Ldif.OUD_ATTR_NEGATION}{joined}"
        if attrs in {c.Ldif.ACL_WILDCARD, ""}:
            return c.Ldif.ACL_WILDCARD
        return attrs.replace(",", c.Ldif.OUD_ATTR_OR).replace(" ", "")

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
        if rule.acl_type == c.Ldif.AclConvertType.ORCLENTRYLEVELACI:
            return c.Ldif.ACL_SCOPE_BASE
        if has_anyone_subject:
            return c.Ldif.ACL_SCOPE_BASE
        return None

    @classmethod
    def convert_subject_to_oud(
        cls,
        subject: m.Ldif.OidAclSubject,
    ) -> r[m.Ldif.AciAllow]:
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
                return r[m.Ldif.AciAllow].fail(
                    f"Subject '{kind}' has no OUD equivalent "
                    f"(manual review required): {value!r}",
                )
        return r[m.Ldif.AciAllow].ok(
            m.Ldif.AciAllow(subject_type=bind_type, subject_value=bind_value),
        )


__all__: list[str] = ["FlextLdifServersOidAclToOud"]
