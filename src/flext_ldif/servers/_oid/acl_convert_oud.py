"""OID→OUD ACL conversion — typed OidAclRule → OUD aci value objects.

Faithful port of the oracle ``algar-oud-mig/scripts`` converter
(``convert_subject_to_oud`` and downstream assembly). Each by-clause subject
maps to one OUD bind-rule (``m.Ldif.AciAllow``); subjects with no OUD
equivalent (``guidattr``/unknown) surface as ``r.fail`` carrying the manual
review note — never a silent drop. Taxonomy is the ``c.Ldif`` SSOT.
"""

from __future__ import annotations

from flext_ldif import c, m, r


class FlextLdifServersOidAclToOud:
    """Convert parsed OID ACL value objects into OUD aci value objects."""

    @staticmethod
    def _normalize_dn(dn: str) -> str:
        normalized = c.Ldif.DN_NORMALIZE_COMMA_RE.sub(",", dn)
        normalized = c.Ldif.DN_NORMALIZE_EQUALS_RE.sub("=", normalized)
        return normalized.strip()

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
