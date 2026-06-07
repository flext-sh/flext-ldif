"""OID→OUD ACL pipeline — entry/line orchestration over the build+render stack.

``convert_acl_values`` runs an entry's OID ACL lines through parse → build →
render (with dedup), yielding raw ``aci`` attribute values; ``convert_entry_acls``
rewrites a whole OID entry, replacing its ``orclaci``/``orclentrylevelaci``
attributes with one ``aci`` attribute. Malformed input surfaces as ``r.fail``.
"""

from __future__ import annotations

from flext_ldif import c, m, r, t
from flext_ldif.servers._oid.acl_assemble import FlextLdifServersOidAclAssemble as Build
from flext_ldif.servers._oid.acl_convert import FlextLdifServersOidAclConvert as Parser
from flext_ldif.servers._oid.acl_render import FlextLdifServersOidAclRender as Render


class FlextLdifServersOidAclPipeline:
    """Top-level OID→OUD ACL conversion orchestration (lines and entries)."""

    @classmethod
    def convert_acl_values(
        cls,
        dn: str,
        oid_acl_lines: t.StrSequence,
        *,
        base_dn: str = "",
    ) -> r[t.StrSequence]:
        """Convert an entry's OID ACL lines to deduplicated OUD ``aci`` values.

        Each ``orclaci:``/``orclentrylevelaci:`` line is parsed → built →
        rendered; deny-only rules emit nothing; duplicate aci values (whitespace-
        and case-normalized) are merged keeping first order. A malformed line or
        unknown perm token surfaces as ``r.fail``. Returned values exclude the
        ``aci: `` prefix (they are raw ``aci`` attribute values).
        """
        values: list[str] = []
        seen: set[str] = set()
        for line in oid_acl_lines:
            rule = Parser.parse_oid_acl_line(dn, line)
            if rule.failure:
                return r[t.StrSequence].fail(rule.error or "OID ACL parse failed")
            aci = Build.build_aci_rule(rule.value, base_dn=base_dn)
            if aci.failure:
                return r[t.StrSequence].fail(aci.error or "OID ACL build failed")
            if not aci.value.allows:
                continue
            rendered = Render.render_aci_string(aci.value).removeprefix(
                c.Ldif.ACI_PREFIX,
            )
            normalized = c.Ldif.WHITESPACE_RE.sub(" ", rendered.strip().lower())
            if normalized in seen:
                continue
            seen.add(normalized)
            values.append(rendered)
        return r[t.StrSequence].ok(tuple(values))

    @classmethod
    def convert_entry_acls(
        cls,
        entry: m.Ldif.Entry,
        source_type_norm: str,
        target_type_norm: str,
        *,
        base_dn: str = "",
    ) -> r[m.Ldif.Entry]:
        """Rewrite an OID entry's ACL attributes to a single OUD ``aci`` attribute.

        Fires only for oid→oud entries carrying ``orclaci``/``orclentrylevelaci``;
        their values convert (via :meth:`convert_acl_values`) into ``aci`` values
        and the OID ACL attributes are removed. A malformed ACL surfaces as
        ``r.fail``; non-matching entries pass through unchanged.
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
        oid_acl_attrs = {
            c.Ldif.AclConvertType.ORCLACI.value,
            c.Ldif.AclConvertType.ORCLENTRYLEVELACI.value,
        }
        acl_names = [name for name in current if name.lower() in oid_acl_attrs]
        if not acl_names:
            return r[m.Ldif.Entry].ok(entry)
        dn_value = entry.dn.value if entry.dn else ""
        oid_lines = [
            f"{name}: {value}" for name in acl_names for value in current[name]
        ]
        converted = cls.convert_acl_values(dn_value, oid_lines, base_dn=base_dn)
        if converted.failure:
            return r[m.Ldif.Entry].fail(converted.error or "OID ACL conversion failed")
        for name in acl_names:
            del current[name]
        if converted.value:
            current[c.Ldif.ACI_ATTR_NAME] = list(converted.value)
        kept_meta = {
            key: value
            for key, value in attrs_model.attribute_metadata.items()
            if key not in acl_names
        }
        new_attrs = attrs_model.model_copy(
            update={"attributes": current, "attribute_metadata": kept_meta},
        )
        return r[m.Ldif.Entry].ok(entry.model_copy(update={"attributes": new_attrs}))


__all__: list[str] = ["FlextLdifServersOidAclPipeline"]
