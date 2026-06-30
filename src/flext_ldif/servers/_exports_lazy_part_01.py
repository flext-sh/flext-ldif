# AUTO-GENERATED FILE — Regenerate with: make gen
"""Lazy export map part."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map

FLEXT_LDIF_SERVERS_LAZY_IMPORTS_PART_01 = build_lazy_import_map(
    {
        "._base.acl": ("FlextLdifServersBaseSchemaAcl",),
        "._base.constants": ("FlextLdifServersBaseConstants",),
        "._base.entry": ("FlextLdifServersBaseEntry",),
        "._base.mixins": ("FlextLdifServerMethodsMixin",),
        "._base.schema": ("FlextLdifServersBaseSchema",),
        "._oid.acl": ("FlextLdifServersOidAcl",),
        "._oid.acl_assemble": ("FlextLdifServersOidAclAssemble",),
        "._oid.acl_convert": ("FlextLdifServersOidAclConvert",),
        "._oid.acl_convert_oud": ("FlextLdifServersOidAclToOud",),
        "._oid.acl_pipeline": ("FlextLdifServersOidAclPipeline",),
        "._oid.acl_render": ("FlextLdifServersOidAclRender",),
        "._oid.constants": ("FlextLdifServersOidConstants",),
        "._oid.entry": ("FlextLdifServersOidEntry",),
        "._oid.schema": ("FlextLdifServersOidSchema",),
        "._oud.aci": ("FlextLdifServersOudAciMixin",),
        "._oud.acl": ("FlextLdifServersOudAcl",),
        "._oud.acl_extract": ("FlextLdifServersOudAclExtractMixin",),
        "._oud.acl_metadata": ("FlextLdifServersOudAclMetadataMixin",),
        "._oud.comments": ("FlextLdifServersOudCommentsMixin",),
        "._oud.constants": ("FlextLdifServersOudConstants",),
        "._oud.entry": ("FlextLdifServersOudEntry",),
        "._oud.helpers": ("FlextLdifServersOudHelpersMixin",),
        "._oud.schema": ("FlextLdifServersOudSchema",),
        ".ad": ("FlextLdifServersAd",),
        ".apache": ("FlextLdifServersApache",),
        ".base": ("FlextLdifServersBase",),
        ".ds389": ("FlextLdifServersDs389",),
        ".novell": ("FlextLdifServersNovell",),
        ".oid": ("FlextLdifServersOid",),
        ".openldap": ("FlextLdifServersOpenldap",),
        ".openldap1": ("FlextLdifServersOpenldap1",),
        ".oud": ("FlextLdifServersOud",),
    },
)

__all__: list[str] = ["FLEXT_LDIF_SERVERS_LAZY_IMPORTS_PART_01"]
