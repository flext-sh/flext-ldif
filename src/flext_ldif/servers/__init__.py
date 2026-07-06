# AUTO-GENERATED FILE — Regenerate with: make gen
"""Servers package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)

if TYPE_CHECKING:
    from flext_ldif.servers._base.acl import FlextLdifServersBaseSchemaAcl
    from flext_ldif.servers._base.constants import FlextLdifServersBaseConstants
    from flext_ldif.servers._base.entry import FlextLdifServersBaseEntry
    from flext_ldif.servers._base.mixins import FlextLdifServerMethodsMixin
    from flext_ldif.servers._base.schema import FlextLdifServersBaseSchema
    from flext_ldif.servers._oid.acl import FlextLdifServersOidAcl
    from flext_ldif.servers._oid.acl_assemble import FlextLdifServersOidAclAssemble
    from flext_ldif.servers._oid.acl_convert import FlextLdifServersOidAclConvert
    from flext_ldif.servers._oid.acl_convert_oud import FlextLdifServersOidAclToOud
    from flext_ldif.servers._oid.acl_pipeline import FlextLdifServersOidAclPipeline
    from flext_ldif.servers._oid.acl_render import FlextLdifServersOidAclRender
    from flext_ldif.servers._oid.constants import FlextLdifServersOidConstants
    from flext_ldif.servers._oid.entry import FlextLdifServersOidEntry
    from flext_ldif.servers._oid.schema import FlextLdifServersOidSchema
    from flext_ldif.servers._oud.aci import FlextLdifServersOudAciMixin
    from flext_ldif.servers._oud.acl import FlextLdifServersOudAcl
    from flext_ldif.servers._oud.acl_extract import FlextLdifServersOudAclExtractMixin
    from flext_ldif.servers._oud.acl_metadata import FlextLdifServersOudAclMetadataMixin
    from flext_ldif.servers._oud.comments import FlextLdifServersOudCommentsMixin
    from flext_ldif.servers._oud.constants import FlextLdifServersOudConstants
    from flext_ldif.servers._oud.entry import FlextLdifServersOudEntry
    from flext_ldif.servers._oud.helpers import FlextLdifServersOudHelpersMixin
    from flext_ldif.servers._oud.schema import FlextLdifServersOudSchema
    from flext_ldif.servers._oud.transform import FlextLdifServersOudTransformMixin
    from flext_ldif.servers._oud.utilities import FlextLdifServersOudUtilities
    from flext_ldif.servers._rfc.acl import FlextLdifServersRfcAcl
    from flext_ldif.servers._rfc.constants import FlextLdifServersRfcConstants
    from flext_ldif.servers._rfc.entry import FlextLdifServersRfcEntry
    from flext_ldif.servers._rfc.schema import FlextLdifServersRfcSchema
    from flext_ldif.servers.ad import FlextLdifServersAd
    from flext_ldif.servers.apache import FlextLdifServersApache
    from flext_ldif.servers.base import FlextLdifServersBase
    from flext_ldif.servers.ds389 import FlextLdifServersDs389
    from flext_ldif.servers.novell import FlextLdifServersNovell
    from flext_ldif.servers.oid import FlextLdifServersOid
    from flext_ldif.servers.openldap import FlextLdifServersOpenldap
    from flext_ldif.servers.openldap1 import FlextLdifServersOpenldap1
    from flext_ldif.servers.oud import FlextLdifServersOud
    from flext_ldif.servers.relaxed import FlextLdifServersRelaxed
    from flext_ldif.servers.rfc import FlextLdifServersRfc
    from flext_ldif.servers.tivoli import FlextLdifServersTivoli
_LAZY_IMPORTS = merge_lazy_imports(
    (
        "._base",
        "._oid",
        "._oud",
        "._rfc",
    ),
    build_lazy_import_map(
        {
            "._base": ("_base",),
            "._base.acl": ("FlextLdifServersBaseSchemaAcl",),
            "._base.constants": ("FlextLdifServersBaseConstants",),
            "._base.entry": ("FlextLdifServersBaseEntry",),
            "._base.mixins": ("FlextLdifServerMethodsMixin",),
            "._base.schema": ("FlextLdifServersBaseSchema",),
            "._oid": ("_oid",),
            "._oid.acl": ("FlextLdifServersOidAcl",),
            "._oid.acl_assemble": ("FlextLdifServersOidAclAssemble",),
            "._oid.acl_convert": ("FlextLdifServersOidAclConvert",),
            "._oid.acl_convert_oud": ("FlextLdifServersOidAclToOud",),
            "._oid.acl_pipeline": ("FlextLdifServersOidAclPipeline",),
            "._oid.acl_render": ("FlextLdifServersOidAclRender",),
            "._oid.constants": ("FlextLdifServersOidConstants",),
            "._oid.entry": ("FlextLdifServersOidEntry",),
            "._oid.schema": ("FlextLdifServersOidSchema",),
            "._oud": ("_oud",),
            "._oud.aci": ("FlextLdifServersOudAciMixin",),
            "._oud.acl": ("FlextLdifServersOudAcl",),
            "._oud.acl_extract": ("FlextLdifServersOudAclExtractMixin",),
            "._oud.acl_metadata": ("FlextLdifServersOudAclMetadataMixin",),
            "._oud.comments": ("FlextLdifServersOudCommentsMixin",),
            "._oud.constants": ("FlextLdifServersOudConstants",),
            "._oud.entry": ("FlextLdifServersOudEntry",),
            "._oud.helpers": ("FlextLdifServersOudHelpersMixin",),
            "._oud.schema": ("FlextLdifServersOudSchema",),
            "._oud.transform": ("FlextLdifServersOudTransformMixin",),
            "._oud.utilities": ("FlextLdifServersOudUtilities",),
            "._rfc": ("_rfc",),
            "._rfc.acl": ("FlextLdifServersRfcAcl",),
            "._rfc.constants": ("FlextLdifServersRfcConstants",),
            "._rfc.entry": ("FlextLdifServersRfcEntry",),
            "._rfc.schema": ("FlextLdifServersRfcSchema",),
            ".ad": ("FlextLdifServersAd",),
            ".apache": ("FlextLdifServersApache",),
            ".base": ("FlextLdifServersBase",),
            ".ds389": ("FlextLdifServersDs389",),
            ".novell": ("FlextLdifServersNovell",),
            ".oid": ("FlextLdifServersOid",),
            ".openldap": ("FlextLdifServersOpenldap",),
            ".openldap1": ("FlextLdifServersOpenldap1",),
            ".oud": ("FlextLdifServersOud",),
            ".relaxed": ("FlextLdifServersRelaxed",),
            ".rfc": ("FlextLdifServersRfc",),
            ".tivoli": ("FlextLdifServersTivoli",),
        },
    ),
    exclude_names=(
        "cleanup_submodule_namespace",
        "install_lazy_exports",
        "lazy_getattr",
        "logger",
        "merge_lazy_imports",
        "output",
        "output_reporting",
        "pytest_addoption",
        "pytest_collect_file",
        "pytest_collection_modifyitems",
        "pytest_configure",
        "pytest_runtest_setup",
        "pytest_runtest_teardown",
        "pytest_sessionfinish",
        "pytest_sessionstart",
        "pytest_terminal_summary",
        "pytest_warning_recorded",
    ),
    module_name=__name__,
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
