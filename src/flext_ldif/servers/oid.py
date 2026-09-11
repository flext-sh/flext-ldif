"""Oracle Internet Directory (OID) Servers."""

from __future__ import annotations

from flext_ldif.servers.rfc import FlextLdifServersRfc

from ._oid.acl import FlextLdifServersOidAcl
from ._oid.acl_assemble import FlextLdifServersOidAclAssemble
from ._oid.acl_convert import FlextLdifServersOidAclConvert
from ._oid.acl_convert_oud import FlextLdifServersOidAclToOud
from ._oid.acl_pipeline import FlextLdifServersOidAclPipeline
from ._oid.acl_render import FlextLdifServersOidAclRender
from ._oid.constants import FlextLdifServersOidConstants
from ._oid.entry import FlextLdifServersOidEntry
from ._oid.schema import FlextLdifServersOidSchema


class FlextLdifServersOid(FlextLdifServersRfc):
    """Oracle OID server servers - implements t.JsonValue."""

    class Constants(FlextLdifServersOidConstants):
        """OID server constants."""

    class Acl(FlextLdifServersOidAcl):
        """OID ACL server."""

    class Schema(FlextLdifServersOidSchema):
        """OID Schema server."""

    class Entry(FlextLdifServersOidEntry):
        """OID Entry server."""


__all__: list[str] = [
    "FlextLdifServersOid",
    "FlextLdifServersOidAcl",
    "FlextLdifServersOidAclAssemble",
    "FlextLdifServersOidAclConvert",
    "FlextLdifServersOidAclPipeline",
    "FlextLdifServersOidAclRender",
    "FlextLdifServersOidAclToOud",
    "FlextLdifServersOidConstants",
    "FlextLdifServersOidEntry",
    "FlextLdifServersOidSchema",
    "FlextLdifServersRfc",
]
