# from flext-ldif_docs/api-reference.md:1030
from __future__ import annotations

from flext_ldif import ServerRegistryService


class ServerRegistryService:
    """Registry for managing LDAP server servers."""

    def get_schemas(self, server_type: str) -> t.SequenceOf[Schema]:
        """Get schema servers for server type.

        Args:
            server_type: Server type identifier

        Returns:
            List of schema servers sorted by priority

        """

    def get_entrys(self, server_type: str) -> t.SequenceOf[Entry]:
        """Get entry servers for server type.

        Args:
            server_type: Server type identifier

        Returns:
            List of entry servers sorted by priority

        """

    def get_acls(self, server_type: str) -> t.SequenceOf[Acl]:
        """Get ACL servers for server type.

        Args:
            server_type: Server type identifier

        Returns:
            List of ACL servers sorted by priority

        """```
**Example Usage**:

