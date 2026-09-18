# from flext-ldif/docs/guides/flext_ldif_parse_acl_usages.md:129
from __future__ import annotations


def parse(
    self, acl_line: str, server_type: str | None = None
) -> p.Result[FlextLdifModels.Acl]:
    """Parse ACL line using appropriate servers.

    Delegates to servers.parse() internally.
    """
    server_result = self._get_for_server(server_type)
    if server_result.failure:
        return r[FlextLdifModels.Acl].fail(...)

    server = server_result.unwrap()
    return server.parse(acl_line)  # ← Calls server.parse()```
**Lines Affected**: 30-40 lines

### Categorized Pipeline

**File**: `~/flext/flext-ldif/src/flext_ldif/categorized_pipeline.py`

**Method**: `_transform_categories()`

