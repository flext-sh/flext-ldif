# from flext-ldif/docs/api-reference.md:979
from __future__ import annotations

from pathlib import Path


class Result:
    def __init__(self, success: bool, value=None) -> None:
        self.success = success
        self._value = value

    def unwrap(self):
        return self._value


class FlextLdifMigration:
    def __init__(
        self,
        input_dir: Path,
        output_dir: Path,
        source_server_type: str,
        target_server_type: str,
    ) -> None:
        pass

    def execute(self) -> Result:
        return Result(True, {"entries_migrated": 100, "schema_files": []})


# OID to OUD migration
pipeline = FlextLdifMigration(
    input_dir=Path("source_oid"),
    output_dir=Path("target_oud"),
    source_server_type="oid",
    target_server_type="oud",
)

result = pipeline.execute()
if result.success:
    data = result.unwrap()
    u.Cli.print(f"Migrated {data['entries_migrated']} entries")
    u.Cli.print(f"Schema files: {data['schema_files']}")

# Works with any server combination
# OpenLDAP to OUD, AD to 389 DS, etc.```
## Servers Registry API

### ServerRegistryService

Central registry for managing server-specific servers.

