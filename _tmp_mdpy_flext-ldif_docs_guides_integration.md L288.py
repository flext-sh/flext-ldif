# from flext-ldif/docs/guides/integration.md:288
from __future__ import annotations

from flext_cli import FlextCliService
from flext_cli import u
from flext_core import FlextSettings
from flext_ldif import ldif
from pathlib import Path

class LdifCLIService(FlextCliService):
    """CLI service for LDIF operations with memory monitoring."""

    def __init__(self) -> None:
        super().__init__()
        self._ldif_api = ldif()

    def parse_command(self, input_file: str, output_format: str = 'summary') -> p.Result[bool]:
        """CLI command for parsing LDIF files with size checking."""
        file_path = Path(input_file)

        # Check file size before processing
        if not file_path.exists():
            return r[bool].fail(f"LDIF file not found: {input_file}")

        file_size = file_path.stat().st_size
        if file_size > 100 * 1024 * 1024:  # 100MB limit
            return r[bool].fail(
                f"LDIF file too large ({file_size} bytes). "
                f"Current implementation limited to 100MB."
            )

        return (
            self._ldif_api.parse_file(file_path)
            .flat_map(lambda entries: self._output_ldif_results(entries, output_format))
            .map_error(lambda error: f"LDIF CLI parse failed: {error}")
        )

    def _output_ldif_results(self, entries, format_type: str) -> p.Result[bool]:
        """Output LDIF parsing results in specified format."""
        if format_type == 'summary':
            u.Cli.print(f"LDIF Processing Summary:")
            u.Cli.print(f"  Total entries: {len(entries)}")

            # Get LDIF-specific statistics
            stats_result = self._ldif_api.get_entry_statistics(entries)
            if stats_result.success:
                stats = stats_result.unwrap()
                u.Cli.print(f"  Object class distribution: {stats}")

            # Count person and group entries
            persons = [e for e in entries if e.is_person()]
            groups = [e for e in entries if e.is_group()]
            u.Cli.print(f"  Person entries: {len(persons)}")
            u.Cli.print(f"  Group entries: {len(groups)}")

            return r[bool].| ok(value=True)
        elif format_type == 'json':
            import json
            output = json.dumps([
                {
                    'dn': entry.dn,
                    'object_classes': entry.get_object_classes(),
                    'is_person': entry.is_person(),
                    'is_group': entry.is_group()
                }
                for entry in entries
            ], indent=2)
            u.Cli.print(output)
            return r[bool].| ok(value=True)
        else:
            return r[bool].fail(f"Unsupported LDIF output format: {format_type}")```
## LDIF Data Pipeline Integration

### Batch LDIF Processing

