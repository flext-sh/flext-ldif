"""FLEXT LDIF - API unified using flext-core patterns.

This module provides the complete LDIF processing API using flext-core
patterns for result handling, configuration, and dependency injection.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from flext_core import FlextResult

from .config import FlextLdifConfig
from .core import TLdif
from .models import FlextLdifEntry, LDIFContent

if TYPE_CHECKING:
    from pathlib import Path


class FlextLdifAPI:
    """Unified LDIF API using flext-core patterns."""

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize LDIF API with configuration."""
        self.config = config or FlextLdifConfig()
        # Specifications now integrated in FlextLdifEntry via composition

    def parse(self, content: str | LDIFContent) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF content with intelligent processing."""
        try:
            # Parse using core functionality
            parse_result = TLdif.parse(content)
            if not parse_result.is_success:
                return parse_result
            
            entries = parse_result.data
            if entries is None:
                return FlextResult.fail("No entries parsed")
            
            # Validate if strict validation enabled
            if self.config.strict_validation:
                validate_result = TLdif.validate_entries(entries)
                if not validate_result.is_success:
                    return validate_result
            
            # Check limits
            if len(entries) > self.config.max_entries:
                return FlextResult.fail(f"Too many entries: {len(entries)} > {self.config.max_entries}")
            
            return FlextResult.ok(entries)
            
        except Exception as e:
            return FlextResult.fail(f"Parse failed: {e}")

    def parse_file(self, file_path: str | Path) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF file with intelligent parsing and validation."""
        try:
            # Parse using core functionality
            parse_result = TLdif.read_file(file_path)
            if not parse_result.is_success:
                return parse_result
            
            entries = parse_result.data
            
            # Apply config limits and validation
            if len(entries) > self.config.max_entries:
                return FlextResult.fail(f"Too many entries: {len(entries)} > {self.config.max_entries}")
            
            if self.config.strict_validation:
                validate_result = TLdif.validate_entries(entries)
                if not validate_result.is_success:
                    return validate_result
            
            return FlextResult.ok(entries)
            
        except Exception as e:
            return FlextResult.fail(f"File parse failed: {e}")

    def validate(self, entries: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate LDIF entries."""
        return TLdif.validate_entries(entries)

    def write(
        self,
        entries: list[FlextLdifEntry],
        file_path: str | Path | None = None,
    ) -> FlextResult[str]:
        """Write LDIF entries to string or file with intelligent formatting."""
        if file_path:
            # Write to file using core functionality
            result = TLdif.write_file(entries, file_path)
            return FlextResult.ok(f"Written to {file_path}") if result.is_success else result
        
        # Return LDIF string using core functionality
        return TLdif.write(entries)

    def filter_persons(
        self, 
        entries: list[FlextLdifEntry]
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter person entries using integrated composition logic."""
        try:
            person_entries = [entry for entry in entries if entry.is_person_entry()]
            return FlextResult.ok(person_entries)
        except Exception as e:
            return FlextResult.fail(f"Failed to filter person entries: {e}")

    def filter_valid(
        self, 
        entries: list[FlextLdifEntry]
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter valid entries using integrated composition logic."""
        try:
            valid_entries = [entry for entry in entries if entry.is_valid_entry()]
            return FlextResult.ok(valid_entries) 
        except Exception as e:
            return FlextResult.fail(f"Failed to filter valid entries: {e}")
    
    def filter_by_objectclass(self, entries: list[FlextLdifEntry], object_class: str) -> list[FlextLdifEntry]:
        """Filter entries by objectClass using intelligent filtering."""
        return [entry for entry in entries if entry.has_object_class(object_class)]
    
    def find_entry_by_dn(self, entries: list[FlextLdifEntry], dn: str) -> FlextLdifEntry | None:
        """Find entry by DN with intelligent search."""
        for entry in entries:
            if str(entry.dn) == dn:
                return entry
        return None
    
    def sort_hierarchically(self, entries: list[FlextLdifEntry]) -> FlextResult[list[FlextLdifEntry]]:
        """Sort entries hierarchically using intelligent sorting."""
        try:
            sorted_entries = sorted(
                entries,
                key=lambda entry: (
                    str(entry.dn).count(","),  # Primary: depth (parents first)
                    str(entry.dn).lower(),     # Secondary: alphabetical
                ),
            )
            return FlextResult.ok(sorted_entries)
        except Exception as e:
            return FlextResult.fail(f"Failed to sort entries hierarchically: {e}")
    
    def entries_to_ldif(self, entries: list[FlextLdifEntry]) -> str:
        """Convert multiple entries to LDIF content using intelligent formatting."""
        result = TLdif.write(entries)
        return result.data if result.is_success else ""

    # ==========================================================================
    # INTELLIGENT FILTERING METHODS (Using integrated composition)
    # ==========================================================================

    def filter_groups(self, entries: list[FlextLdifEntry]) -> FlextResult[list[FlextLdifEntry]]:
        """Filter group entries using integrated composition logic."""
        try:
            group_entries = [entry for entry in entries if entry.is_group_entry()]
            return FlextResult.ok(group_entries)
        except Exception as e:
            return FlextResult.fail(f"Failed to filter group entries: {e}")

    def filter_organizational_units(self, entries: list[FlextLdifEntry]) -> FlextResult[list[FlextLdifEntry]]:
        """Filter organizational unit entries using integrated composition logic."""
        try:
            ou_entries = [entry for entry in entries if entry.is_organizational_unit()]
            return FlextResult.ok(ou_entries)
        except Exception as e:
            return FlextResult.fail(f"Failed to filter OU entries: {e}")

    def filter_change_records(self, entries: list[FlextLdifEntry]) -> FlextResult[list[FlextLdifEntry]]:
        """Filter change record entries using integrated composition logic."""
        try:
            change_entries = [entry for entry in entries if entry.is_change_record()]
            return FlextResult.ok(change_entries)
        except Exception as e:
            return FlextResult.fail(f"Failed to filter change records: {e}")

    def get_entry_statistics(self, entries: list[FlextLdifEntry]) -> dict[str, int]:
        """Get entry statistics using integrated composition analysis."""
        stats = {
            "total_entries": len(entries),
            "valid_entries": sum(1 for entry in entries if entry.is_valid_entry()),
            "person_entries": sum(1 for entry in entries if entry.is_person_entry()),
            "group_entries": sum(1 for entry in entries if entry.is_group_entry()),
            "ou_entries": sum(1 for entry in entries if entry.is_organizational_unit()),
            "change_records": sum(1 for entry in entries if entry.is_change_record()),
        }
        return stats


# Global API instance
_api_instance: FlextLdifAPI | None = None


def flext_ldif_get_api(config: FlextLdifConfig | None = None) -> FlextLdifAPI:
    """Get global LDIF API instance."""
    global _api_instance
    if _api_instance is None or config is not None:
        _api_instance = FlextLdifAPI(config)
    return _api_instance


# Convenience functions using global API
def flext_ldif_parse(content: str | LDIFContent) -> list[FlextLdifEntry]:
    """Parse LDIF content - convenience function."""
    result = flext_ldif_get_api().parse(content)
    return result.data if result.is_success else []


def flext_ldif_validate(content: str | LDIFContent) -> bool:
    """Validate LDIF content - convenience function."""
    parse_result = flext_ldif_get_api().parse(content)
    if not parse_result.is_success:
        return False
    
    validate_result = flext_ldif_get_api().validate(parse_result.data)
    return validate_result.is_success and validate_result.data


def flext_ldif_write(entries: list[FlextLdifEntry], output_path: str | None = None) -> str:
    """Write LDIF entries - convenience function."""
    result = flext_ldif_get_api().write(entries, output_path)
    return result.data if result.is_success else ""


__all__ = [
    "FlextLdifAPI",
    "flext_ldif_get_api",
    "flext_ldif_parse", 
    "flext_ldif_validate",
    "flext_ldif_write",
]