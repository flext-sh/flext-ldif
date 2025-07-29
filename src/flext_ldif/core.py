"""FlextLdif core functionality using flext-core patterns.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from io import StringIO
from pathlib import Path
from typing import TYPE_CHECKING, Any, TextIO

from flext_core import FlextResult, get_logger

try:
    from ldif3 import LDIFParser as Ldif3Parser
    from ldif3 import LDIFWriter as Ldif3Writer
except ImportError:
    Ldif3Parser = None
    Ldif3Writer = None

if TYPE_CHECKING:
    from .models import FlextLdifEntry
    from .types import LDIFContent

logger = get_logger(__name__)


class TLdif:
    """Core LDIF processing functionality using flext-core patterns."""
    
    # Validation patterns
    DN_PATTERN = re.compile(r"^[a-zA-Z]+=.+")
    ATTR_NAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9-]*$")
    
    @classmethod
    def parse(cls, content: str | LDIFContent) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF content into entries.
        
        Args:
            content: LDIF content string
            
        Returns:
            FlextResult containing list of FlextLdifEntry objects
        """
        try:
            content_str = str(content)
            
            # Try ldif3 library first for better parsing
            if Ldif3Parser is not None:
                return cls._parse_with_ldif3(content_str)
            
            # Fallback to custom parser
            return cls._parse_custom(content_str)
            
        except Exception as e:
            return FlextResult.fail(f"Parse failed: {e}")
    
    @classmethod
    def _parse_with_ldif3(cls, content: str) -> FlextResult[list[FlextLdifEntry]]:
        """Parse using ldif3 library."""
        from .models import FlextLdifEntry
        
        try:
            entries = []
            parser = Ldif3Parser(StringIO(content))
            
            for dn, attrs in parser.parse():
                if dn and attrs:
                    entry = FlextLdifEntry.from_ldif_dict(dn, attrs)
                    entries.append(entry)
                    
            return FlextResult.ok(entries)
            
        except Exception as e:
            return FlextResult.fail(f"ldif3 parse failed: {e}")
    
    @classmethod
    def _parse_custom(cls, content: str) -> FlextResult[list[FlextLdifEntry]]:
        """Custom LDIF parser."""
        from .models import FlextLdifEntry
        
        try:
            entries = []
            blocks = content.strip().split('\n\n')
            
            for block in blocks:
                if block.strip():
                    entry = FlextLdifEntry.from_ldif_block(block)
                    entries.append(entry)
                    
            return FlextResult.ok(entries)
            
        except Exception as e:
            return FlextResult.fail(f"Custom parse failed: {e}")
    
    @classmethod
    def validate(cls, entry: FlextLdifEntry) -> FlextResult[bool]:
        """Validate LDIF entry.
        
        Args:
            entry: FlextLdifEntry to validate
            
        Returns:
            FlextResult indicating validation success
        """
        try:
            # Validate DN format
            if not cls.DN_PATTERN.match(str(entry.dn)):
                return FlextResult.fail(f"Invalid DN format: {entry.dn}")
            
            # Validate attribute names
            for attr_name in entry.attributes.attributes:
                if not cls.ATTR_NAME_PATTERN.match(attr_name):
                    return FlextResult.fail(f"Invalid attribute name: {attr_name}")
            
            # Validate required objectClass attribute
            if not entry.has_attribute("objectClass"):
                return FlextResult.fail("Entry missing required objectClass attribute")
            
            return FlextResult.ok(True)
            
        except Exception as e:
            return FlextResult.fail(f"Validation failed: {e}")
    
    @classmethod
    def validate_entries(cls, entries: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate multiple LDIF entries.
        
        Args:
            entries: List of FlextLdifEntry objects
            
        Returns:
            FlextResult indicating validation success
        """
        try:
            for i, entry in enumerate(entries):
                result = cls.validate(entry)
                if not result.is_success:
                    return FlextResult.fail(f"Entry {i}: {result.error}")
            
            return FlextResult.ok(True)
            
        except Exception as e:
            return FlextResult.fail(f"Bulk validation failed: {e}")
    
    @classmethod
    def write(cls, entries: list[FlextLdifEntry]) -> FlextResult[str]:
        """Write entries to LDIF string.
        
        Args:
            entries: List of FlextLdifEntry objects
            
        Returns:
            FlextResult containing LDIF string
        """
        try:
            # Try ldif3 library first
            if Ldif3Writer is not None:
                return cls._write_with_ldif3(entries)
            
            # Fallback to custom writer
            return cls._write_custom(entries)
            
        except Exception as e:
            return FlextResult.fail(f"Write failed: {e}")
    
    @classmethod
    def _write_with_ldif3(cls, entries: list[FlextLdifEntry]) -> FlextResult[str]:
        """Write using ldif3 library."""
        try:
            output = StringIO()
            writer = Ldif3Writer(output)
            
            for entry in entries:
                dn = str(entry.dn)
                attrs = entry.attributes.attributes
                writer.unparse(dn, attrs)
            
            return FlextResult.ok(output.getvalue())
            
        except Exception as e:
            return FlextResult.fail(f"ldif3 write failed: {e}")
    
    @classmethod
    def _write_custom(cls, entries: list[FlextLdifEntry]) -> FlextResult[str]:
        """Custom LDIF writer."""
        try:
            ldif_blocks = [entry.to_ldif() for entry in entries]
            return FlextResult.ok('\n'.join(ldif_blocks))
            
        except Exception as e:
            return FlextResult.fail(f"Custom write failed: {e}")
    
    @classmethod
    def write_file(cls, entries: list[FlextLdifEntry], file_path: str | Path) -> FlextResult[bool]:
        """Write entries to LDIF file.
        
        Args:
            entries: List of FlextLdifEntry objects
            file_path: Output file path
            
        Returns:
            FlextResult indicating success
        """
        try:
            file_path = Path(file_path)
            
            # Get LDIF content
            content_result = cls.write(entries)
            if not content_result.is_success:
                return FlextResult.fail(content_result.error or "Write failed")
            
            # Write to file
            with file_path.open('w', encoding='utf-8') as f:
                f.write(content_result.data)
            
            return FlextResult.ok(True)
            
        except Exception as e:
            return FlextResult.fail(f"File write failed: {e}")
    
    @classmethod
    def read_file(cls, file_path: str | Path) -> FlextResult[list[FlextLdifEntry]]:
        """Read and parse LDIF file.
        
        Args:
            file_path: Input file path
            
        Returns:
            FlextResult containing list of FlextLdifEntry objects
        """
        try:
            file_path = Path(file_path)
            
            if not file_path.exists():
                return FlextResult.fail(f"File not found: {file_path}")
            
            # Read file content
            with file_path.open('r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse content
            return cls.parse(content)
            
        except Exception as e:
            return FlextResult.fail(f"File read failed: {e}")


__all__ = [
    "TLdif",
]