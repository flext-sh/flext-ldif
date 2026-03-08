"""Real LDIF test data provider for comprehensive testing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import NamedTuple


class LdifSample(NamedTuple):
    """LDIF sample with metadata."""

    content: str
    description: str
    expected_entries: int
    has_binary: bool = False
    has_changes: bool = False


class LdifTestData:
    """Real LDIF test data provider for comprehensive testing."""

    @staticmethod
    def basic_entries() -> LdifSample:
        """Basic LDIF entries following RFC 2849."""
        content = "dn: uid=john.doe,ou=people,dc=example,dc=com\nobjectClass: inetOrgPerson\nobjectClass: organizationalPerson\nobjectClass: person\nobjectClass: top\nuid: john.doe\ncn: John Doe\nsn: Doe\ngivenName: John\nmail: john.doe@example.com\ntelephoneNumber: +1-555-123-4567\nemployeeNumber: E12345\n\ndn: uid=jane.smith,ou=people,dc=example,dc=com\nobjectClass: inetOrgPerson\nobjectClass: organizationalPerson\nobjectClass: person\nobjectClass: top\nuid: jane.smith\ncn: Jane Smith\nsn: Smith\ngivenName: Jane\nmail: jane.smith@example.com\ntelephoneNumber: +1-555-234-5678\nemployeeNumber: E23456\n\ndn: cn=Engineering,ou=groups,dc=example,dc=com\nobjectClass: groupOfNames\nobjectClass: top\ncn: Engineering\ndescription: Engineering Department Group\nmember: uid=john.doe,ou=people,dc=example,dc=com\n"
        return LdifSample(
            content=content,
            description="Basic LDIF entries with people and groups",
            expected_entries=3,
        )

    @staticmethod
    def with_binary_data() -> LdifSample:
        """LDIF with binary data (base64 encoded)."""
        binary_data = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        )
        encoded_data = base64.b64encode(binary_data).decode("ascii")
        content = f"dn: uid=photo.user,ou=people,dc=example,dc=com\nobjectClass: inetOrgPerson\nobjectClass: organizationalPerson\nobjectClass: person\nobjectClass: top\nuid: photo.user\ncn: Photo User\nsn: User\ngivenName: Photo\nmail: photo.user@example.com\njpegPhoto:: {encoded_data}\n"
        return LdifSample(
            content=content,
            description="LDIF with binary data (base64 encoded)",
            expected_entries=1,
            has_binary=True,
        )

    @staticmethod
    def with_changes() -> LdifSample:
        """LDIF with change records."""
        content = "dn: uid=john.doe,ou=people,dc=example,dc=com\nchangetype: modify\nreplace: mail\nmail: john.doe.updated@example.com\n-\nadd: description\ndescription: Software Engineer\n-\n\ndn: uid=new.employee,ou=people,dc=example,dc=com\nchangetype: add\nobjectClass: inetOrgPerson\nobjectClass: organizationalPerson\nobjectClass: person\nobjectClass: top\nuid: new.employee\ncn: New Employee\nsn: Employee\ngivenName: New\nmail: new.employee@example.com\n\ndn: uid=old.employee,ou=people,dc=example,dc=com\nchangetype: delete\n"
        return LdifSample(
            content=content,
            description="LDIF with change records (modify, add, delete)",
            expected_entries=3,
            has_changes=True,
        )

    @staticmethod
    def multi_valued_attributes() -> LdifSample:
        """LDIF with multi-valued attributes."""
        content = "dn: uid=multi.user,ou=people,dc=example,dc=com\nobjectClass: inetOrgPerson\nobjectClass: organizationalPerson\nobjectClass: person\nobjectClass: top\nuid: multi.user\ncn: Multi User\nsn: User\ngivenName: Multi\nmail: multi.user@example.com\nmail: multi.user.alt@example.com\ntelephoneNumber: +1-555-111-1111\ntelephoneNumber: +1-555-222-2222\ndescription: Primary description\ndescription: Secondary description\n"
        return LdifSample(
            content=content,
            description="LDIF with multi-valued attributes",
            expected_entries=1,
        )

    @staticmethod
    def long_lines() -> LdifSample:
        """LDIF with line continuations."""
        long_description = "This is a very long description that spans multiple lines and needs to be wrapped according to LDIF specification which requires lines longer than 76 characters to be continued on the next line with a single space prefix"
        content = f"dn: uid=long.lines,ou=people,dc=example,dc=com\nobjectClass: inetOrgPerson\nobjectClass: organizationalPerson\nobjectClass: person\nobjectClass: top\nuid: long.lines\ncn: Long Lines User\nsn: User\ngivenName: Long Lines\nmail: long.lines@example.com\ndescription: {long_description}\n"
        return LdifSample(
            content=content,
            description="LDIF with long lines requiring continuation",
            expected_entries=1,
        )

    @staticmethod
    def special_characters() -> LdifSample:
        """LDIF with special characters and UTF-8."""
        content = "dn: uid=special.chars,ou=people,dc=example,dc=com\nobjectClass: inetOrgPerson\nobjectClass: organizationalPerson\nobjectClass: person\nobjectClass: top\nuid: special.chars\ncn: José María Ñuñez\nsn: Ñuñez\ngivenName: José María\nmail: jose.maria@example.com\ndescription: User with special UTF-8 characters: áéíóú ÁÉÍÓÚ ñÑ ¿¡\npostalAddress: Calle de la Paz, 123$ Piso 2º$ Madrid, España\n"
        return LdifSample(
            content=content,
            description="LDIF with UTF-8 special characters",
            expected_entries=1,
        )

    @staticmethod
    def empty_and_null_values() -> LdifSample:
        """LDIF with empty values and edge cases."""
        content = "dn: uid=empty.values,ou=people,dc=example,dc=com\nobjectClass: inetOrgPerson\nobjectClass: organizationalPerson\nobjectClass: person\nobjectClass: top\nuid: empty.values\ncn: Empty Values User\nsn: User\ngivenName: Empty Values\nmail: empty.values@example.com\ndescription:\ntelephoneNumber:\n"
        return LdifSample(
            content=content,
            description="LDIF with empty attribute values",
            expected_entries=1,
        )

    @staticmethod
    def invalid_data() -> LdifSample:
        """Invalid LDIF data for error testing."""
        content = "dn: invalid-dn-without-equals\nobjectClass: nonExistentClass\ninvalidAttribute: value\nmissing required attributes for objectClass\n\ndn:\nobjectClass: person\nempty DN above\n\ndn: uid=malformed,dc=example,dc=com\nobjectClass: person\nmissing required attributes like cn, sn\n"
        return LdifSample(
            content=content,
            description="Invalid LDIF data for error testing",
            expected_entries=0,
        )

    @staticmethod
    def large_dataset(num_entries: int = 100) -> LdifSample:
        """Generate large LDIF dataset for performance testing."""
        entries: list[str] = []
        for i in range(num_entries):
            entry = f"dn: uid=user{i:04d},ou=people,dc=example,dc=com\nobjectClass: inetOrgPerson\nobjectClass: organizationalPerson\nobjectClass: person\nobjectClass: top\nuid: user{i:04d}\ncn: User {i:04d}\nsn: User\ngivenName: Test\nmail: user{i:04d}@example.com\nemployeeNumber: E{i:06d}\n\n"
            entries.append(entry)
        content = "".join(entries).rstrip()
        return LdifSample(
            content=content,
            description=f"Large LDIF dataset with {num_entries} entries",
            expected_entries=num_entries,
        )

    @classmethod
    def all_samples(cls) -> dict[str, LdifSample]:
        """Get all available LDIF samples."""
        return {
            "basic_entries": cls.basic_entries(),
            "with_binary_data": cls.with_binary_data(),
            "with_changes": cls.with_changes(),
            "multi_valued_attributes": cls.multi_valued_attributes(),
            "long_lines": cls.long_lines(),
            "special_characters": cls.special_characters(),
            "empty_and_null_values": cls.empty_and_null_values(),
            "invalid_data": cls.invalid_data(),
        }

    @classmethod
    def write_sample_files(cls, directory: Path) -> dict[str, Path]:
        """Write all samples to files in the given directory."""
        directory.mkdir(exist_ok=True)
        files: dict[str, Path] = {}
        for name, sample in cls.all_samples().items():
            file_path = directory / f"{name}.ldif"
            _ = file_path.write_text(sample.content, encoding="utf-8")
            files[name] = file_path
        return files
