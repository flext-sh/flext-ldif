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
        content = """dn: uid=john.doe,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: john.doe
cn: John Doe
sn: Doe
givenName: John
mail: john.doe@example.com
telephoneNumber: +1-555-123-4567
employeeNumber: E12345

dn: uid=jane.smith,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: jane.smith
cn: Jane Smith
sn: Smith
givenName: Jane
mail: jane.smith@example.com
telephoneNumber: +1-555-234-5678
employeeNumber: E23456

dn: cn=Engineering,ou=groups,dc=example,dc=com
objectClass: groupOfNames
objectClass: top
cn: Engineering
description: Engineering Department Group
member: uid=john.doe,ou=people,dc=example,dc=com
"""

        return LdifSample(
            content=content,
            description="Basic LDIF entries with people and groups",
            expected_entries=3,
        )

    @staticmethod
    def with_binary_data() -> LdifSample:
        """LDIF with binary data (base64 encoded)."""
        # Create a small PNG-like binary data
        binary_data = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        )
        encoded_data = base64.b64encode(binary_data).decode("ascii")

        content = f"""dn: uid=photo.user,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: photo.user
cn: Photo User
sn: User
givenName: Photo
mail: photo.user@example.com
jpegPhoto:: {encoded_data}
"""

        return LdifSample(
            content=content,
            description="LDIF with binary data (base64 encoded)",
            expected_entries=1,
            has_binary=True,
        )

    @staticmethod
    def with_changes() -> LdifSample:
        """LDIF with change records."""
        content = """dn: uid=john.doe,ou=people,dc=example,dc=com
changetype: modify
replace: mail
mail: john.doe.updated@example.com
-
add: description
description: Software Engineer
-

dn: uid=new.employee,ou=people,dc=example,dc=com
changetype: add
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: new.employee
cn: New Employee
sn: Employee
givenName: New
mail: new.employee@example.com

dn: uid=old.employee,ou=people,dc=example,dc=com
changetype: delete
"""

        return LdifSample(
            content=content,
            description="LDIF with change records (modify, add, delete)",
            expected_entries=3,
            has_changes=True,
        )

    @staticmethod
    def multi_valued_attributes() -> LdifSample:
        """LDIF with multi-valued attributes."""
        content = """dn: uid=multi.user,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: multi.user
cn: Multi User
sn: User
givenName: Multi
mail: multi.user@example.com
mail: multi.user.alt@example.com
telephoneNumber: +1-555-111-1111
telephoneNumber: +1-555-222-2222
description: Primary description
description: Secondary description
"""

        return LdifSample(
            content=content,
            description="LDIF with multi-valued attributes",
            expected_entries=1,
        )

    @staticmethod
    def long_lines() -> LdifSample:
        """LDIF with line continuations."""
        long_description = "This is a very long description that spans multiple lines and needs to be wrapped according to LDIF specification which requires lines longer than 76 characters to be continued on the next line with a single space prefix"

        content = f"""dn: uid=long.lines,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: long.lines
cn: Long Lines User
sn: User
givenName: Long Lines
mail: long.lines@example.com
description: {long_description}
"""

        return LdifSample(
            content=content,
            description="LDIF with long lines requiring continuation",
            expected_entries=1,
        )

    @staticmethod
    def special_characters() -> LdifSample:
        """LDIF with special characters and UTF-8."""
        content = """dn: uid=special.chars,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: special.chars
cn: José María Ñuñez
sn: Ñuñez
givenName: José María
mail: jose.maria@example.com
description: User with special UTF-8 characters: áéíóú ÁÉÍÓÚ ñÑ ¿¡
postalAddress: Calle de la Paz, 123$ Piso 2º$ Madrid, España
"""

        return LdifSample(
            content=content,
            description="LDIF with UTF-8 special characters",
            expected_entries=1,
        )

    @staticmethod
    def empty_and_null_values() -> LdifSample:
        """LDIF with empty values and edge cases."""
        content = """dn: uid=empty.values,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: empty.values
cn: Empty Values User
sn: User
givenName: Empty Values
mail: empty.values@example.com
description:
telephoneNumber:
"""

        return LdifSample(
            content=content,
            description="LDIF with empty attribute values",
            expected_entries=1,
        )

    @staticmethod
    def invalid_data() -> LdifSample:
        """Invalid LDIF data for error testing."""
        content = """dn: invalid-dn-without-equals
objectClass: nonExistentClass
invalidAttribute: value
missing required attributes for objectClass

dn:
objectClass: person
empty DN above

dn: uid=malformed,dc=example,dc=com
objectClass: person
missing required attributes like cn, sn
"""

        return LdifSample(
            content=content,
            description="Invalid LDIF data for error testing",
            expected_entries=0,  # Should fail parsing
        )

    @staticmethod
    def large_dataset(num_entries: int = 100) -> LdifSample:
        """Generate large LDIF dataset for performance testing."""
        entries: list[str] = []
        for i in range(num_entries):
            entry = f"""dn: uid=user{i:04d},ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: user{i:04d}
cn: User {i:04d}
sn: User
givenName: Test
mail: user{i:04d}@example.com
employeeNumber: E{i:06d}

"""

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
            file_path.write_text(sample.content, encoding="utf-8")
            files[name] = file_path

        return files
