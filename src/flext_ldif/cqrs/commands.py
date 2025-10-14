"""CQRS Command Definitions for FLEXT-LDIF.

This module defines command classes for write operations that modify LDIF data.
Commands represent user intentions to change state (parse, write, migrate, build).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from flext_ldif.models import FlextLdifModels


class ParseLdifCommand(BaseModel):
    r"""Command to parse LDIF file or content string.

    Represents the intention to parse LDIF data from a file path or content string,
    applying server-specific quirks for proper parsing.

    Attributes:
        source: File path (Path) or LDIF content string to parse
        server_type: Server type for quirk selection (e.g., 'rfc', 'oid', 'oud', 'openldap')

    Example:
        # Parse from file
        command = ParseLdifCommand(
            source=Path("data.ldif"),
            server_type="oid"
        )

        # Parse from string
        command = ParseLdifCommand(
            source="dn: cn=test\ncn: test\n",
            server_type="rfc"
        )

    """

    source: str | Path = Field(
        ...,
        description="File path or LDIF content string to parse",
    )
    server_type: str = Field(
        default="rfc",
        description="Server type for quirk selection (rfc, oid, oud, openldap)",
        pattern="^[a-z0-9_]+$",
    )


class WriteLdifCommand(BaseModel):
    """Command to write LDIF entries to file or string.

    Represents the intention to serialize LDIF entries to LDIF format,
    either writing to a file or returning as a string.

    Attributes:
        entries: List of LDIF Entry models to write
        output_path: Optional path to write LDIF file (None returns string)

    Example:
        command = WriteLdifCommand(
            entries=[entry1, entry2],
            output_path=Path("output.ldif")
        )

    """

    entries: list[
        FlextLdifModels.Entry
    ]  # FlextLdifModels.Entry - avoid circular import
    output_path: Path | None = Field(
        default=None,
        description="Optional output file path (None returns LDIF string)",
    )


class MigrateLdifCommand(BaseModel):
    """Command to migrate LDIF data between server types.

    Represents the intention to migrate LDIF files from one LDAP server type
    to another, applying appropriate quirks and transformations.

    Attributes:
        input_dir: Directory containing source LDIF files
        output_dir: Directory for migrated LDIF files
        from_server: Source server type (e.g., 'oid')
        to_server: Target server type (e.g., 'oud')
        process_schema: Whether to process schema files
        process_entries: Whether to process entry files

    Example:
        command = MigrateLdifCommand(
            input_dir=Path("data/oid"),
            output_dir=Path("data/oud"),
            from_server="oid",
            to_server="oud",
            process_schema=True,
            process_entries=True
        )

    """

    input_dir: Path = Field(
        ...,
        description="Input directory containing source LDIF files",
    )
    output_dir: Path = Field(
        ...,
        description="Output directory for migrated LDIF files",
    )
    from_server: str = Field(
        ...,
        description="Source server type (oid, oud, openldap, etc.)",
        pattern="^[a-z0-9_]+$",
    )
    to_server: str = Field(
        ...,
        description="Target server type (oid, oud, openldap, etc.)",
        pattern="^[a-z0-9_]+$",
    )
    process_schema: bool = Field(
        default=True,
        description="Whether to process schema files during migration",
    )
    process_entries: bool = Field(
        default=True,
        description="Whether to process entry files during migration",
    )


class BuildPersonEntryCommand(BaseModel):
    """Command to build a person entry with standard attributes.

    Represents the intention to create a new person entry with common
    attributes following LDAP schema conventions.

    Attributes:
        cn: Common name
        sn: Surname
        base_dn: Base DN for entry
        uid: User ID (optional)
        mail: Email address (optional)
        given_name: Given name (optional)
        additional_attrs: Additional attributes (optional)

    Example:
        command = BuildPersonEntryCommand(
            cn="Alice Johnson",
            sn="Johnson",
            base_dn="ou=People,dc=example,dc=com",
            mail="alice@example.com",
            uid="ajohnson"
        )

    """

    cn: str = Field(
        ...,
        description="Common name",
        min_length=1,
        max_length=255,
    )
    sn: str = Field(
        ...,
        description="Surname",
        min_length=1,
        max_length=255,
    )
    base_dn: str = Field(
        ...,
        description="Base DN for the entry",
        min_length=1,
    )
    uid: str | None = Field(
        default=None,
        description="User ID",
        max_length=255,
    )
    mail: str | None = Field(
        default=None,
        description="Email address",
        max_length=255,
    )
    given_name: str | None = Field(
        default=None,
        description="Given name",
        max_length=255,
    )
    additional_attrs: dict[str, list[str]] | None = Field(
        default=None,
        description="Additional LDAP attributes as dict",
    )


class BuildGroupEntryCommand(BaseModel):
    """Command to build a group entry with members.

    Represents the intention to create a new group entry with members
    following LDAP groupOfNames schema.

    Attributes:
        cn: Common name (group name)
        base_dn: Base DN for entry
        members: List of member DNs (optional)
        description: Group description (optional)
        additional_attrs: Additional attributes (optional)

    Example:
        command = BuildGroupEntryCommand(
            cn="Admins",
            base_dn="ou=Groups,dc=example,dc=com",
            members=["cn=alice,ou=People,dc=example,dc=com"],
            description="Administrator group"
        )

    """

    cn: str = Field(
        ...,
        description="Common name (group name)",
        min_length=1,
        max_length=255,
    )
    base_dn: str = Field(
        ...,
        description="Base DN for the entry",
        min_length=1,
    )
    members: list[str] | None = Field(
        default=None,
        description="List of member DNs",
    )
    description: str | None = Field(
        default=None,
        description="Group description",
        max_length=1024,
    )
    additional_attrs: dict[str, list[str]] | None = Field(
        default=None,
        description="Additional LDAP attributes as dict",
    )


class BuildOrganizationalUnitCommand(BaseModel):
    """Command to build an organizational unit entry.

    Represents the intention to create a new organizational unit (OU)
    following LDAP organizationalUnit schema.

    Attributes:
        ou: Organizational unit name
        base_dn: Base DN for entry
        description: OU description (optional)
        additional_attrs: Additional attributes (optional)

    Example:
        command = BuildOrganizationalUnitCommand(
            ou="People",
            base_dn="dc=example,dc=com",
            description="User accounts container"
        )

    """

    ou: str = Field(
        ...,
        description="Organizational unit name",
        min_length=1,
        max_length=255,
    )
    base_dn: str = Field(
        ...,
        description="Base DN for the entry",
        min_length=1,
    )
    description: str | None = Field(
        default=None,
        description="OU description",
        max_length=1024,
    )
    additional_attrs: dict[str, list[str]] | None = Field(
        default=None,
        description="Additional LDAP attributes as dict",
    )


__all__ = [
    "BuildGroupEntryCommand",
    "BuildOrganizationalUnitCommand",
    "BuildPersonEntryCommand",
    "MigrateLdifCommand",
    "ParseLdifCommand",
    "WriteLdifCommand",
]
