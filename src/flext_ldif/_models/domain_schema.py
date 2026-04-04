"""Domain models for LDIF schema elements.

Extracted schema-related inner classes: SchemaAttribute, Syntax, SchemaObjectClass.
These are composed into FlextLdifModels via MRO.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re
import struct
from collections.abc import MutableSequence
from typing import Annotated, Self

from pydantic import Field, field_validator

from flext_ldif import (
    FlextLdifConstants as c,
    FlextLdifModelsBases,
    FlextLdifModelsDomainMetadata,
)


class FlextLdifModelsDomainSchema:
    """Namespace mixin for LDIF schema domain models."""

    class SchemaAttribute(FlextLdifModelsBases.SchemaElement):
        """LDAP schema attribute definition model (RFC 4512 compliant).

        Represents an LDAP attribute type definition from schema with full
        RFC 4512 support.

        Inherits from FlextLdifModelsBases.SchemaElement:
        - model_config (strict=True, validate_default=True, validate_assignment=True)
        - has_metadata computed field
        - server_type computed field
        - has_server_extensions computed field
        """

        name: Annotated[str, Field(..., description="Attribute name")]
        oid: Annotated[str, Field(..., description="Attribute OID")]
        desc: Annotated[
            str | None,
            Field(description="Attribute description (RFC 4512 DESC)"),
        ] = None
        sup: Annotated[
            str | None,
            Field(description="Superior attribute type (RFC 4512 SUP)"),
        ] = None
        equality: Annotated[
            str | None,
            Field(
                description="Equality matching rule (RFC 4512 EQUALITY)",
            ),
        ] = None
        ordering: Annotated[
            str | None,
            Field(
                description="Ordering matching rule (RFC 4512 ORDERING)",
            ),
        ] = None
        substr: Annotated[
            str | None,
            Field(
                description="Substring matching rule (RFC 4512 SUBSTR)",
            ),
        ] = None
        syntax: Annotated[
            str | None,
            Field(description="Attribute syntax OID (RFC 4512 SYNTAX)"),
        ] = None
        length: Annotated[
            int | None,
            Field(description="Maximum length constraint"),
        ] = None
        usage: Annotated[
            str | None,
            Field(description="Attribute usage (RFC 4512 USAGE)"),
        ] = None
        single_value: Annotated[
            bool,
            Field(
                description="Whether attribute is single-valued (RFC 4512 SINGLE-VALUE)",
            ),
        ] = False
        collective: Annotated[
            bool,
            Field(
                description="Whether attribute is collective (RFC 4512 COLLECTIVE)",
            ),
        ] = False
        no_user_modification: Annotated[
            bool,
            Field(
                description="Whether users can modify this attribute (RFC 4512 NO-USER-MODIFICATION)",
            ),
        ] = False
        immutable: Annotated[
            bool,
            Field(
                description="Whether attribute is immutable (OUD extension)",
            ),
        ] = False
        user_modification: Annotated[
            bool,
            Field(
                description="Whether users can modify this attribute (OUD extension)",
            ),
        ] = True
        obsolete: Annotated[
            bool,
            Field(
                description="Whether attribute is obsolete (OUD extension)",
            ),
        ] = False
        x_origin: Annotated[
            str | None,
            Field(
                description="Origin of attribute definition (server-specific X-ORIGIN extension)",
            ),
        ] = None
        x_file_ref: Annotated[
            str | None,
            Field(
                description="File reference for attribute definition (server-specific X-FILE-REF extension)",
            ),
        ] = None
        x_name: Annotated[
            str | None,
            Field(
                description="Extended name for attribute (server-specific X-NAME extension)",
            ),
        ] = None
        x_alias: Annotated[
            str | None,
            Field(
                description="Extended alias for attribute (server-specific X-ALIAS extension)",
            ),
        ] = None
        x_oid: Annotated[
            str | None,
            Field(
                description="Extended OID for attribute (server-specific X-OID extension)",
            ),
        ] = None
        metadata: FlextLdifModelsDomainMetadata.QuirkMetadata | None = Field(
            default=None, description="Quirk-specific metadata for schema attribute"
        )

    class Syntax(FlextLdifModelsBases.SchemaElement):
        """LDAP attribute syntax definition model (RFC 4517 compliant).

        Represents an LDAP attribute syntax OID and its validation rules per RFC 4517.

        Inherits from FlextLdifModelsBases.SchemaElement:
        - model_config (strict=True, validate_default=True, validate_assignment=True)
        - has_metadata computed field
        - server_type computed field
        - has_server_extensions computed field
        """

        oid: Annotated[
            str,
            Field(
                ...,
                description="Syntax OID (RFC 4517, format: 1.3.6.1.4.1.1466.115.121.1.X)",
            ),
        ]
        name: Annotated[
            str | None,
            Field(
                None,
                description="Human-readable syntax name (e.g., 'Boolean', 'Integer')",
            ),
        ]
        desc: Annotated[
            str | None,
            Field(None, description="Syntax description and purpose"),
        ]
        type_category: Annotated[
            str,
            Field(
                description="Syntax type category: string, integer, binary, dn, time, boolean",
            ),
        ] = "string"
        is_binary: Annotated[
            bool,
            Field(
                description="Whether this syntax uses binary encoding",
            ),
        ] = False
        max_length: Annotated[
            int | None,
            Field(description="Maximum length in bytes (if applicable)"),
        ] = None
        case_insensitive: Annotated[
            bool,
            Field(
                description="Whether comparisons are case-insensitive",
            ),
        ] = False
        allows_multivalued: Annotated[
            bool,
            Field(
                description="Whether attributes using this syntax can be multivalued",
            ),
        ] = True
        encoding: Annotated[
            c.Ldif.EncodingLiteral,
            Field(
                description="Expected character encoding (utf-8, ascii, iso-8859-1, etc.)",
            ),
        ] = c.Ldif.Encoding.UTF8
        validation_pattern: Annotated[
            str | None,
            Field(description="Optional regex pattern for value validation"),
        ] = None
        metadata: FlextLdifModelsDomainMetadata.QuirkMetadata | None = Field(
            default=None, description="Server-specific quirk metadata"
        )

        @classmethod
        def resolve_syntax_oid(
            cls,
            oid: str,
            server_type: c.Ldif.ServerTypeLiteral = c.Ldif.ServerTypes.RFC,
        ) -> Self | None:
            """Resolve a syntax OID to a Syntax model using RFC 4517 validation.

            This method is used by both models and the syntax service to avoid
            circular dependencies.

            Args:
                oid: Syntax OID to resolve
                server_type: LDAP server type for quirk metadata

            Returns:
                Resolved Syntax model with RFC 4517 compliance details, or None if:
                - oid is None or empty
                - syntax OID validation fails
                - syntax resolution fails

            """
            if not oid or not oid.strip():
                return None
            try:
                oid_pattern = re.compile(r"^\d+(\.\d+)*$")
                if not oid_pattern.match(oid):
                    return None
                oid_to_name = dict(c.Ldif.OID_TO_NAME)
                name = oid_to_name.get(oid)
                type_category = (
                    c.Ldif.NAME_TO_TYPE_CATEGORY.get(name, "string")
                    if name
                    else "string"
                )
                metadata = (
                    FlextLdifModelsDomainMetadata.QuirkMetadata.model_validate({
                        "quirk_type": server_type,
                    })
                    if server_type != c.Ldif.ServerTypes.RFC.value
                    else None
                )
                return cls(
                    oid=oid,
                    name=name,
                    desc=None,
                    type_category=type_category,
                    max_length=None,
                    is_binary=False,
                    case_insensitive=False,
                    allows_multivalued=True,
                    encoding=c.Ldif.Encoding.UTF8,
                    validation_pattern=None,
                    validation_metadata=None,
                    metadata=metadata,
                )
            except (
                ValueError,
                KeyError,
                AttributeError,
                UnicodeDecodeError,
                struct.error,
            ):
                return None

        @field_validator("oid")
        @classmethod
        def validate_oid(cls, v: str) -> str:
            """Validate that OID is not empty."""
            if not v or not v.strip():
                msg = "OID cannot be empty"
                raise ValueError(msg)
            return v

    class SchemaObjectClass(FlextLdifModelsBases.SchemaElement):
        """LDAP schema t.NormalizedValue class definition model (RFC 4512 compliant).

        Represents an LDAP t.NormalizedValue class definition from schema with full
        RFC 4512 support.

        Inherits from FlextLdifModelsBases.SchemaElement:
        - model_config (strict=True, validate_default=True, validate_assignment=True)
        - has_metadata computed field
        - server_type computed field
        - has_server_extensions computed field
        """

        name: Annotated[str, Field(..., description="Object class name")]
        oid: Annotated[str, Field(..., description="Object class OID")]
        desc: Annotated[
            str | None,
            Field(description="Object class description (RFC 4512 DESC)"),
        ] = None
        sup: Annotated[
            str | MutableSequence[str] | None,
            Field(
                description="Superior t.NormalizedValue class(es) (RFC 4512 SUP)",
            ),
        ] = None
        kind: Annotated[
            str,
            Field(
                description="Object class kind (RFC 4512: STRUCTURAL, AUXILIARY, ABSTRACT)",
            ),
        ] = "STRUCTURAL"
        must: Annotated[
            MutableSequence[str] | None,
            Field(description="Required attributes (RFC 4512 MUST)"),
        ] = None
        may: Annotated[
            MutableSequence[str] | None,
            Field(description="Optional attributes (RFC 4512 MAY)"),
        ] = None
        metadata: FlextLdifModelsDomainMetadata.QuirkMetadata | None = Field(
            default=None, description="Quirk-specific metadata for schema object class"
        )


__all__ = ["FlextLdifModelsDomainSchema"]
