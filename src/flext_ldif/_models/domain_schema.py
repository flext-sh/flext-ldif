"""Domain models for LDIF schema elements.

Extracted schema-related inner classes: SchemaAttribute, Syntax, SchemaObjectClass.
These are composed into FlextLdifModels via MRO.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Annotated

from flext_core import u
from flext_ldif import c, t
from flext_ldif._models.base import FlextLdifModelsBases as mb
from flext_ldif._models.domain_metadata import FlextLdifModelsDomainMetadata as mdm


class FlextLdifModelsDomainSchema:
    """Namespace mixin for LDIF schema domain models."""

    class SchemaAttribute(mb.SchemaElement):
        """LDAP schema attribute definition model (RFC 4512 compliant).

        Represents an LDAP attribute type definition from schema with full
        RFC 4512 support.

        Inherits from mb.SchemaElement:
        - model_config (strict=True, validate_default=True, validate_assignment=True)
        - has_metadata computed field
        - server_type computed field
        - has_server_extensions computed field
        """

        name: Annotated[str, u.Field(..., description="Attribute name")]
        oid: Annotated[str, u.Field(..., description="Attribute OID")]
        desc: Annotated[
            str | None,
            u.Field(description="Attribute description (RFC 4512 DESC)"),
        ] = None
        sup: Annotated[
            str | None,
            u.Field(description="Superior attribute type (RFC 4512 SUP)"),
        ] = None
        equality: Annotated[
            str | None,
            u.Field(
                description="Equality matching rule (RFC 4512 EQUALITY)",
            ),
        ] = None
        ordering: Annotated[
            str | None,
            u.Field(
                description="Ordering matching rule (RFC 4512 ORDERING)",
            ),
        ] = None
        substr: Annotated[
            str | None,
            u.Field(
                description="Substring matching rule (RFC 4512 SUBSTR)",
            ),
        ] = None
        syntax: Annotated[
            str | None,
            u.Field(description="Attribute syntax OID (RFC 4512 SYNTAX)"),
        ] = None
        length: Annotated[
            int | None,
            u.Field(description="Maximum length constraint"),
        ] = None
        usage: Annotated[
            str | None,
            u.Field(description="Attribute usage (RFC 4512 USAGE)"),
        ] = None
        single_value: Annotated[
            bool,
            u.Field(
                description="Whether attribute is single-valued (RFC 4512 SINGLE-VALUE)",
            ),
        ] = False
        collective: Annotated[
            bool,
            u.Field(
                description="Whether attribute is collective (RFC 4512 COLLECTIVE)",
            ),
        ] = False
        no_user_modification: Annotated[
            bool,
            u.Field(
                description="Whether users can modify this attribute (RFC 4512 NO-USER-MODIFICATION)",
            ),
        ] = False
        immutable: Annotated[
            bool,
            u.Field(
                description="Whether attribute is immutable (OUD extension)",
            ),
        ] = False
        user_modification: Annotated[
            bool,
            u.Field(
                description="Whether users can modify this attribute (OUD extension)",
            ),
        ] = True
        obsolete: Annotated[
            bool,
            u.Field(
                description="Whether attribute is obsolete (OUD extension)",
            ),
        ] = False
        x_origin: Annotated[
            str | None,
            u.Field(
                description="Origin of attribute definition (server-specific X-ORIGIN extension)",
            ),
        ] = None
        x_file_ref: Annotated[
            str | None,
            u.Field(
                description="File reference for attribute definition (server-specific X-FILE-REF extension)",
            ),
        ] = None
        x_name: Annotated[
            str | None,
            u.Field(
                description="Extended name for attribute (server-specific X-NAME extension)",
            ),
        ] = None
        x_alias: Annotated[
            str | None,
            u.Field(
                description="Extended alias for attribute (server-specific X-ALIAS extension)",
            ),
        ] = None
        x_oid: Annotated[
            str | None,
            u.Field(
                description="Extended OID for attribute (server-specific X-OID extension)",
            ),
        ] = None
        metadata: Annotated[
            mdm.ServerMetadata | None,
            u.Field(description="Server-specific metadata for schema attribute"),
        ] = None

    class Syntax(mb.SchemaElement):
        """LDAP attribute syntax definition model (RFC 4517 compliant).

        Represents an LDAP attribute syntax OID and its validation rules per RFC 4517.

        Inherits from mb.SchemaElement:
        - model_config (strict=True, validate_default=True, validate_assignment=True)
        - has_metadata computed field
        - server_type computed field
        - has_server_extensions computed field
        """

        oid: Annotated[
            str,
            u.Field(
                ...,
                description="Syntax OID (RFC 4517, format: 1.3.6.1.4.1.1466.115.121.1.X)",
            ),
        ]
        name: Annotated[
            str | None,
            u.Field(
                None,
                description="Human-readable syntax name (e.g., 'Boolean', 'Integer')",
            ),
        ]
        desc: Annotated[
            str | None,
            u.Field(None, description="Syntax description and purpose"),
        ]
        type_category: Annotated[
            str,
            u.Field(
                description="Syntax type category: string, integer, binary, dn, time, boolean",
            ),
        ] = "string"
        is_binary: Annotated[
            bool,
            u.Field(
                description="Whether this syntax uses binary encoding",
            ),
        ] = False
        max_length: Annotated[
            int | None,
            u.Field(description="Maximum length in bytes (if applicable)"),
        ] = None
        case_insensitive: Annotated[
            bool,
            u.Field(
                description="Whether comparisons are case-insensitive",
            ),
        ] = False
        allows_multivalued: Annotated[
            bool,
            u.Field(
                description="Whether attributes using this syntax can be multivalued",
            ),
        ] = True
        encoding: Annotated[
            c.Ldif.Encoding,
            u.Field(
                description="Expected character encoding (utf-8, ascii, iso-8859-1, etc.)",
            ),
        ] = c.Ldif.Encoding.UTF8
        validation_pattern: Annotated[
            str | None,
            u.Field(description="Optional regex pattern for value validation"),
        ] = None
        metadata: Annotated[
            mdm.ServerMetadata | None,
            u.Field(description="Server-specific server metadata"),
        ] = None

        @u.field_validator("oid")
        @classmethod
        def validate_oid(cls, v: str) -> str:
            """Validate that OID is not empty."""
            if not v or not v.strip():
                msg = "OID cannot be empty"
                raise ValueError(msg)
            return v

    class SchemaObjectClass(mb.SchemaElement):
        """LDAP schema object class definition model (RFC 4512 compliant).

        Represents an LDAP object class definition from schema with full
        RFC 4512 support.

        Inherits from mb.SchemaElement:
        - model_config (strict=True, validate_default=True, validate_assignment=True)
        - has_metadata computed field
        - server_type computed field
        - has_server_extensions computed field
        """

        name: Annotated[str, u.Field(..., description="Object class name")]
        oid: Annotated[str, u.Field(..., description="Object class OID")]
        desc: Annotated[
            str | None,
            u.Field(description="Object class description (RFC 4512 DESC)"),
        ] = None
        sup: Annotated[
            str | t.MutableSequenceOf[str] | None,
            u.Field(
                description="Superior object class(es) (RFC 4512 SUP)",
            ),
        ] = None
        kind: Annotated[
            str,
            u.Field(
                description="Object class kind (RFC 4512: STRUCTURAL, AUXILIARY, ABSTRACT)",
            ),
        ] = "STRUCTURAL"
        must: Annotated[
            t.MutableSequenceOf[str] | None,
            u.Field(description="Required attributes (RFC 4512 MUST)"),
        ] = None
        may: Annotated[
            t.MutableSequenceOf[str] | None,
            u.Field(description="Optional attributes (RFC 4512 MAY)"),
        ] = None
        metadata: Annotated[
            mdm.ServerMetadata | None,
            u.Field(description="Server-specific metadata for schema object class"),
        ] = None


__all__: list[str] = ["FlextLdifModelsDomainSchema"]
