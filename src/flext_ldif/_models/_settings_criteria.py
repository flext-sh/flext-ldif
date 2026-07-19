"""LDIF settings mix-in: criteria.

from flext_ldif import m
from flext_ldif import u
Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Annotated

from flext_core import FlextUtilities as u, m
from flext_ldif import c, t


class FlextLdifModelsSettingsCriteria:
    """LDIF settings mix-in: criteria."""

    class ServerPatternsConfig(m.Value):
        """Configuration for server pattern matching."""

        oid_pattern: Annotated[
            str,
            u.Field(description="Regex pattern used for schema OID detection"),
        ] = ""

        dn_patterns: Annotated[
            tuple[t.StrSequence, ...],
            u.Field(
                description="Tuple of DN pattern tuples - entry matches if ALL patterns in ANY tuple match",
            ),
        ] = ()
        attr_prefixes: Annotated[
            t.StrSequence | frozenset[str],
            u.Field(description="Attribute name prefixes to check"),
        ] = ()
        attr_names: Annotated[
            frozenset[str] | set[str],
            u.Field(
                description="Set of attribute names that indicate this server",
            ),
        ] = frozenset()
        keyword_patterns: Annotated[
            t.StrSequence,
            u.Field(description="Keywords to search in attribute names"),
        ] = ()
        detection_string: Annotated[
            str | None,
            u.Field(description="Optional substring used for server name matching"),
        ] = None
        name_regex: Annotated[
            str | None,
            u.Field(
                description="Optional regex used to extract schema names from raw definitions",
            ),
        ] = None
        use_prefix_match: Annotated[
            bool,
            u.Field(
                description="Whether detection names match by prefix instead of exact value",
            ),
        ] = False
        match_definition_text: Annotated[
            bool,
            u.Field(
                description="Whether raw definition text should be scanned for detection markers",
            ),
        ] = False

    class EntryCriteriaConfig(m.Value):
        """Configuration for entry criteria matching.

        Consolidates parameters for matches_criteria utility function.
        Reduces function signature from 7 parameters to 1 model.

        Example:
            settings = FlextLdifModelsSettings.EntryCriteriaConfig(
                objectclasses=["inetOrgPerson", "person"],
                objectclass_mode="any",
                required_attrs=["cn", "sn"],
            )
            matches = FlextLdifUtilities.Entry.matches_criteria(entry, settings)

        """

        objectclasses: Annotated[
            t.MutableSequenceOf[str] | None,
            u.Field(description="Required objectClasses"),
        ] = None
        objectclass_mode: Annotated[
            c.Ldif.EntryCriteriaMode,
            u.Field(description='"any" (has any) or "all" (has all)'),
        ] = c.Ldif.EntryCriteriaMode.ANY
        required_attrs: Annotated[
            t.MutableSequenceOf[str] | None,
            u.Field(description="All of these attributes must exist"),
        ] = None
        any_attrs: Annotated[
            t.MutableSequenceOf[str] | None,
            u.Field(
                description="At least one of these attributes must exist",
            ),
        ] = None
        dn_pattern: Annotated[
            str | None,
            u.Field(description="Regex pattern that DN must match"),
        ] = None
        is_schema: Annotated[
            bool | None,
            u.Field(
                description="If set, entry must (True) or must not (False) be schema",
            ),
        ] = None

    class EntryParseMetadataConfig(m.Value):
        """Configuration for building entry parse metadata.

        Consolidates parameters for build_entry_parse_metadata utility function.
        Reduces function signature from 7 parameters to 1 model.

        Example:
            settings = FlextLdifModelsSettings.EntryParseMetadataConfig(
                server_type="oid",
                original_entry_dn="cn=test,dc=example",
                cleaned_dn="cn=test,dc=example",
                original_dn_line="dn: cn=test,dc=example",
            )
            metadata = FlextLdifUtilities.Metadata.build_entry_parse_metadata(settings)

        """

        server_type: Annotated[
            c.Ldif.ServerTypes,
            u.Field(
                ...,
                description="Server type performing the parse (oid, oud, rfc, etc.)",
            ),
        ]
        original_entry_dn: Annotated[
            str,
            u.Field(..., description="Original DN as parsed from LDIF"),
        ]
        cleaned_dn: Annotated[str, u.Field(..., description="Cleaned/normalized DN")]
        original_dn_line: Annotated[
            str | None,
            u.Field(
                description="Original DN line from LDIF (with folding if present)",
            ),
        ] = None
        original_attr_lines: Annotated[
            t.MutableSequenceOf[str] | None,
            u.Field(description="Original attribute lines from LDIF"),
        ] = None
        dn_was_base64: Annotated[
            bool,
            u.Field(description="Whether DN was base64 encoded"),
        ] = False
        original_attribute_case: Annotated[
            t.MutableStrMapping | None,
            u.Field(
                description="Mapping of attribute names to original case",
            ),
        ] = None
