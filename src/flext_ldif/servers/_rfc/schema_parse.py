"""RFC schema server — objectClass core parsing and schema extraction.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import ClassVar

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers._base.schema import FlextLdifServersBaseSchema
from flext_ldif.servers.base import FlextLdifServersBase


class FlextLdifServersRfcSchemaParseMixin(FlextLdifServersBase.Schema):
    """Parse RFC 4512 objectClass definitions and extract schema from LDIF."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    @staticmethod
    def _detect_oc_via_constants(
        oc_definition: str | m.Ldif.SchemaObjectClass,
        *,
        settings: m.Ldif.ServerPatternsConfig,
        name_regex: str,
    ) -> bool:
        """Detect objectClass definitions through centralized server pattern settings.

        Returns:
            The resulting ``bool``.
        """
        if isinstance(oc_definition, m.Ldif.SchemaObjectClass):
            matches_server_patterns: bool = u.Ldif.matches_server_patterns(
                value=oc_definition,
                settings=settings,
            )
            return matches_server_patterns
        if settings.oid_pattern and c.Ldif.compile_pattern(settings.oid_pattern).search(
            oc_definition,
        ):
            return True
        name_matches = c.Ldif.compile_pattern(name_regex, ignorecase=True).findall(
            oc_definition,
        )
        attr_names = {name.lower() for name in settings.attr_names}
        return any(name.lower() in attr_names for name in name_matches)

    def extract_schemas_from_ldif(
        self,
        ldif_content: str,
        *,
        validate_dependencies: bool = False,
    ) -> p.Result[
        MutableMapping[
            str,
            t.MutableSequenceOf[m.Ldif.SchemaAttribute]
            | t.MutableSequenceOf[m.Ldif.SchemaObjectClass],
        ]
    ]:
        """Extract schema definitions from LDIF using u.

        Returns:
            The resulting ``p.Result[MutableMapping[str,
                t.MutableSequenceOf[m.Ldif.SchemaAttribute] |
                t.MutableSequenceOf[m.Ldif.SchemaObjectClass]]]``.
        """
        try:
            return self._extract_schemas_from_ldif(
                ldif_content,
                validate_dependencies=validate_dependencies,
            )
        except c.Ldif.EXC_LDIF_PARSE as e:
            self._module_logger.exception(
                "Schema extraction failed",
            )
            return r[
                MutableMapping[
                    str,
                    t.MutableSequenceOf[m.Ldif.SchemaAttribute]
                    | t.MutableSequenceOf[m.Ldif.SchemaObjectClass],
                ]
            ].fail_op("Schema extraction", e)

    def _extract_schemas_from_ldif(
        self,
        ldif_content: str,
        *,
        validate_dependencies: bool,
    ) -> p.Result[
        MutableMapping[
            str,
            t.MutableSequenceOf[m.Ldif.SchemaAttribute]
            | t.MutableSequenceOf[m.Ldif.SchemaObjectClass],
        ]
    ]:
        """Extract schema definitions and optionally validate dependencies.

        Returns:
            The resulting ``p.Result[MutableMapping[str,
                t.MutableSequenceOf[m.Ldif.SchemaAttribute] |
                t.MutableSequenceOf[m.Ldif.SchemaObjectClass]]]``.
        """
        attributes_parsed = u.Ldif.extract_attributes_from_lines(
            ldif_content,
            self.parse_attribute,
        )
        if validate_dependencies:
            available_attrs = u.Ldif.build_available_attributes_set(attributes_parsed)
            validation_result = self._hook_validate_attributes(
                attributes_parsed,
                available_attrs,
            )
            if not validation_result.success:
                return r[
                    MutableMapping[
                        str,
                        t.MutableSequenceOf[m.Ldif.SchemaAttribute]
                        | t.MutableSequenceOf[m.Ldif.SchemaObjectClass],
                    ]
                ].fail_op("Attribute validation", validation_result.error)

        objectclasses_parsed = u.Ldif.extract_objectclasses_from_lines(
            ldif_content,
            self.parse_objectclass,
        )
        schema_dict: MutableMapping[
            str,
            t.MutableSequenceOf[m.Ldif.SchemaAttribute]
            | t.MutableSequenceOf[m.Ldif.SchemaObjectClass],
        ] = {
            str(c.Ldif.DictKeys.ATTRIBUTES): attributes_parsed,
            str(c.Ldif.DictKeys.OBJECTCLASS): objectclasses_parsed,
        }
        return r[
            MutableMapping[
                str,
                t.MutableSequenceOf[m.Ldif.SchemaAttribute]
                | t.MutableSequenceOf[m.Ldif.SchemaObjectClass],
            ]
        ].ok(schema_dict)

    def _build_objectclass_metadata(
        self,
        oc_definition: str,
        metadata_extensions: MutableMapping[
            str,
            t.MutableSequenceOf[str] | str | bool | None,
        ],
    ) -> m.Ldif.ServerMetadata:
        """Build objectClass metadata with extensions.

        Returns:
            The resulting ``m.Ldif.ServerMetadata``.
        """
        server_type = self._get_server_type()
        metadata_extensions[c.Ldif.SCHEMA_SOURCE_SERVER] = server_type
        metadata = m.Ldif.ServerMetadata(
            server_type=server_type,
            # Why: mro-4p0t — coerce schema extension values to JsonMapping.
            extensions=(
                t.json_dict_adapter().validate_python(metadata_extensions)
                if metadata_extensions
                else {}
            ),
            original_server_type=server_type,
            target_server_type=server_type,
        )
        u.Ldif.preserve_schema_formatting(metadata, oc_definition)
        return metadata

    def _parse_objectclass_core(
        self,
        oc_definition: str,
    ) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Core RFC 4512 objectClass parsing per Section 4.1.1.

        Returns:
            The resulting ``p.Result[m.Ldif.SchemaObjectClass]``.
        """
        try:
            return self._parse_rfc_objectclass_core(oc_definition)
        except c.EXC_BASIC_TYPE as e:
            self._module_logger.exception(
                "RFC objectClass parsing exception",
            )
            return r[m.Ldif.SchemaObjectClass].fail_op("RFC objectClass parsing", e)

    def _parse_rfc_objectclass_core(
        self,
        oc_definition: str,
    ) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Parse RFC objectClass definition into the canonical model.

        Returns:
            The resulting ``p.Result[m.Ldif.SchemaObjectClass]``.
        """
        parsed = u.Ldif.parse_objectclass(oc_definition)
        metadata_extensions = self._convert_extensions_for_server(
            self._coerce_dynamic_metadata(parsed.get("metadata_extensions")),
        )
        metadata_extensions[c.Ldif.ORIGINAL_FORMAT] = oc_definition.strip()
        metadata_extensions[c.Ldif.SCHEMA_ORIGINAL_STRING_COMPLETE] = oc_definition
        objectclass_oid = parsed.get("oid")
        match objectclass_oid:
            case None:
                FlextLdifServersBaseSchema.validate_and_track_oid(
                    metadata_extensions,
                    objectclass_oid,
                    "objectClass",
                )
            case str() as objectclass_oid_str:
                FlextLdifServersBaseSchema.validate_and_track_oid(
                    metadata_extensions,
                    objectclass_oid_str,
                    "objectClass",
                )
            case _:
                pass
        objectclass_sup_oid = parsed.get("sup")
        match objectclass_sup_oid:
            case None:
                FlextLdifServersBaseSchema.validate_and_track_oid(
                    metadata_extensions,
                    objectclass_sup_oid,
                    "objectClass SUP",
                )
            case str() as objectclass_sup_oid_str:
                FlextLdifServersBaseSchema.validate_and_track_oid(
                    metadata_extensions,
                    objectclass_sup_oid_str,
                    "objectClass SUP",
                )
            case _:
                pass
        must_list = self._to_string_list(parsed.get("must"))
        self._validate_oid_list(must_list, "MUST", metadata_extensions)
        may_list = self._to_string_list(parsed.get("may"))
        self._validate_oid_list(may_list, "MAY", metadata_extensions)
        metadata = self._build_objectclass_metadata(oc_definition, metadata_extensions)
        objectclass = m.Ldif.SchemaObjectClass.model_validate({
            "oid": self._to_required_value(parsed.get("oid")),
            "name": self._to_required_value(parsed.get("name")),
            "desc": self._to_optional_str(parsed.get("desc")),
            "sup": self._to_optional_str_or_list(parsed.get("sup")),
            "kind": self._to_required_value(parsed.get("kind"), default="STRUCTURAL"),
            "must": self._to_string_list(parsed.get("must")),
            "may": self._to_string_list(parsed.get("may")),
            "metadata": metadata,
        })
        return r[m.Ldif.SchemaObjectClass].ok(objectclass)

    @staticmethod
    def _validate_oid_list(
        oids: t.MutableSequenceOf[str] | None,
        oid_type: str,
        metadata_extensions: MutableMapping[
            str,
            t.MutableSequenceOf[str] | str | bool | None,
        ],
    ) -> None:
        """Validate OID list and track in metadata."""
        if not oids:
            return
        for idx, oid in enumerate(oids):
            match oid:
                case str() as oid_str if oid_str:
                    FlextLdifServersBaseSchema.validate_and_track_oid(
                        metadata_extensions,
                        oid_str,
                        f"objectClass {oid_type}[{idx}]",
                    )
                case _:
                    pass


__all__: list[str] = ["FlextLdifServersRfcSchemaParseMixin"]
