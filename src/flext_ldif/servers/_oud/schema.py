"""Oracle Unified Directory (OUD) Servers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar, override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers._oud import FlextLdifServersOudConstants
from flext_ldif.servers._rfc import FlextLdifServersRfcSchema

if TYPE_CHECKING:
    from collections.abc import MutableMapping


class FlextLdifServersOudSchema(FlextLdifServersRfcSchema):
    """Oracle OUD Schema Implementation (RFC 4512 + OUD Extensions)."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    @override
    def write(
        self,
        entries: t.MutableSequenceOf[m.Ldif.Entry],
        write_options: m.Ldif.WriteFormatOptions | None = None,
    ) -> p.Result[str]:
        """Write entries, sanitizing schema values for OUD acceptance.

        Returns:
            The resulting ``p.Result[str]``.
        """
        return super().write(
            self._sanitize_schema_carriers(list(entries)),
            write_options,
        )

    def _sanitize_schema_carriers(
        self,
        entries: t.MutableSequenceOf[m.Ldif.Entry],
    ) -> t.MutableSequenceOf[m.Ldif.Entry]:
        """Rewrite schema carrier values into the OUD-acceptable dialect.

        OUD's schema parser refuses LDAP transfer options inside names,
        RFC-illegal underscores, syntax length qualifiers and NO-USER-
        MODIFICATION without an operational usage; it also refuses
        objectClass definitions referencing attributes the corpus does not
        declare. Every rewrite is deterministic string surgery.

        Returns:
            The resulting ``t.MutableSequenceOf[m.Ldif.Entry]``.
        """
        sanitized: t.MutableSequenceOf[m.Ldif.Entry] = []
        declared: set[str] = set()
        prepass: list[tuple[m.Ldif.Entry, list[m.Ldif.ChangeOperation]]] = []
        for entry in entries:
            ops = []
            for op in entry.change_operations:
                if op.attribute in {"attributetypes", "objectclasses"}:
                    ops.append(
                        op.model_copy(
                            update={
                                "values": self._strip_names_for_registry(
                                    op.values,
                                ),
                            },
                        ),
                    )
                    declared.update(self._declared_names(op.values))
                else:
                    ops.append(op)
            prepass.append((entry, ops))
        sanitized_entries: list[m.Ldif.Entry] = []
        for entry, ops in prepass:
            new_ops = []
            for op in ops:
                if op.attribute in {"attributetypes", "objectclasses"}:
                    new_ops.append(
                        op.model_copy(
                            update={
                                "values": self._sanitize_schema_values(
                                    op.values,
                                ),
                            },
                        ),
                    )
                else:
                    new_ops.append(op)
            sanitized_entries.append(
                entry.model_copy(update={"change_operations": new_ops}),
            )
        sanitized.extend(sanitized_entries)
        return sanitized

    @staticmethod
    def _declared_names(
        values: t.MutableSequenceOf[m.Ldif.ChangeOperationValue],
    ) -> set[str]:
        declared = set()
        for v in values:
            matched = re.search(r"NAME '([^';]+)'", v.value)
            if matched:
                declared.add(matched.group(1).replace("_", "-").casefold())
        return declared

    @staticmethod
    def _sanitize_schema_values(
        values: t.MutableSequenceOf[m.Ldif.ChangeOperationValue],
    ) -> t.MutableSequenceOf[m.Ldif.ChangeOperationValue]:
        sanitized: list[m.Ldif.ChangeOperationValue] = []
        for value in values:
            raw = value.value
            updated = raw
            if re.search(r"NAME '[^']*;[^']*'", updated):
                updated = re.sub(
                    r"(NAME '[^';]+);[^']*",
                    r"\1",
                    updated,
                )
            if "_" in updated:
                updated = updated.replace("_", "-")
            updated = re.sub(
                r"(SYNTAX [\w.]+)\{\d+\}",
                r"\1",
                updated,
            )
            if "NO-USER-MODIFICATION" in updated and "USAGE" not in updated:
                updated = updated.replace(
                    "NO-USER-MODIFICATION",
                    "USAGE directoryOperation NO-USER-MODIFICATION",
                )
            sanitized.append(value.model_copy(update={"value": updated}))
        return sanitized

    def __init__(
        self,
        schema_service: p.Ldif.SchemaServer | None = None,
        parent_server: p.Ldif.SchemaServer | None = None,
        **kwargs: t.Ldif.Scalar | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> None:
        """Initialize OUD schema server."""
        self._init_base_schema(
            schema_service,
            parent_server,
            frozenset({"_parent_server", "_schema_service"}),
            **kwargs,
        )

    @override
    def extract_schemas_from_ldif(
        self,
        ldif_content: str,
        *,
        validate_dependencies: bool = True,
    ) -> p.Result[
        MutableMapping[
            str,
            t.MutableSequenceOf[m.Ldif.SchemaAttribute]
            | t.MutableSequenceOf[m.Ldif.SchemaObjectClass],
        ]
    ]:
        """Extract and parse all schema definitions from LDIF content.

        Returns:
            The resulting ``p.Result[MutableMapping[str,
                t.MutableSequenceOf[m.Ldif.SchemaAttribute] |
                t.MutableSequenceOf[m.Ldif.SchemaObjectClass]]]``.
        """
        return super().extract_schemas_from_ldif(
            ldif_content,
            validate_dependencies=validate_dependencies,
        )

    @staticmethod
    def _transform_by_matching_rules(
        attr_data: m.Ldif.SchemaAttribute,
    ) -> tuple[str | None, str | None]:
        """Apply OUD-specific matching rule transformations.

        Returns:
            The resulting ``tuple[str | None, str | None]``.
        """
        fixed_equality = attr_data.equality
        fixed_substr = attr_data.substr
        if fixed_equality == "caseIgnoreSubstringsMatch":
            FlextLdifServersOudSchema._module_logger.warning(
                "Moved caseIgnoreSubstringsMatch from EQUALITY to SUBSTR",
                attribute_name=attr_data.name,
            )
            fixed_substr = "caseIgnoreSubstringsMatch"
            fixed_equality = None
        original_substr = fixed_substr
        fixed_substr = u.Ldif.replace_invalid_substr_rule(
            fixed_substr,
            FlextLdifServersOudConstants.INVALID_SUBSTR_RULES,
        )
        if fixed_substr != original_substr:
            FlextLdifServersOudSchema._module_logger.warning(
                "Replaced invalid SUBSTR rule",
                attribute_name=attr_data.name,
                attribute_oid=attr_data.oid,
                original_substr=original_substr or "",
                replacement_substr=fixed_substr or "",
            )
        return (fixed_equality, fixed_substr)

    def _apply_attribute_oid_metadata(
        self,
        attr: m.Ldif.SchemaAttribute,
    ) -> m.Ldif.SchemaAttribute:
        """Apply OID validation and tracking metadata to attribute.

        Returns:
            The resulting ``m.Ldif.SchemaAttribute``.
        """
        if not attr or not attr.oid:
            return attr
        oid_str = attr.oid
        oid_validation = self._validate_attribute_oid(oid_str)
        if oid_validation.failure:
            return attr
        is_valid_oud_oid = oid_validation.value
        existing_metadata = attr.metadata
        if not existing_metadata:
            existing_metadata = u.Ldif.server_metadata_for("oud")
        current_extensions = (
            dict(existing_metadata.extensions) if existing_metadata.extensions else {}
        )
        current_extensions[c.Ldif.SYNTAX_OID_VALID] = is_valid_oud_oid
        if oid_str.endswith("-oid"):
            current_extensions["oid_format_extension"] = True
        updated_attr: m.Ldif.SchemaAttribute = attr.model_copy(
            update={
                "metadata": existing_metadata.model_copy(
                    update={"extensions": current_extensions},
                ),
            },
        )
        return updated_attr

    @staticmethod
    def _collect_attribute_extensions(
        attr: m.Ldif.SchemaAttribute,
    ) -> t.MutableSequenceOf[str]:
        """Collect OUD X-* extensions from attribute.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        extensions: t.MutableSequenceOf[str] = []
        if attr.x_origin:
            extensions.append("X-ORIGIN")
        if attr.x_file_ref:
            extensions.append("X-FILE-REF")
        if attr.x_name:
            extensions.append("X-NAME")
        if attr.x_alias:
            extensions.append("X-ALIAS")
        if attr.x_oid:
            extensions.append("X-OID")
        return extensions

    @override
    def _hook_post_parse_attribute(
        self,
        attr: m.Ldif.SchemaAttribute,
    ) -> p.Result[m.Ldif.SchemaAttribute]:
        """Validate OUD-specific attribute features after RFC parsing.

        Returns:
            The resulting ``p.Result[m.Ldif.SchemaAttribute]``.
        """
        if not attr or not attr.oid:
            return r[m.Ldif.SchemaAttribute].ok(attr)
        if "_" in attr.name:
            # OUD's schema parser refuses RFC-illegal attribute names
            # (invalidAttributeSyntax): the underscore maps to the hyphen,
            # the LDAP-standard letter joiner.
            sanitized_name = attr.name.replace("_", "-")
            FlextLdifServersOudSchema._module_logger.warning(
                "Sanitized attribute name underscores",
                attribute_name=attr.name,
                attribute_oid=attr.oid,
                sanitized_name=sanitized_name,
            )
            attr = attr.model_copy(update={"name": sanitized_name})
        normalized_equality, normalized_substr = u.Ldif.normalize_matching_rules(
            attr.equality,
            attr.substr,
            replacements=FlextLdifServersOudConstants.MATCHING_RULE_TO_RFC,
            normalized_substr_values=FlextLdifServersOudConstants.MATCHING_RULE_TO_RFC,
        )
        normalized_ordering = attr.ordering
        if attr.ordering:
            normalized_ordering = FlextLdifServersOudConstants.MATCHING_RULE_TO_RFC.get(
                attr.ordering,
                attr.ordering,
            )
        attr = attr.model_copy(
            update={
                "equality": normalized_equality,
                "substr": normalized_substr,
                "ordering": normalized_ordering,
            },
        )
        oid = attr.oid
        oid_validation = self._validate_attribute_oid(oid)
        if oid_validation.failure:
            return r[m.Ldif.SchemaAttribute].from_failure(oid_validation)
        is_valid_oud_oid = oid_validation.value
        existing_metadata = attr.metadata
        if not existing_metadata:
            existing_metadata = u.Ldif.server_metadata_for("oud")
        current_extensions = (
            dict(existing_metadata.extensions) if existing_metadata.extensions else {}
        )
        current_extensions[c.Ldif.SYNTAX_OID_VALID] = is_valid_oud_oid
        if oid.endswith("-oid"):
            current_extensions["oid_format_extension"] = True
        attr = attr.model_copy(
            update={
                "metadata": existing_metadata.model_copy(
                    update={"extensions": current_extensions},
                ),
            },
        )
        oud_extensions = self._collect_attribute_extensions(attr)
        if oud_extensions:
            FlextLdifServersOudSchema._module_logger.debug(
                "Attribute has OUD X-* extensions",
                attribute_name=attr.name,
                attribute_oid=attr.oid,
                extensions=",".join(oud_extensions),
                extension_count=len(oud_extensions),
            )
        return r[m.Ldif.SchemaAttribute].ok(attr)

    @override
    def _hook_post_parse_objectclass(
        self,
        oc: m.Ldif.SchemaObjectClass,
    ) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Validate OUD-specific objectClass features after RFC parsing.

        Returns:
            The resulting ``p.Result[m.Ldif.SchemaObjectClass]``.
        """
        sanitized_oc = oc
        updates: dict[str, t.Ldif.Scalar | list[str]] = {}
        if oc.name and "_" in oc.name:
            updates["name"] = oc.name.replace("_", "-")
        if oc.must:
            sanitized_must = [item.replace("_", "-") for item in oc.must]
            if sanitized_must != oc.must:
                updates["must"] = sanitized_must
        if oc.may:
            sanitized_may = [item.replace("_", "-") for item in oc.may]
            if sanitized_may != oc.may:
                updates["may"] = sanitized_may
        if updates:
            FlextLdifServersOudSchema._module_logger.warning(
                "Sanitized objectClass name underscores",
                objectclass_name=oc.name,
                objectclass_oid=oc.oid,
                sanitized_name=updates.get("name", oc.name),
            )
            sanitized_oc = oc.model_copy(update=updates)
            oc = sanitized_oc
        sup_validation = self._validate_objectclass_sup(oc)
        if sup_validation.failure:
            return r[m.Ldif.SchemaObjectClass].from_failure(sup_validation)
        oid_and_sup_validation = self._validate_objectclass_oid_and_sup(oc)
        if oid_and_sup_validation.failure:
            return r[m.Ldif.SchemaObjectClass].from_failure(oid_and_sup_validation)
        oc = oid_and_sup_validation.value
        sup_str = str(oc.sup) if oc.sup else "none"
        FlextLdifServersOudSchema._module_logger.debug(
            "ObjectClass validated: SingleSUP constraint OK",
            objectclass_name=oc.name,
            objectclass_oid=oc.oid,
            sup_value=sup_str,
        )
        return r[m.Ldif.SchemaObjectClass].ok(oc)

    @override
    def _transform_attribute_for_write(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> m.Ldif.SchemaAttribute:
        """Apply OUD-specific attribute transformations before writing.

        Returns:
            The resulting ``m.Ldif.SchemaAttribute``.
        """
        fixed_equality, fixed_substr = self._transform_by_matching_rules(attr_data)
        fixed_name = attr_data.name
        if "_" in fixed_name:
            fixed_name = fixed_name.replace("_", "-")
        if ";" in fixed_name:
            # OUD's schema parser refuses LDAP transfer options inside an
            # attribute type name (invalidAttributeSyntax): the base type is
            # declared and the binary transfer is served implicitly for the
            # certificate/octet-string syntaxes.
            stripped_name = fixed_name.split(";", 1)[0]
            FlextLdifServersOudSchema._module_logger.warning(
                "Stripped transfer option from attribute name",
                attribute_name=attr_data.name,
                attribute_oid=attr_data.oid,
                stripped_name=stripped_name,
            )
            fixed_name = stripped_name
        is_boolean = u.Ldif.boolean_attribute(
            fixed_name,
            set(FlextLdifServersOudConstants.BOOLEAN_ATTRIBUTES),
        )
        if is_boolean:
            FlextLdifServersOudSchema._module_logger.debug(
                "Identified boolean attribute",
                attribute_name=fixed_name,
                attribute_oid=attr_data.oid,
            )
        fixed_usage = attr_data.usage
        fixed_no_user_mod = attr_data.no_user_modification
        if fixed_no_user_mod and not fixed_usage:
            # OUD refuses NO-USER-MODIFICATION without an explicit operational
            # usage (invalidAttributeSyntax): directoryOperation is the RFC
            # 4512-mandated pairing.
            fixed_usage = "directoryOperation"
            FlextLdifServersOudSchema._module_logger.warning(
                "Added operational usage for no-user-modification attribute",
                attribute_name=fixed_name,
                attribute_oid=attr_data.oid,
            )
        fixed_syntax = attr_data.syntax
        if fixed_syntax and "{" in fixed_syntax:
            # OUD's schema modify parser rejects syntax length qualifiers
            # (invalidAttributeSyntax): the bare syntax OID is declared and
            # the length guidance is dropped.
            fixed_syntax = fixed_syntax.split("{", 1)[0]
            FlextLdifServersOudSchema._module_logger.warning(
                "Stripped syntax length qualifier",
                attribute_name=fixed_name,
                attribute_oid=attr_data.oid,
                stripped_syntax=fixed_syntax,
            )
        updated_attr = attr_data.model_copy(
            update={
                "name": fixed_name,
                "equality": fixed_equality,
                "substr": fixed_substr,
                "usage": fixed_usage,
                "syntax": fixed_syntax,
            },
        )
        # The declared-name registry feeds the objectClass reference filter:
        # OUD refuses an objectClass whose MUST/MAY names an attribute the
        # server does not carry (invalidAttributeSyntax), and the corpus may
        # reference OID-internal attributes OUD declines.
        registry = self.__dict__.get("_declared_attribute_names")
        if registry is None:
            registry = set()
            self._declared_attribute_names = registry
        registry.add(fixed_name.casefold())
        return self._apply_attribute_oid_metadata(updated_attr)

    @override
    def _transform_objectclass_for_write(
        self,
        oc_data: m.Ldif.SchemaObjectClass,
    ) -> m.Ldif.SchemaObjectClass:
        """Apply OUD-specific objectClass transformations before writing.

        Returns:
            The resulting ``m.Ldif.SchemaObjectClass``.
        """
        updates: dict[str, object] = {}
        if oc_data.name and "_" in oc_data.name:
            updates["name"] = oc_data.name.replace("_", "-")
        for role in ("must", "may"):
            names = getattr(oc_data, role)
            if not names:
                continue
            sanitized = [item.replace("_", "-") for item in names]
            registry = self.__dict__.get("_declared_attribute_names") or set()
            declared = [item for item in sanitized if item.casefold() in registry]
            if declared != names:
                dropped = sorted(set(sanitized) - set(declared))
                FlextLdifServersOudSchema._module_logger.warning(
                    "Dropped objectClass attribute references the translated "
                    "corpus does not declare",
                    objectclass_name=oc_data.name,
                    objectclass_oid=oc_data.oid,
                    role=role,
                    dropped=",".join(dropped),
                )
                updates[role] = declared
        if updates:
            if "name" not in updates and oc_data.name and "_" in oc_data.name:
                updates["name"] = oc_data.name.replace("_", "-")
            FlextLdifServersOudSchema._module_logger.warning(
                "Sanitized objectClass for the OUD schema writer",
                objectclass_name=oc_data.name,
                objectclass_oid=oc_data.oid,
            )
        return oc_data.model_copy(update=updates) if updates else oc_data

    @staticmethod
    def _validate_attribute_oid(oid: str) -> p.Result[bool]:
        """Validate attribute OID format for OUD.

        Returns:
            The resulting ``p.Result[bool]``.
        """
        oid_validation_result = u.Ldif.validate_format(oid)
        if oid_validation_result.failure:
            return r[bool].fail_op("OID validation", oid_validation_result.error)
        is_valid_basic_oid = oid_validation_result.value
        is_valid_oud_oid = is_valid_basic_oid
        if not is_valid_oud_oid and oid.endswith("-oid"):
            base_oid = oid[:-4]
            base_validation = u.Ldif.validate_format(base_oid)
            if base_validation.success:
                is_valid_oud_oid = base_validation.value
        if not is_valid_oud_oid:
            return r[bool].fail(
                f"Invalid OUD OID format: {oid} "
                f"(must be numeric RFC OID or end with -oid suffix)",
            )
        return r[bool].ok(is_valid_oud_oid)

    def _validate_objectclass_oid_and_sup(
        self,
        oc: m.Ldif.SchemaObjectClass,
    ) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Validate ObjectClass OID and SUP OID formats.

        Returns:
            The resulting ``p.Result[m.Ldif.SchemaObjectClass]``.
        """
        if oc and oc.oid:
            oid_str = oc.oid
            oid_validation = self._validate_attribute_oid(oid_str)
            if oid_validation.failure:
                return r[m.Ldif.SchemaObjectClass].fail_op(
                    "ObjectClass OID validation",
                    oid_validation.error,
                )
            is_valid_oud_oid = oid_validation.value
            existing_oc_metadata = oc.metadata
            if not existing_oc_metadata:
                existing_oc_metadata = u.Ldif.server_metadata_for("oud")
            oc_extensions = (
                dict(existing_oc_metadata.extensions)
                if existing_oc_metadata.extensions
                else {}
            )
            oc_extensions[c.Ldif.SYNTAX_OID_VALID] = is_valid_oud_oid
            if oid_str.endswith("-oid"):
                oc_extensions["oid_format_extension"] = True
            oc = oc.model_copy(
                update={
                    "metadata": existing_oc_metadata.model_copy(
                        update={"extensions": oc_extensions},
                    ),
                },
            )
        sup = oc.sup
        if sup:
            sup_str = str(sup)
            if sup_str and "." in sup_str and sup_str[0].isdigit():
                sup_validation = self._validate_attribute_oid(sup_str)
                if sup_validation.failure:
                    return r[m.Ldif.SchemaObjectClass].fail_op(
                        "ObjectClass SUP OID validation",
                        sup_validation.error,
                    )
        return r[m.Ldif.SchemaObjectClass].ok(oc)

    @staticmethod
    def _validate_objectclass_sup(oc: m.Ldif.SchemaObjectClass) -> p.Result[bool]:
        """Validate objectClass SUP constraint for OUD.

        Returns:
            The resulting ``p.Result[bool]``.
        """
        sup = oc.sup
        if sup:
            sup_str = str(sup)
            if "$" in sup_str:
                return r[bool].fail(
                    f"OUD objectClass '{oc.name}' has multiple SUPs: {sup_str}. "
                    f"OUD only allows single SUP "
                    f"(use AUXILIARY classes for additional features).",
                )
        return r[bool].ok(value=True)
