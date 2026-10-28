"""Base Server Classes for LDIF/LDAP Server Extensions.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from abc import ABC, abstractmethod
from collections.abc import Callable, MutableSequence
from typing import Annotated, ClassVar, override

from flext_ldif import c, m, p, r, s, t, u
from flext_ldif.servers._base import FlextLdifServerMethods


class FlextLdifServersBaseSchemaAcl(
    s[t.Ldif.AclPayload],
    FlextLdifServerMethods,
    ABC,
):
    """Base class for ACL servers - satisfies Acl (structural typing)."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    acl_attribute_name: ClassVar[str] = "acl"
    server_type: Annotated[
        str,
        m.Field(
            description="Server type identifier (e.g., 'oid', 'oud', 'openldap', "
            "'rfc')",
        ),
    ] = "rfc"
    priority: Annotated[
        int,
        m.Field(description="Server priority (lower number = higher priority)"),
    ] = 0
    parent_server: Annotated[
        t.Port[p.Ldif.ServerServer] | None,
        m.Field(
            exclude=True,
            repr=False,
            description="Reference to parent server instance for server-level access",
        ),
    ] = None

    @abstractmethod
    def resolve_acl_attributes(self) -> MutableSequence[str]:
        """Return the ACL attribute names owned by this server flavor.

        Raises:
            NotImplementedError: Always; concrete server flavors must override.

        """
        msg = "ACL servers must implement resolve_acl_attributes"
        raise NotImplementedError(msg)

    def matches_acl_attribute(self, attribute_name: str) -> bool:
        """Check whether an attribute name is this server's ACL attribute.

        Args:
            attribute_name: Attribute name to test.

        Returns:
            True when the name matches case-insensitively.

        """
        all_attrs_lower = {a.lower() for a in self.resolve_acl_attributes()}
        return attribute_name.lower() in all_attrs_lower

    def can_handle(self, acl_line: str | m.Ldif.Acl) -> bool:
        """Check whether this server can handle the ACL after normalization.

        Args:
            acl_line: Raw ACL string or parsed ACL model.

        Returns:
            True when the normalized ACL is non-empty and dispatchable.

        """
        normalized = self._normalize_acl_line(acl_line)
        if not normalized:
            return False
        return self.can_handle_acl(normalized)

    @abstractmethod
    def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool:
        """Check whether this server can handle the ACL definition.

        Args:
            acl_line: Raw ACL string or parsed ACL model.

        Raises:
            NotImplementedError: Always; concrete server flavors must override.

        """
        del acl_line
        msg = "ACL servers must implement can_handle_acl"
        raise NotImplementedError(msg)

    @staticmethod
    def _normalize_acl_line(acl_line: str | m.Ldif.Acl) -> str | None:
        """Extract and strip the raw ACL string from either input type.

        Args:
            acl_line: Raw ACL string or parsed ACL model.

        Returns:
            Stripped raw ACL string, or None when no raw string is available.

        """
        if isinstance(acl_line, str):
            return acl_line.strip()
        raw_acl = getattr(acl_line, "raw_acl", None)
        if not isinstance(raw_acl, str):
            return None
        return raw_acl.strip()

    @abstractmethod
    def can_handle_attribute(self, attribute: m.Ldif.SchemaAttribute) -> bool:
        """Check whether this ACL server is aware of an attribute definition.

        Args:
            attribute: Schema attribute definition to test.

        Raises:
            NotImplementedError: Always; concrete server flavors must override.

        """
        del attribute
        msg = "ACL servers must implement can_handle_attribute"
        raise NotImplementedError(msg)

    @abstractmethod
    def can_handle_objectclass(self, objectclass: m.Ldif.SchemaObjectClass) -> bool:
        """Check whether this ACL server is aware of an objectClass definition.

        Args:
            objectclass: Schema objectClass definition to test.

        Raises:
            NotImplementedError: Always; concrete server flavors must override.

        """
        del objectclass
        msg = "ACL servers must implement can_handle_objectclass"
        raise NotImplementedError(msg)

    def create_metadata(
        self,
        original_format: str,
        extensions: t.Ldif.MetadataInputMapping | None = None,
    ) -> m.Ldif.ServerMetadata:
        """Create server metadata tagged with this server's type.

        Args:
            original_format: Original ACL format identifier to record.
            extensions: Optional extra metadata entries merged over the base.

        Returns:
            Validated server metadata carrying the format and extensions.

        """
        all_extensions: t.Ldif.MutableMetadataInputMapping = {
            "original_format": original_format,
        }
        if extensions:
            all_extensions.update(extensions)
        # mro-wgwh.5 (agent: kimi-coder) — DynamicMetadata removed: the ServerMetadata
        # boundary validates the plain mapping.
        return m.Ldif.ServerMetadata(
            server_type=self._get_server_type(),
            extensions=all_extensions,
        )

    @override
    def execute(
        self,
        *,
        data: str | m.Ldif.Acl | None = None,
        operation: str | None = None,
        **kwargs: t.Ldif.Scalar,
    ) -> p.Result[t.Ldif.AclPayload]:
        """Execute the ACL operation, auto-detecting parse for str, write for Acl.

        Args:
            data: Raw ACL string or parsed ACL model to process.
            operation: Explicit operation token ("parse" or "write").
            kwargs: Extra scalar parameters resolved for data and operation.

        Returns:
            Typed result carrying the parsed or written ACL payload.

        """
        kwargs_dict: t.MutableJsonMapping = {
            key: u.json_value_adapter().validate_python(u.to_jsonable_python(value))
            for key, value in kwargs.items()
        }
        data = self._resolve_data(data, kwargs_dict)
        operation = self._resolve_operation(operation, kwargs_dict)
        if data is None:
            return r[t.Ldif.AclPayload].ok(m.Ldif.Acl())
        detected_op = self._detect_operation(operation, data)
        return self._execute_detected_operation(detected_op=detected_op, data=data)

    def format_acl_value(
        self,
        acl_value: str,
        acl_metadata: m.Ldif.AclWriteMetadata,
        *,
        use_original_format_as_name: bool = False,
    ) -> p.Result[str]:
        """Format an ACL value for writing, optionally renaming from the original.

        Args:
            acl_value: Raw ACL value string to format.
            acl_metadata: Write metadata that may carry the original format.
            use_original_format_as_name: When True, rewrite the ACL name from the
                recorded original format using the server's name pattern.

        Returns:
            Typed result carrying the formatted ACL value.

        """
        result: p.Result[str]
        if not use_original_format_as_name or not acl_metadata.has_original_format():
            result = r[str].ok(acl_value)
        else:
            original_format = acl_metadata.original_format
            if not original_format:
                result = r[str].ok(acl_value)
            else:
                sanitize_result_raw: tuple[str, bool] = u.Ldif.sanitize_acl_name(
                    original_format,
                )
                sanitized_name, _was_sanitized = sanitize_result_raw
                if not sanitized_name:
                    result = r[str].ok(acl_value)
                else:
                    pattern_result = self._hook_format_acl_name_pattern()
                    if pattern_result.failure:
                        result = r[str].ok(acl_value)
                    else:
                        pattern, replacement_template = pattern_result.value
                        formatted_value = pattern.sub(
                            replacement_template.format(sanitized_name),
                            acl_value,
                        )
                        result = r[str].ok(formatted_value)
        return result

    def parse_server(self, value: str) -> p.Result[m.Ldif.Acl]:
        """Parse one server-specific ACL line into the canonical Acl model.

        Args:
            value: Raw ACL line in the server's dialect.

        Returns:
            Typed result carrying the parsed ACL model.

        """
        return self._parse_acl(value)

    def parse_input(self, acl_text: str) -> p.Result[m.Ldif.Acl]:
        """Parse raw ACL text through the server-specific parser.

        Args:
            acl_text: Raw ACL text in the server's dialect.

        Returns:
            Typed result carrying the parsed ACL model.

        """
        return self.parse_server(acl_text)

    def write(self, acl_data: m.Ldif.Acl) -> p.Result[str]:
        """Serialize the Acl model back to its string format.

        Args:
            acl_data: Canonical ACL model to serialize.

        Returns:
            Typed result carrying the serialized ACL string.

        """
        return self._write_acl(acl_data)

    @staticmethod
    def _coerce_acl_data(
        value: str | t.JsonValue | m.Ldif.Acl | None,
    ) -> str | m.Ldif.Acl | None:
        """Coerce a generic value to the ACL payload union.

        Args:
            value: String, JSON value, ACL model, or None.

        Returns:
            The coerced string or ACL model, or None for a None input.

        Raises:
            ValidationError: When the value is not a valid ACL model.

        """
        if value is None:
            return None
        if isinstance(value, str):
            return value
        try:
            acl: m.Ldif.Acl = m.Ldif.Acl.model_validate(value)
        except c.ValidationError as exc:
            FlextLdifServersBaseSchemaAcl._module_logger.warning(
                "Failed to coerce value to ACL model",
                error=str(exc),
                error_type=type(exc).__name__,
            )
            raise
        else:
            return acl

    @staticmethod
    def _coerce_operation(value: str) -> str | None:
        """Coerce an operation token to a supported ACL operation.

        Args:
            value: Candidate operation token.

        Returns:
            The normalized token, or None when unsupported.

        """
        if value in {"parse", "write"}:
            return value
        return None

    @staticmethod
    def _detect_operation(operation: str | None, data: str | m.Ldif.Acl) -> str:
        """Detect the operation from the explicit token or the data type.

        Args:
            operation: Explicit operation token, when provided.
            data: Payload whose type selects the default operation.

        Returns:
            The detected operation token ("parse" or "write").

        """
        if operation is not None and operation in {"parse", "write"}:
            return "parse" if operation == "parse" else "write"
        return "parse" if isinstance(data, str) else "write"

    def _execute_acl_parse(self, data: str) -> p.Result[t.Ldif.AclPayload]:
        """Execute the ACL parse operation.

        Args:
            data: Raw ACL string to parse.

        Returns:
            Typed result carrying the parsed ACL payload. Failure metadata
            from the server parse (error code, data, exception) is preserved
            unchanged.

        """
        parse_result = self.parse_server(data)
        if parse_result.success:
            return r[t.Ldif.AclPayload].ok(parse_result.value)
        return r[t.Ldif.AclPayload].from_failure(parse_result)

    def _execute_acl_write(self, data: m.Ldif.Acl) -> p.Result[t.Ldif.AclPayload]:
        """Execute the ACL write operation.

        Args:
            data: Canonical ACL model to write.

        Returns:
            Typed result carrying the written ACL payload. Failure metadata
            from the server write (error code, data, exception) is preserved
            unchanged.

        """
        write_result = self.write(data)
        if write_result.success:
            return r[t.Ldif.AclPayload].ok(write_result.value)
        return r[t.Ldif.AclPayload].from_failure(write_result)

    def _execute_detected_operation(
        self,
        *,
        detected_op: str,
        data: str | m.Ldif.Acl,
    ) -> p.Result[t.Ldif.AclPayload]:
        """Execute parse or write with strongly typed dispatch.

        Args:
            detected_op: Operation token selected by detection.
            data: Payload dispatched to the matching operation.

        Returns:
            Typed result carrying the operation's ACL payload.

        """
        if detected_op == "parse":
            if not isinstance(data, str):
                return r[t.Ldif.AclPayload].fail(
                    f"parse requires str, got {type(data).__name__}",
                )
            return self._execute_acl_parse(data)
        parsed_acl = self._coerce_acl_data(data)
        if parsed_acl is None or isinstance(parsed_acl, str):
            return r[t.Ldif.AclPayload].fail(
                f"write requires Acl, got {type(data).__name__}",
            )
        return self._execute_acl_write(parsed_acl)

    def _extract_acl_parameters(
        self,
        kwargs: t.MutableJsonMapping,
    ) -> tuple[str | m.Ldif.Acl | None, str | None]:
        """Extract and validate ACL operation parameters from kwargs.

        Args:
            kwargs: Mutable mapping holding data and operation entries.

        Returns:
            Tuple of the coerced data payload and normalized operation token.

        """
        data_raw = kwargs.get("data")
        data: str | m.Ldif.Acl | None = self._coerce_acl_data(data_raw)
        operation_raw = kwargs.get(c.ContextScope.OPERATION)
        operation = (
            self._coerce_operation(operation_raw)
            if isinstance(operation_raw, str)
            else None
        )
        return (data, operation)

    @abstractmethod
    def _get_feature_fallback(self, _feature_id: str) -> str | None:
        """Return the RFC fallback value for an unsupported vendor feature.

        Args:
            _feature_id: Identifier of the unsupported vendor feature.

        Raises:
            NotImplementedError: Always; concrete server flavors must override.

        """
        del _feature_id
        msg = "ACL servers must implement _get_feature_fallback"
        raise NotImplementedError(msg)

    @staticmethod
    def _hook_format_acl_name_pattern() -> p.Result[tuple[t.Ldif.RegexPattern, str]]:
        """Provide the server-specific ACL name matching pattern.

        Returns:
            Typed result carrying the name pattern and replacement template.

        """
        pattern = c.Ldif.ACL_NAME_QUOTED_RE
        replacement_template = 'acl "{0}"'
        return r[tuple[t.Ldif.RegexPattern, str]].ok((pattern, replacement_template))

    @staticmethod
    def _hook_post_parse_acl(acl: m.Ldif.Acl) -> p.Result[m.Ldif.Acl]:
        """Run the post-parse hook on a freshly parsed ACL.

        Args:
            acl: ACL model produced by the dialect parser.

        Returns:
            Typed result carrying the (possibly adjusted) ACL model.

        """
        return r[m.Ldif.Acl].ok(acl)

    @abstractmethod
    def _parse_acl(self, acl_line: str) -> p.Result[m.Ldif.Acl]:
        """Parse a server-specific ACL definition (internal, required).

        Args:
            acl_line: Raw ACL line in the server's dialect.

        Raises:
            NotImplementedError: Always; concrete server flavors must override.

        """
        del acl_line
        msg = "ACL servers must implement _parse_acl"
        raise NotImplementedError(msg)

    @staticmethod
    def _parse_dialect_acl(
        acl_line: str,
        parser: Callable[[str], p.Result[m.Ldif.Acl]],
        context: str,
    ) -> p.Result[m.Ldif.Acl]:
        """Parse through one dialect parser, converting typed parse errors.

        Args:
            acl_line: The raw ACL line to parse.
            parser: The dialect-specific ACL parser callable.
            context: The operation context for the typed failure.

        Returns:
            Typed result carrying the parsed ACL model.

        """
        try:
            return parser(acl_line)
        except c.EXC_BASIC_TYPE as exc:
            return r[m.Ldif.Acl].fail_op(context, exc)

    @staticmethod
    def _write_dialect_acl(
        acl_data: m.Ldif.Acl,
        writer: Callable[[m.Ldif.Acl], p.Result[str]],
        context: str,
    ) -> p.Result[str]:
        """Write through one dialect writer, converting typed write errors.

        Args:
            acl_data: The canonical ACL to write.
            writer: The dialect-specific ACL writer callable.
            context: The operation context for the typed failure.

        Returns:
            Typed result carrying the serialized ACL string.

        """
        try:
            return writer(acl_data)
        except c.EXC_BASIC_TYPE as exc:
            return r[str].fail_op(context, exc)

    def _resolve_data(
        self,
        data: str | m.Ldif.Acl | None,
        kwargs: t.JsonMapping,
    ) -> str | m.Ldif.Acl | None:
        """Resolve the data payload from the parameter or kwargs.

        Args:
            data: Explicit data payload, when provided.
            kwargs: Mapping that may carry a "data" entry.

        Returns:
            The resolved data payload, or None when absent.

        """
        if data is not None:
            return data
        data_raw = kwargs.get("data")
        return self._coerce_acl_data(data_raw)

    def _resolve_operation(
        self,
        operation: str | None,
        kwargs: t.JsonMapping,
    ) -> str | None:
        """Resolve the operation token from the parameter or kwargs.

        Args:
            operation: Explicit operation token, when provided.
            kwargs: Mapping that may carry an c.ContextScope.OPERATION entry.

        Returns:
            The resolved operation token, or None when absent.

        """
        if operation is not None:
            return operation
        return self.parse_operation_kwarg(kwargs).unwrap()

    @abstractmethod
    def _supports_feature(self, _feature_id: str) -> bool:
        """Check whether this server supports a specific vendor feature.

        Args:
            _feature_id: Identifier of the vendor feature to test.

        Raises:
            NotImplementedError: Always; concrete server flavors must override.

        """
        del _feature_id
        msg = "ACL servers must implement _supports_feature"
        raise NotImplementedError(msg)

    @abstractmethod
    def _write_acl(self, acl_data: m.Ldif.Acl) -> p.Result[str]:
        """Write ACL data to the RFC-compliant string format (internal).

        Args:
            acl_data: Canonical ACL model to serialize.

        Raises:
            NotImplementedError: Always; concrete server flavors must override.

        """
        del acl_data
        msg = "ACL servers must implement _write_acl"
        raise NotImplementedError(msg)


__all__: list[str] = ["FlextLdifServersBaseSchemaAcl"]
