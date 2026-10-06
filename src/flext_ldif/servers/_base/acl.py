"""Base Server Classes for LDIF/LDAP Server Extensions.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated, ClassVar, Self, override

from flext_ldif import c, m, p, r, s, t, u
from flext_ldif.servers._base.mixins import FlextLdifServerMethodsMixin


class FlextLdifServersBaseSchemaAcl(s[t.Ldif.AclPayload], FlextLdifServerMethodsMixin):
    """Base class for ACL servers - satisfies Acl (structural typing)."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    acl_attribute_name: ClassVar[str] = "acl"
    server_type: Annotated[
        str,
        u.Field(
            description="Server type identifier (e.g., 'oid', 'oud', 'openldap', "
            "'rfc')",
        ),
    ] = "rfc"
    priority: Annotated[
        int,
        u.Field(description="Server priority (lower number = higher priority)"),
    ] = 0
    parent_server: Annotated[
        Self | None,
        u.Field(
            exclude=True,
            repr=False,
            description="Reference to parent server instance for server-level access",
        ),
    ] = None

    def __init__(
        self,
        acl_service: p.Ldif.AclServer | None = None,
        _parent_server: Self | None = None,
    ) -> None:
        """Initialize ACL server service with optional DI service injection."""
        super().__init__()
        self._acl_service = acl_service
        if _parent_server is not None:
            object.__setattr__(self, "_parent_server", _parent_server)

    def resolve_acl_attributes(self) -> t.MutableSequenceOf[str]:
        """Get ACL attributes for this server."""
        msg = "ACL servers must implement resolve_acl_attributes"
        raise NotImplementedError(msg)

    def matches_acl_attribute(self, attribute_name: str) -> bool:
        """Check if attribute is ACL attribute (case-insensitive).

        Returns:
            The resulting ``bool``.
        """
        all_attrs_lower = {a.lower() for a in self.resolve_acl_attributes()}
        return attribute_name.lower() in all_attrs_lower

    auto_execute: ClassVar[bool] = False

    def can_handle(self, acl_line: str | m.Ldif.Acl) -> bool:
        """Check if this ACL can be handled after parsing and normalising.

        Returns:
            The resulting ``bool``.
        """
        normalized = self._normalize_acl_line(acl_line)
        if not normalized:
            return False
        return self.can_handle_acl(normalized)

    def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool:
        """Check if this server can handle the ACL definition."""
        msg = "ACL servers must implement can_handle_acl"
        raise NotImplementedError(msg)

    @staticmethod
    def _normalize_acl_line(acl_line: str | m.Ldif.Acl) -> str | None:
        """Extract and strip the raw ACL string from any input type.

        Returns:
            The resulting ``str | None``.
        """
        if isinstance(acl_line, str):
            return acl_line.strip()
        raw_acl = getattr(acl_line, "raw_acl", None)
        if not isinstance(raw_acl, str):
            return None
        return raw_acl.strip()

    def can_handle_attribute(self, attribute: m.Ldif.SchemaAttribute) -> bool:
        """Check if this ACL server is aware of an attribute definition."""
        msg = "ACL servers must implement can_handle_attribute"
        raise NotImplementedError(msg)

    def can_handle_objectclass(self, objectclass: m.Ldif.SchemaObjectClass) -> bool:
        """Check if this ACL server is aware of an objectClass definition."""
        msg = "ACL servers must implement can_handle_objectclass"
        raise NotImplementedError(msg)

    def create_metadata(
        self,
        original_format: str,
        extensions: t.Ldif.MetadataInputMapping | None = None,
    ) -> m.Ldif.ServerMetadata:
        """Create ACL server metadata.

        Returns:
            The resulting ``m.Ldif.ServerMetadata``.
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
        """Execute ACL operation with auto-detection: str→parse, Acl→write.

        Returns:
            The resulting ``p.Result[t.Ldif.AclPayload]``.
        """
        kwargs_dict: t.MutableJsonMapping = {
            key: t.json_value_adapter().validate_python(u.to_jsonable_python(value))
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
        """Format ACL value for writing, optionally using original format as name.

        Returns:
            The resulting ``p.Result[str]``.
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
        """Parse ACL line to Acl model.

        Returns:
            The resulting ``p.Result[m.Ldif.Acl]``.
        """
        return self._parse_acl(value)

    def parse_input(self, acl_text: str) -> p.Result[m.Ldif.Acl]:
        """Compatibility parser entrypoint for direct ACL server consumers.

        Returns:
            The resulting ``p.Result[m.Ldif.Acl]``.
        """
        return self.parse_server(acl_text)

    def write(self, acl_data: m.Ldif.Acl) -> p.Result[str]:
        """Write Acl model to string format.

        Returns:
            The resulting ``p.Result[str]``.
        """
        return self._write_acl(acl_data)

    @staticmethod
    def _coerce_acl_data(
        value: str | t.JsonValue | m.Ldif.Acl | None,
    ) -> str | m.Ldif.Acl | None:
        """Coerce generic value to ACL payload union.

        Returns:
            The resulting ``str | m.Ldif.Acl | None``.

        Raises:
            ValidationError: If a ``c.ValidationError`` is caught.
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
        """Coerce operation token to supported ACL operation.

        Returns:
            The resulting ``str | None``.
        """
        if value in {"parse", "write"}:
            return value
        return None

    @staticmethod
    def _detect_operation(operation: str | None, data: str | m.Ldif.Acl) -> str:
        """Detect operation type from explicit param or data type.

        Returns:
            The resulting ``str``.
        """
        if operation is not None and operation in {"parse", "write"}:
            return "parse" if operation == "parse" else "write"
        return "parse" if isinstance(data, str) else "write"

    def _execute_acl_parse(self, data: str) -> p.Result[t.Ldif.AclPayload]:
        """Execute ACL parse operation.

        Returns:
            The resulting ``p.Result[t.Ldif.AclPayload]``.
        """
        parse_result = self.parse_server(data)
        if parse_result.success:
            return r[t.Ldif.AclPayload].ok(parse_result.value)
        return r[t.Ldif.AclPayload].fail(parse_result.error or "Parse failed")

    def _execute_acl_write(self, data: m.Ldif.Acl) -> p.Result[t.Ldif.AclPayload]:
        """Execute ACL write operation.

        Returns:
            The resulting ``p.Result[t.Ldif.AclPayload]``.
        """
        write_result = self.write(data)
        if write_result.success:
            return r[t.Ldif.AclPayload].ok(write_result.value)
        return r[t.Ldif.AclPayload].fail(write_result.error or "Write failed")

    def _execute_detected_operation(
        self,
        *,
        detected_op: str,
        data: str | m.Ldif.Acl,
    ) -> p.Result[t.Ldif.AclPayload]:
        """Execute parse/write with strongly typed dispatch.

        Returns:
            The resulting ``p.Result[t.Ldif.AclPayload]``.
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

        Returns:
            The resulting ``tuple[str | m.Ldif.Acl | None, str | None]``.
        """
        data_raw = kwargs.get("data")
        data: str | m.Ldif.Acl | None = self._coerce_acl_data(data_raw)
        operation_raw = kwargs.get("operation")
        operation = (
            self._coerce_operation(operation_raw)
            if isinstance(operation_raw, str)
            else None
        )
        return (data, operation)

    def _get_feature_fallback(self, _feature_id: str) -> str | None:
        """Get RFC fallback value for unsupported vendor feature."""
        msg = "ACL servers must implement _get_feature_fallback"
        raise NotImplementedError(msg)

    @staticmethod
    def _hook_format_acl_name_pattern() -> p.Result[tuple[t.Ldif.RegexPattern, str]]:
        """Provide server-specific ACL name pattern matching.

        Returns:
            The resulting ``p.Result[tuple[t.Ldif.RegexPattern, str]]``.
        """
        pattern = c.Ldif.ACL_NAME_QUOTED_RE
        replacement_template = 'acl "{0}"'
        return r[tuple[t.Ldif.RegexPattern, str]].ok((pattern, replacement_template))

    @staticmethod
    def _hook_post_parse_acl(acl: m.Ldif.Acl) -> p.Result[m.Ldif.Acl]:
        """Run hook after parsing an ACL line.

        Returns:
            The resulting ``p.Result[m.Ldif.Acl]``.
        """
        return r[m.Ldif.Acl].ok(acl)

    def _parse_acl(self, acl_line: str) -> p.Result[m.Ldif.Acl]:
        """Parse server-specific ACL definition (internal, required)."""
        msg = "ACL servers must implement _parse_acl"
        raise NotImplementedError(msg)

    def _parse_dialect_acl(
        self,
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
            The resulting ``p.Result[m.Ldif.Acl]``.
        """
        try:
            return parser(acl_line)
        except c.EXC_BASIC_TYPE as exc:
            return r[m.Ldif.Acl].fail_op(context, exc)

    def _write_dialect_acl(
        self,
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
            The resulting ``p.Result[str]``.
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
        """Resolve data from parameter or kwargs.

        Returns:
            The resulting ``str | m.Ldif.Acl | None``.
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
        """Resolve operation from parameter or kwargs.

        Returns:
            The resulting ``str | None``.
        """
        if operation is not None:
            return operation
        return self._parse_operation_kwarg(kwargs).unwrap()

    @staticmethod
    def _parse_operation_kwarg(kwargs: t.JsonMapping) -> p.Result[str]:
        """Validate the raw 'operation' kwarg as a string, propagating failures.

        Returns:
            The resulting ``p.Result[str]``.
        """
        try:
            operation_raw = t.str_adapter().validate_python(kwargs.get("operation"))
        except c.ValidationError as exc:
            return r[str].fail(str(exc), exception=exc)
        return r[str].ok(operation_raw)

    def _supports_feature(self, _feature_id: str) -> bool:
        """Check if this server supports a specific feature."""
        msg = "ACL servers must implement _supports_feature"
        raise NotImplementedError(msg)

    def _write_acl(self, acl_data: m.Ldif.Acl) -> p.Result[str]:
        """Write ACL data to RFC-compliant string format (internal)."""
        msg = "ACL servers must implement _write_acl"
        raise NotImplementedError(msg)
