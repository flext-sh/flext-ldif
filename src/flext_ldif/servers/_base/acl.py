"""Base Quirk Classes for LDIF/LDAP Server Extensions."""

from __future__ import annotations

import re
from collections.abc import (
    MutableSequence,
)
from typing import Annotated, ClassVar, Self, override

from flext_ldif import (
    FlextLdifServerMethodsMixin,
    c,
    m,
    p,
    r,
    s,
    t,
    u,
)

logger = u.fetch_logger(__name__)


class FlextLdifServersBaseSchemaAcl(
    s[t.Ldif.AclPayload],
    FlextLdifServerMethodsMixin,
):
    """Base class for ACL quirks - satisfies Acl (structural typing)."""

    acl_attribute_name: ClassVar[str] = "acl"
    server_type: Annotated[
        str,
        u.Field(
            description="Server type identifier (e.g., 'oid', 'oud', 'openldap', 'rfc')",
        ),
    ] = "rfc"
    priority: Annotated[
        int,
        u.Field(
            description="Quirk priority (lower number = higher priority)",
        ),
    ] = 0
    parent_quirk: Annotated[
        Self | None,
        u.Field(
            exclude=True,
            repr=False,
            description="Reference to parent quirk instance for server-level access",
        ),
    ] = None

    def __init__(
        self,
        acl_service: p.Ldif.AclQuirk | None = None,
        _parent_quirk: Self | None = None,
    ) -> None:
        """Initialize ACL quirk service with optional DI service injection."""
        super().__init__()
        self._acl_service = acl_service
        if _parent_quirk is not None:
            object.__setattr__(self, "_parent_quirk", _parent_quirk)

    RFC_ACL_ATTRIBUTES: ClassVar[tuple[str, ...]] = c.Ldif.RFC_ACL_ATTRIBUTES

    def resolve_acl_attributes(self) -> MutableSequence[str]:
        """Get ACL attributes for this server."""
        return list(self.RFC_ACL_ATTRIBUTES)

    def matches_acl_attribute(self, attribute_name: str) -> bool:
        """Check if attribute is ACL attribute (case-insensitive)."""
        all_attrs_lower = {a.lower() for a in self.resolve_acl_attributes()}
        return attribute_name.lower() in all_attrs_lower

    auto_execute: ClassVar[bool] = False

    def can_handle(self, acl_line: str | m.Ldif.Acl) -> bool:
        """Check if this ACL can be handled after parsing."""
        _ = acl_line
        return True

    def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool:
        """Check if this quirk can handle the ACL definition."""
        _ = acl_line
        return False

    def can_handle_attribute(self, attribute: m.Ldif.SchemaAttribute) -> bool:
        """Check if this ACL quirk should be aware of a specific attribute definition."""
        _ = attribute
        return False

    def can_handle_objectclass(self, objectclass: m.Ldif.SchemaObjectClass) -> bool:
        """Check if this ACL quirk should be aware of a specific objectClass definition."""
        _ = objectclass
        return False

    def convert_rfc_acl_to_aci(
        self,
        rfc_acl_attrs: t.MutableStrSequenceMapping,
        target_server: str,
    ) -> r[t.MutableStrSequenceMapping]:
        """Convert RFC ACL format to server-specific ACI format."""
        _ = target_server
        return r[t.MutableStrSequenceMapping].ok(rfc_acl_attrs)

    def create_metadata(
        self,
        original_format: str,
        extensions: t.Ldif.MetadataInputMapping | None = None,
    ) -> m.Ldif.QuirkMetadata:
        """Create ACL quirk metadata."""
        all_extensions: t.Ldif.MutableMetadataInputMapping = {
            "original_format": original_format,
        }
        if extensions:
            all_extensions.update(extensions)
        extensions_model = m.Ldif.DynamicMetadata.from_dict(
            all_extensions,
        )
        return m.Ldif.QuirkMetadata(
            quirk_type=self._get_server_type(),
            extensions=extensions_model,
        )

    @override
    def execute(
        self,
        *,
        data: str | m.Ldif.Acl | None = None,
        operation: str | None = None,
        **kwargs: t.Ldif.Scalar,
    ) -> r[t.Ldif.AclPayload]:
        """Execute ACL operation with auto-detection: str→parse, Acl→write."""
        json_value_adapter = t.json_value_adapter()
        kwargs_dict: t.MutableJsonMapping = {
            key: json_value_adapter.validate_python(u.to_jsonable_python(value))
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
    ) -> r[str]:
        """Format ACL value for writing, optionally using original format as name."""
        if not use_original_format_as_name:
            return r[str].ok(acl_value)
        if not acl_metadata.has_original_format():
            return r[str].ok(acl_value)
        original_format = acl_metadata.original_format
        if not original_format:
            return r[str].ok(acl_value)
        sanitize_result_raw: tuple[str, bool] = u.Ldif.sanitize_acl_name(
            original_format,
        )
        sanitized_name, _was_sanitized = sanitize_result_raw
        if not sanitized_name:
            return r[str].ok(acl_value)
        pattern_result = self._hook_format_acl_name_pattern()
        if pattern_result.failure:
            return r[str].ok(acl_value)
        pattern, replacement_template = pattern_result.value
        formatted_value = pattern.sub(
            replacement_template.format(sanitized_name),
            acl_value,
        )
        return r[str].ok(formatted_value)

    def parse_quirk(self, value: str) -> r[m.Ldif.Acl]:
        """Parse ACL line to Acl model."""
        return self._parse_acl(value)

    def parse_input(self, acl_text: str) -> r[m.Ldif.Acl]:
        """Compatibility parser entrypoint for direct ACL quirk consumers."""
        return self.parse_quirk(acl_text)

    def write(self, acl_data: m.Ldif.Acl) -> r[str]:
        """Write Acl model to string format."""
        return self._write_acl(acl_data)

    def _coerce_acl_data(
        self,
        value: t.JsonValue | m.Ldif.Acl | None,
    ) -> str | m.Ldif.Acl | None:
        """Coerce generic value to ACL payload union."""
        if value is None:
            return None
        raw_value: object = value
        if isinstance(raw_value, str):
            return raw_value
        try:
            return m.Ldif.Acl.model_validate(value)
        except c.ValidationError as exc:
            logger.warning(
                "Failed to coerce value to ACL model",
                error=str(exc),
                error_type=type(exc).__name__,
            )
            return None

    def _coerce_operation(self, value: str) -> str | None:
        """Coerce operation token to supported ACL operation."""
        if value in {"parse", "write"}:
            return value
        return None

    def _detect_operation(self, operation: str | None, data: str | m.Ldif.Acl) -> str:
        """Detect operation type from explicit param or data type."""
        if operation is not None and operation in {"parse", "write"}:
            return "parse" if operation == "parse" else "write"
        return "parse" if isinstance(data, str) else "write"

    def _execute_acl_parse(self, data: str) -> r[t.Ldif.AclPayload]:
        """Execute ACL parse operation."""
        parse_result = self.parse_quirk(data)
        if parse_result.success:
            return r[t.Ldif.AclPayload].ok(parse_result.value)
        return r[t.Ldif.AclPayload].fail(parse_result.error or "Parse failed")

    def _execute_acl_write(self, data: m.Ldif.Acl) -> r[t.Ldif.AclPayload]:
        """Execute ACL write operation."""
        write_result = self.write(data)
        if write_result.success:
            return r[t.Ldif.AclPayload].ok(write_result.value)
        return r[t.Ldif.AclPayload].fail(write_result.error or "Write failed")

    def _execute_detected_operation(
        self,
        *,
        detected_op: str,
        data: str | m.Ldif.Acl,
    ) -> r[t.Ldif.AclPayload]:
        """Execute parse/write with strongly typed dispatch."""
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
        """Extract and validate ACL operation parameters from kwargs."""
        data_raw = kwargs.get("data")
        data: str | m.Ldif.Acl | None = self._coerce_acl_data(data_raw)
        operation_raw: object = kwargs.get("operation")
        operation = (
            self._coerce_operation(operation_raw)
            if isinstance(operation_raw, str)
            else None
        )
        return (data, operation)

    def _get_feature_fallback(self, _feature_id: str) -> str | None:
        """Get RFC fallback value for unsupported vendor feature."""
        return None

    def _hook_format_acl_name_pattern(self) -> r[tuple[re.Pattern[str], str]]:
        """Hook for server-specific ACL name pattern matching."""
        pattern = re.compile(r'acl\\s+"[^"]*"')
        replacement_template = 'acl "{0}"'
        return r[tuple[re.Pattern[str], str]].ok((
            pattern,
            replacement_template,
        ))

    def _hook_post_parse_acl(self, acl: m.Ldif.Acl) -> r[m.Ldif.Acl]:
        """Hook called after parsing an ACL line."""
        return r[m.Ldif.Acl].ok(acl)

    def _parse_acl(self, acl_line: str) -> r[m.Ldif.Acl]:
        """REQUIRED: Parse server-specific ACL definition (internal)."""
        _ = acl_line
        return r[m.Ldif.Acl].fail("Must be implemented by subclass")

    def _resolve_data(
        self,
        data: str | m.Ldif.Acl | None,
        kwargs: t.JsonMapping,
    ) -> str | m.Ldif.Acl | None:
        """Resolve data from parameter or kwargs."""
        if data is not None:
            return data
        data_raw = kwargs.get("data")
        return self._coerce_acl_data(data_raw)

    def _resolve_operation(
        self,
        operation: str | None,
        kwargs: t.JsonMapping,
    ) -> str | None:
        """Resolve operation from parameter or kwargs."""
        if operation is not None:
            return operation
        operation_raw: object = kwargs.get("operation")
        if not isinstance(operation_raw, str):
            return None
        return self._coerce_operation(operation_raw)

    def _supports_feature(self, _feature_id: str) -> bool:
        """Check if this server supports a specific feature."""
        return False

    def _write_acl(self, acl_data: m.Ldif.Acl) -> r[str]:
        """Write ACL data to RFC-compliant string format (internal)."""
        _ = acl_data
        return r[str].fail("Must be implemented by subclass")
