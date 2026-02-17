"""Base Quirk Classes for LDIF/LDAP Server Extensions."""

from __future__ import annotations

import re
from typing import ClassVar

from flext_core import FlextLogger, FlextResult, FlextService
from pydantic import Field

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
from flext_ldif.models import m
from flext_ldif.servers._base.constants import QuirkMethodsMixin
from flext_ldif.typings import t

logger = FlextLogger(__name__)


class FlextLdifServersBaseSchemaAcl(
    QuirkMethodsMixin,
    FlextService[m.Ldif.Acl | str],
):
    """Base class for ACL quirks - satisfies AclProtocol (structural typing)."""

    acl_attribute_name: ClassVar[str] = "acl"

    server_type: str = "rfc"
    """Server type identifier (e.g., 'oid', 'oud', 'openldap', 'rfc')."""

    priority: int = 0
    """Quirk priority (lower number = higher priority)."""

    parent_quirk: object | None = Field(
        default=None,
        exclude=True,
        repr=False,
        description=("Reference to parent quirk instance for server-level access"),
    )

    def __init__(
        self,
        acl_service: object | None = None,
        _parent_quirk: object | None = None,
        **kwargs: t.GeneralValueType,
    ) -> None:
        """Initialize ACL quirk service with optional DI service injection."""
        super().__init__(**kwargs)
        self._acl_service = acl_service

        if _parent_quirk is not None:
            object.__setattr__(self, "_parent_quirk", _parent_quirk)

    RFC_ACL_ATTRIBUTES: ClassVar[list[str]] = [
        "aci",
        "acl",
        "olcAccess",
        "aclRights",
        "aclEntry",
    ]

    def get_acl_attributes(self) -> list[str]:
        """Get ACL attributes for this server."""
        return self.RFC_ACL_ATTRIBUTES

    def is_acl_attribute(self, attribute_name: str) -> bool:
        """Check if attribute is ACL attribute (case-insensitive)."""
        all_attrs_lower = {a.lower() for a in self.get_acl_attributes()}
        return attribute_name.lower() in all_attrs_lower

    auto_execute: ClassVar[bool] = False

    def _hook_post_parse_acl(
        self,
        acl: m.Ldif.Acl,
    ) -> FlextResult[m.Ldif.Acl]:
        """Hook called after parsing an ACL line."""
        return FlextResult.ok(acl)

    def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool:
        """Check if this quirk can handle the ACL definition."""
        _ = acl_line
        return False

    def can_handle(self, acl_line: str | m.Ldif.Acl) -> bool:
        """Check if this ACL can be handled after parsing."""
        _ = acl_line
        return True

    def _supports_feature(self, _feature_id: str) -> bool:
        """Check if this server supports a specific feature."""
        return False

    def _get_feature_fallback(self, _feature_id: str) -> str | None:
        """Get RFC fallback value for unsupported vendor feature."""
        return None

    def _parse_acl(self, acl_line: str) -> FlextResult[m.Ldif.Acl]:
        """REQUIRED: Parse server-specific ACL definition (internal)."""
        _ = acl_line
        return FlextResult.fail("Must be implemented by subclass")

    def can_handle_attribute(
        self,
        attribute: m.Ldif.SchemaAttribute,
    ) -> bool:
        """Check if this ACL quirk should be aware of a specific attribute definition."""
        _ = attribute
        return False

    def can_handle_objectclass(
        self,
        objectclass: m.Ldif.SchemaObjectClass,
    ) -> bool:
        """Check if this ACL quirk should be aware of a specific objectClass definition."""
        _ = objectclass
        return False

    def _write_acl(self, acl_data: FlextLdifModelsDomains.Acl) -> FlextResult[str]:
        """Write ACL data to RFC-compliant string format (internal)."""
        _ = acl_data
        return FlextResult[str].fail("Must be implemented by subclass")

    def parse(self, acl_line: str) -> FlextResult[m.Ldif.Acl]:
        """Parse ACL line to Acl model."""
        return self._parse_acl(acl_line)

    def write(self, acl_data: FlextLdifModelsDomains.Acl) -> FlextResult[str]:
        """Write Acl model to string format."""
        return self._write_acl(acl_data)

    def _extract_acl_parameters(
        self,
        kwargs: dict[
            str,
            str
            | int
            | float
            | bool
            | list[str]
            | dict[str, str | int | float | bool | list[str] | None]
            | None,
        ],
    ) -> tuple[
        str | m.Ldif.Acl | None,
        str | None,
    ]:
        """Extract and validate ACL operation parameters from kwargs."""
        data_raw = kwargs.get("data")
        data: str | m.Ldif.Acl | None = (
            data_raw if isinstance(data_raw, (str, m.Ldif.Acl, type(None))) else None
        )

        operation_raw = kwargs.get("operation")
        operation: str | None = None
        if isinstance(operation_raw, str) and operation_raw in {"parse", "write"}:
            operation = "parse" if operation_raw == "parse" else "write"

        return data, operation

    def _execute_acl_parse(
        self,
        data: str,
    ) -> FlextResult[m.Ldif.Acl | str]:
        """Execute ACL parse operation."""
        parse_result = self.parse(data)
        if parse_result.is_success:
            return FlextResult[m.Ldif.Acl | str].ok(parse_result.value)
        return FlextResult[m.Ldif.Acl | str].fail(
            parse_result.error or "Parse failed",
        )

    def _execute_acl_write(
        self,
        data: m.Ldif.Acl,
    ) -> FlextResult[m.Ldif.Acl | str]:
        """Execute ACL write operation."""
        write_result = self.write(data)
        if write_result.is_success:
            return FlextResult[m.Ldif.Acl | str].ok(write_result.value)
        return FlextResult[m.Ldif.Acl | str].fail(
            write_result.error or "Write failed",
        )

    def _resolve_data(
        self,
        data: str | m.Ldif.Acl | None,
        kwargs: dict[str, dict[str, t.GeneralValueType]],
    ) -> str | m.Ldif.Acl | None:
        """Resolve data from parameter or kwargs."""
        if data is not None:
            return data
        data_raw = kwargs.get("data")
        if isinstance(data_raw, (str, m.Ldif.Acl)):
            return data_raw
        return None

    def _resolve_operation(
        self,
        operation: str | None,
        kwargs: dict[str, dict[str, t.GeneralValueType]],
    ) -> str | None:
        """Resolve operation from parameter or kwargs."""
        if operation is not None:
            return operation
        operation_raw = kwargs.get("operation")
        if isinstance(operation_raw, str) and operation_raw in {"parse", "write"}:
            return operation_raw
        return None

    def _detect_operation(
        self,
        operation: str | None,
        data: str | m.Ldif.Acl,
    ) -> str:
        """Detect operation type from explicit param or data type."""
        if operation is not None and operation in {"parse", "write"}:
            return "parse" if operation == "parse" else "write"
        return "parse" if isinstance(data, str) else "write"

    def execute(
        self,
        *,
        data: str | m.Ldif.Acl | None = None,
        operation: str | None = None,
        **kwargs: dict[str, t.GeneralValueType],
    ) -> FlextResult[m.Ldif.Acl | str]:
        """Execute ACL operation with auto-detection: str→parse, Acl→write."""
        kwargs_dict = dict(kwargs)
        data = self._resolve_data(data, kwargs_dict)
        operation = self._resolve_operation(operation, kwargs_dict)

        if data is None:
            return FlextResult[m.Ldif.Acl | str].ok(m.Ldif.Acl())

        detected_op = self._detect_operation(operation, data)

        if detected_op == "parse":
            if not isinstance(data, str):
                return FlextResult[m.Ldif.Acl | str].fail(
                    f"parse requires str, got {type(data).__name__}",
                )
            return self._execute_acl_parse(data)

        if not isinstance(data, m.Ldif.Acl):
            return FlextResult[m.Ldif.Acl | str].fail(
                f"write requires Acl, got {type(data).__name__}",
            )
        return self._execute_acl_write(data)

    def create_metadata(
        self,
        original_format: str,
        extensions: dict[str, t.MetadataAttributeValue] | None = None,
    ) -> m.Ldif.QuirkMetadata:
        """Create ACL quirk metadata."""
        all_extensions: dict[str, t.MetadataAttributeValue] = {
            "original_format": original_format,
        }
        if extensions:
            all_extensions.update(extensions)

        extensions_model = FlextLdifModelsMetadata.DynamicMetadata.from_dict(
            all_extensions
        )
        return m.Ldif.QuirkMetadata(
            quirk_type=self._get_server_type(),
            extensions=extensions_model,
        )

    def format_acl_value(
        self,
        acl_value: str,
        acl_metadata: m.Ldif.AclWriteMetadata,
        *,
        use_original_format_as_name: bool = False,
    ) -> FlextResult[str]:
        """Format ACL value for writing, optionally using original format as name."""
        if not use_original_format_as_name:
            return FlextResult[str].ok(acl_value)

        if not acl_metadata.has_original_format():
            return FlextResult[str].ok(acl_value)

        original_format = acl_metadata.original_format
        if not original_format:
            return FlextResult[str].ok(acl_value)

        sanitize_result = FlextLdifUtilitiesACL.sanitize_acl_name(original_format)

        sanitized_name: str
        _was_sanitized: bool
        tuple_length_pair = 2
        if (
            isinstance(sanitize_result, tuple)
            and len(sanitize_result) == tuple_length_pair
        ):
            sanitized_name, _was_sanitized = sanitize_result
        else:
            sanitized_name = original_format
            _was_sanitized = False

        if not sanitized_name:
            return FlextResult[str].ok(acl_value)

        pattern_result = self._hook_format_acl_name_pattern()
        if pattern_result.is_failure:
            return FlextResult[str].ok(acl_value)

        pattern, replacement_template = pattern_result.value
        formatted_value = pattern.sub(
            replacement_template.format(sanitized_name),
            acl_value,
        )

        return FlextResult[str].ok(formatted_value)

    def _hook_format_acl_name_pattern(
        self,
    ) -> FlextResult[tuple[re.Pattern[str], str]]:
        """Hook for server-specific ACL name pattern matching."""
        pattern = re.compile(r'acl\s+"[^"]*"')
        replacement_template = 'acl "{0}"'
        return FlextResult[tuple[re.Pattern[str], str]].ok((
            pattern,
            replacement_template,
        ))

    def convert_rfc_acl_to_aci(
        self,
        rfc_acl_attrs: dict[str, list[str]],
        target_server: str,
    ) -> FlextResult[dict[str, list[str]]]:
        """Convert RFC ACL format to server-specific ACI format."""
        _ = target_server
        return FlextResult[dict[str, list[str]]].ok(rfc_acl_attrs)
