"""Unit tests for FlextLdifConversion facade.

Tests the universal translation matrix for converting LDAP data between
different server quirks using RFC as intermediate format.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar, cast

import pytest
from flext_core import FlextResult
from pydantic import Field

from flext_ldif import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.servers.oud import FlextLdifServersOud
from flext_ldif.services.conversion import FlextLdifConversion
from flext_ldif.typings import FlextLdifTypes
from tests.fixtures.typing import GenericFieldsDict
from tests.helpers.test_deduplication_helpers import TestDeduplicationHelpers

from .servers.conftest import ConversionTestConstants

# Conversion test constants - defined at top of module without type checking
CONVERSION_TEST_CONSTANTS = ConversionTestConstants()


# Real test quirks for error path testing
class FailingParseQuirk(FlextLdifServersBase.Schema):
    """Real FlextLdifServersBase.Schema subclass that fails on parse."""

    class Constants:
        """Constants for test quirk."""

        SERVER_TYPE: str = "test_failing_parse"
        PRIORITY: int = 100

    error_msg: str = Field(default="parse failed", exclude=True)

    def __init__(
        self,
        schema_service: object | None = None,
        error_msg: str = "parse failed",
        **kwargs: object,
    ) -> None:
        """Initialize quirk."""
        # Cast schema_service to expected type for type checker
        # Schema.__init__ expects _schema_service (with underscore) and **kwargs: str | float | bool | None
        filtered_kwargs: dict[str, str | float | bool | None] = {
            k: v
            for k, v in kwargs.items()
            if isinstance(v, (str, float, bool, type(None)))
        }
        super().__init__(
            _schema_service=cast(
                "FlextLdifProtocols.Services.HasParseMethodProtocol | None",
                schema_service,
            ),
            **filtered_kwargs,  # type: ignore[arg-type]
        )
        object.__setattr__(self, "error_msg", error_msg)
        # schema_quirk is already set by parent __init__

    def execute(
        self,
        **kwargs: object,
    ) -> FlextResult[
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
    ]:
        """Execute schema quirk operation - delegate to parse_attribute/write_attribute."""
        data = kwargs.get("data")
        operation = kwargs.get("operation")

        if data is None:
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].ok("")

        # Auto-detect operation
        if operation is None:
            operation = "parse" if isinstance(data, str) else "write"

        if operation == "parse":
            if isinstance(data, str):
                # Cast return type to match expected return type
                result = self.parse_attribute(data)
                return cast(
                    "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                    result,
                )
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].fail(
                "parse requires str",
            )

        # operation == "write"
        if isinstance(data, FlextLdifModels.SchemaAttribute):
            # write_attribute returns FlextResult[str]
            # Cast to match expected union return type
            write_result = self.write_attribute(data)
            return cast(
                "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                write_result,
            )
        if isinstance(data, FlextLdifModels.SchemaObjectClass):
            # write_objectclass returns FlextResult[str]
            # Cast to match expected union return type
            write_oc_result = self.write_objectclass(data)
            return cast(
                "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                write_oc_result,
            )
        return FlextResult[
            FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
        ].fail(
            "write requires SchemaAttribute or SchemaObjectClass",
        )

    def can_handle_attribute(
        self,
        attr_definition: str | FlextLdifModels.SchemaAttribute,
    ) -> bool:
        """Always handle attributes for testing."""
        return True

    def can_handle_objectclass(
        self,
        oc_definition: str | FlextLdifModels.SchemaObjectClass,
    ) -> bool:
        """Always handle objectClass for testing."""
        return True

    def can_handle_acl(self, acl_line: str | FlextLdifModels.Acl) -> bool:
        """Always handle ACL for testing."""
        return True

    def _parse_attribute(
        self,
        attr_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        return FlextResult.fail(self.error_msg)

    def _parse_objectclass(
        self,
        oc_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        return FlextResult.fail(self.error_msg)

    def _write_attribute(
        self,
        attr_data: FlextLdifModels.SchemaAttribute,
    ) -> FlextResult[str]:
        return FlextResult.fail(self.error_msg)

    def _write_objectclass(
        self,
        oc_data: FlextLdifModels.SchemaObjectClass,
    ) -> FlextResult[str]:
        return FlextResult.fail(self.error_msg)

    def parse(
        self,
        definition: str,
    ) -> FlextResult[
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass
    ]:
        """Parse schema definition - always fails for testing."""
        # Try to detect if it's attribute or objectclass
        if "NAME" in definition and (
            "SUP" in definition
            or "STRUCTURAL" in definition
            or "AUXILIARY" in definition
        ):
            # _parse_objectclass returns FlextResult[SchemaObjectClass]
            # Cast to match expected union return type
            parse_oc_result = self._parse_objectclass(definition)
            return cast(
                "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass]",
                parse_oc_result,
            )
        # _parse_attribute returns FlextResult[SchemaAttribute]
        # Cast to match expected union return type
        parse_attr_result = self._parse_attribute(definition)
        return cast(
            "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass]",
            parse_attr_result,
        )


class SuccessfulParseQuirk(FlextLdifServersBase.Schema):
    """Real FlextLdifServersBase.Schema subclass for successful operations."""

    class Constants:
        """Constants for test quirk."""

        SERVER_TYPE: str = "test_successful_parse"
        PRIORITY: int = 100

    def __init__(self, schema_service: object | None = None, **kwargs: object) -> None:
        """Initialize quirk."""
        # Cast schema_service to expected type for type checker
        # Schema.__init__ expects _schema_service (with underscore) and **kwargs: str | float | bool | None
        filtered_kwargs: dict[str, str | float | bool | None] = {
            k: v
            for k, v in kwargs.items()
            if isinstance(v, (str, float, bool, type(None)))
        }
        super().__init__(
            _schema_service=cast(
                "FlextLdifProtocols.Services.HasParseMethodProtocol | None",
                schema_service,
            ),
            **filtered_kwargs,  # type: ignore[arg-type]
        )

    def execute(
        self,
        **kwargs: object,
    ) -> FlextResult[
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
    ]:
        """Execute schema quirk operation - delegate to parse_attribute/write_attribute."""
        data = kwargs.get("data")
        operation = kwargs.get("operation")

        if data is None:
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].ok("")

        # Auto-detect operation
        if operation is None:
            operation = "parse" if isinstance(data, str) else "write"

        if operation == "parse":
            if isinstance(data, str):
                # Cast return type to match expected return type
                result = self.parse_attribute(data)
                return cast(
                    "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                    result,
                )
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].fail(
                "parse requires str",
            )

        # operation == "write"
        if isinstance(data, FlextLdifModels.SchemaAttribute):
            # write_attribute returns FlextResult[str]
            # Cast to match expected union return type
            write_result = self.write_attribute(data)
            return cast(
                "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                write_result,
            )
        if isinstance(data, FlextLdifModels.SchemaObjectClass):
            # write_objectclass returns FlextResult[str]
            # Cast to match expected union return type
            write_oc_result = self.write_objectclass(data)
            return cast(
                "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                write_oc_result,
            )
        return FlextResult[
            FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
        ].fail(
            "write requires SchemaAttribute or SchemaObjectClass",
        )

    def can_handle_attribute(
        self,
        attr_definition: str | FlextLdifModels.SchemaAttribute,
    ) -> bool:
        """Always handle attributes for testing."""
        return True

    def can_handle_objectclass(
        self,
        oc_definition: str | FlextLdifModels.SchemaObjectClass,
    ) -> bool:
        """Always handle objectClass for testing."""
        return True

    def _parse_attribute(
        self,
        attr_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        # Create SchemaAttribute with all required fields
        return FlextResult.ok(
            FlextLdifModels.SchemaAttribute(
                oid="1.2.3.4.5",
                name="test",
                desc="",
                sup="",
                equality="",
                ordering="",
                substr="",
                syntax="",
                length=None,
                usage="",
                x_origin="",
                x_file_ref="",
                x_name="",
                x_alias="",
                x_oid="",
            ),
        )

    def _parse_objectclass(
        self,
        oc_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        # Create SchemaObjectClass with all required fields
        return FlextResult.ok(
            FlextLdifModels.SchemaObjectClass(
                oid="1.2.3.4.6",
                name="test",
                desc="",
                sup="",
            ),
        )

    def _write_attribute(
        self,
        attr_data: FlextLdifModels.SchemaAttribute,
    ) -> FlextResult[str]:
        # Generate valid LDAP attribute definition with OID
        oid = attr_data.oid or "1.2.3.4.5"
        name = attr_data.name or "test"
        return FlextResult.ok(f"({oid} NAME '{name}')")

    def _write_objectclass(
        self,
        oc_data: FlextLdifModels.SchemaObjectClass,
    ) -> FlextResult[str]:
        # Generate valid LDAP objectClass definition with OID
        oid = oc_data.oid or "1.2.3.4.6"
        name = oc_data.name or "test"
        return FlextResult.ok(f"({oid} NAME '{name}' SUP top STRUCTURAL)")

    def parse(
        self,
        definition: str,
    ) -> FlextResult[
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass
    ]:
        """Parse schema definition."""
        # Try to detect if it's attribute or objectclass
        if "NAME" in definition and (
            "SUP" in definition
            or "STRUCTURAL" in definition
            or "AUXILIARY" in definition
        ):
            # Cast union return type to match expected type
            parse_oc_result = self._parse_objectclass(definition)
            return cast(
                "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass]",
                parse_oc_result,
            )
        # Cast union return type to match expected type
        parse_attr_result = self._parse_attribute(definition)
        return cast(
            "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass]",
            parse_attr_result,
        )


class ConversionFailingQuirk(FlextLdifServersBase.Schema):
    """Real FlextLdifServersBase.Schema subclass that fails on conversion."""

    class Constants:
        """Constants for test quirk."""

        SERVER_TYPE: str = "test_conversion_failing"
        PRIORITY: int = 100

    fail_on: str = Field(default="to_rfc", exclude=True)

    def __init__(
        self,
        schema_service: object | None = None,
        fail_on: str = "to_rfc",
        **kwargs: object,
    ) -> None:
        """Initialize quirk with failure mode."""
        # Cast schema_service to expected type and filter kwargs
        filtered_kwargs: dict[str, str | float | bool | None] = {
            k: v
            for k, v in kwargs.items()
            if isinstance(v, (str, float, bool, type(None)))
        }
        super().__init__(
            _schema_service=cast(
                "FlextLdifProtocols.Services.HasParseMethodProtocol | None",
                schema_service,
            ),
            **filtered_kwargs,  # type: ignore[arg-type]
        )
        object.__setattr__(self, "fail_on", fail_on)
        # schema_quirk is already set by parent __init__

    def execute(
        self,
        **kwargs: object,
    ) -> FlextResult[
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
    ]:
        """Execute schema quirk operation - delegate to parse_attribute/write_attribute."""
        data = kwargs.get("data")
        operation = kwargs.get("operation")

        if data is None:
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].ok("")

        # Auto-detect operation
        if operation is None:
            operation = "parse" if isinstance(data, str) else "write"

        if operation == "parse":
            if isinstance(data, str):
                # Cast return type to match expected return type
                result = self.parse_attribute(data)
                return cast(
                    "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                    result,
                )
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].fail(
                "parse requires str",
            )

        # operation == "write"
        if isinstance(data, FlextLdifModels.SchemaAttribute):
            # write_attribute returns FlextResult[str]
            # Cast to match expected union return type
            write_result = self.write_attribute(data)
            return cast(
                "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                write_result,
            )
        if isinstance(data, FlextLdifModels.SchemaObjectClass):
            # write_objectclass returns FlextResult[str]
            # Cast to match expected union return type
            write_oc_result = self.write_objectclass(data)
            return cast(
                "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                write_oc_result,
            )
        return FlextResult[
            FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
        ].fail(
            "write requires SchemaAttribute or SchemaObjectClass",
        )

    def can_handle_attribute(
        self,
        attr_definition: str | FlextLdifModels.SchemaAttribute,
    ) -> bool:
        """Always handle attributes for testing."""
        return True

    def can_handle_objectclass(
        self,
        oc_definition: str | FlextLdifModels.SchemaObjectClass,
    ) -> bool:
        """Always handle objectClass for testing."""
        return True

    def can_handle_acl(self, acl_line: str | FlextLdifModels.Acl) -> bool:
        """Always handle ACL for testing."""
        return True

    def _parse_attribute(
        self,
        attr_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        # Create SchemaAttribute with all required fields
        return FlextResult.ok(
            FlextLdifModels.SchemaAttribute(
                oid="1.2.3.4",
                name="test",
                desc="",
                sup="",
                equality="",
                ordering="",
                substr="",
                syntax="",
                length=None,
                usage="",
                x_origin="",
                x_file_ref="",
                x_name="",
                x_alias="",
                x_oid="",
            ),
        )

    def _write_attribute(
        self,
        attr_data: FlextLdifModels.SchemaAttribute,
    ) -> FlextResult[str]:
        if self.fail_on == "write":
            return FlextResult.fail("write failed")
        return FlextResult.ok(f"({attr_data.oid} NAME '{attr_data.name}')")

    def _parse_objectclass(
        self,
        oc_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        # Create SchemaObjectClass with all required fields
        return FlextResult.ok(
            FlextLdifModels.SchemaObjectClass(
                oid="1.2.3.5",
                name="test",
                desc="",
                sup="",
            ),
        )

    def _write_objectclass(
        self,
        oc_data: FlextLdifModels.SchemaObjectClass,
    ) -> FlextResult[str]:
        if self.fail_on == "write":
            return FlextResult.fail("write failed")
        return FlextResult.ok(f"({oc_data.oid} NAME '{oc_data.name}')")

    def parse(
        self,
        definition: str,
    ) -> FlextResult[
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass
    ]:
        """Parse schema definition."""
        # Try to detect if it's attribute or objectclass
        if "NAME" in definition and (
            "SUP" in definition
            or "STRUCTURAL" in definition
            or "AUXILIARY" in definition
        ):
            # Cast union return type to match expected type
            parse_oc_result = self._parse_objectclass(definition)
            return cast(
                "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass]",
                parse_oc_result,
            )
        # Cast union return type to match expected type
        parse_attr_result = self._parse_attribute(definition)
        return cast(
            "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass]",
            parse_attr_result,
        )


class ExceptionThrowingQuirk(FlextLdifServersBase.Schema):
    """Real FlextLdifServersBase.Schema subclass that throws exceptions."""

    class Constants:
        """Constants for test quirk."""

        SERVER_TYPE: str = "test_exception_throwing"
        PRIORITY: int = 100

    def __init__(self, schema_service: object | None = None, **kwargs: object) -> None:
        """Initialize quirk."""
        # Cast schema_service to expected type for type checker
        # Schema.__init__ expects _schema_service (with underscore) and **kwargs: str | float | bool | None
        filtered_kwargs: dict[str, str | float | bool | None] = {
            k: v
            for k, v in kwargs.items()
            if isinstance(v, (str, float, bool, type(None)))
        }
        super().__init__(
            _schema_service=cast(
                "FlextLdifProtocols.Services.HasParseMethodProtocol | None",
                schema_service,
            ),
            **filtered_kwargs,  # type: ignore[arg-type]
        )
        # schema_quirk is already set by parent __init__

    def execute(
        self,
        **kwargs: object,
    ) -> FlextResult[
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
    ]:
        """Execute schema quirk operation - always throws exception for testing."""
        msg = "unexpected error"
        raise RuntimeError(msg)

    def can_handle_attribute(
        self,
        attr_definition: str | FlextLdifModels.SchemaAttribute,
    ) -> bool:
        """Always handle attributes for testing."""
        return True

    def can_handle_objectclass(
        self,
        oc_definition: str | FlextLdifModels.SchemaObjectClass,
    ) -> bool:
        """Always handle objectClass for testing."""
        return True

    def can_handle_acl(self, acl_line: str | FlextLdifModels.Acl) -> bool:
        """Always handle ACL for testing."""
        return True

    def _parse_attribute(
        self,
        attr_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        msg = "unexpected error"
        raise RuntimeError(msg)

    def _parse_objectclass(
        self,
        oc_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        msg = "unexpected error"
        raise RuntimeError(msg)

    def _write_attribute(
        self,
        attr_data: FlextLdifModels.SchemaAttribute,
    ) -> FlextResult[str]:
        msg = "unexpected error"
        raise RuntimeError(msg)

    def _write_objectclass(
        self,
        oc_data: FlextLdifModels.SchemaObjectClass,
    ) -> FlextResult[str]:
        msg = "unexpected error"
        raise RuntimeError(msg)

    def parse(
        self,
        definition: str,
    ) -> FlextResult[
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass
    ]:
        """Parse schema definition - always throws exception for testing."""
        msg = "unexpected error"
        raise RuntimeError(msg)


class MissingParseObjectClassQuirk(FlextLdifServersBase.Schema):
    """Real quirk missing parse_objectclass method."""

    class Constants:
        """Constants for test quirk."""

        SERVER_TYPE: str = "test_missing_parse_oc"
        PRIORITY: int = 100

    def __init__(self, schema_service: object | None = None, **kwargs: object) -> None:
        """Initialize quirk."""
        # Cast schema_service to expected type for type checker
        # Schema.__init__ expects _schema_service (with underscore) and **kwargs: str | float | bool | None
        filtered_kwargs: dict[str, str | float | bool | None] = {
            k: v
            for k, v in kwargs.items()
            if isinstance(v, (str, float, bool, type(None)))
        }
        super().__init__(
            _schema_service=cast(
                "FlextLdifProtocols.Services.HasParseMethodProtocol | None",
                schema_service,
            ),
            **filtered_kwargs,  # type: ignore[arg-type]
        )

    def execute(
        self,
        **kwargs: object,
    ) -> FlextResult[
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
    ]:
        """Execute schema quirk operation - delegate to parse_attribute/write_attribute."""
        data = kwargs.get("data")
        operation = kwargs.get("operation")

        if data is None:
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].ok("")

        # Auto-detect operation
        if operation is None:
            operation = "parse" if isinstance(data, str) else "write"

        if operation == "parse":
            if isinstance(data, str):
                # Cast return type to match expected return type
                result = self.parse_attribute(data)
                return cast(
                    "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                    result,
                )
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].fail(
                "parse requires str",
            )

        # operation == "write"
        if isinstance(data, FlextLdifModels.SchemaAttribute):
            # write_attribute returns FlextResult[str]
            # Cast to match expected union return type
            write_result = self.write_attribute(data)
            return cast(
                "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                write_result,
            )
        if isinstance(data, FlextLdifModels.SchemaObjectClass):
            # write_objectclass returns FlextResult[str]
            # Cast to match expected union return type
            write_oc_result = self.write_objectclass(data)
            return cast(
                "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                write_oc_result,
            )
        return FlextResult[
            FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
        ].fail(
            "write requires SchemaAttribute or SchemaObjectClass",
        )

    def can_handle_attribute(
        self,
        attr_definition: str | FlextLdifModels.SchemaAttribute,
    ) -> bool:
        """Always handle attributes for testing."""
        return True

    def can_handle_objectclass(
        self,
        oc_definition: str | FlextLdifModels.SchemaObjectClass,
    ) -> bool:
        """Does NOT handle objectClass - that's the point of this test."""
        return False

    def can_handle_acl(self, acl_line: str | FlextLdifModels.Acl) -> bool:
        """Always handle ACL for testing."""
        return True

    def _parse_attribute(
        self,
        attr_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Dummy implementation."""
        return FlextResult.ok(
            FlextLdifModels.SchemaAttribute(oid="1.2.3.4", name="test"),
        )

    def _parse_objectclass(
        self,
        oc_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Should never be called since can_handle_objectclass returns False."""
        return FlextResult.fail("Not implemented")

    def _write_attribute(
        self,
        attr_data: FlextLdifModels.SchemaAttribute,
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def _write_objectclass(
        self,
        oc_data: FlextLdifModels.SchemaObjectClass,
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")


class ObjectClassParseOnlyQuirk(FlextLdifServersBase.Schema):
    """Real quirk with parse and to_rfc only."""

    class Constants:
        """Constants for test quirk."""

        SERVER_TYPE: str = "test_parse_only"
        PRIORITY: int = 100

    def __init__(self, schema_service: object | None = None, **kwargs: object) -> None:
        """Initialize quirk."""
        # Cast schema_service to expected type for type checker
        # Schema.__init__ expects _schema_service (with underscore) and **kwargs: str | float | bool | None
        filtered_kwargs: dict[str, str | float | bool | None] = {
            k: v
            for k, v in kwargs.items()
            if isinstance(v, (str, float, bool, type(None)))
        }
        super().__init__(
            _schema_service=cast(
                "FlextLdifProtocols.Services.HasParseMethodProtocol | None",
                schema_service,
            ),
            **filtered_kwargs,  # type: ignore[arg-type]
        )

    def execute(
        self,
        **kwargs: object,
    ) -> FlextResult[
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
    ]:
        """Execute schema quirk operation - delegate to parse_attribute/write_attribute."""
        data = kwargs.get("data")
        operation = kwargs.get("operation")

        if data is None:
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].ok("")

        # Auto-detect operation
        if operation is None:
            operation = "parse" if isinstance(data, str) else "write"

        if operation == "parse":
            if isinstance(data, str):
                # Cast return type to match expected return type
                result = self.parse_attribute(data)
                return cast(
                    "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                    result,
                )
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].fail(
                "parse requires str",
            )

        # operation == "write"
        if isinstance(data, FlextLdifModels.SchemaAttribute):
            # write_attribute returns FlextResult[str]
            # Cast to match expected union return type
            write_result = self.write_attribute(data)
            return cast(
                "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                write_result,
            )
        if isinstance(data, FlextLdifModels.SchemaObjectClass):
            # write_objectclass returns FlextResult[str]
            # Cast to match expected union return type
            write_oc_result = self.write_objectclass(data)
            return cast(
                "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                write_oc_result,
            )
        return FlextResult[
            FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
        ].fail(
            "write requires SchemaAttribute or SchemaObjectClass",
        )

    def can_handle_attribute(
        self,
        attr_definition: str | FlextLdifModels.SchemaAttribute,
    ) -> bool:
        return True

    def can_handle_objectclass(
        self,
        oc_definition: str | FlextLdifModels.SchemaObjectClass,
    ) -> bool:
        return True

    def can_handle_acl(self, acl_line: str | FlextLdifModels.Acl) -> bool:
        return True

    def _parse_attribute(
        self,
        attr_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        # Create SchemaAttribute with all required fields
        return FlextResult.ok(
            FlextLdifModels.SchemaAttribute(
                oid="1.2.3.4",
                name="test",
                desc="",
                sup="",
                equality="",
                ordering="",
                substr="",
                syntax="",
                length=None,
                usage="",
                x_origin="",
                x_file_ref="",
                x_name="",
                x_alias="",
                x_oid="",
            ),
        )

    def _parse_objectclass(
        self,
        oc_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        # Create SchemaObjectClass with all required fields
        return FlextResult.ok(
            FlextLdifModels.SchemaObjectClass(
                oid="1.2.3.5",
                name="test",
                desc="",
                sup="",
            ),
        )

    def _write_attribute(
        self,
        attr_data: FlextLdifModels.SchemaAttribute,
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def _write_objectclass(
        self,
        oc_data: FlextLdifModels.SchemaObjectClass,
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")


class MissingParseAcl(FlextLdifServersBase.Schema):
    """Real quirk missing parse method."""

    class Constants:
        """Constants for test quirk."""

        SERVER_TYPE: str = "test_missing_parse"
        PRIORITY: int = 100

    def __init__(self, schema_service: object | None = None, **kwargs: object) -> None:
        """Initialize quirk."""
        # Cast schema_service to expected type for type checker
        # Schema.__init__ expects _schema_service (with underscore) and **kwargs: str | float | bool | None
        filtered_kwargs: dict[str, str | float | bool | None] = {
            k: v
            for k, v in kwargs.items()
            if isinstance(v, (str, float, bool, type(None)))
        }
        super().__init__(
            _schema_service=cast(
                "FlextLdifProtocols.Services.HasParseMethodProtocol | None",
                schema_service,
            ),
            **filtered_kwargs,  # type: ignore[arg-type]
        )

    def execute(
        self,
        **kwargs: object,
    ) -> FlextResult[
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
    ]:
        """Execute schema quirk operation - delegate to parse_attribute/write_attribute."""
        data = kwargs.get("data")
        operation = kwargs.get("operation")

        if data is None:
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].ok("")

        # Auto-detect operation
        if operation is None:
            operation = "parse" if isinstance(data, str) else "write"

        if operation == "parse":
            if isinstance(data, str):
                # Cast return type to match expected return type
                result = self.parse_attribute(data)
                return cast(
                    "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                    result,
                )
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].fail(
                "parse requires str",
            )

        # operation == "write"
        if isinstance(data, FlextLdifModels.SchemaAttribute):
            # write_attribute returns FlextResult[str]
            # Cast to match expected union return type
            write_result = self.write_attribute(data)
            return cast(
                "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                write_result,
            )
        if isinstance(data, FlextLdifModels.SchemaObjectClass):
            # write_objectclass returns FlextResult[str]
            # Cast to match expected union return type
            write_oc_result = self.write_objectclass(data)
            return cast(
                "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                write_oc_result,
            )
        return FlextResult[
            FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
        ].fail(
            "write requires SchemaAttribute or SchemaObjectClass",
        )

    def can_handle_attribute(
        self,
        attr_definition: str | FlextLdifModels.SchemaAttribute,
    ) -> bool:
        return False

    def can_handle_objectclass(
        self,
        oc_definition: str | FlextLdifModels.SchemaObjectClass,
    ) -> bool:
        return False

    def can_handle_acl(self, acl_line: str | FlextLdifModels.Acl) -> bool:
        return True

    def _parse_attribute(
        self,
        attr_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        return FlextResult.fail("Not implemented")

    def _write_attribute(
        self,
        attr_data: FlextLdifModels.SchemaAttribute,
    ) -> FlextResult[str]:
        return FlextResult.fail("Not implemented")

    def _parse_objectclass(
        self,
        oc_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        return FlextResult.fail("Not implemented")

    def _write_objectclass(
        self,
        oc_data: FlextLdifModels.SchemaObjectClass,
    ) -> FlextResult[str]:
        return FlextResult.fail("Not implemented")

    def _write_acl(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
        return FlextResult.ok("test")


class MissingWriteAcl(FlextLdifServersBase.Schema):
    """Real quirk missing write_acl_to_rfc method."""

    class Constants:
        """Constants for test quirk."""

        SERVER_TYPE: str = "test_missing_write_acl"
        PRIORITY: int = 100

    def __init__(self, schema_service: object | None = None, **kwargs: object) -> None:
        """Initialize quirk."""
        # Cast schema_service to expected type for type checker
        # Schema.__init__ expects _schema_service (with underscore) and **kwargs: str | float | bool | None
        filtered_kwargs: dict[str, str | float | bool | None] = {
            k: v
            for k, v in kwargs.items()
            if isinstance(v, (str, float, bool, type(None)))
        }
        super().__init__(
            _schema_service=cast(
                "FlextLdifProtocols.Services.HasParseMethodProtocol | None",
                schema_service,
            ),
            **filtered_kwargs,  # type: ignore[arg-type]
        )

    def execute(
        self,
        **kwargs: object,
    ) -> FlextResult[
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
    ]:
        """Execute schema quirk operation - delegate to parse_attribute/write_attribute."""
        data = kwargs.get("data")
        operation = kwargs.get("operation")

        if data is None:
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].ok("")

        # Auto-detect operation
        if operation is None:
            operation = "parse" if isinstance(data, str) else "write"

        if operation == "parse":
            if isinstance(data, str):
                # Cast return type to match expected return type
                result = self.parse_attribute(data)
                return cast(
                    "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                    result,
                )
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].fail(
                "parse requires str",
            )

        # operation == "write"
        if isinstance(data, FlextLdifModels.SchemaAttribute):
            # write_attribute returns FlextResult[str]
            # Cast to match expected union return type
            write_result = self.write_attribute(data)
            return cast(
                "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                write_result,
            )
        if isinstance(data, FlextLdifModels.SchemaObjectClass):
            # write_objectclass returns FlextResult[str]
            # Cast to match expected union return type
            write_oc_result = self.write_objectclass(data)
            return cast(
                "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                write_oc_result,
            )
        return FlextResult[
            FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
        ].fail(
            "write requires SchemaAttribute or SchemaObjectClass",
        )

    def can_handle_attribute(
        self,
        attr_definition: str | FlextLdifModels.SchemaAttribute,
    ) -> bool:
        return False

    def can_handle_objectclass(
        self,
        oc_definition: str | FlextLdifModels.SchemaObjectClass,
    ) -> bool:
        return False

    def can_handle_acl(self, acl_line: str | FlextLdifModels.Acl) -> bool:
        return True

    def _parse_attribute(
        self,
        attr_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        return FlextResult.fail("Not implemented")

    def _write_attribute(
        self,
        attr_data: FlextLdifModels.SchemaAttribute,
    ) -> FlextResult[str]:
        return FlextResult.fail("Not implemented")

    def _parse_objectclass(
        self,
        oc_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        return FlextResult.fail("Not implemented")

    def _write_objectclass(
        self,
        oc_data: FlextLdifModels.SchemaObjectClass,
    ) -> FlextResult[str]:
        return FlextResult.fail("Not implemented")


class EntryConversionQuirk(FlextLdifServersBase.Schema):
    """Real quirk with entry conversion support.

    Note: Sets entry_quirk as a marker for entry support.
    """

    class Constants:
        """Constants for test quirk."""

        SERVER_TYPE: str = "test_entry_conversion"
        PRIORITY: int = 100

    def __init__(self, schema_service: object | None = None, **kwargs: object) -> None:
        """Initialize quirk."""
        # Cast schema_service to expected type for type checker
        # Schema.__init__ expects _schema_service (with underscore) and **kwargs: str | float | bool | None
        filtered_kwargs: dict[str, str | float | bool | None] = {
            k: v
            for k, v in kwargs.items()
            if isinstance(v, (str, float, bool, type(None)))
        }
        super().__init__(
            _schema_service=cast(
                "FlextLdifProtocols.Services.HasParseMethodProtocol | None",
                schema_service,
            ),
            **filtered_kwargs,  # type: ignore[arg-type]
        )
        # Create a minimal entry quirk for testing

        class MinimalEntryQuirk:
            def parse(self, ldif_text: str) -> FlextResult[list[FlextLdifModels.Entry]]:
                return FlextResult.ok([])

        object.__setattr__(self, "_entry_quirk", MinimalEntryQuirk())

    def execute(
        self,
        **kwargs: object,
    ) -> FlextResult[
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
    ]:
        """Execute schema quirk operation - delegate to parse_attribute/write_attribute."""
        data = kwargs.get("data")
        operation = kwargs.get("operation")

        if data is None:
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].ok("")

        # Auto-detect operation
        if operation is None:
            operation = "parse" if isinstance(data, str) else "write"

        if operation == "parse":
            if isinstance(data, str):
                # Cast return type to match expected return type
                result = self.parse_attribute(data)
                return cast(
                    "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                    result,
                )
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].fail(
                "parse requires str",
            )

        # operation == "write"
        if isinstance(data, FlextLdifModels.SchemaAttribute):
            # write_attribute returns FlextResult[str]
            # Cast to match expected union return type
            write_result = self.write_attribute(data)
            return cast(
                "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                write_result,
            )
        if isinstance(data, FlextLdifModels.SchemaObjectClass):
            # write_objectclass returns FlextResult[str]
            # Cast to match expected union return type
            write_oc_result = self.write_objectclass(data)
            return cast(
                "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                write_oc_result,
            )
        return FlextResult[
            FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
        ].fail(
            "write requires SchemaAttribute or SchemaObjectClass",
        )

    def can_handle_attribute(
        self,
        attr_definition: str | FlextLdifModels.SchemaAttribute,
    ) -> bool:
        return True  # Supports attribute parsing

    def _parse_attribute(
        self,
        attr_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        # Create SchemaAttribute with all required fields
        return FlextResult.ok(
            FlextLdifModels.SchemaAttribute(
                oid="1.2.3.4",
                name="test",
                desc="",
                sup="",
                equality="",
                ordering="",
                substr="",
                syntax="",
                length=None,
                usage="",
                x_origin="",
                x_file_ref="",
                x_name="",
                x_alias="",
                x_oid="",
            ),
        )

    def can_handle_objectclass(
        self,
        oc_definition: str | FlextLdifModels.SchemaObjectClass,
    ) -> bool:
        return False

    def _parse_objectclass(
        self,
        oc_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        # Create SchemaObjectClass with all required fields
        return FlextResult.ok(
            FlextLdifModels.SchemaObjectClass(
                oid="1.2.3.5",
                name="test",
                desc="",
                sup="",
            ),
        )

    def _write_attribute(
        self,
        attr_data: FlextLdifModels.SchemaAttribute,
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def _write_objectclass(
        self,
        oc_data: FlextLdifModels.SchemaObjectClass,
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")


class MinimalQuirk(FlextLdifServersBase.Schema):
    """Real quirk with minimal functionality."""

    class Constants:
        """Constants for test quirk."""

        SERVER_TYPE: str = "test_minimal"
        PRIORITY: int = 100

    def __init__(self, schema_service: object | None = None, **kwargs: object) -> None:
        """Initialize quirk."""
        # Cast schema_service to expected type for type checker
        # Schema.__init__ expects _schema_service (with underscore) and **kwargs: str | float | bool | None
        filtered_kwargs: dict[str, str | float | bool | None] = {
            k: v
            for k, v in kwargs.items()
            if isinstance(v, (str, float, bool, type(None)))
        }
        super().__init__(
            _schema_service=cast(
                "FlextLdifProtocols.Services.HasParseMethodProtocol | None",
                schema_service,
            ),
            **filtered_kwargs,  # type: ignore[arg-type]
        )
        # schema_quirk is already set by parent __init__

    def execute(
        self,
        **kwargs: object,
    ) -> FlextResult[
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
    ]:
        """Execute schema quirk operation - delegate to parse_attribute/write_attribute."""
        data = kwargs.get("data")
        operation = kwargs.get("operation")

        if data is None:
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].ok("")

        # Auto-detect operation
        if operation is None:
            operation = "parse" if isinstance(data, str) else "write"

        if operation == "parse":
            if isinstance(data, str):
                # Cast return type to match expected return type
                result = self.parse_attribute(data)
                return cast(
                    "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                    result,
                )
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].fail(
                "parse requires str",
            )

        # operation == "write"
        if isinstance(data, FlextLdifModels.SchemaAttribute):
            # write_attribute returns FlextResult[str]
            # Cast to match expected union return type
            write_result = self.write_attribute(data)
            return cast(
                "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                write_result,
            )
        if isinstance(data, FlextLdifModels.SchemaObjectClass):
            # write_objectclass returns FlextResult[str]
            # Cast to match expected union return type
            write_oc_result = self.write_objectclass(data)
            return cast(
                "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                write_oc_result,
            )
        return FlextResult[
            FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
        ].fail(
            "write requires SchemaAttribute or SchemaObjectClass",
        )

    def can_handle_attribute(
        self,
        attr_definition: str | FlextLdifModels.SchemaAttribute,
    ) -> bool:
        return False

    def _parse_attribute(
        self,
        attr_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        # Create SchemaAttribute with all required fields
        return FlextResult.ok(
            FlextLdifModels.SchemaAttribute(
                oid="1.2.3.4",
                name="test",
                desc="",
                sup="",
                equality="",
                ordering="",
                substr="",
                syntax="",
                length=None,
                usage="",
                x_origin="",
                x_file_ref="",
                x_name="",
                x_alias="",
                x_oid="",
            ),
        )

    def can_handle_objectclass(
        self,
        oc_definition: str | FlextLdifModels.SchemaObjectClass,
    ) -> bool:
        return False

    def _parse_objectclass(
        self,
        oc_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        # Create SchemaObjectClass with all required fields
        return FlextResult.ok(
            FlextLdifModels.SchemaObjectClass(
                oid="1.2.3.5",
                name="test",
                desc="",
                sup="",
            ),
        )

    def _write_attribute(
        self,
        attr_data: FlextLdifModels.SchemaAttribute,
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def _write_objectclass(
        self,
        oc_data: FlextLdifModels.SchemaObjectClass,
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")


class PartialAttributeQuirk(FlextLdifServersBase.Schema):
    """Real quirk with only attribute parsing support."""

    class Constants:
        """Constants for test quirk."""

        SERVER_TYPE: str = "test_partial_attr"
        PRIORITY: int = 100

    def __init__(self, schema_service: object | None = None, **kwargs: object) -> None:
        """Initialize quirk."""
        # Cast schema_service to expected type for type checker
        # Schema.__init__ expects _schema_service (with underscore) and **kwargs: str | float | bool | None
        filtered_kwargs: dict[str, str | float | bool | None] = {
            k: v
            for k, v in kwargs.items()
            if isinstance(v, (str, float, bool, type(None)))
        }
        super().__init__(
            _schema_service=cast(
                "FlextLdifProtocols.Services.HasParseMethodProtocol | None",
                schema_service,
            ),
            **filtered_kwargs,  # type: ignore[arg-type]
        )
        # schema_quirk is already set by parent __init__

    def execute(
        self,
        **kwargs: object,
    ) -> FlextResult[
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
    ]:
        """Execute schema quirk operation - delegate to parse_attribute/write_attribute."""
        data = kwargs.get("data")
        operation = kwargs.get("operation")

        if data is None:
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].ok("")

        # Auto-detect operation
        if operation is None:
            operation = "parse" if isinstance(data, str) else "write"

        if operation == "parse":
            if isinstance(data, str):
                # Cast return type to match expected return type
                result = self.parse_attribute(data)
                return cast(
                    "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                    result,
                )
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].fail(
                "parse requires str",
            )

        # operation == "write"
        if isinstance(data, FlextLdifModels.SchemaAttribute):
            # write_attribute returns FlextResult[str]
            # Cast to match expected union return type
            write_result = self.write_attribute(data)
            return cast(
                "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                write_result,
            )
        if isinstance(data, FlextLdifModels.SchemaObjectClass):
            # write_objectclass returns FlextResult[str]
            # Cast to match expected union return type
            write_oc_result = self.write_objectclass(data)
            return cast(
                "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                write_oc_result,
            )
        return FlextResult[
            FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
        ].fail(
            "write requires SchemaAttribute or SchemaObjectClass",
        )

    def can_handle_attribute(
        self,
        attr_definition: str | FlextLdifModels.SchemaAttribute,
    ) -> bool:
        return True

    def _parse_attribute(
        self,
        attr_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        # Create SchemaAttribute with all required fields
        return FlextResult.ok(
            FlextLdifModels.SchemaAttribute(
                oid="1.2.3.4",
                name="test",
                desc="",
                sup="",
                equality="",
                ordering="",
                substr="",
                syntax="",
                length=None,
                usage="",
                x_origin="",
                x_file_ref="",
                x_name="",
                x_alias="",
                x_oid="",
            ),
        )

    def can_handle_objectclass(
        self,
        oc_definition: str | FlextLdifModels.SchemaObjectClass,
    ) -> bool:
        return False

    def _parse_objectclass(
        self,
        oc_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        return FlextResult.fail("Not supported")

    def _write_attribute(
        self,
        attr_data: FlextLdifModels.SchemaAttribute,
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def _write_objectclass(
        self,
        oc_data: FlextLdifModels.SchemaObjectClass,
    ) -> FlextResult[str]:
        return FlextResult.fail("Not supported")


class TestAclQuirk:
    """Test ACL quirk that always handles ACLs.

    Standalone test class that implements ACL interface without inheriting
    from FlextLdifServersBase.Acl to avoid pytest collection warnings.
    """

    def can_handle_acl(self, acl_line: str | FlextLdifModels.Acl) -> bool:
        return True

    def parse(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
        """Parse ACL definition."""
        return FlextResult.ok(FlextLdifModels.Acl(raw_acl=acl_line))

    def _parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
        return FlextResult.ok(FlextLdifModels.Acl(raw_acl=acl_line))

    def _write_acl(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
        return FlextResult.ok(acl_data.raw_acl)


class AclOnlyQuirk(FlextLdifServersBase.Schema):
    """Real quirk with only ACL support."""

    class Constants:
        """Constants for test quirk."""

        SERVER_TYPE: str = "test_acl_only"
        PRIORITY: int = 100

    def __init__(self, schema_service: object | None = None, **kwargs: object) -> None:
        """Initialize quirk."""
        # Cast schema_service to expected type for type checker
        # Schema.__init__ expects _schema_service (with underscore) and **kwargs: str | float | bool | None
        filtered_kwargs: dict[str, str | float | bool | None] = {
            k: v
            for k, v in kwargs.items()
            if isinstance(v, (str, float, bool, type(None)))
        }
        super().__init__(
            _schema_service=cast(
                "FlextLdifProtocols.Services.HasParseMethodProtocol | None",
                schema_service,
            ),
            **filtered_kwargs,  # type: ignore[arg-type]
        )
        # schema_quirk is already set by parent __init__
        # Override acl_quirk for get_supported_conversions
        # Use object.__setattr__ to bypass Pydantic validation
        object.__setattr__(self, "_acl_quirk", TestAclQuirk())

    def execute(
        self,
        **kwargs: object,
    ) -> FlextResult[
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
    ]:
        """Execute schema quirk operation - delegate to parse_attribute/write_attribute."""
        data = kwargs.get("data")
        operation = kwargs.get("operation")

        if data is None:
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].ok("")

        # Auto-detect operation
        if operation is None:
            operation = "parse" if isinstance(data, str) else "write"

        if operation == "parse":
            if isinstance(data, str):
                # Cast return type to match expected return type
                result = self.parse_attribute(data)
                return cast(
                    "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                    result,
                )
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].fail(
                "parse requires str",
            )

        # operation == "write"
        if isinstance(data, FlextLdifModels.SchemaAttribute):
            # write_attribute returns FlextResult[str]
            # Cast to match expected union return type
            write_result = self.write_attribute(data)
            return cast(
                "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                write_result,
            )
        if isinstance(data, FlextLdifModels.SchemaObjectClass):
            # write_objectclass returns FlextResult[str]
            # Cast to match expected union return type
            write_oc_result = self.write_objectclass(data)
            return cast(
                "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                write_oc_result,
            )
        return FlextResult[
            FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
        ].fail(
            "write requires SchemaAttribute or SchemaObjectClass",
        )

    def can_handle_attribute(
        self,
        attr_definition: str | FlextLdifModels.SchemaAttribute,
    ) -> bool:
        return False

    def _parse_attribute(
        self,
        attr_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        # Create SchemaAttribute with all required fields
        return FlextResult.ok(
            FlextLdifModels.SchemaAttribute(
                oid="1.2.3.4",
                name="test",
                desc="",
                sup="",
                equality="",
                ordering="",
                substr="",
                syntax="",
                length=None,
                usage="",
                x_origin="",
                x_file_ref="",
                x_name="",
                x_alias="",
                x_oid="",
            ),
        )

    def can_handle_objectclass(
        self,
        oc_definition: str | FlextLdifModels.SchemaObjectClass,
    ) -> bool:
        return False

    def can_handle_acl(self, acl_line: str | FlextLdifModels.Acl) -> bool:
        return True  # Only ACL support

    def _parse_objectclass(
        self,
        oc_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        # Create SchemaObjectClass with all required fields
        return FlextResult.ok(
            FlextLdifModels.SchemaObjectClass(
                oid="1.2.3.5",
                name="test",
                desc="",
                sup="",
            ),
        )

    def _write_attribute(
        self,
        attr_data: FlextLdifModels.SchemaAttribute,
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def _write_objectclass(
        self,
        oc_data: FlextLdifModels.SchemaObjectClass,
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")


class EntryOnlyQuirk(FlextLdifServersBase.Schema):
    """Real quirk with only entry support.

    Note: Sets entry_quirk as a marker for entry support.
    """

    class Constants:
        """Constants for test quirk."""

        SERVER_TYPE: str = "test_entry_only"
        PRIORITY: int = 100

    def __init__(self, schema_service: object | None = None, **kwargs: object) -> None:
        """Initialize quirk."""
        # Cast schema_service to expected type for type checker
        # Schema.__init__ expects _schema_service (with underscore) and **kwargs: str | float | bool | None
        filtered_kwargs: dict[str, str | float | bool | None] = {
            k: v
            for k, v in kwargs.items()
            if isinstance(v, (str, float, bool, type(None)))
        }
        super().__init__(
            _schema_service=cast(
                "FlextLdifProtocols.Services.HasParseMethodProtocol | None",
                schema_service,
            ),
            **filtered_kwargs,  # type: ignore[arg-type]
        )
        # schema_quirk is already set by parent __init__
        # Create a minimal entry quirk for testing

        class MinimalEntryQuirk:
            def parse(self, ldif_text: str) -> FlextResult[list[FlextLdifModels.Entry]]:
                return FlextResult.ok([])

        object.__setattr__(self, "_entry_quirk", MinimalEntryQuirk())

    def execute(
        self,
        **kwargs: object,
    ) -> FlextResult[
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
    ]:
        """Execute schema quirk operation - delegate to parse_attribute/write_attribute."""
        data = kwargs.get("data")
        operation = kwargs.get("operation")

        if data is None:
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].ok("")

        # Auto-detect operation
        if operation is None:
            operation = "parse" if isinstance(data, str) else "write"

        if operation == "parse":
            if isinstance(data, str):
                # Cast return type to match expected return type
                result = self.parse_attribute(data)
                return cast(
                    "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                    result,
                )
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].fail(
                "parse requires str",
            )

        # operation == "write"
        if isinstance(data, FlextLdifModels.SchemaAttribute):
            # write_attribute returns FlextResult[str]
            # Cast to match expected union return type
            write_result = self.write_attribute(data)
            return cast(
                "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                write_result,
            )
        if isinstance(data, FlextLdifModels.SchemaObjectClass):
            # write_objectclass returns FlextResult[str]
            # Cast to match expected union return type
            write_oc_result = self.write_objectclass(data)
            return cast(
                "FlextResult[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str]",
                write_oc_result,
            )
        return FlextResult[
            FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
        ].fail(
            "write requires SchemaAttribute or SchemaObjectClass",
        )

    def can_handle_attribute(
        self,
        attr_definition: str | FlextLdifModels.SchemaAttribute,
    ) -> bool:
        return False

    def _parse_attribute(
        self,
        attr_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        # Create SchemaAttribute with all required fields
        return FlextResult.ok(
            FlextLdifModels.SchemaAttribute(
                oid="1.2.3.4",
                name="test",
                desc="",
                sup="",
                equality="",
                ordering="",
                substr="",
                syntax="",
                length=None,
                usage="",
                x_origin="",
                x_file_ref="",
                x_name="",
                x_alias="",
                x_oid="",
            ),
        )

    def can_handle_objectclass(
        self,
        oc_definition: str | FlextLdifModels.SchemaObjectClass,
    ) -> bool:
        return False

    def _parse_objectclass(
        self,
        oc_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        # Create SchemaObjectClass with all required fields
        return FlextResult.ok(
            FlextLdifModels.SchemaObjectClass(
                oid="1.2.3.5",
                name="test",
                desc="",
                sup="",
            ),
        )

    def _write_attribute(
        self,
        attr_data: FlextLdifModels.SchemaAttribute,
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def _write_objectclass(
        self,
        oc_data: FlextLdifModels.SchemaObjectClass,
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")


# ═════════════════════════════════════════════════════════════════════════════
# CONSOLIDATED TEST CLASSES - 14 original classes → 5 parametrized classes
# ═════════════════════════════════════════════════════════════════════════════


class InitializationScenario(StrEnum):
    """Scenarios for initialization tests."""

    INSTANTIATION = "instantiation"
    METHODS_EXIST = "methods_exist"


class TestConversionMatrixInitialization:
    """Consolidated initialization tests (2 original tests)."""

    SCENARIOS: ClassVar[dict[str, tuple[str, ...]]] = {
        InitializationScenario.INSTANTIATION: ("instantiation",),
        InitializationScenario.METHODS_EXIST: ("methods_exist",),
    }

    @pytest.mark.parametrize(
        "scenario",
        SCENARIOS.values(),
        ids=list(SCENARIOS.keys()),
    )
    def test_initialization(
        self,
        scenario: str,
        conversion_matrix: FlextLdifConversion,
    ) -> None:
        """Test initialization scenarios."""
        if scenario == "instantiation":
            assert conversion_matrix is not None
            assert hasattr(conversion_matrix, "dn_registry")
        elif scenario == "methods_exist":
            assert hasattr(conversion_matrix, "convert")
            assert hasattr(conversion_matrix, "batch_convert")


class TestGetSupportedConversions:
    """Consolidated support check tests (2 original tests)."""

    @pytest.mark.parametrize(
        "quirk_type",
        ["oud_quirk", "oid_quirk"],
        ids=["oud", "oid"],
    )
    def test_supported_conversions(
        self,
        quirk_type: str,
        conversion_matrix: FlextLdifConversion,
        request: pytest.FixtureRequest,
    ) -> None:
        """Test supported conversions."""
        quirk = request.getfixturevalue(quirk_type)
        TestDeduplicationHelpers.helper_get_supported_conversions_and_assert(
            conversion_matrix,
            quirk,
            must_have_keys=["attribute", "objectClass", "acl", "entry"],
            expected_support={"attribute": True, "objectClass": True},
        )


class TestAttributeConversion:
    """Consolidated attribute conversion tests."""

    @pytest.mark.parametrize(
        ("source", "target", "test_data"),
        [
            ("oud_quirk", "oid_quirk", "OUD_ATTRIBUTE_ORCLGUID"),
            ("oid_quirk", "oud_quirk", "OID_ATTRIBUTE_ORCLGUID"),
        ],
        ids=["oud_to_oid", "oid_to_oud"],
    )
    def test_attribute_conversion(
        self,
        source: str,
        target: str,
        test_data: str,
        conversion_matrix: FlextLdifConversion,
        conversion_constants: ConversionTestConstants,
        request: pytest.FixtureRequest,
    ) -> None:
        """Test attribute conversion."""
        source_quirk = request.getfixturevalue(source)
        target_quirk = request.getfixturevalue(target)
        data = getattr(conversion_constants, test_data)
        TestDeduplicationHelpers.helper_convert_and_assert_strings(
            conversion_matrix,
            source_quirk,
            target_quirk,
            "attribute",
            data,
            must_contain=["2.16.840.1.113894"],
            expected_type=str,
        )


class TestObjectClassConversion:
    """Consolidated objectclass conversion tests."""

    @pytest.mark.parametrize(
        ("source", "target", "test_data"),
        [
            ("oud_quirk", "oid_quirk", "OUD_OBJECTCLASS_ORCLCONTEXT"),
            ("oid_quirk", "oud_quirk", "OID_OBJECTCLASS_ORCLCONTEXT"),
        ],
        ids=["oud_to_oid", "oid_to_oud"],
    )
    def test_objectclass_conversion(
        self,
        source: str,
        target: str,
        test_data: str,
        conversion_matrix: FlextLdifConversion,
        conversion_constants: ConversionTestConstants,
        request: pytest.FixtureRequest,
    ) -> None:
        """Test objectclass conversion."""
        source_quirk = request.getfixturevalue(source)
        target_quirk = request.getfixturevalue(target)
        data = getattr(conversion_constants, test_data)
        TestDeduplicationHelpers.helper_convert_and_assert_strings(
            conversion_matrix,
            source_quirk,
            target_quirk,
            "objectClass",
            data,
            must_contain=["2.16.840.1.113894"],
            expected_type=str,
        )


class TestBatchConversion:
    """Consolidated batch tests (original: 2 classes)."""

    @pytest.mark.parametrize(
        "model_type",
        ["attribute", "objectclass"],
        ids=["attribute", "objectclass"],
    )
    def test_batch_conversion(
        self,
        model_type: str,
        conversion_matrix: FlextLdifConversion,
        conversion_constants: ConversionTestConstants,
        oid_quirk: FlextLdifServersOid,
        oud_quirk: FlextLdifServersOud,
    ) -> None:
        """Test batch conversions."""
        items: list[str | GenericFieldsDict | FlextLdifModels.Entry]
        if model_type == "attribute":
            items = [
                conversion_constants.OID_ATTRIBUTE_ORCLGUID,
                conversion_constants.OID_ATTRIBUTE_ORCLDBNAME,
            ]
            TestDeduplicationHelpers.helper_batch_convert_and_assert(
                conversion_matrix,
                oid_quirk,
                oud_quirk,
                "attribute",
                items,
                expected_count=len(items),
            )
        else:
            items = [
                conversion_constants.OID_OBJECTCLASS_ORCLCONTEXT,
                conversion_constants.OID_OBJECTCLASS_ORCLCONTAINER,
            ]
            TestDeduplicationHelpers.helper_batch_convert_and_assert(
                conversion_matrix,
                oid_quirk,
                oud_quirk,
                "objectClass",
                items,
                expected_count=len(items),
            )


class TestErrorHandling:
    """Consolidated error handling tests (original: 5+ classes)."""

    @pytest.mark.parametrize(
        "error_type",
        ["invalid_source", "invalid_target"],
        ids=["invalid_source", "invalid_target"],
    )
    def test_error_handling(
        self,
        error_type: str,
        conversion_matrix: FlextLdifConversion,
        oid_quirk: FlextLdifServersOid,
    ) -> None:
        """Test error handling."""
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(attributes={}),
        )
        # Cast Entry to ConvertibleModel for type checker
        convertible_entry = cast("FlextLdifTypes.ConvertibleModel", entry)
        if error_type == "invalid_source":
            result = conversion_matrix.convert("invalid", oid_quirk, convertible_entry)
        else:
            result = conversion_matrix.convert(oid_quirk, "invalid", convertible_entry)
        assert result.is_failure


class TestConversionMatrixConstants:
    """Test conversion matrix constants."""

    def test_constants_exist(self) -> None:
        """Test that constants are properly defined."""
        assert CONVERSION_TEST_CONSTANTS is not None
        assert hasattr(CONVERSION_TEST_CONSTANTS, "OID_ATTRIBUTE_ORCLGUID")
