"""Simple test quirk classes - no auto-registration."""

from flext_core import FlextResult
from pydantic import Field

from flext_ldif.servers.base import FlextLdifServersBase


class ObjectClassParseOnlyQuirk(FlextLdifServersBase.Schema):
    """Simple test quirk with parse and to_rfc only - NO AUTO-REGISTRATION."""

    server_type: str = Field(default="test_parse_only_no_register")
    priority: int = Field(default=100)

    def __init_subclass__(cls) -> None:
        """Override to prevent auto-registration."""
        # Do NOT call super() to avoid registration

    def model_post_init(self, _context: object, /) -> None:
        pass

    def can_handle_attribute(self, attr_definition: str) -> bool:
        return True

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        return True

    def can_handle_acl(self, acl_definition: str) -> bool:
        return True

    def parse_attribute(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.ok({})

    def parse_objectclass(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.ok({"name": "test"})

    def parse_acl(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.ok({})

    def convert_attribute_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_objectclass_to_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_attribute_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def convert_objectclass_from_rfc(
        self, data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        return FlextResult.ok(data)

    def write_attribute_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def write_objectclass_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.ok("(test)")


# Create similar quirks for other test cases...
