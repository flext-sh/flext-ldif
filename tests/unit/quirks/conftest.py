"""Simple test quirk classes - no auto-registration."""

from flext_core import FlextResult

from flext_ldif.servers.base import FlextLdifServersBase


class ObjectClassParseOnlyQuirk(FlextLdifServersBase.Schema):
    """Simple test quirk with parse and to_rfc only - NO AUTO-REGISTRATION."""

    # NOTE: server_type and priority are now @property in base class
    # They are accessed from parent Constants, so no need to define as fields here
    # Remove Field definitions to avoid shadowing parent properties

    def __init_subclass__(cls) -> None:
        """Override to prevent auto-registration."""
        # Do NOT call super() to avoid registration

    def model_post_init(self, _context: object, /) -> None:
        pass

    def can_handle_attribute(self, attr_definition: str) -> bool:
        return True

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        return True

    def can_handle(self, acl_definition: str) -> bool:
        return True

    def parse_attribute(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.ok({})

    def parse_objectclass(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.ok({"name": "test"})

    def parse(self, data: str) -> FlextResult[dict[str, object]]:
        return FlextResult.ok({})

    def write_attribute_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def write_objectclass_to_rfc(self, data: dict[str, object]) -> FlextResult[str]:
        return FlextResult.ok("(test)")


# Create similar quirks for other test cases...
