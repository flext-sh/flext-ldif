"""FLEXT LDIF Entries Coordinator.

Unified entry management coordinator using flext-core paradigm with nested operation classes.
"""

from pydantic import ConfigDict

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif.entry import FlextLdifEntryBuilder
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks import FlextLdifEntryQuirks


class FlextLdifEntries(FlextService[dict[str, object]]):
    """Unified entry management coordinator following flext-core single class paradigm."""

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        validate_assignment=False,
        extra="allow",
    )

    class Builder:
        """Nested class for entry building operations."""

        def __init__(self, parent: "FlextLdifEntries") -> None:
            """Initialize entry builder with parent coordinator reference."""
            self._parent = parent
            self._builder = FlextLdifEntryBuilder()
            self._logger = FlextLogger(__name__)

        def build_person(
            self,
            cn: str,
            sn: str,
            base_dn: str,
            attributes: dict[str, list[str]] | None = None,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Build person entry."""
            return self._builder.build_person_entry(
                cn, sn, base_dn, additional_attrs=attributes
            )

        def build_group(
            self,
            cn: str,
            base_dn: str,
            members: list[str] | None = None,
            attributes: dict[str, list[str]] | None = None,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Build group entry."""
            return self._builder.build_group_entry(
                cn, base_dn, members, additional_attrs=attributes
            )

        def build_organizational_unit(
            self, ou: str, base_dn: str, attributes: dict[str, list[str]] | None = None
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Build organizational unit entry."""
            return self._builder.build_organizational_unit_entry(
                ou, base_dn, additional_attrs=attributes
            )

        def build_from_json(
            self, json_data: str
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Build entries from JSON data."""
            return self._builder.build_entries_from_json(json_data)

    class Validator:
        """Nested class for entry validation operations."""

        def __init__(self, parent: "FlextLdifEntries") -> None:
            """Initialize entry validator with parent coordinator reference."""
            self._parent = parent
            self._logger = FlextLogger(__name__)

        def validate_dn(self, dn: str) -> FlextResult[bool]:
            """Validate distinguished name format."""
            try:
                dn_result: FlextResult[FlextLdifModels.DistinguishedName] = (
                    FlextLdifModels.DistinguishedName.create(dn)  # type: ignore[assignment]
                )
                if dn_result.is_success:
                    return FlextResult[bool].ok(True)
                return FlextResult[bool].fail(dn_result.error or "Invalid DN")
            except Exception as e:
                return FlextResult[bool].fail(f"DN validation failed: {e}")

        def validate_attributes(
            self, attributes: dict[str, list[str]]
        ) -> FlextResult[bool]:
            """Validate entry attributes."""
            if not attributes:
                return FlextResult[bool].fail("Attributes cannot be empty")

            for attr_name, attr_values in attributes.items():
                if not attr_name or not attr_name.strip():
                    return FlextResult[bool].fail("Attribute name cannot be empty")
                if not attr_values or not any(attr_values):
                    return FlextResult[bool].fail(
                        f"Attribute '{attr_name}' has no values"
                    )

            return FlextResult[bool].ok(True)

        def validate_objectclasses(self, objectclasses: list[str]) -> FlextResult[bool]:
            """Validate objectclass list."""
            if not objectclasses:
                return FlextResult[bool].fail("ObjectClass list cannot be empty")

            required_classes = {"top"}
            missing = required_classes - set(objectclasses)
            if missing:
                return FlextResult[bool].fail(
                    f"Missing required objectclasses: {missing}"
                )

            return FlextResult[bool].ok(True)

        def validate_entry(self, entry: FlextLdifModels.Entry) -> FlextResult[bool]:
            """Validate complete entry."""
            return entry.validate_business_rules()

    class Transformer:
        """Nested class for entry transformation operations."""

        def __init__(self, parent: "FlextLdifEntries") -> None:
            """Initialize entry transformer with parent coordinator reference."""
            self._parent = parent
            self._entry_quirks = FlextLdifEntryQuirks()
            self._logger = FlextLogger(__name__)

        def normalize_attributes(
            self, entry: FlextLdifModels.Entry
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Normalize entry attributes."""
            try:
                normalized_attrs = {}
                for attr_name, attr_values in entry.attributes.data.items():
                    normalized_name = attr_name.lower()
                    normalized_attrs[normalized_name] = attr_values

                return FlextLdifModels.Entry.create(
                    dn=entry.dn.value,  # type: ignore[misc]
                    attributes=normalized_attrs,  # type: ignore[misc]
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Normalization failed: {e}"
                )

        def adapt_for_server(
            self, entry: FlextLdifModels.Entry, server_type: str
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Adapt entry for specific server type."""
            return self._entry_quirks.adapt_entry(entry, server_type)

        def convert_to_json(
            self, entry: FlextLdifModels.Entry
        ) -> FlextResult[dict[str, object]]:
            """Convert entry to JSON representation."""
            try:
                entry_dict: dict[str, object] = {
                    "dn": entry.dn.value,
                    "attributes": entry.attributes.data,
                }
                return FlextResult[dict[str, object]].ok(entry_dict)
            except Exception as e:
                return FlextResult[dict[str, object]].fail(
                    f"JSON conversion failed: {e}"
                )

    def __init__(self) -> None:
        """Initialize entry coordinator with nested operation classes."""
        super().__init__()
        self._logger = FlextLogger(__name__)

        self.builder = self.Builder(self)
        self.validator = self.Validator(self)
        self.transformer = self.Transformer(self)

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute health check - required by FlextService."""
        return FlextResult[dict[str, object]].ok({
            "status": "healthy",
            "service": "FlextLdifEntries",
            "operations": ["builder", "validator", "transformer"],
        })

    async def execute_async(self) -> FlextResult[dict[str, object]]:
        """Execute health check - required by FlextService."""
        return FlextResult[dict[str, object]].ok({
            "status": "healthy",
            "service": "FlextLdifEntries",
            "operations": ["builder", "validator", "transformer"],
        })


__all__ = ["FlextLdifEntries"]
