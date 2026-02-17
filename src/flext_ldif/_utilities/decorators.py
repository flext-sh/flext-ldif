"""Standardized decorators for quirk metadata assignment across all servers."""

from __future__ import annotations

from datetime import UTC, datetime
from functools import wraps

from flext_core import FlextLogger, r

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif._shared import normalize_server_type
from flext_ldif.models import m
from flext_ldif.typings import t

logger = FlextLogger(__name__)


def generate_iso_timestamp() -> str:
    """Generate ISO 8601 timestamp string."""
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class FlextLdifUtilitiesDecorators:
    """Decorators for LDIF server quirk metadata assignment."""

    @staticmethod
    def _get_server_type_from_class(
        obj: (
            m.Ldif.Entry
            | m.Ldif.SchemaAttribute
            | m.Ldif.SchemaObjectClass
            | m.Ldif.Acl
            | str
            | float
        ),
    ) -> str | None:
        """Extract SERVER_TYPE from class Constants via MRO traversal."""
        if not hasattr(obj, "__class__"):
            return None

        for cls in obj.__class__.__mro__:
            if hasattr(cls, "Constants") and hasattr(cls.Constants, "SERVER_TYPE"):
                return str(cls.Constants.SERVER_TYPE)

        return None

    @staticmethod
    def _attach_metadata_if_present(
        result_value: (
            m.Ldif.Entry
            | m.Ldif.SchemaAttribute
            | m.Ldif.SchemaObjectClass
            | m.Ldif.Acl
            | str
            | float
            | None
        ),
        quirk_type: str,
        server_type: str | None,
    ) -> None:
        """Attach metadata to result value if it has metadata attribute."""
        # Only attach metadata to models with metadata attribute
        if not (
            getattr(result_value, "metadata", None) is not None
            or hasattr(result_value, "metadata")
        ):
            return

        # Create metadata with extensions
        extensions_dict = {
            "server_type": server_type,
            "parsed_timestamp": generate_iso_timestamp(),
        }
        # Normalize quirk_type if provided, otherwise None
        # normalize_server_type validates and returns a valid ServerTypeLiteral string
        normalized_quirk_type: str | None = (
            normalize_server_type(quirk_type) if quirk_type else None
        )
        metadata = FlextLdifModelsDomains.QuirkMetadata.create_for(
            quirk_type=normalized_quirk_type,
            extensions=FlextLdifModelsMetadata.DynamicMetadata.from_dict(
                extensions_dict
            ),
        )

        # Attach metadata by checking if object is a model instance with metadata
        # Use runtime type check instead of protocol isinstance to avoid mypy issues
        if (
            hasattr(result_value, "metadata")
            and hasattr(type(result_value), "model_fields")  # Check class, not instance
            and isinstance(
                result_value,
                (
                    m.Ldif.Entry,
                    m.Ldif.SchemaAttribute,
                    m.Ldif.SchemaObjectClass,
                    m.Ldif.Acl,
                ),
            )
        ):
            # This is a Pydantic model with metadata field
            # Use model_copy to create updated instance (respects validate_assignment)
            try:
                updated_model = result_value.model_copy(update={"metadata": metadata})
                # Replace the original reference if possible
                if hasattr(result_value, "__dict__"):
                    result_value.__dict__.update(updated_model.__dict__)
                elif hasattr(result_value, "__slots__"):
                    # For slotted classes, we can't easily update in-place
                    # This is a limitation we'll work around by not updating slotted models
                    pass
            except Exception as e:
                # If model_copy fails, skip metadata attachment
                # This is safe - metadata attachment is optional for frozen models
                logger.debug("Failed to attach metadata", error=str(e))

    @staticmethod
    def attach_parse_metadata(
        quirk_type: str,
    ) -> t.Ldif.Decorators.ParseMethodDecorator:
        """Decorator to automatically attach metadata to parse method results."""

        def decorator(
            func: t.Ldif.Decorators.ParseMethod,
        ) -> t.Ldif.Decorators.ParseMethod:
            """Wrapper function for parse methods."""

            @wraps(func)
            def wrapper(
                self: object,
                arg: str,
            ) -> r[object]:
                """Call original function and attach metadata to result."""
                result = func(self, arg)

                # If result is successful, attach metadata using helper methods
                if result.is_success:
                    unwrapped = result.value
                    # Type narrowing: self is a protocol, but we need concrete types
                    # Check if unwrapped is one of the supported types
                    if isinstance(
                        unwrapped,
                        (
                            m.Ldif.Entry,
                            m.Ldif.SchemaAttribute,
                            m.Ldif.SchemaObjectClass,
                            m.Ldif.Acl,
                        ),
                    ):
                        server_type = (
                            FlextLdifUtilitiesDecorators._get_server_type_from_class(
                                unwrapped,
                            )
                        )
                        FlextLdifUtilitiesDecorators._attach_metadata_if_present(
                            unwrapped,
                            quirk_type,
                            server_type,
                        )

                return result

            # Type narrowing: wrapper is compatible with ParseMethod type
            return wrapper

        return decorator

    @staticmethod
    def attach_write_metadata(
        _quirk_type: str,
    ) -> t.Ldif.Decorators.WriteMethodDecorator:
        """Decorator to automatically attach metadata to write method results."""

        def decorator(
            func: t.Ldif.Decorators.WriteMethod,
        ) -> t.Ldif.Decorators.WriteMethod:
            """Wrapper function for write methods."""

            @wraps(func)
            def wrapper(
                self: t.Ldif.Decorators.ProtocolType,
                arg: t.Ldif.Decorators.WriteMethodArg,
            ) -> object:
                """Call original function - write methods don't modify inputs."""
                # Write methods typically return strings, not models
                # So metadata attachment would be on the input model
                return func(self, arg)

            # Type narrowing: wrapper is compatible with WriteMethod type
            return wrapper

        return decorator

    @staticmethod
    def _safe_operation(
        operation_name: str,
    ) -> t.Ldif.Decorators.SafeMethodDecorator:
        """Generic decorator to wrap methods with standardized error handling."""

        def decorator(
            func: t.Ldif.Decorators.SafeMethod,
        ) -> t.Ldif.Decorators.SafeMethod:
            """Wrapper that adds error handling."""

            @wraps(func)
            def wrapper(
                self: t.Ldif.Decorators.ProtocolType,
                arg: t.Ldif.Decorators.ParseMethodArg,
            ) -> object:
                """Execute function with automatic error handling."""
                try:
                    return func(self, arg)
                except BaseException as e:
                    error_msg = f"{operation_name} failed: {e}"
                    logger.exception(
                        error_msg,
                    )  # Log error with message (no traceback for KeyboardInterrupt)
                    return r[str].fail(error_msg)

            # Type narrowing: wrapper is compatible with SafeMethod type
            return wrapper

        return decorator

    @staticmethod
    def safe_parse(
        operation_name: str,
    ) -> t.Ldif.Decorators.SafeMethodDecorator:
        """Decorator to wrap parse methods with standardized error handling."""
        return FlextLdifUtilitiesDecorators._safe_operation(operation_name)

    @staticmethod
    def safe_write(
        operation_name: str,
    ) -> t.Ldif.Decorators.SafeMethodDecorator:
        """Decorator to wrap write methods with standardized error handling."""
        return FlextLdifUtilitiesDecorators._safe_operation(operation_name)


# Use FlextLdifUtilitiesDecorators directly - no aliases needed
# Access via: FlextLdifUtilitiesDecorators.attach_parse_metadata(...)

__all__ = [
    "FlextLdifUtilitiesDecorators",
]
