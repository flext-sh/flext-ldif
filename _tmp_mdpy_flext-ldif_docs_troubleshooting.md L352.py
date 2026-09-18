# from flext-ldif/docs/troubleshooting.md:352
from __future__ import annotations


def debug_container_issues() -> None:
    """Debug FlextContainer registration issues."""
    from flext_ldif import ldif

    container = FlextContainer.get_global()

    # Check container status
    u.Cli.print(f"Container type: {type(container)}")

    # Try registration with error handling
    api = ldif()
    registration_result = container.bind("ldif_api", api)

    if registration_result.success:
        u.Cli.print("✓ Service registered successfully")

        # Test retrieval
        retrieval_result = container.resolve("ldif_api")
        if retrieval_result.success:
            retrieved_api = retrieval_result.unwrap()
            u.Cli.print(f"✓ Service retrieved: {type(retrieved_api)}")
        else:
            u.Cli.print(f"✗ Retrieval failed: {retrieval_result.error}")
    else:
        u.Cli.print(f"✗ Registration failed: {registration_result.error}")


def safe_service_registration() -> p.Result[ldif]:
    """Safely register LDIF service with error handling."""
    container = FlextContainer.get_global()

    # Create API instance
    api = ldif()

    # Attempt registration
    registration_result = container.bind("ldif_api", api)
    if registration_result.failure:
        return r[ldif].fail(f"Failed to register LDIF API: {registration_result.error}")

    # Verify registration by retrieving
    retrieval_result = container.resolve("ldif_api")
    if retrieval_result.failure:
        return r[ldif].fail(f"Failed to retrieve LDIF API: {retrieval_result.error}")

    return r[ldif].ok(retrieval_result.unwrap())```
#### r Chain Errors

**Symptom**: Railway-oriented programming chains fail unexpectedly.

