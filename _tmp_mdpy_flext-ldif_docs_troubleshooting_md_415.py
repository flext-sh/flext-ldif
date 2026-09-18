# from flext-ldif_docs/troubleshooting.md:415
from __future__ import annotations


def correct_railway_chaining(file_path: str) -> p.Result[list]:
    """Demonstrate correct r chaining."""
    api = ldif()

    return (
        # Parse file
        api
        .parse_file(file_path)
        # Validate entries (return original entries on success)
        .flat_map(
            lambda entries: api.validate_entries(entries).map(lambda _: entries)
        )  # Discard bool, return entries
        # Filter persons
        .flat_map(api.filter_persons)
        # Add error context
        .map_error(lambda error: f"Processing chain failed: {error}")
    )


def debug_railway_chain(file_path: str) -> p.Result[list]:
    """Debug railway-oriented programming chains."""
    api = ldif()

    # Step 1: Parse
    u.Cli.print("Step 1: Parsing file...")
    parse_result = api.parse_file(file_path)
    if parse_result.failure:
        u.Cli.print(f"❌ Parse failed: {parse_result.error}")
        return parse_result

    entries = parse_result.unwrap()
    u.Cli.print(f"✓ Parsed {len(entries)} entries")

    # Step 2: Validate
    u.Cli.print("Step 2: Validating entries...")
    validation_result = api.validate_entries(entries)
    if validation_result.failure:
        u.Cli.print(f"❌ Validation failed: {validation_result.error}")
        return r[list].fail(validation_result.error)

    u.Cli.print("✓ Validation passed")

    # Step 3: Filter
    u.Cli.print("Step 3: Filtering persons...")
    filter_result = api.filter_persons(entries)
    if filter_result.failure:
        u.Cli.print(f"❌ Filtering failed: {filter_result.error}")
        return filter_result

    persons = filter_result.unwrap()
    u.Cli.print(f"✓ Found {len(persons)} person entries")

    return r[list].ok(persons)```
## Diagnostic Tools

### Health Check Utility

