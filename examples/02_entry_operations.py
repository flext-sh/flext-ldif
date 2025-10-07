"""Example 2: Entry Building and Operations.

Demonstrates FlextLdif entry-related functionality:
- Building entries with direct API methods (person, group, OU, custom)
- Filtering entries by objectClass
- Using Entry models
- Converting entries to/from JSON and dict formats with batch methods

All functionality accessed through FlextLdif facade using direct methods.
No manual instantiation of builder classes required.
"""

from __future__ import annotations

from flext_ldif import FlextLdif


def build_person_entries() -> None:
    """Build person entries using direct API method."""
    api = FlextLdif.get_instance()

    # Build a person entry directly (no builder instantiation needed)
    person_result = api.build_person_entry(
        cn="Alice Johnson",
        sn="Johnson",
        base_dn="ou=People,dc=example,dc=com",
        mail="alice.johnson@example.com",
        telephone_number="+1-555-0101",
    )

    if person_result.is_success:
        person_entry = person_result.unwrap()
        _ = person_entry.dn
        _ = person_entry.attributes


def build_group_entries() -> None:
    """Build group entries using direct API method."""
    api = FlextLdif.get_instance()

    # Build a group entry directly (no builder instantiation needed)
    group_result = api.build_group_entry(
        cn="Admins",
        base_dn="ou=Groups,dc=example,dc=com",
        members=[
            "cn=Alice Johnson,ou=People,dc=example,dc=com",
            "cn=Bob Williams,ou=People,dc=example,dc=com",
        ],
        description="System REDACTED_LDAP_BIND_PASSWORDistrators group",
    )

    if group_result.is_success:
        group_entry = group_result.unwrap()
        _ = group_entry.dn
        _ = group_entry.attributes.get("member", [])


def build_organizational_unit() -> None:
    """Build organizational unit entries using direct API method."""
    api = FlextLdif.get_instance()

    # Build OU entry directly (no builder instantiation needed)
    ou_result = api.build_organizational_unit(
        ou="People",
        base_dn="dc=example,dc=com",
        description="Container for person entries",
    )

    if ou_result.is_success:
        ou_entry = ou_result.unwrap()
        _ = ou_entry.dn


def build_custom_entries() -> None:
    """Build custom entries using direct API method."""
    api = FlextLdif.get_instance()

    # Build custom entry directly (no builder instantiation needed)
    custom_result = api.build_custom_entry(
        dn="cn=schema,cn=config",
        attributes={
            "objectClass": ["top", "ldapSubentry", "subschema"],
            "cn": ["schema"],
            "description": ["Custom schema entry"],
        },
    )

    if custom_result.is_success:
        custom_entry = custom_result.unwrap()
        _ = custom_entry.attributes


def filter_entries_by_objectclass() -> None:
    """Filter entries using objectClass attribute."""
    api = FlextLdif.get_instance()

    ldif_content = """dn: cn=Alice,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: Alice
sn: Johnson

dn: cn=Admins,ou=Groups,dc=example,dc=com
objectClass: groupOfNames
cn: Admins
member: cn=Alice,ou=People,dc=example,dc=com

dn: cn=Bob,ou=People,dc=example,dc=com
objectClass: person
cn: Bob
sn: Williams
"""

    parse_result = api.parse(ldif_content)

    if parse_result.is_failure:
        return

    entries = parse_result.unwrap()

    # Filter by objectClass
    person_result = api.filter_by_objectclass(entries, "person")

    if person_result.is_success:
        person_entries = person_result.unwrap()
        # Only person entries returned
        _ = len(person_entries)


def filter_person_entries() -> None:
    """Use convenience method to filter person entries."""
    api = FlextLdif.get_instance()

    ldif_content = """dn: cn=Alice,ou=People,dc=example,dc=com
objectClass: person
cn: Alice
sn: Johnson

dn: cn=Test Group,ou=Groups,dc=example,dc=com
objectClass: groupOfNames
cn: Test Group
member: cn=Alice,ou=People,dc=example,dc=com
"""

    parse_result = api.parse(ldif_content)

    if parse_result.is_failure:
        return

    entries = parse_result.unwrap()

    # Filter persons using convenience method
    person_result = api.filter_persons(entries)

    if person_result.is_success:
        persons = person_result.unwrap()
        _ = len(persons)


def work_with_entry_models() -> None:
    """Create and manipulate entries using models."""
    api = FlextLdif.get_instance()

    # Create entry using Entry model (accessed via api.models)
    entry = api.models.Entry(
        dn="cn=Direct Model,ou=People,dc=example,dc=com",
        attributes={
            "objectClass": ["person"],
            "cn": ["Direct Model"],
            "sn": ["Model"],
        },
    )

    # Entry can be used in API operations
    write_result = api.write([entry])

    if write_result.is_success:
        ldif_string = write_result.unwrap()
        _ = len(ldif_string)


def convert_entries_json_dict() -> None:
    """Convert entries to/from JSON and dict formats using batch methods."""
    api = FlextLdif.get_instance()

    # Build some entries using direct API method
    person_result = api.build_person_entry(
        cn="Convert Test",
        sn="Test",
        base_dn="ou=People,dc=example,dc=com",
    )

    if person_result.is_failure:
        return

    person_entry = person_result.unwrap()

    # Convert entry to dict using direct API method
    dict_result = api.entry_to_dict(person_entry)

    if dict_result.is_success:
        entry_dict = dict_result.unwrap()
        _ = entry_dict["dn"]
        _ = entry_dict["attributes"]

    # Convert entries to JSON using direct API method
    json_result = api.entries_to_json([person_entry])

    if json_result.is_success:
        json_string = json_result.unwrap()
        _ = len(json_string)

    # Convert from JSON using direct API method
    from_json_result = api.json_to_entries(json_string)

    if from_json_result.is_success:
        entries_from_json = from_json_result.unwrap()
        _ = len(entries_from_json)

    # Batch convert entries to dicts (NEW - eliminates manual loops!)
    entry_dicts = api.entries_to_dicts([person_entry])
    _ = len(entry_dicts)

    # Batch convert dicts to entries (NEW - eliminates manual loops!)
    dict_data = [
        {
            "dn": "cn=FromDict,ou=People,dc=example,dc=com",
            "objectClass": ["person"],
            "cn": ["FromDict"],
            "sn": ["Dict"],
        }
    ]
    entries_from_dicts = api.dicts_to_entries(dict_data)
    _ = len(entries_from_dicts)
