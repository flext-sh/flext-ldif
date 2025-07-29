#!/usr/bin/env python3
"""Example of running FLEXT-LDIF examples with Docker OpenLDAP container.

This script automatically starts an OpenLDAP container, populates it with test data,
exports LDIF, and demonstrates FLEXT-LDIF processing capabilities.
Perfect for testing and demonstration without needing a manual LDAP setup.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Add src to path for local testing
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))


def start_openldap_container() -> bool:
    """Start OpenLDAP container for LDIF testing."""
    try:
        # Stop any existing container
        subprocess.run(
            ["docker", "stop", "flext-ldif-demo", "2>/dev/null"],
            check=False,
            shell=True,
        )
        subprocess.run(
            ["docker", "rm", "flext-ldif-demo", "2>/dev/null"],
            check=False,
            shell=True,
        )

        print("🐳 Starting OpenLDAP container for FLEXT-LDIF demo...")
        
        # Start new container
        subprocess.run([
            "docker", "run", "-d",
            "--name", "flext-ldif-demo",
            "-p", "3391:389",
            "-e", "LDAP_ORGANISATION=FLEXT LDIF Demo Org",
            "-e", "LDAP_DOMAIN=flext-ldif.demo",
            "-e", "LDAP_ADMIN_PASSWORD=admin123",
            "-e", "LDAP_CONFIG_PASSWORD=config123",
            "-e", "LDAP_READONLY_USER=false",
            "-e", "LDAP_RFC2307BIS_SCHEMA=true",
            "-e", "LDAP_BACKEND=mdb",
            "-e", "LDAP_TLS=false",
            "-e", "LDAP_REMOVE_CONFIG_AFTER_SETUP=true",
            "osixia/openldap:1.5.0"
        ], check=True)

        # Wait for container to be ready
        print("⏳ Waiting for OpenLDAP to be ready...")
        for attempt in range(30):
            try:
                result = subprocess.run([
                    "docker", "exec", "flext-ldif-demo",
                    "ldapsearch", "-x", 
                    "-H", "ldap://localhost:389",
                    "-D", "cn=admin,dc=flext-ldif,dc=demo",
                    "-w", "admin123",
                    "-b", "dc=flext-ldif,dc=demo",
                    "-s", "base",
                    "(objectClass=*)"
                ], capture_output=True, check=True)
                
                if result.returncode == 0:
                    print("✅ OpenLDAP container is ready!")
                    return True
                    
            except subprocess.CalledProcessError:
                time.sleep(1)
                
        print("❌ OpenLDAP container failed to start properly")
        return False
        
    except Exception as e:
        print(f"❌ Failed to start OpenLDAP container: {e}")
        return False


def populate_test_data() -> bool:
    """Populate OpenLDAP container with comprehensive test data."""
    try:
        print("📊 Populating OpenLDAP with comprehensive test data...")
        
        test_ldif = """
# Base organization
dn: dc=flext-ldif,dc=demo
objectClass: dcObject
objectClass: organization
dc: flext-ldif
o: FLEXT LDIF Demo Organization

# Organizational units
dn: ou=people,dc=flext-ldif,dc=demo
objectClass: organizationalUnit
ou: people
description: People in the organization

dn: ou=groups,dc=flext-ldif,dc=demo
objectClass: organizationalUnit
ou: groups
description: Groups in the organization

dn: ou=departments,dc=flext-ldif,dc=demo
objectClass: organizationalUnit
ou: departments
description: Company departments

# Departments
dn: ou=Engineering,ou=departments,dc=flext-ldif,dc=demo
objectClass: organizationalUnit
ou: Engineering
description: Software Engineering Department

dn: ou=Marketing,ou=departments,dc=flext-ldif,dc=demo
objectClass: organizationalUnit
ou: Marketing
description: Marketing Department

dn: ou=Sales,ou=departments,dc=flext-ldif,dc=demo
objectClass: organizationalUnit
ou: Sales
description: Sales Department

# Engineering team members
dn: uid=alice.johnson,ou=people,dc=flext-ldif,dc=demo
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: alice.johnson
cn: Alice Johnson
sn: Johnson
givenName: Alice
displayName: Alice Johnson
mail: alice.johnson@flext-ldif.demo
telephoneNumber: +1 555 100 1001
employeeNumber: 10001
departmentNumber: Engineering
title: Senior Software Engineer
description: Full-stack developer specializing in Python and React

dn: uid=bob.smith,ou=people,dc=flext-ldif,dc=demo
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: bob.smith
cn: Bob Smith
sn: Smith
givenName: Bob
displayName: Bob Smith
mail: bob.smith@flext-ldif.demo
telephoneNumber: +1 555 100 1002
employeeNumber: 10002
departmentNumber: Engineering
title: DevOps Engineer
description: Infrastructure and deployment automation specialist

dn: uid=carol.davis,ou=people,dc=flext-ldif,dc=demo
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: carol.davis
cn: Carol Davis
sn: Davis
givenName: Carol
displayName: Carol Davis
mail: carol.davis@flext-ldif.demo
telephoneNumber: +1 555 100 1003
employeeNumber: 10003
departmentNumber: Engineering
title: Engineering Manager
description: Engineering team lead with 10+ years experience

# Marketing team members
dn: uid=david.wilson,ou=people,dc=flext-ldif,dc=demo
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: david.wilson
cn: David Wilson
sn: Wilson
givenName: David
displayName: David Wilson
mail: david.wilson@flext-ldif.demo
telephoneNumber: +1 555 200 2001
employeeNumber: 20001
departmentNumber: Marketing
title: Marketing Manager
description: Digital marketing and brand strategy specialist

dn: uid=eva.brown,ou=people,dc=flext-ldif,dc=demo
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: eva.brown
cn: Eva Brown
sn: Brown
givenName: Eva
displayName: Eva Brown
mail: eva.brown@flext-ldif.demo
telephoneNumber: +1 555 200 2002
employeeNumber: 20002
departmentNumber: Marketing
title: Content Creator
description: Social media and content marketing specialist

# Sales team members
dn: uid=frank.miller,ou=people,dc=flext-ldif,dc=demo
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: frank.miller
cn: Frank Miller
sn: Miller
givenName: Frank
displayName: Frank Miller
mail: frank.miller@flext-ldif.demo
telephoneNumber: +1 555 300 3001
employeeNumber: 30001
departmentNumber: Sales
title: Sales Representative
description: Enterprise sales specialist

dn: uid=grace.taylor,ou=people,dc=flext-ldif,dc=demo
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: grace.taylor
cn: Grace Taylor
sn: Taylor
givenName: Grace
displayName: Grace Taylor
mail: grace.taylor@flext-ldif.demo
telephoneNumber: +1 555 300 3002
employeeNumber: 30002
departmentNumber: Sales
title: Sales Manager
description: Regional sales manager with proven track record

# Groups
dn: cn=Engineering Team,ou=groups,dc=flext-ldif,dc=demo
objectClass: groupOfNames
objectClass: top
cn: Engineering Team
description: All engineering department members
member: uid=alice.johnson,ou=people,dc=flext-ldif,dc=demo
member: uid=bob.smith,ou=people,dc=flext-ldif,dc=demo
member: uid=carol.davis,ou=people,dc=flext-ldif,dc=demo

dn: cn=Marketing Team,ou=groups,dc=flext-ldif,dc=demo
objectClass: groupOfNames
objectClass: top
cn: Marketing Team
description: All marketing department members
member: uid=david.wilson,ou=people,dc=flext-ldif,dc=demo
member: uid=eva.brown,ou=people,dc=flext-ldif,dc=demo

dn: cn=Sales Team,ou=groups,dc=flext-ldif,dc=demo
objectClass: groupOfNames
objectClass: top
cn: Sales Team
description: All sales department members
member: uid=frank.miller,ou=people,dc=flext-ldif,dc=demo
member: uid=grace.taylor,ou=people,dc=flext-ldif,dc=demo

dn: cn=Managers,ou=groups,dc=flext-ldif,dc=demo
objectClass: groupOfNames
objectClass: top
cn: Managers
description: All department managers
member: uid=carol.davis,ou=people,dc=flext-ldif,dc=demo
member: uid=david.wilson,ou=people,dc=flext-ldif,dc=demo
member: uid=grace.taylor,ou=people,dc=flext-ldif,dc=demo

dn: cn=All Employees,ou=groups,dc=flext-ldif,dc=demo
objectClass: groupOfNames
objectClass: top
cn: All Employees
description: All company employees
member: uid=alice.johnson,ou=people,dc=flext-ldif,dc=demo
member: uid=bob.smith,ou=people,dc=flext-ldif,dc=demo
member: uid=carol.davis,ou=people,dc=flext-ldif,dc=demo
member: uid=david.wilson,ou=people,dc=flext-ldif,dc=demo
member: uid=eva.brown,ou=people,dc=flext-ldif,dc=demo
member: uid=frank.miller,ou=people,dc=flext-ldif,dc=demo
member: uid=grace.taylor,ou=people,dc=flext-ldif,dc=demo
"""

        # Write LDIF to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ldif', delete=False) as f:
            f.write(test_ldif)
            temp_file = f.name

        # Copy LDIF to container
        subprocess.run([
            "docker", "cp", temp_file, "flext-ldif-demo:/tmp/test_data.ldif"
        ], check=True)

        # Import LDIF data
        result = subprocess.run([
            "docker", "exec", "flext-ldif-demo",
            "ldapadd", "-x",
            "-H", "ldap://localhost:389",
            "-D", "cn=admin,dc=flext-ldif,dc=demo",
            "-w", "admin123",
            "-f", "/tmp/test_data.ldif"
        ], capture_output=True)

        # Clean up temp file
        os.unlink(temp_file)

        if result.returncode == 0:
            print("✅ Test data populated successfully")
            return True
        else:
            print(f"⚠️  Failed to populate test data: {result.stderr.decode()}")
            return False

    except Exception as e:
        print(f"⚠️  Error populating test data: {e}")
        return False


def export_ldif_from_container() -> str:
    """Export LDIF data from the container."""
    try:
        print("📤 Exporting LDIF data from container...")
        
        result = subprocess.run([
            "docker", "exec", "flext-ldif-demo",
            "ldapsearch", "-x",
            "-H", "ldap://localhost:389",
            "-D", "cn=admin,dc=flext-ldif,dc=demo",
            "-w", "admin123",
            "-b", "dc=flext-ldif,dc=demo",
            "-s", "sub",
            "(objectClass=*)",
            "-LLL"  # LDIF format without comments
        ], capture_output=True, check=True)
        
        ldif_data = result.stdout.decode()
        print(f"✅ Exported {len(ldif_data.splitlines())} lines of LDIF data")
        return ldif_data
        
    except Exception as e:
        print(f"❌ Failed to export LDIF data: {e}")
        return ""


def stop_openldap_container() -> None:
    """Stop and remove OpenLDAP container."""
    try:
        print("🛑 Stopping OpenLDAP container...")
        subprocess.run(["docker", "stop", "flext-ldif-demo"], check=False)
        subprocess.run(["docker", "rm", "flext-ldif-demo"], check=False)
        print("✅ Container stopped and removed")
    except Exception as e:
        print(f"⚠️  Error stopping container: {e}")


async def run_flext_ldif_examples(ldif_data: str) -> None:
    """Run FLEXT-LDIF examples against real OpenLDAP data."""
    from flext_ldif import (
        FlextLdifParser,
        FlextLdifProcessor,
        FlextLdifValidator,
        parse_ldif,
        validate_ldif,
        write_ldif,
    )
    from flext_ldif.domain.specifications import (
        FlextLdifPersonSpecification,
        FlextLdifGroupSpecification,
        FlextLdifOrganizationalUnitSpecification,
    )
    
    print("\n🚀 Running FLEXT-LDIF Examples with Real OpenLDAP Data")
    print("=" * 60)
    
    # Example 1: Simple parsing
    print("\n📋 Example 1: Simple LDIF Parsing")
    print("-" * 40)
    
    entries = parse_ldif(ldif_data)
    print(f"✅ Parsed {len(entries)} entries from OpenLDAP")
    
    # Show some entry details
    for i, entry in enumerate(entries[:3]):
        print(f"   Entry {i+1}: {entry.dn}")
        if entry.has_attribute('cn'):
            print(f"      CN: {entry.get_single_attribute('cn')}")
        if entry.has_attribute('objectClass'):
            print(f"      Object Classes: {', '.join(entry.get_attribute_values('objectClass'))}")
    
    if len(entries) > 3:
        print(f"   ... and {len(entries) - 3} more entries")
    
    # Example 2: Advanced processing
    print("\n🔧 Example 2: Advanced Processing with FlextLdifProcessor")
    print("-" * 55)
    
    processor = FlextLdifProcessor()
    result = processor.parse_ldif_content(ldif_data)
    
    if result.is_success:
        print(f"✅ FlextLdifProcessor parsed {len(result.data)} entries")
        
        # Filter person entries
        person_result = processor.filter_person_entries(result.data)
        if person_result.is_success:
            print(f"✅ Found {len(person_result.data)} person entries")
            
            # Show person details
            for person in person_result.data[:3]:
                if person.has_attribute('cn'):
                    name = person.get_single_attribute('cn')
                    title = person.get_single_attribute('title') or 'N/A'
                    dept = person.get_single_attribute('departmentNumber') or 'N/A'
                    print(f"   👤 {name} - {title} ({dept})")
        
        # Filter valid entries
        valid_result = processor.filter_valid_entries(result.data)
        if valid_result.is_success:
            print(f"✅ Found {len(valid_result.data)} valid entries")
    
    # Example 3: Domain specifications
    print("\n🎯 Example 3: Domain Specifications")
    print("-" * 38)
    
    person_spec = FlextLdifPersonSpecification()
    group_spec = FlextLdifGroupSpecification()
    ou_spec = FlextLdifOrganizationalUnitSpecification()
    
    person_count = sum(1 for entry in entries if person_spec.is_satisfied_by(entry))
    group_count = sum(1 for entry in entries if group_spec.is_satisfied_by(entry))
    ou_count = sum(1 for entry in entries if ou_spec.is_satisfied_by(entry))
    
    print(f"✅ Domain specifications results:")
    print(f"   👥 Person entries: {person_count}")
    print(f"   🏢 Group entries: {group_count}")
    print(f"   📁 Organizational Unit entries: {ou_count}")
    print(f"   📊 Total entries: {len(entries)}")
    
    # Example 4: Validation
    print("\n✅ Example 4: LDIF Validation")
    print("-" * 32)
    
    is_valid = validate_ldif(ldif_data)
    print(f"✅ LDIF validation result: {'VALID' if is_valid else 'INVALID'}")
    
    validator = FlextLdifValidator()
    validation_result = validator.validate_entries(entries)
    if validation_result.is_success:
        print("✅ All entries passed detailed validation")
    else:
        print(f"⚠️  Validation issues: {validation_result.error}")
    
    # Example 5: Write LDIF
    print("\n📝 Example 5: Writing LDIF")
    print("-" * 28)
    
    # Filter person entries for writing
    person_entries = [entry for entry in entries if person_spec.is_satisfied_by(entry)]
    
    if person_entries:
        output_ldif = write_ldif(person_entries)
        
        # Save to file
        output_file = Path("flext_ldif_demo_output.ldif")
        output_file.write_text(output_ldif)
        
        print(f"✅ Wrote {len(person_entries)} person entries to {output_file}")
        print(f"✅ Output file size: {len(output_ldif)} bytes")
        
        # Show a sample of the output
        print("\n📄 Sample output (first 5 lines):")
        for line in output_ldif.split('\n')[:5]:
            if line.strip():
                print(f"   {line}")
        print("   ...")
    
    # Example 6: Performance measurement
    print("\n⚡ Example 6: Performance Measurement")
    print("-" * 38)
    
    import time
    
    # Measure parsing performance
    start_time = time.time()
    for _ in range(10):
        parse_ldif(ldif_data)
    parse_time = (time.time() - start_time) / 10
    
    # Measure validation performance
    start_time = time.time()
    for _ in range(10):
        validate_ldif(ldif_data)
    validation_time = (time.time() - start_time) / 10
    
    entries_per_second = len(entries) / max(parse_time, 0.001)
    
    print(f"✅ Performance results (average of 10 runs):")
    print(f"   📊 Entries processed: {len(entries)}")
    print(f"   ⏱️  Parse time: {parse_time:.4f}s")
    print(f"   ✅ Validation time: {validation_time:.4f}s")
    print(f"   🚀 Processing rate: {entries_per_second:.1f} entries/second")


async def main() -> None:
    """Main execution function."""
    print("🌟 FLEXT-LDIF Docker OpenLDAP Demo")
    print("=" * 50)
    
    # Start container
    if not start_openldap_container():
        print("💥 Failed to start OpenLDAP container. Exiting.")
        return
    
    # Populate with test data
    if not populate_test_data():
        print("💥 Failed to populate test data. Continuing with basic data.")
    
    try:
        # Export LDIF data
        ldif_data = export_ldif_from_container()
        if not ldif_data:
            print("💥 Failed to export LDIF data. Exiting.")
            return
        
        # Run examples
        await run_flext_ldif_examples(ldif_data)
        
    finally:
        # Always cleanup
        stop_openldap_container()
        
    print("\n🎉 FLEXT-LDIF Demo completed successfully!")
    print("\n📁 Check the generated file: flext_ldif_demo_output.ldif")


if __name__ == "__main__":
    # Check if Docker is available
    try:
        subprocess.run(["docker", "--version"], check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ Docker is not available. Please install Docker to run this demo.")
        sys.exit(1)
        
    asyncio.run(main())