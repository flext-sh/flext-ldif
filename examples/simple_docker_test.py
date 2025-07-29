#!/usr/bin/env python3
"""Simple example of how to use Docker OpenLDAP container for testing.

This demonstrates how to manually use the Docker container functionality
for testing and development purposes.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add src and tests to path for local testing
src_path = Path(__file__).parent.parent / "src"
tests_path = Path(__file__).parent.parent / "tests"
sys.path.insert(0, str(src_path))
sys.path.insert(0, str(tests_path))


def test_with_docker_container():
    """Example of manual Docker container usage for testing."""
    from docker_fixtures import OpenLDAPContainerManager, check_docker_available
    from flext_ldif import parse_ldif, validate_ldif
    
    # Check if Docker is available
    if not check_docker_available():
        print("❌ Docker is not available. Skipping test.")
        return False
    
    print("🐳 Starting OpenLDAP container for manual testing...")
    
    # Create container manager
    manager = OpenLDAPContainerManager()
    
    try:
        # Start container (this will populate it with test data)
        container = manager.start_container()
        print(f"✅ Container started: {container.name}")
        
        # Export LDIF data from container
        print("📤 Exporting LDIF data...")
        ldif_data = manager.get_ldif_export()
        
        if not ldif_data:
            print("❌ No LDIF data exported")
            return False
        
        print(f"✅ Exported {len(ldif_data.splitlines())} lines of LDIF data")
        
        # Test parsing
        print("🔍 Testing LDIF parsing...")
        entries = parse_ldif(ldif_data)
        print(f"✅ Parsed {len(entries)} entries")
        
        # Show entry details
        for i, entry in enumerate(entries[:3]):
            print(f"   Entry {i+1}: {entry.dn}")
            if entry.has_attribute('cn'):
                print(f"      CN: {entry.get_single_attribute('cn')}")
        
        if len(entries) > 3:
            print(f"   ... and {len(entries) - 3} more entries")
        
        # Test validation
        print("✅ Testing LDIF validation...")
        is_valid = validate_ldif(ldif_data)
        print(f"✅ Validation result: {'VALID' if is_valid else 'INVALID'}")
        
        # Test domain specifications
        print("🎯 Testing domain specifications...")
        from flext_ldif.domain.specifications import (
            FlextLdifPersonSpecification,
            FlextLdifGroupSpecification,
            FlextLdifOrganizationalUnitSpecification,
        )
        
        person_spec = FlextLdifPersonSpecification()
        group_spec = FlextLdifGroupSpecification()
        ou_spec = FlextLdifOrganizationalUnitSpecification()
        
        person_count = sum(1 for entry in entries if person_spec.is_satisfied_by(entry))
        group_count = sum(1 for entry in entries if group_spec.is_satisfied_by(entry))
        ou_count = sum(1 for entry in entries if ou_spec.is_satisfied_by(entry))
        
        print(f"   👥 Person entries: {person_count}")
        print(f"   🏢 Group entries: {group_count}")
        print(f"   📁 OU entries: {ou_count}")
        print(f"   📊 Total entries: {len(entries)}")
        
        print("✅ All tests passed with real OpenLDAP data!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False
        
    finally:
        # Always cleanup
        print("🧹 Cleaning up container...")
        manager.stop_container()
        print("✅ Container cleaned up")


if __name__ == "__main__":
    print("🧪 Simple Docker OpenLDAP Test")
    print("=" * 40)
    
    success = test_with_docker_container()
    
    if success:
        print("\n🎉 Test completed successfully!")
        print("📝 This demonstrates how to use Docker containers")
        print("   for testing FLEXT-LDIF against real LDAP data.")
    else:
        print("\n💥 Test failed!")
        sys.exit(1)