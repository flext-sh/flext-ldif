#!/usr/bin/env python3
"""CLI integration example.

Demonstrates integration with flext-cli patterns and programmatic
CLI usage for enterprise automation scenarios.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from flext_cli import get_config
from flext_ldif import FlextLdifAPI, FlextLdifConfig


def run_cli_command(command_args: list[str]) -> tuple[int, str, str]:
    """Run flext-ldif CLI command programmatically.
    
    Args:
        command_args: CLI command arguments
        
    Returns:
        Tuple of (exit_code, stdout, stderr)
    """
    try:
        # Build command
        cmd = ["poetry", "run", "flext-ldif"] + command_args
        
        # Execute
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        
        return result.returncode, result.stdout, result.stderr
        
    except subprocess.TimeoutExpired:
        return 124, "", "Command timed out"
    except Exception as e:
        return 1, "", str(e)


def main() -> None:
    """Demonstrate CLI integration patterns."""
    print("🖥️  FLEXT LDIF CLI Integration Example")
    print("=" * 50)

    # Test flext-cli configuration integration
    print("🔧 Testing flext-cli configuration...")
    cli_config = get_config()
    print(f"✅ CLI config loaded: output_format={cli_config.output_format}")
    
    # Create sample files for CLI testing
    sample_file = Path(__file__).parent / "sample_basic.ldif"
    output_file = Path(__file__).parent / "cli_output.ldif"
    
    # Test 1: Parse command
    print("\n📖 Testing CLI parse command...")
    exit_code, stdout, stderr = run_cli_command([
        "parse", str(sample_file)
    ])
    
    print(f"Exit code: {exit_code}")
    if exit_code == 0:
        print("✅ Parse command successful")
        print(f"Output: {stdout.strip()}")
    else:
        print(f"❌ Parse command failed: {stderr}")
    
    # Test 2: Validation command
    print("\n🔍 Testing CLI validate command...")
    exit_code, stdout, stderr = run_cli_command([
        "validate", str(sample_file), "--strict"
    ])
    
    print(f"Exit code: {exit_code}")
    if exit_code == 0:
        print("✅ Validate command successful")
        print(f"Output: {stdout.strip()}")
    else:
        print(f"❌ Validate command failed: {stderr}")
    
    # Test 3: Statistics command with JSON output
    print("\n📊 Testing CLI stats command with JSON output...")
    exit_code, stdout, stderr = run_cli_command([
        "stats", str(sample_file), "--format", "json"
    ])
    
    print(f"Exit code: {exit_code}")
    if exit_code == 0:
        print("✅ Stats command successful")
        print("JSON output:")
        print(stdout)
    else:
        print(f"❌ Stats command failed: {stderr}")
    
    # Test 4: Transform command with filtering
    print("\n🔄 Testing CLI transform command...")
    exit_code, stdout, stderr = run_cli_command([
        "transform", str(sample_file), str(output_file),
        "--filter-type", "persons"
    ])
    
    print(f"Exit code: {exit_code}")
    if exit_code == 0:
        print("✅ Transform command successful")
        print(f"Output: {stdout.strip()}")
        
        # Check if output file was created
        if output_file.exists():
            print(f"✅ Output file created: {output_file}")
            
            # Parse the output file to verify
            api = FlextLdifAPI()
            result = api.parse_file(output_file)
            if result.is_success and result.data:
                print(f"✅ Output file contains {len(result.data)} entries")
            
            # Clean up
            output_file.unlink()
        else:
            print("⚠️  Output file not found")
    else:
        print(f"❌ Transform command failed: {stderr}")
    
    # Test 5: Convert command to JSON
    print("\n🔀 Testing CLI convert command to JSON...")
    json_output = Path(__file__).parent / "cli_output.json"
    
    exit_code, stdout, stderr = run_cli_command([
        "convert", str(sample_file), str(json_output),
        "--output-format", "json"
    ])
    
    print(f"Exit code: {exit_code}")
    if exit_code == 0:
        print("✅ Convert command successful")
        print(f"Output: {stdout.strip()}")
        
        if json_output.exists():
            print(f"✅ JSON file created: {json_output}")
            # Clean up
            json_output.unlink()
    else:
        print(f"❌ Convert command failed: {stderr}")
    
    # Test 6: Config check command
    print("\n⚙️  Testing CLI config-check command...")
    exit_code, stdout, stderr = run_cli_command(["config-check"])
    
    print(f"Exit code: {exit_code}")
    if exit_code == 0:
        print("✅ Config check successful")
        print(f"Configuration: {stdout.strip()}")
    else:
        print(f"❌ Config check failed: {stderr}")
    
    # Test 7: Global options
    print("\n🌐 Testing global CLI options...")
    exit_code, stdout, stderr = run_cli_command([
        "--format", "yaml", "--verbose", "--debug",
        "stats", str(sample_file)
    ])
    
    print(f"Exit code: {exit_code}")
    if exit_code == 0:
        print("✅ Global options successful")
        print("YAML output with verbose/debug:")
        print(stdout)
    else:
        print(f"❌ Global options failed: {stderr}")
    
    # Demonstrate programmatic API usage alongside CLI
    print("\n🔧 Demonstrating programmatic API usage...")
    
    # Create API with custom configuration
    config = FlextLdifConfig(
        strict_validation=True,
        max_entries=10,
    )
    api = FlextLdifAPI(config)
    
    # Parse and process
    result = api.parse_file(sample_file)
    if result.is_success and result.data:
        entries = result.data
        stats = api.get_entry_statistics(entries)
        
        print(f"✅ API processed {len(entries)} entries")
        print("📊 Statistics from API:")
        for key, value in stats.items():
            print(f"  {key}: {value}")
    
    print("\n🏆 CLI Integration Summary:")
    print("  ✅ flext-cli configuration integration")
    print("  ✅ Programmatic CLI command execution")
    print("  ✅ Multiple output formats (JSON, YAML, text)")
    print("  ✅ Command chaining and automation")
    print("  ✅ Error handling and exit codes")
    print("  ✅ Global options and configuration")
    
    print("\n🎉 CLI integration example completed!")


if __name__ == "__main__":
    main()