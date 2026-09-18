# from flext-ldif_tests/README.md:158
from __future__ import annotations


def test_e2e_ldif_processing_workflow(tmp_path):
    """Test complete LDIF processing workflow."""
    input_file = tmp_path / "input.ldif"
    output_file = tmp_path / "output.ldif"

    # Create test LDIF file
    input_file.write_text(SAMPLE_LDIF_CONTENT)

    # Execute CLI command (pseudo-code helper)
    rc, out, err = run_cli([
        sys.executable,
        "-m",
        "flext_ldif.cli",
        "transform",
        "--filter",
        "objectClass=person",
        str(input_file),
        str(output_file),
    ])
    assert rc == 0
    assert output_file.exists()
