#!/usr/bin/env python3
"""Analyze and replace ALL references and hard-coded values in the codebase.

This script:
1. Analyzes the entire project for constant references
2. Finds ALL hard-coded values that should be constants
3. Generates a complete migration plan
4. Performs dry-run validation before applying changes
5. Can execute replacements when approved

Usage:
    # Analyze only (no changes)
    python scripts/analyze_and_replace.py --report-only

    # Dry-run (show what would be replaced)
    python scripts/analyze_and_replace.py --dry-run

    # Execute replacements (CAUTION!)
    python scripts/analyze_and_replace.py --execute
"""

import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Reference:
    """Reference to a constant."""

    file: Path
    line_number: int
    line_content: str
    old__value: str
    new__value: str
    reference_type: str  # "hardcoded", "old_reference", "import"


class ConstantsAnalyzer:
    """Analyze ALL constant usage in codebase."""

    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root
        self.references: list[Reference] = []

        # Mapping of hard-coded values to constants
        self.hardcoded_map = self._build_hardcoded_map()

        # Mapping of old references to new ones
        self.reference_map = self._build_reference_map()

    def _build_hardcoded_map(self) -> dict[str, str]:
        """Build mapping of hard-coded values to constants.

        Examples:
        - "oid" → FlextLdifConstants.ServerTypes.OID
        - "dn" → FlextLdifConstants.DictKeys.DN

        """
        return {
            # Server types (hard-coded strings)
            '"oid"': "FlextLdifConstants.ServerTypes.OID",
            "'oid'": "FlextLdifConstants.ServerTypes.OID",
            '"oud"': "FlextLdifConstants.ServerTypes.OUD",
            "'oud'": "FlextLdifConstants.ServerTypes.OUD",
            '"ad"': "FlextLdifConstants.ServerTypes.AD",
            "'ad'": "FlextLdifConstants.ServerTypes.AD",
            '"active_directory"': "FlextLdifConstants.ServerTypes.AD",
            "'active_directory'": "FlextLdifConstants.ServerTypes.AD",
            '"openldap"': "FlextLdifConstants.ServerTypes.OPENLDAP",
            "'openldap'": "FlextLdifConstants.ServerTypes.OPENLDAP",
            '"openldap1"': "FlextLdifConstants.ServerTypes.OPENLDAP1",
            "'openldap1'": "FlextLdifConstants.ServerTypes.OPENLDAP1",
            '"openldap2"': "FlextLdifConstants.ServerTypes.OPENLDAP2",
            "'openldap2'": "FlextLdifConstants.ServerTypes.OPENLDAP2",
            '"389ds"': "FlextLdifConstants.ServerTypes.DS389",
            "'389ds'": "FlextLdifConstants.ServerTypes.DS389",
            '"novell_edirectory"': "FlextLdifConstants.ServerTypes.NOVELL",
            "'novell_edirectory'": "FlextLdifConstants.ServerTypes.NOVELL",
            '"ibm_tivoli"': "FlextLdifConstants.ServerTypes.TIVOLI",
            "'ibm_tivoli'": "FlextLdifConstants.ServerTypes.TIVOLI",
            '"apache_directory"': "FlextLdifConstants.ServerTypes.APACHE",
            "'apache_directory'": "FlextLdifConstants.ServerTypes.APACHE",
            '"relaxed"': "FlextLdifConstants.ServerTypes.RELAXED",
            "'relaxed'": "FlextLdifConstants.ServerTypes.RELAXED",
            '"rfc"': "FlextLdifConstants.ServerTypes.RFC",
            "'rfc'": "FlextLdifConstants.ServerTypes.RFC",
            '"generic"': "FlextLdifConstants.ServerTypes.GENERIC",
            "'generic'": "FlextLdifConstants.ServerTypes.GENERIC",
            # Dict keys (hard-coded strings)
            '"dn"': "FlextLdifConstants.DictKeys.DN",
            "'dn'": "FlextLdifConstants.DictKeys.DN",
            '"attributes"': "FlextLdifConstants.DictKeys.ATTRIBUTES",
            "'attributes'": "FlextLdifConstants.DictKeys.ATTRIBUTES",
            '"objectClass"': "FlextLdifConstants.DictKeys.OBJECTCLASS",
            "'objectClass'": "FlextLdifConstants.DictKeys.OBJECTCLASS",
            '"cn"': "FlextLdifConstants.DictKeys.CN",
            "'cn'": "FlextLdifConstants.DictKeys.CN",
            # Encodings
            '"utf-8"': "FlextLdifConstants.DEFAULT_ENCODING",
            "'utf-8'": "FlextLdifConstants.DEFAULT_ENCODING",
            # Entry types
            '"person"': "FlextLdifConstants.EntryTypes.PERSON",
            "'person'": "FlextLdifConstants.EntryTypes.PERSON",
            '"group"': "FlextLdifConstants.EntryTypes.GROUP",
            "'group'": "FlextLdifConstants.EntryTypes.GROUP",
            # Change types
            '"add"': "FlextLdifConstants.ChangeTypes.ADD",
            "'add'": "FlextLdifConstants.ChangeTypes.ADD",
            '"delete"': "FlextLdifConstants.ChangeTypes.DELETE",
            "'delete'": "FlextLdifConstants.ChangeTypes.DELETE",
            '"modify"': "FlextLdifConstants.ChangeTypes.MODIFY",
            "'modify'": "FlextLdifConstants.ChangeTypes.MODIFY",
        }

    def _build_reference_map(self) -> dict[str, str]:
        """Build mapping of old references to new ones.

        Examples:
        - FlextLdifConstants.EntryType → FlextLdifConstants.EntryTypes

        """
        return {
            # Renamed classes
            "FlextLdifConstants.EntryType": "FlextLdifConstants.EntryTypes",
            "FlextLdifConstants.AclSubjectType": "FlextLdifConstants.AclSubjectTypes",
        }

    def analyze_file(self, file_path: Path) -> list[Reference]:
        """Analyze single file for constant references."""
        refs = []

        try:
            content = file_path.read_text(encoding="utf-8")
            lines = content.splitlines()

            for line_num, line in enumerate(lines, 1):
                # Check for hard-coded values
                for old_val, new_val in self.hardcoded_map.items():
                    if old_val in line:
                        # Verify context (not in comment, not in string that shouldn't be replaced)
                        if self._should_replace_hardcoded(line, old_val):
                            refs.append(
                                Reference(
                                    file=file_path,
                                    line_number=line_num,
                                    line_content=line,
                                    old_value=old_val,
                                    new_value=new_val,
                                    reference_type="hardcoded",
                                )
                            )

                # Check for old references
                for old_ref, new_ref in self.reference_map.items():
                    if old_ref in line:
                        refs.append(
                            Reference(
                                file=file_path,
                                line_number=line_num,
                                line_content=line,
                                old_value=old_ref,
                                new_value=new_ref or "ERROR_REMOVED_CLASS",
                                reference_type="reference",
                            )
                        )

        except Exception as e:
            print(f"Error analyzing {file_path}: {e}", file=sys.stderr)

        return refs

    def _should_replace_hardcoded(self, line: str, _value: str) -> bool:
        """Determine if hard-coded value should be replaced."""
        line_stripped = line.strip()

        # Skip comments
        if line_stripped.startswith("#"):
            return False

        # Skip docstrings (rough heuristic)
        if '"""' in line or "'''" in line:
            return False

        # For now, simple check: if assignment or parameter
        return bool("=" in line or "(" in line)

    def analyze_project(self) -> dict[str, list[Reference]]:
        """Analyze entire project."""
        all_refs = defaultdict(list)

        # Find all Python files
        src_dir = self.project_root / "src"
        for py_file in src_dir.rglob("*.py"):
            # Skip migration module itself
            if "_migration" in str(py_file):
                continue

            refs = self.analyze_file(py_file)
            if refs:
                all_refs[str(py_file)] = refs

        return dict(all_refs)

    def generate_report(self, references: dict[str, list[Reference]]) -> str:
        """Generate analysis report."""
        lines = []
        lines.extend(("=" * 80, "CONSTANTS USAGE ANALYSIS REPORT", "=" * 80, ""))

        # Summary
        total_refs = sum(len(refs) for refs in references.values())
        hardcoded_count = sum(
            1
            for refs in references.values()
            for ref in refs
            if ref.reference_type == "hardcoded"
        )
        reference_count = total_refs - hardcoded_count

        lines.append(f"Total references found: {total_refs}")
        lines.append(f"  - Hard-coded values: {hardcoded_count}")
        lines.append(f"  - Old references: {reference_count}")
        lines.append(f"Files affected: {len(references)}")
        lines.append("")

        # By type
        lines.append("HARD-CODED VALUES TO REPLACE:")
        hardcoded_by_value = defaultdict(int)
        for refs in references.values():
            for ref in refs:
                if ref.reference_type == "hardcoded":
                    hardcoded_by_value[ref.old_value] += 1

        for value, count in sorted(hardcoded_by_value.items(), key=lambda x: -x[1]):
            lines.append(f"  {value}: {count} occurrences")
        lines.append("")

        # By file
        lines.append("REPLACEMENTS BY FILE:")
        for file_path, refs in sorted(references.items()):
            lines.append(f"\n{file_path}: {len(refs)} replacements")
            # Show first 5
            lines.extend(
                f"  Line {ref.line_number}: {ref.old_value} → {ref.new_value}"
                for ref in refs[:5]
            )
            if len(refs) > 5:
                lines.append(f"  ... and {len(refs) - 5} more")

        lines.extend(("", "=" * 80))
        return "\n".join(lines)

    def dry_run_replace(self, references: dict[str, list[Reference]]) -> dict[str, str]:
        """Dry-run: show what would be replaced.
        Returns dict of {file_path: new_content}.
        """
        dry_run_results = {}

        for file_path, refs in references.items():
            # Read file
            with Path(file_path).open("r", encoding="utf-8") as f:
                content = f.read()

            # Apply replacements
            new_content = content
            for ref in refs:
                new_content = new_content.replace(ref.old_value, ref.new_value)

            dry_run_results[file_path] = new_content

        return dry_run_results

    def apply_replacements(self, references: dict[str, list[Reference]]) -> None:
        """Apply replacements to files (CAUTION!)."""
        for file_path, refs in references.items():
            # Read file
            with Path(file_path).open("r", encoding="utf-8") as f:
                content = f.read()

            # Apply replacements
            new_content = content
            for ref in refs:
                new_content = new_content.replace(ref.old_value, ref.new_value)

            # Write back
            with Path(file_path).open("w", encoding="utf-8") as f:
                f.write(new_content)

            print(f"✅ Updated {file_path}")


def main() -> None:
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Analyze and replace constants")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Run in dry-run mode (default)",
    )
    parser.add_argument(
        "--execute", action="store_true", help="Execute replacements (CAUTION!)"
    )
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Only generate report, no replacements",
    )

    args = parser.parse_args()

    project_root = Path(__file__).parent.parent
    analyzer = ConstantsAnalyzer(project_root)

    print("🔍 Analyzing project for constant references...")
    references = analyzer.analyze_project()

    print("\n" + analyzer.generate_report(references))

    if args.report_only:
        return

    if args.execute:
        print("\n⚠️  EXECUTING REPLACEMENTS - This will modify files!")
        confirm = input("Type 'yes' to proceed: ")
        if confirm.lower() == "yes":
            analyzer.apply_replacements(references)
            print("\n✅ Replacements applied!")
        else:
            print("Cancelled.")
    else:
        print("\n🔍 DRY RUN MODE - No files will be modified")
        dry_run = analyzer.dry_run_replace(references)
        print(f"Would modify {len(dry_run)} files")


if __name__ == "__main__":
    main()
