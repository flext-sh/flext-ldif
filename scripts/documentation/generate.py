"""Generate project-level docs from workspace SSOT guides."""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path

from shared import Scope, build_scopes, write_json, write_markdown


@dataclass(frozen=True)
class GeneratedFile:
    """Record of a single generated file and whether it was written."""

    path: str
    written: bool


HEADING_RE = re.compile(r"^#{1,6}\s+(.+?)\s*$", re.MULTILINE)
ANCHOR_LINK_RE = re.compile(r"\[([^\]]+)\]\(#([^)]+)\)")


def normalize_anchor(value: str) -> str:
    """Convert a heading to a GitHub-compatible anchor slug."""
    text = value.strip().lower()
    text = re.sub(r"[^a-z0-9\s-]", "", text)
    text = re.sub(r"\s+", "-", text)
    text = re.sub(r"-+", "-", text)
    return text.strip("-")


def sanitize_internal_anchor_links(content: str) -> str:
    """Normalize generated guides by stripping in-page anchor links."""

    def replace(match: re.Match[str]) -> str:
        label, _anchor = match.groups()
        return label

    return ANCHOR_LINK_RE.sub(replace, content)


def write_if_needed(path: Path, content: str, *, apply: bool) -> GeneratedFile:
    """Write *content* to *path* only when changed and *apply* is True."""
    exists = path.exists()
    current = path.read_text(encoding="utf-8") if exists else ""
    if current == content:
        return GeneratedFile(path=path.as_posix(), written=False)
    if apply:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return GeneratedFile(path=path.as_posix(), written=apply)


def project_guide_content(content: str, project: str, source_name: str) -> str:
    """Render workspace guide *content* with a project-specific heading."""
    lines = content.splitlines()
    out: list[str] = [
        f"<!-- Generated from docs/guides/{source_name} for {project}. -->",
        "<!-- Source of truth: workspace docs/guides/. -->",
        "",
    ]
    heading_done = False
    for line in lines:
        if not heading_done and line.startswith("# "):
            title = line[2:].strip()
            out.extend([
                f"# {project} - {title}",
                "",
                f"> Project profile: `{project}`",
                "",
            ])
            heading_done = True
            continue
        out.append(line)
    rendered = "\n".join(out).rstrip() + "\n"
    return sanitize_internal_anchor_links(rendered)


def generate_root_docs(scope: Scope, *, apply: bool) -> list[GeneratedFile]:
    """Generate placeholder docs at the workspace root."""
    changelog = (
        "# Changelog\n\nThis file is managed by `make docs DOCS_PHASE=generate`.\n"
    )
    release = "# Latest Release\n\nNo tagged release notes were generated yet.\n"
    roadmap = (
        "# Roadmap\n\nRoadmap updates are generated from docs validation outputs.\n"
    )
    return [
        write_if_needed(scope.path / "docs/CHANGELOG.md", changelog, apply=apply),
        write_if_needed(scope.path / "docs/releases/latest.md", release, apply=apply),
        write_if_needed(scope.path / "docs/roadmap/index.md", roadmap, apply=apply),
    ]


def generate_project_guides(
    scope: Scope, workspace_root: Path, *, apply: bool
) -> list[GeneratedFile]:
    """Copy workspace guides into a project, injecting the project name."""
    source_dir = workspace_root / "docs/guides"
    if not source_dir.exists():
        return []
    files: list[GeneratedFile] = []
    for source in sorted(source_dir.glob("*.md")):
        rendered = project_guide_content(
            content=source.read_text(encoding="utf-8"),
            project=scope.name,
            source_name=source.name,
        )
        files.append(
            write_if_needed(
                scope.path / "docs/guides" / source.name, rendered, apply=apply
            )
        )
    return files


def run_scope(scope: Scope, *, apply: bool, workspace_root: Path) -> int:
    """Generate docs for *scope* and write reports."""
    if scope.name == "root":
        files = generate_root_docs(scope=scope, apply=apply)
        source = "root-generated-artifacts"
    else:
        files = generate_project_guides(
            scope=scope, workspace_root=workspace_root, apply=apply
        )
        source = "workspace-docs-guides"

    generated = sum(1 for item in files if item.written)
    write_json(
        scope.report_dir / "generate-summary.json",
        {
            "summary": {
                "scope": scope.name,
                "generated": generated,
                "apply": apply,
                "source": source,
            },
            "files": [item.__dict__ for item in files],
        },
    )
    write_markdown(
        scope.report_dir / "generate-report.md",
        [
            "# Docs Generate Report",
            "",
            f"Scope: {scope.name}",
            f"Apply: {int(apply)}",
            f"Generated files: {generated}",
            f"Source: {source}",
        ],
    )
    result = "OK" if apply else "WARN"
    reason = f"generated:{generated}" if apply else "dry-run"
    print(f"PROJECT={scope.name} PHASE=generate RESULT={result} REASON={reason}")
    return 0


def main() -> int:
    """CLI entry point for the documentation generator."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--project")
    parser.add_argument("--projects")
    parser.add_argument("--output-dir", default=".reports/docs")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    scopes = build_scopes(
        root=root,
        project=args.project,
        projects=args.projects,
        output_dir=args.output_dir,
    )
    for scope in scopes:
        run_scope(scope=scope, apply=args.apply, workspace_root=root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
