"""MkDocs hooks: publish repository Markdown files as site pages.

SECURITY.md has to live at the repository root (GitHub looks for it there, and the "Report a vulnerability" button
depends on it), and each extension's changelog lives beside its crate. They are also pages the sites should carry, so
they are added to the build from where they are rather than copied into a docs directory and left to drift. Each site
names its own in `extra.repo_pages`, repository file -> page; every site in the repository uses this one hook.
"""

from pathlib import Path

from mkdocs.config.defaults import MkDocsConfig
from mkdocs.structure.files import File, Files

ROOT = Path(__file__).parent


def on_files(files: Files, config: MkDocsConfig) -> Files:
    """Add the site's repository pages to the build without copying them into its docs directory."""
    for source, page in config.extra.get("repo_pages", {}).items():
        content = (ROOT / source).read_text(encoding="utf-8")
        files.append(File.generated(config, page, content=content))
    return files
