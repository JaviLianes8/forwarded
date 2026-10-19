"""The README examples run and print what their comments say; docs and versions agree."""

from __future__ import annotations

import contextlib
import io
import itertools
import re
from pathlib import Path

import forwarded

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")


def _python_blocks() -> list[str]:
    return re.findall(r"```python\n(.*?)```", README, flags=re.DOTALL)


def _expected_output(block: str) -> list[str]:
    """Each print line is followed by the comment lines that hold what it prints."""
    expected: list[str] = []
    lines = block.splitlines()
    for index, line in enumerate(lines):
        if not line.strip().startswith("print("):
            continue
        for following in itertools.takewhile(
            lambda text: text.strip().startswith("# "), lines[index + 1 :]
        ):
            expected.append(following.strip()[2:])
    return expected


def test_every_readme_example_runs_and_prints_its_comment() -> None:
    checked = 0
    for block in _python_blocks():
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            exec(compile(block, "README.md", "exec"), {"__name__": "readme"})
        expected = _expected_output(block)
        assert expected, block
        assert out.getvalue().splitlines() == expected
        checked += len(expected)
    assert len(_python_blocks()) == 4
    assert checked == 17


def test_every_print_in_the_readme_shows_its_output() -> None:
    for block in _python_blocks():
        lines = block.splitlines()
        for index, line in enumerate(lines):
            if line.strip().startswith("print("):
                assert lines[index + 1].strip().startswith("# "), line


def test_the_api_table_lists_every_public_name() -> None:
    table = README.split("## API", 1)[1].split("\n## ", 1)[0]
    for name in forwarded.__all__:
        assert f"`{name}" in table, name


def test_version_matches_pyproject() -> None:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"$', text, flags=re.MULTILINE)
    assert match is not None
    assert match.group(1) == forwarded.__version__


def test_changelog_has_an_entry_for_this_version() -> None:
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## [{forwarded.__version__}]" in text


def test_no_em_dash_anywhere_in_the_tree() -> None:
    suffixes = {".py", ".md", ".toml", ".ps1", ".txt", ".yml"}
    for path in ROOT.rglob("*"):
        parts = path.relative_to(ROOT).parts
        if not path.is_file() or path.suffix not in suffixes or parts[:2] == ("tests", "upstream"):
            continue
        if any(
            (part.startswith(".") and part != ".github") or part == "__pycache__" for part in parts
        ):
            continue
        assert chr(0x2014) not in path.read_text(encoding="utf-8"), path


def test_source_files_stay_under_two_hundred_lines() -> None:
    for path in [*ROOT.joinpath("src").rglob("*.py"), *ROOT.joinpath("tests").rglob("*.py")]:
        assert len(path.read_text(encoding="utf-8").splitlines()) <= 200, path


def test_readme_links_are_absolute_so_they_work_on_pypi() -> None:
    links = re.findall(r"\]\(([^)]+)\)", README)
    assert len(links) >= 5
    assert all(link.startswith("https://") for link in links), links


def test_the_guide_covers_every_public_name_it_documents() -> None:
    guide = (ROOT / "GUIDE.md").read_text(encoding="utf-8")
    for name in ("client_from_forwarded", "client_from_x_forwarded", "parse", "build"):
        assert f"`{name}" in guide, name


def test_the_release_script_stops_when_a_native_command_fails() -> None:
    # $ErrorActionPreference does not stop on a native command's non-zero exit.
    script = (ROOT / "scripts" / "release.ps1").read_text(encoding="utf-8")
    code = [line for line in script.splitlines() if not line.lstrip().startswith("#")]
    natives = [line for line in code if re.search(r"(^|[{(\s])(python|git)\s", line)]
    assert len(natives) == 4, natives
    assert all("Invoke-Native" in line for line in natives), natives
    helper = script.split("function Invoke-Native", 1)[1].split("\n}", 1)[0]
    assert "$LASTEXITCODE -ne 0" in helper and "throw" in helper
