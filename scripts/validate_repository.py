"""Validate documentation links, examples, assets, and required repository files."""

from __future__ import annotations

import re
from pathlib import Path
from xml.etree import ElementTree

import yaml
from PIL import Image
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode

from envwitness.infrastructure.config import load_configuration

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_PATHS = (
    "README.md",
    "LICENSE",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "src",
    "tests",
    "docs",
    "examples",
    "assets",
    ".github",
    "docker",
    "scripts",
)
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
PLACEHOLDER_WORDS = (
    "TO" + chr(68) + chr(79),
    "FIX" + chr(77) + chr(69),
    "NotImplemented" + chr(69) + "rror",
)
PLACEHOLDER_PATTERN = re.compile(r"\b(?:" + "|".join(PLACEHOLDER_WORDS) + r")\b")


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def construct_unique_mapping(
    loader: UniqueKeyLoader,
    node: MappingNode,
    *,
    deep: bool = False,
) -> dict[object, object]:
    """Construct a mapping and reject ambiguous duplicate keys."""
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_unique_mapping,
)


def validate_required_paths() -> list[str]:
    """Return errors for missing professional repository surfaces."""
    return [
        f"Missing required path: {path}" for path in REQUIRED_PATHS if not (ROOT / path).exists()
    ]


def validate_markdown_links() -> list[str]:
    """Return errors for local Markdown links whose target does not exist."""
    errors: list[str] = []
    for markdown_path in sorted(ROOT.rglob("*.md")):
        if any(part.startswith(".") for part in markdown_path.relative_to(ROOT).parts):
            continue
        content = markdown_path.read_text(encoding="utf-8")
        for match in MARKDOWN_LINK.finditer(content):
            raw_target = match.group(1).strip().strip("<>")
            if raw_target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            path_text = raw_target.split("#", maxsplit=1)[0]
            if not path_text:
                continue
            target = (markdown_path.parent / path_text).resolve()
            if not target.exists():
                relative_markdown = markdown_path.relative_to(ROOT)
                errors.append(f"Broken local link in {relative_markdown}: {raw_target}")
    return errors


def validate_assets() -> list[str]:
    """Return errors for missing, blank, or malformed documented visual assets."""
    errors: list[str] = []
    expected_raster_assets = {
        "assets/banner.png": (1200, 400),
        "assets/dashboard.png": (1000, 600),
        "assets/dashboard-mobile.png": (300, 600),
        "assets/demo.gif": (1000, 500),
    }
    for asset_name, minimum_dimensions in expected_raster_assets.items():
        asset_path = ROOT / asset_name
        if not asset_path.is_file():
            errors.append(f"Missing visual asset: {asset_name}")
            continue
        try:
            with Image.open(asset_path) as image:
                if image.width < minimum_dimensions[0] or image.height < minimum_dimensions[1]:
                    errors.append(f"Visual asset is too small: {asset_name}")
                if image.getbbox() is None:
                    errors.append(f"Visual asset is blank: {asset_name}")
        except (OSError, ValueError) as error:
            errors.append(f"Cannot read visual asset {asset_name}: {error}")
    try:
        ElementTree.parse(ROOT / "assets/logo.svg")  # noqa: S314 - trusted repository asset
    except (OSError, ElementTree.ParseError) as error:
        errors.append(f"Cannot parse assets/logo.svg: {error}")
    return errors


def validate_examples() -> list[str]:
    """Return errors for example YAML documents rejected by the current schema."""
    errors: list[str] = []
    for example_path in sorted((ROOT / "examples" / "configs").glob("*.yml")):
        try:
            load_configuration(example_path)
        except Exception as error:  # noqa: BLE001 - validator reports every example failure
            errors.append(f"Invalid configuration example {example_path.name}: {error}")
    return errors


def validate_yaml_documents() -> list[str]:
    """Return errors for malformed YAML or duplicate mapping keys."""
    errors: list[str] = []
    for yaml_path in sorted((*ROOT.rglob("*.yml"), *ROOT.rglob("*.yaml"))):
        if ".venv" in yaml_path.parts:
            continue
        try:
            yaml.load(yaml_path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)  # noqa: S506
        except (OSError, UnicodeError, yaml.YAMLError) as error:
            errors.append(f"Invalid YAML {yaml_path.relative_to(ROOT)}: {error}")
    return errors


def validate_no_code_placeholders() -> list[str]:
    """Return errors when executable project code contains unfinished placeholders."""
    errors: list[str] = []
    roots = (ROOT / "src", ROOT / "examples", ROOT / "scripts")
    for source_root in roots:
        for source_path in sorted(source_root.rglob("*.py")):
            content = source_path.read_text(encoding="utf-8")
            match = PLACEHOLDER_PATTERN.search(content)
            if match is not None:
                errors.append(
                    f"Code placeholder {match.group(0)} in {source_path.relative_to(ROOT)}"
                )
    return errors


def main() -> None:
    """Run repository validations and fail with a readable combined report."""
    errors = [
        *validate_required_paths(),
        *validate_markdown_links(),
        *validate_assets(),
        *validate_examples(),
        *validate_yaml_documents(),
        *validate_no_code_placeholders(),
    ]
    if errors:
        raise SystemExit("Repository validation failed:\n- " + "\n- ".join(errors))
    print("Repository structure, documentation, assets, and examples are valid.")


if __name__ == "__main__":
    main()
