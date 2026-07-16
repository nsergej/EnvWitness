"""Strict YAML configuration loading and safe default generation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from envwitness.domain.errors import ConfigurationError
from envwitness.domain.models import has_unsafe_control_characters


@dataclass(slots=True)
class _RegexGroupComplexity:
    """Track ambiguity inside one regular-expression group."""

    has_variable_repeat: bool = False
    has_alternation: bool = False


def validate_telemetry_endpoint(endpoint: str) -> str:
    """Validate one optional HTTPS telemetry endpoint without URL ambiguity."""
    if not endpoint:
        return endpoint
    if endpoint != endpoint.strip() or any(ord(character) < 32 for character in endpoint):
        raise ValueError("Telemetry endpoint must be a valid HTTPS URL")
    try:
        parsed_endpoint = urlsplit(endpoint)
        hostname = parsed_endpoint.hostname
        _ = parsed_endpoint.port
    except ValueError as error:
        raise ValueError("Telemetry endpoint must be a valid HTTPS URL") from error
    if (
        parsed_endpoint.scheme.lower() != "https"
        or not parsed_endpoint.netloc
        or not hostname
        or parsed_endpoint.username is not None
        or parsed_endpoint.password is not None
        or "#" in endpoint
        or "\\" in parsed_endpoint.netloc
        or any(character.isspace() for character in hostname)
    ):
        raise ValueError(
            "Telemetry endpoint must use HTTPS with a hostname and no credentials or fragment"
        )
    return endpoint


def _validate_redaction_pattern_complexity(pattern: str) -> None:  # noqa: PLR0912
    """Reject constructs commonly responsible for catastrophic regex backtracking."""
    if "(?P=" in pattern:
        raise ValueError("Redaction expressions cannot contain backreferences")

    groups = [_RegexGroupComplexity()]
    closed_group: _RegexGroupComplexity | None = None
    index = 0
    quantifier_count = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "\\":
            if index + 1 < len(pattern) and pattern[index + 1] in "123456789":
                raise ValueError("Redaction expressions cannot contain backreferences")
            index += 2
            closed_group = None
            continue
        if character == "[":
            index += 1
            while index < len(pattern):
                if pattern[index] == "\\":
                    index += 2
                    continue
                if pattern[index] == "]":
                    index += 1
                    break
                index += 1
            closed_group = None
            continue
        if character == "(":
            groups.append(_RegexGroupComplexity())
            if len(groups) > 13:
                raise ValueError("Redaction expressions cannot nest more than 12 groups")
            closed_group = None
            index += 1
            if index < len(pattern) and pattern[index] == "?":
                if pattern.startswith("?P<", index):
                    name_end = pattern.find(">", index + 3)
                    index = len(pattern) if name_end < 0 else name_end + 1
                elif pattern.startswith(("?<=", "?<!"), index):
                    index += 3
                elif pattern.startswith(("?:", "?=", "?!", "?>"), index):
                    index += 2
                else:
                    prefix_end = min(
                        (
                            position
                            for position in (
                                pattern.find(":", index + 1),
                                pattern.find(")", index + 1),
                            )
                            if position >= 0
                        ),
                        default=-1,
                    )
                    if prefix_end >= 0 and pattern[prefix_end] == ":":
                        index = prefix_end + 1
            continue
        if character == ")" and len(groups) > 1:
            closed_group = groups.pop()
            groups[-1].has_variable_repeat |= closed_group.has_variable_repeat
            groups[-1].has_alternation |= closed_group.has_alternation
            index += 1
            continue
        if character == "|":
            groups[-1].has_alternation = True
            closed_group = None
            index += 1
            continue

        quantifier = _parse_regex_quantifier(pattern, index)
        if quantifier is not None:
            next_index, variable_repeat, maximum_repetitions = quantifier
            quantifier_count += 1
            if quantifier_count > 32:
                raise ValueError("Redaction expressions cannot contain more than 32 quantifiers")
            if maximum_repetitions is not None and maximum_repetitions > 1_000:
                raise ValueError("Redaction expression repetition limit cannot exceed 1000")
            repeats_group = maximum_repetitions is None or maximum_repetitions > 1
            if (
                closed_group is not None
                and repeats_group
                and (closed_group.has_variable_repeat or closed_group.has_alternation)
            ):
                raise ValueError(
                    "Redaction expressions cannot repeat ambiguous or variably repeated groups"
                )
            groups[-1].has_variable_repeat |= variable_repeat
            closed_group = None
            index = next_index
            continue

        closed_group = None
        index += 1


def _parse_regex_quantifier(
    pattern: str,
    index: int,
) -> tuple[int, bool, int | None] | None:
    """Return the end, variability, and upper bound of a quantifier at an index."""
    character = pattern[index]
    if character in "*+":
        return index + 1, True, None
    if character == "?":
        return index + 1, True, 1
    if character != "{":
        return None
    match = re.match(r"\{(\d+)(?:,(\d*)?)?\}", pattern[index:])
    if match is None:
        return None
    minimum = int(match.group(1))
    maximum_text = match.group(2)
    has_comma = "," in match.group(0)
    maximum = None if has_comma and maximum_text == "" else int(maximum_text or minimum)
    return index + len(match.group(0)), has_comma and maximum != minimum, maximum


class RuntimeProbeConfiguration(BaseModel):
    """One bounded command used to report an installed runtime version."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=60, pattern=r"^[a-z0-9][a-z0-9.-]*$")
    command: tuple[str, ...] = Field(min_length=1, max_length=16)
    timeout_seconds: int = Field(default=5, ge=1, le=30)

    @field_validator("command")
    @classmethod
    def command_has_safe_arguments(cls, command: tuple[str, ...]) -> tuple[str, ...]:
        """Reject process arguments that cannot be passed to an operating system."""
        if any(not argument or "\x00" in argument for argument in command):
            raise ValueError("Runtime probe arguments must be non-empty and cannot contain nulls")
        return command


class CaptureConfiguration(BaseModel):
    """Resource limits and disclosure choices for built-in collectors."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    command_timeout_seconds: int = Field(default=300, ge=1, le=86_400)
    maximum_output_bytes: int = Field(default=1_048_576, ge=4_096, le=16_777_216)
    include_environment_names: bool = True
    environment_value_allowlist: tuple[str, ...] = ()
    file_content_allowlist: tuple[str, ...] = ()
    runtime_probes: tuple[RuntimeProbeConfiguration, ...] = (
        RuntimeProbeConfiguration(name="python", command=("python", "--version")),
        RuntimeProbeConfiguration(name="git", command=("git", "--version")),
    )

    @field_validator("environment_value_allowlist")
    @classmethod
    def environment_names_are_valid(cls, names: tuple[str, ...]) -> tuple[str, ...]:
        """Require explicit environment variable names without wildcard expansion."""
        for name in names:
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name):
                raise ValueError(f"Invalid environment variable name: {name}")
        if len(names) != len(set(names)):
            raise ValueError("Environment allowlist cannot contain duplicates")
        return names

    @field_validator("file_content_allowlist")
    @classmethod
    def file_paths_are_relative(cls, paths: tuple[str, ...]) -> tuple[str, ...]:
        """Reject absolute and parent-traversing file disclosure paths."""
        for configured_path in paths:
            path = Path(configured_path)
            if path.is_absolute() or ".." in path.parts or not path.parts:
                raise ValueError(f"File disclosure path must stay inside the project: {path}")
        if len(paths) != len(set(paths)):
            raise ValueError("File content allowlist cannot contain duplicates")
        return paths


class RedactionRuleConfiguration(BaseModel):
    """One operator-defined text redaction expression."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=60, pattern=r"^[a-z0-9][a-z0-9-]*$")
    pattern: str = Field(min_length=1, max_length=256)

    @field_validator("pattern")
    @classmethod
    def pattern_compiles(cls, pattern: str) -> str:
        """Compile bounded custom patterns during configuration loading."""
        _validate_redaction_pattern_complexity(pattern)
        try:
            re.compile(pattern)
        except re.error as error:
            raise ValueError(f"Invalid redaction expression: {error}") from error
        return pattern


class RedactionConfiguration(BaseModel):
    """Global privacy policy applied after every collector finishes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    custom_rules: tuple[RedactionRuleConfiguration, ...] = ()


class PluginConfiguration(BaseModel):
    """Explicit opt-in configuration for one external collector process."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=60, pattern=r"^[a-z0-9][a-z0-9.-]*$")
    command: tuple[str, ...] = Field(min_length=1, max_length=32)
    enabled: bool = False
    timeout_seconds: int = Field(default=10, ge=1, le=120)
    maximum_output_bytes: int = Field(default=262_144, ge=1_024, le=4_194_304)

    @field_validator("command")
    @classmethod
    def plugin_command_is_valid(cls, command: tuple[str, ...]) -> tuple[str, ...]:
        """Reject empty and null-containing plugin process arguments."""
        if any(not argument or "\x00" in argument for argument in command):
            raise ValueError("Plugin command arguments must be non-empty and cannot contain nulls")
        return command


class ApiConfiguration(BaseModel):
    """Local REST API binding and storage configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str = Field(default="127.0.0.1", pattern=r"^(127\.0\.0\.1|localhost|::1)$")
    port: int = Field(default=8765, ge=1_024, le=65_535)
    token_environment_variable: str = Field(
        default="ENVWITNESS_API_TOKEN",
        pattern=r"^[A-Z_][A-Z0-9_]{0,127}$",
    )
    storage_directory: str = ".envwitness/capsules"


class TelemetryConfiguration(BaseModel):
    """Explicit consent and endpoint for aggregate usage events."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = False
    endpoint: str = ""

    @field_validator("endpoint")
    @classmethod
    def endpoint_requires_https(cls, endpoint: str) -> str:
        """Require an unambiguous encrypted endpoint whenever one is configured."""
        return validate_telemetry_endpoint(endpoint)


class UpdateConfiguration(BaseModel):
    """Opt-in package update behavior."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    automatic_check: bool = False
    automatic_install: bool = False
    metadata_url: str = "https://pypi.org/pypi/envwitness/json"
    check_interval_hours: int = Field(default=24, ge=1, le=720)

    @field_validator("metadata_url")
    @classmethod
    def metadata_source_is_trusted(cls, metadata_url: str) -> str:
        """Restrict updates to the canonical encrypted PyPI metadata endpoint."""
        if metadata_url != "https://pypi.org/pypi/envwitness/json":
            raise ValueError("Update metadata URL must be the canonical PyPI endpoint")
        return metadata_url

    @model_validator(mode="after")
    def automatic_install_requires_checks(self) -> UpdateConfiguration:
        """Prevent an installation policy that can never discover a release."""
        if self.automatic_install and not self.automatic_check:
            raise ValueError("Automatic installation requires automatic checks")
        return self


class EnvWitnessConfiguration(BaseModel):
    """Top-level versioned configuration document."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(default="1.0", pattern=r"^1\.0$")
    project_name: str = Field(default="", max_length=120)
    capture: CaptureConfiguration = CaptureConfiguration()
    redaction: RedactionConfiguration = RedactionConfiguration()
    plugins: tuple[PluginConfiguration, ...] = ()
    api: ApiConfiguration = ApiConfiguration()
    telemetry: TelemetryConfiguration = TelemetryConfiguration()
    updates: UpdateConfiguration = UpdateConfiguration()

    @field_validator("project_name")
    @classmethod
    def project_name_is_display_safe(cls, project_name: str) -> str:
        """Reject control characters before a project name reaches paths or displays."""
        if has_unsafe_control_characters(project_name):
            raise ValueError("Project name cannot contain control characters")
        return project_name

    @field_validator("plugins")
    @classmethod
    def plugin_names_are_unique(
        cls,
        plugins: tuple[PluginConfiguration, ...],
    ) -> tuple[PluginConfiguration, ...]:
        """Ensure one authoritative configuration exists per plugin name."""
        names = [plugin.name for plugin in plugins]
        if len(names) != len(set(names)):
            raise ValueError("Plugin names must be unique")
        return plugins


def load_configuration(path: Path | None) -> EnvWitnessConfiguration:
    """Load strict YAML configuration or return safe defaults.

    Args:
        path: Optional configuration path. A missing explicit path is an error.

    Returns:
        Fully validated immutable configuration.
    """
    if path is None:
        return EnvWitnessConfiguration()
    if not path.exists() or not path.is_file():
        raise ConfigurationError(f"Configuration file does not exist: {path}")
    if path.stat().st_size > 1_048_576:
        raise ConfigurationError("Configuration file exceeds the 1 MiB safety limit")
    try:
        raw_data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if raw_data is None:
            raw_data = {}
        if not isinstance(raw_data, dict):
            raise ConfigurationError("Configuration root must be a YAML mapping")
        return EnvWitnessConfiguration.model_validate(raw_data)
    except (OSError, UnicodeError, yaml.YAMLError, ValidationError) as error:
        raise ConfigurationError(f"Invalid configuration: {error}") from error


def write_default_configuration(path: Path, *, overwrite: bool = False) -> Path:
    """Write a documented, security-first starter configuration atomically."""
    if path.exists() and not overwrite:
        raise ConfigurationError(f"Refusing to overwrite existing configuration: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_suffix(path.suffix + ".temporary")
    content = """schema_version: \"1.0\"
project_name: \"\"

capture:
  command_timeout_seconds: 300
  maximum_output_bytes: 1048576
  include_environment_names: true
  environment_value_allowlist: []
  file_content_allowlist: []
  runtime_probes:
    - name: python
      command: [python, --version]
      timeout_seconds: 5
    - name: git
      command: [git, --version]
      timeout_seconds: 5

redaction:
  custom_rules: []

plugins: []

api:
  host: 127.0.0.1
  port: 8765
  token_environment_variable: ENVWITNESS_API_TOKEN
  storage_directory: .envwitness/capsules

telemetry:
  enabled: false
  endpoint: \"\"

updates:
  automatic_check: false
  automatic_install: false
  metadata_url: https://pypi.org/pypi/envwitness/json
  check_interval_hours: 24
"""
    try:
        temporary_path.write_text(content, encoding="utf-8", newline="\n")
        temporary_path.replace(path)
    except OSError as error:
        temporary_path.unlink(missing_ok=True)
        raise ConfigurationError(f"Cannot write configuration: {error}") from error
    return path
