"""Deterministic global redaction for all built-in and plugin evidence."""

from __future__ import annotations

import re
import unicodedata
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import JsonValue

from envwitness.application.ports import CollectedFact
from envwitness.domain.errors import CaptureError
from envwitness.domain.models import EvidenceFact, RedactionSummary, Sensitivity
from envwitness.infrastructure.config import RedactionRuleConfiguration


@dataclass(frozen=True, slots=True)
class CompiledRedactionRule:
    """Named compiled expression used by the deterministic redaction pass."""

    name: str
    expression: re.Pattern[str]


BUILT_IN_RULES = (
    CompiledRedactionRule(
        "control-character",
        re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"),
    ),
    CompiledRedactionRule(
        "private-key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?"
            r"-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
        ),
    ),
    CompiledRedactionRule(
        "authorization-header",
        re.compile(r"(?i)\b(authorization\s*[:=]\s*)(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+"),
    ),
    CompiledRedactionRule("github-token", re.compile(r"\b(?:gh[opurs]_[A-Za-z0-9]{20,255})\b")),
    CompiledRedactionRule("openai-key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,255}\b")),
    CompiledRedactionRule("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    CompiledRedactionRule(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    ),
    CompiledRedactionRule(
        "credential-url",
        re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/@]+:[^\s/@]+(@)"),
    ),
    CompiledRedactionRule(
        "sensitive-assignment",
        re.compile(
            r"(?i)\b(password|passwd|secret|client_secret|access_token|token|api_key|apikey)"
            r"(\s*[:=]\s*)([^\s,;&\]\}\"']+)"
        ),
    ),
)

SENSITIVE_ARGUMENT_NAMES = frozenset(
    {
        "access-key",
        "access-token",
        "api-key",
        "apikey",
        "authorization",
        "client-secret",
        "credential",
        "credentials",
        "password",
        "passwd",
        "private-key",
        "secret",
        "token",
    }
)
IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")


class DeterministicRedactor:
    """Apply transparent rules recursively before any evidence is persisted."""

    def __init__(self, custom_rules: tuple[RedactionRuleConfiguration, ...] = ()) -> None:
        """Compile built-in and validated operator-provided rules."""
        compiled_custom_rules = tuple(
            CompiledRedactionRule(rule.name, re.compile(rule.pattern)) for rule in custom_rules
        )
        self._rules = BUILT_IN_RULES + self._home_directory_rules() + compiled_custom_rules

    def redact(
        self,
        facts: list[CollectedFact],
    ) -> tuple[list[EvidenceFact], RedactionSummary]:
        """Redact every fact recursively and summarize all replacements."""
        stored_facts: list[EvidenceFact] = []
        rule_counts: Counter[str] = Counter()
        redacted_fact_count = 0
        total_replacements = 0

        for fact in facts:
            self._validate_semantic_identifier(fact.key, "Fact key")
            self._validate_semantic_identifier(fact.collector, "Collector identifier")

            triggered_rules: tuple[str, ...]
            if fact.sensitivity is Sensitivity.SECRET:
                stored_value: JsonValue = "[REDACTED:secret-classification]"
                triggered_rules = ("secret-classification",)
                replacements = 1
            elif fact.key == "envwitness.command.arguments":
                stored_value, triggered_rules, replacements = self._redact_arguments(fact.value)
            else:
                stored_value, triggered_rules, replacements = self._redact_value(fact.value)
            stored_source, source_rules, source_replacements = self._redact_text(fact.source)
            triggered_rules += source_rules
            replacements += source_replacements
            was_redacted = replacements > 0
            if was_redacted:
                redacted_fact_count += 1
                total_replacements += replacements
                rule_counts.update(triggered_rules)
            stored_facts.append(
                EvidenceFact.create(
                    key=fact.key,
                    value=stored_value,
                    collector=fact.collector,
                    source=stored_source,
                    sensitivity=fact.sensitivity,
                    captured_at=fact.captured_at,
                    redacted=was_redacted,
                    redaction_rules=tuple(sorted(set(triggered_rules))) if was_redacted else (),
                )
            )

        summary = RedactionSummary(
            facts_scanned=len(facts),
            facts_redacted=redacted_fact_count,
            replacements=total_replacements,
            rules_triggered=dict(sorted(rule_counts.items())),
        )
        return stored_facts, summary

    def _redact_value(self, value: JsonValue) -> tuple[JsonValue, tuple[str, ...], int]:
        """Recursively redact strings while preserving JSON structure and types."""
        if isinstance(value, str):
            return self._redact_text(value)
        if isinstance(value, list):
            redacted_items: list[JsonValue] = []
            triggered_rules: list[str] = []
            replacements = 0
            for item in value:
                redacted_item, item_rules, item_replacements = self._redact_value(item)
                redacted_items.append(redacted_item)
                triggered_rules.extend(item_rules)
                replacements += item_replacements
            return redacted_items, tuple(triggered_rules), replacements
        if isinstance(value, dict):
            redacted_mapping: dict[str, JsonValue] = {}
            triggered_rules = []
            replacements = 0
            for key, item in sorted(value.items(), key=lambda pair: pair[0]):
                redacted_key, key_rules, key_replacements = self._redact_text(key)
                unique_key = redacted_key
                collision_index = 2
                while unique_key in redacted_mapping:
                    unique_key = f"{redacted_key}#{collision_index}"
                    collision_index += 1
                redacted_item, item_rules, item_replacements = self._redact_value(item)
                redacted_mapping[unique_key] = redacted_item
                triggered_rules.extend(key_rules)
                triggered_rules.extend(item_rules)
                replacements += key_replacements + item_replacements
            return redacted_mapping, tuple(triggered_rules), replacements
        return value, (), 0

    def _redact_arguments(
        self,
        value: JsonValue,
    ) -> tuple[JsonValue, tuple[str, ...], int]:
        """Mask secret-bearing command options while retaining non-secret diagnostics."""
        if not isinstance(value, list):
            raise CaptureError("Command argument metadata must be a list of strings")
        arguments: list[str] = []
        for item in value:
            if not isinstance(item, str):
                raise CaptureError("Command argument metadata must be a list of strings")
            arguments.append(item)

        redacted_arguments: list[JsonValue] = []
        triggered_rules: list[str] = []
        replacements = 0
        redact_next = False
        for argument in arguments:
            if redact_next:
                redacted_arguments.append("[REDACTED:command-argument]")
                triggered_rules.append("command-argument")
                replacements += 1
                redact_next = False
                continue

            option_name, separator, _ = argument.partition("=")
            normalized_name = self._normalized_option_name(option_name)
            if normalized_name in SENSITIVE_ARGUMENT_NAMES:
                if separator:
                    redacted_arguments.append(f"{option_name}=[REDACTED:command-argument]")
                    triggered_rules.append("command-argument")
                    replacements += 1
                else:
                    redacted_arguments.append(argument)
                    redact_next = True
                continue

            redacted_argument, argument_rules, argument_replacements = self._redact_url_argument(
                argument
            )
            excluded_rules: set[str] = set()
            if "credential-url" in argument_rules:
                excluded_rules.add("credential-url")
            if "url-query" in argument_rules:
                excluded_rules.add("sensitive-assignment")
            redacted_argument, text_rules, text_replacements = self._redact_text(
                redacted_argument,
                excluded_rules=frozenset(excluded_rules),
            )
            redacted_arguments.append(redacted_argument)
            triggered_rules.extend(argument_rules)
            triggered_rules.extend(text_rules)
            replacements += argument_replacements + text_replacements

        return redacted_arguments, tuple(triggered_rules), replacements

    def _redact_url_argument(self, value: str) -> tuple[str, tuple[str, ...], int]:
        """Remove user information and sensitive query parameters from one URL argument."""
        try:
            parsed = urlsplit(value)
        except ValueError:
            return value, (), 0
        if not parsed.scheme or not parsed.netloc:
            return value, (), 0

        netloc = parsed.netloc
        triggered_rules: list[str] = []
        replacements = 0
        if parsed.username is not None or parsed.password is not None:
            host = parsed.hostname or ""
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            try:
                parsed_port = parsed.port
            except ValueError:
                parsed_port = None
            port = f":{parsed_port}" if parsed_port is not None else ""
            netloc = f"[REDACTED-credential-url]@{host}{port}"
            triggered_rules.append("credential-url")
            replacements += 1

        query_items: list[tuple[str, str]] = []
        for name, query_value in parse_qsl(parsed.query, keep_blank_values=True):
            if self._normalized_option_name(name) in SENSITIVE_ARGUMENT_NAMES:
                query_items.append((name, "[REDACTED:url-query]"))
                triggered_rules.append("url-query")
                replacements += 1
            else:
                query_items.append((name, query_value))
        query = urlencode(query_items, doseq=True)
        return (
            urlunsplit((parsed.scheme, netloc, parsed.path, query, parsed.fragment)),
            tuple(triggered_rules),
            replacements,
        )

    def _redact_text(
        self,
        value: str,
        *,
        excluded_rules: frozenset[str] | None = None,
    ) -> tuple[str, tuple[str, ...], int]:
        """Apply each named rule and retain useful non-secret surrounding context."""
        redacted_characters: list[str] = []
        format_character_count = 0
        for character in value:
            if unicodedata.category(character) == "Cf":
                redacted_characters.append("[REDACTED:format-character]")
                format_character_count += 1
            else:
                redacted_characters.append(character)
        redacted_value = "".join(redacted_characters)
        triggered_rules: list[str] = ["format-character"] * format_character_count
        replacements = format_character_count
        for rule in self._rules:
            if excluded_rules is not None and rule.name in excluded_rules:
                continue

            def replace_match(match: re.Match[str], rule_name: str = rule.name) -> str:
                """Replace one regex match while retaining rule-specific context."""
                return self._replacement(match, rule_name)

            redacted_value, replacement_count = rule.expression.subn(
                replace_match,
                redacted_value,
            )
            if replacement_count:
                triggered_rules.extend([rule.name] * replacement_count)
                replacements += replacement_count
        return redacted_value, tuple(triggered_rules), replacements

    def _validate_semantic_identifier(self, value: str, label: str) -> None:
        """Reject invalid or secret-bearing semantic identifiers before persistence."""
        if not IDENTIFIER_PATTERN.fullmatch(value):
            raise CaptureError(f"{label} is not a valid semantic identifier")
        redacted_value, _, replacements = self._redact_text(value)
        if replacements or redacted_value != value:
            raise CaptureError(f"{label} contains sensitive material")

    @staticmethod
    def _normalized_option_name(value: str) -> str:
        """Normalize command option and query names for exact secret-name matching."""
        return value.lstrip("-").strip().lower().replace("_", "-")

    @staticmethod
    def _home_directory_rules() -> tuple[CompiledRedactionRule, ...]:
        """Build one dynamic rule for native and slash-normalized home paths."""
        try:
            home_directory = Path.home().resolve(strict=True)
        except OSError:
            return ()
        if not home_directory.name:
            return ()
        path_variants = {str(home_directory), home_directory.as_posix()}
        pattern = "|".join(
            re.escape(path_variant) for path_variant in sorted(path_variants, key=len, reverse=True)
        )
        flags = re.IGNORECASE if Path("A") == Path("a") else 0
        return (CompiledRedactionRule("home-directory", re.compile(pattern, flags)),)

    @staticmethod
    def _replacement(match: re.Match[str], rule_name: str) -> str:
        """Preserve safe prefixes for structured credential patterns."""
        if rule_name == "authorization-header":
            return f"{match.group(1)}[REDACTED:{rule_name}]"
        if rule_name == "credential-url":
            return f"{match.group(1)}[REDACTED:{rule_name}]{match.group(2)}"
        if rule_name == "sensitive-assignment":
            return f"{match.group(1)}{match.group(2)}[REDACTED:{rule_name}]"
        return f"[REDACTED:{rule_name}]"
