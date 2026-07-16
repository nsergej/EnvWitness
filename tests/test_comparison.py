from __future__ import annotations

import pytest

from envwitness.application.services import ComparisonService, ReportRenderer
from envwitness.domain.models import Capsule, DiagnosticHint, EvidenceFact, Sensitivity


def capsule_with(
    sample_capsule: Capsule,
    facts: tuple[EvidenceFact, ...],
    identifier: str,
) -> Capsule:
    return sample_capsule.model_copy(
        update={"capsule_identifier": identifier, "facts": facts, "integrity": None}
    ).seal()


def fact(key: str, value: object) -> EvidenceFact:
    return EvidenceFact.create(
        key=key,
        value=value,
        collector="test",
        source="test fixture",
        sensitivity=Sensitivity.PUBLIC,
    )


def test_identical_capsules_have_no_differences(sample_capsule: Capsule) -> None:
    report = ComparisonService().compare(sample_capsule, sample_capsule)
    assert report.identical is True
    assert report.differences == ()
    assert "No semantic drift" in ReportRenderer().comparison_to_markdown(report)


def test_comparison_ranks_runtime_and_source_hints(sample_capsule: Capsule) -> None:
    baseline = capsule_with(
        sample_capsule,
        (fact("runtime.python.version", "3.12"), fact("git.commit", "a" * 40)),
        "ew-baseline-01234567",
    )
    candidate = capsule_with(
        sample_capsule,
        (
            fact("runtime.python.version", "3.13"),
            fact("git.commit", "b" * 40),
            fact("command.exit_code", 1),
        ),
        "ew-candidate-0123456",
    )
    report = ComparisonService().compare(baseline, candidate)
    assert report.identical is False
    assert report.differences[0].severity.value == "critical"
    assert [hint.code for hint in report.hints] == [
        "RUNTIME_DRIFT",
        "SOURCE_STATE_DRIFT",
        "COMMAND_OUTCOME_DRIFT",
    ]
    assert "runtime.python.version" in ReportRenderer().comparison_to_markdown(report)


def test_comparison_reports_removed_fact(sample_capsule: Capsule) -> None:
    candidate = capsule_with(sample_capsule, (), "ew-candidate-0123456")
    report = ComparisonService().compare(sample_capsule, candidate)
    assert report.differences[0].kind.value == "removed"


def test_comparison_classifies_informational_fact_and_lockfile_hint(
    sample_capsule: Capsule,
) -> None:
    baseline = capsule_with(
        sample_capsule,
        (fact("application.mode", "development"), fact("file.hash.lock", "a")),
        "ew-baseline-01234567",
    )
    candidate = capsule_with(
        sample_capsule,
        (fact("application.mode", "production"), fact("file.hash.lock", "b")),
        "ew-candidate-0123456",
    )

    report = ComparisonService().compare(baseline, candidate)

    severities = {difference.key: difference.severity.value for difference in report.differences}
    assert severities["application.mode"] == "information"
    assert [hint.code for hint in report.hints] == ["DEPENDENCY_INPUT_DRIFT"]


def test_capsule_markdown_does_not_activate_injected_markup(sample_capsule: Capsule) -> None:
    markdown_it = pytest.importorskip("markdown_it")
    hostile_fact = fact(
        "runtime.hostile.value",
        "````` | <img src=x onerror=alert(1)>\n# injected",
    )
    hostile_capsule = sample_capsule.model_copy(
        update={
            "project_name": "<img src=x onerror=alert(1)>\n# injected",
            "facts": (hostile_fact,),
            "integrity": None,
        }
    ).seal()

    markdown = ReportRenderer().capsule_to_markdown(hostile_capsule)
    rendered_html = (
        markdown_it.MarkdownIt(
            "commonmark",
            {"html": True},
        )
        .enable("table")
        .render(markdown)
    )

    assert "<img" not in rendered_html
    assert rendered_html.count("<h1>") == 1
    assert "<table>" in rendered_html


def test_comparison_markdown_does_not_activate_hint_markup(sample_capsule: Capsule) -> None:
    markdown_it = pytest.importorskip("markdown_it")
    baseline = capsule_with(
        sample_capsule,
        (fact("runtime.python.version", "baseline | ```"),),
        "ew-baseline-01234567",
    )
    candidate = capsule_with(
        sample_capsule,
        (fact("runtime.python.version", "![x](javascript:alert(1))"),),
        "ew-candidate-0123456",
    )
    report = (
        ComparisonService()
        .compare(baseline, candidate)
        .model_copy(
            update={
                "hints": (
                    DiagnosticHint(
                        code="SAFE_RENDERING",
                        priority=1,
                        title="`` <img src=x onerror=alert(1)>",
                        explanation="[click](javascript:alert(1))",
                        related_keys=("runtime.python.version",),
                    ),
                )
            }
        )
    )

    markdown = ReportRenderer().comparison_to_markdown(report)
    rendered_html = (
        markdown_it.MarkdownIt(
            "commonmark",
            {"html": True},
        )
        .enable("table")
        .render(markdown)
    )

    assert "<img" not in rendered_html
    assert "<a href" not in rendered_html
    assert "<table>" in rendered_html


def test_markdown_renderer_escapes_unicode_display_controls() -> None:
    rendered = ReportRenderer._code_span("safe\u202eunsafe")

    assert "\u202e" not in rendered
    assert "\\u202e" in rendered
