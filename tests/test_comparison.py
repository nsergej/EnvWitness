from __future__ import annotations

from envwitness.application.services import ComparisonService, ReportRenderer
from envwitness.domain.models import Capsule, EvidenceFact, Sensitivity


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
