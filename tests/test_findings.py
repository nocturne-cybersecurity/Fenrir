import pytest

from fenrir.core.state import Finding, FindingStatus, StateGraph


def test_finding_is_stored_in_state_and_can_be_confirmed():
    state = StateGraph()
    finding = Finding(
        target="23.227.38.68",
        service="http",
        title="Exposed administrative endpoint",
        severity="medium",
        confidence=0.82,
        evidence=[{"url": "http://23.227.38.68/admin"}],
        references=["CWE-200"],
    )

    state.add_finding(finding)
    confirmed = state.update_finding_status(finding.id, FindingStatus.CONFIRMED)

    assert confirmed.status is FindingStatus.CONFIRMED
    assert state.findings(status="confirmed")[0].title == finding.title
    assert state.get(finding.id).type.value == "finding"


def test_finding_rejects_invalid_transition_and_confidence():
    with pytest.raises(ValueError, match="between 0 and 1"):
        Finding("target", "http", "title", "low", 1.1)

    finding = Finding("target", None, "title", "low", 0.5)
    finding.transition_to(FindingStatus.CONFIRMED)
    with pytest.raises(ValueError, match="invalid finding transition"):
        finding.transition_to(FindingStatus.POTENTIAL)


def test_finding_serialization_preserves_lifecycle_fields():
    finding = Finding("target", "ssh", "Weak configuration", "high", 0.9)

    serialized = finding.to_dict()

    assert serialized["id"] == finding.id
    assert serialized["status"] == "potential"
    assert serialized["service"] == "ssh"
