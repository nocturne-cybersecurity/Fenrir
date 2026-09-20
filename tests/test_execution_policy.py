from fenrir.core.capabilities import Capability, ExecutionPolicy


def test_policy_escalates_only_when_explicitly_requested():
    assert ExecutionPolicy.from_flags().max_capability is Capability.VALIDATION
    assert ExecutionPolicy.from_flags(exploit=True).allows(Capability.EXPLOIT)
    assert ExecutionPolicy.from_flags(post=True).allows(Capability.POST_EXPLOITATION)
    assert ExecutionPolicy.from_flags(privesc=True).allows(Capability.PRIVILEGE_ESCALATION)
    assert not ExecutionPolicy.from_flags().allows(Capability.EXPLOIT)
