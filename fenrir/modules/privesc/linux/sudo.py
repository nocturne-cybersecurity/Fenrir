from fenrir.interfaces.privesc import PrivEscModule


class SudoOpportunity(PrivEscModule):
    name = "linux_sudo_opportunity"
    priority = 20

    def discover(self, session_id, state):
        session = state.get(session_id)
        if session and session.data.get("platform") == "linux":
            return [{"type": "sudo", "status": "needs_manual_review"}]
        return []
