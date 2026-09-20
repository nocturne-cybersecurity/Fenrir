from fenrir.interfaces.post import PostModule


class SessionSystemMetadata(PostModule):
    name = "session_system_metadata"
    priority = 30

    def inspect(self, session_id, state):
        session = state.get(session_id)
        return {
            "session_id": session_id,
            "platform": session.data.get("platform", "unknown") if session else "unknown",
            "architecture": session.data.get("architecture", "unknown") if session else "unknown",
        }
