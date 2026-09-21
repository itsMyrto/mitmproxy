import enum
from dataclasses import dataclass
from dataclasses import field


class RaceGroupError(Exception):
    """An illegal race group registration or state transition."""


class MemberState(enum.Enum):
    """Lifecycle of a single stream within a race group."""

    PENDING = "pending"
    """Registered as a member, but its completion has not been withheld yet."""
    STAGED = "staged"
    """Completion withheld and ready to be released with the rest of the group."""
    LOST = "lost"
    """Gone for good, so the group can never complete."""


@dataclass
class RaceGroup:
    """A set of streams on one connection whose completions are released together."""

    id: str
    expected: int
    members: dict[int, MemberState] = field(default_factory=dict)
    released: bool = False

    @property
    def is_armed(self) -> bool:
        """Check if every expected member is staged and nothing has been released yet."""
        return (
            not self.released
            and len(self.members) == self.expected
            and all(state is MemberState.STAGED for state in self.members.values())
        )

    @property
    def is_failed(self) -> bool:
        """Check if any member can no longer take part."""
        return any(state is MemberState.LOST for state in self.members.values())


class RaceRegistry:
    """Owns the race groups on a connection and every transition their members make."""

    def __init__(self) -> None:
        self._groups: dict[str, RaceGroup] = {}
        self._group_of: dict[int, str] = {}

    def register(self, stream_id: int, group_id: str, expected: int) -> RaceGroup:
        """Add a stream to a group, creating the group if this is its first member."""
        if expected < 1:
            raise RaceGroupError(f"group {group_id!r} cannot expect {expected} members")
        group = self._groups.get(group_id)
        if group is None:
            group = self._groups[group_id] = RaceGroup(group_id, expected)
        elif group.expected != expected:
            raise RaceGroupError(
                f"group {group_id!r} expects {group.expected} members, not {expected}"
            )

        current = self._group_of.get(stream_id)
        if current is not None:
            if current != group_id:
                raise RaceGroupError(
                    f"stream {stream_id} is already in group {current!r}"
                )
            return group  # idempotent: same stream, same group, same size.
        if len(group.members) >= group.expected:
            raise RaceGroupError(
                f"group {group_id!r} is full at {group.expected} members"
            )

        group.members[stream_id] = MemberState.PENDING
        self._group_of[stream_id] = group_id
        return group

    def group_for(self, stream_id: int) -> RaceGroup | None:
        """Look up the group a stream belongs to, if any."""
        group_id = self._group_of.get(stream_id)
        return self._groups[group_id] if group_id is not None else None

    def group(self, group_id: str) -> RaceGroup | None:
        """Look up a group by name, if it is still live."""
        return self._groups.get(group_id)

    def stage(self, stream_id: int) -> RaceGroup:
        """Mark a member's completion as withheld and ready to release."""
        group = self.group_for(stream_id)
        if group is None:
            raise RaceGroupError(f"stream {stream_id} is not a race group member")
        state = group.members[stream_id]
        if state is not MemberState.PENDING:
            raise RaceGroupError(f"cannot stage stream {stream_id} from {state.value}")
        group.members[stream_id] = MemberState.STAGED
        return group

    def lose(self, stream_id: int) -> RaceGroup | None:
        """Mark a member as gone, which leaves its group permanently unsatisfiable."""
        group = self.group_for(stream_id)
        if group is None:
            return None
        group.members[stream_id] = MemberState.LOST
        return group

    def finish(self, group_id: str) -> None:
        """Drop a group and every mapping pointing at it."""
        group = self._groups.pop(group_id, None)
        if group is None:
            return
        for stream_id in group.members:
            self._group_of.pop(stream_id, None)

    def clear(self) -> None:
        """Drop every group on this connection."""
        self._groups.clear()
        self._group_of.clear()
