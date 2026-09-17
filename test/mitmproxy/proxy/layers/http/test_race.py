"""Unit tests for the HTTP/2 race group state machine."""

import pytest

from mitmproxy.io import tnetstring
from mitmproxy.proxy.layers.http._race import MemberState
from mitmproxy.proxy.layers.http._race import RaceGroupError
from mitmproxy.proxy.layers.http._race import RaceGroupSpec
from mitmproxy.proxy.layers.http._race import RaceRegistry
from mitmproxy.proxy.layers.http._race import spec_from_metadata


def test_register_creates_group_with_pending_member():
    """Test that the first registration creates the group and its member is pending."""
    reg = RaceRegistry()
    group = reg.register(1, "g", expected=2)
    assert group.members == {1: MemberState.PENDING}
    assert reg.group_for(1) is group
    assert not group.is_armed
    assert not group.is_failed


def test_group_for_unknown_stream_is_none():
    """Test that looking up a stream that was never registered returns None."""
    assert RaceRegistry().group_for(7) is None


def test_register_is_idempotent_for_an_identical_call():
    """Test that re-registering the same stream the same way changes nothing."""
    reg = RaceRegistry()
    first = reg.register(1, "g", expected=2)
    assert reg.register(1, "g", expected=2) is first
    assert first.members == {1: MemberState.PENDING}


def test_register_rejects_a_stream_already_in_another_group():
    """Test that a stream cannot belong to two groups at once."""
    reg = RaceRegistry()
    reg.register(1, "g", expected=2)
    with pytest.raises(RaceGroupError, match="already in group"):
        reg.register(1, "other", expected=2)


def test_register_rejects_oversubscription():
    """Test that a group cannot take more members than it expects."""
    reg = RaceRegistry()
    reg.register(1, "g", expected=2)
    reg.register(3, "g", expected=2)
    with pytest.raises(RaceGroupError, match="is full"):
        reg.register(5, "g", expected=2)


def test_register_rejects_an_inconsistent_expected_count():
    """Test that reusing a group id with a different size fails instead of silently winning."""
    reg = RaceRegistry()
    reg.register(1, "g", expected=2)
    with pytest.raises(RaceGroupError, match="expects 2 members, not 3"):
        reg.register(3, "g", expected=3)


def test_register_rejects_a_meaningless_size():
    """Test that a group must expect at least one member."""
    with pytest.raises(RaceGroupError, match="cannot expect"):
        RaceRegistry().register(1, "g", expected=0)


def test_group_arms_only_once_every_member_is_staged():
    """Test that a group arms when its last pending member is staged."""
    reg = RaceRegistry()
    reg.register(1, "g", expected=2)
    group = reg.register(3, "g", expected=2)

    reg.stage(1)
    assert not group.is_armed

    reg.stage(3)
    assert group.is_armed
    assert not group.is_failed


def test_a_released_group_is_not_armed():
    """Test that releasing a group takes it out of the armed state."""
    reg = RaceRegistry()
    group = reg.register(1, "g", expected=1)
    reg.stage(1)
    assert group.is_armed

    group.released = True
    assert not group.is_armed


def test_stage_rejects_a_non_member():
    """Test that staging a stream outside any group fails."""
    with pytest.raises(RaceGroupError, match="not a race group member"):
        RaceRegistry().stage(1)


def test_stage_rejects_a_repeated_stage():
    """Test that staging the same stream twice fails rather than passing silently."""
    reg = RaceRegistry()
    reg.register(1, "g", expected=1)
    reg.stage(1)
    with pytest.raises(RaceGroupError, match="from staged"):
        reg.stage(1)


def test_stage_rejects_a_lost_member():
    """Test that a lost member can never be staged."""
    reg = RaceRegistry()
    reg.register(1, "g", expected=1)
    reg.lose(1)
    with pytest.raises(RaceGroupError, match="from lost"):
        reg.stage(1)


def test_lose_marks_the_member_and_fails_the_group():
    """Test that losing a member leaves the group unsatisfiable rather than short."""
    reg = RaceRegistry()
    reg.register(1, "g", expected=2)
    group = reg.register(3, "g", expected=2)
    reg.stage(1)

    assert reg.lose(3) is group
    assert group.members[3] is MemberState.LOST
    assert group.is_failed
    # The group still has both members: it fails loudly instead of waiting forever.
    assert len(group.members) == 2
    assert not group.is_armed


def test_lose_after_staging_is_allowed():
    """Test that a member reset after staging is still marked lost."""
    reg = RaceRegistry()
    group = reg.register(1, "g", expected=1)
    reg.stage(1)
    reg.lose(1)
    assert group.is_failed
    assert not group.is_armed


def test_lose_ignores_streams_outside_any_group():
    """Test that resetting an unrelated stream is harmless."""
    assert RaceRegistry().lose(9) is None


def test_finish_removes_the_group_and_its_reverse_mappings():
    """Test that finishing a group leaves no half-dead state behind."""
    reg = RaceRegistry()
    reg.register(1, "g", expected=2)
    reg.register(3, "g", expected=2)

    reg.finish("g")

    assert reg.group_for(1) is None
    assert reg.group_for(3) is None
    # The stream ids are free to be registered again afterwards.
    reg.register(1, "g2", expected=1)
    assert reg.group_for(1).id == "g2"


def test_finish_is_harmless_for_an_unknown_group():
    """Test that finishing a group that is already gone does nothing."""
    RaceRegistry().finish("nope")


def test_clear_drops_every_group():
    """Test that clearing the registry forgets all groups and mappings."""
    reg = RaceRegistry()
    reg.register(1, "g", expected=1)
    reg.register(3, "h", expected=1)

    reg.clear()

    assert reg.group_for(1) is None
    assert reg.group_for(3) is None


def test_spec_from_metadata_without_a_declaration():
    """Test that a flow carrying no declaration produces no spec."""
    assert spec_from_metadata({}) is None


def test_spec_from_metadata_reads_a_declaration():
    """Test that a well-formed declaration is read off the metadata."""
    spec = spec_from_metadata({"race_group": {"id": "coupons", "expected": 3}})
    assert spec == RaceGroupSpec("coupons", 3)


def test_spec_from_metadata_rejects_a_spec_object():
    """Test that the declaration must stay a plain dict."""
    # flow.metadata is tnetstring-serialised when flows are saved, and anything
    # that is not a plain type makes saving fail.
    with pytest.raises(RaceGroupError, match="must be a dict"):
        spec_from_metadata({"race_group": RaceGroupSpec("coupons", 3)})


def test_a_declaration_survives_flow_serialisation():
    """Test that the declared dict can be written out with the flow."""
    declaration = {"id": "coupons", "expected": 3}
    assert spec_from_metadata({"race_group": declaration}) == RaceGroupSpec(
        "coupons", 3
    )
    assert tnetstring.loads(tnetstring.dumps({"race_group": declaration})) == {
        "race_group": declaration
    }


@pytest.mark.parametrize(
    "declaration",
    [
        "coupons",
        {"id": "", "expected": 3},
        {"id": 7, "expected": 3},
        {"expected": 3},
        {"id": "coupons", "expected": 0},
        {"id": "coupons", "expected": -1},
        {"id": "coupons", "expected": "3"},
        {"id": "coupons", "expected": True},
        {"id": "coupons"},
    ],
)
def test_spec_from_metadata_rejects_a_malformed_declaration(declaration):
    """Test that a malformed declaration is reported rather than half-read."""
    with pytest.raises(RaceGroupError):
        spec_from_metadata({"race_group": declaration})
