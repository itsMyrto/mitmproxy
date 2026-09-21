from logging import WARNING

import hyperframe.frame
import pytest

from mitmproxy.http import Headers
from mitmproxy.http import HTTPFlow
from mitmproxy.http import RaceGroupSpec
from mitmproxy.http import Request
from mitmproxy.proxy.commands import Log
from mitmproxy.proxy.commands import RequestWakeup
from mitmproxy.proxy.commands import SendData
from mitmproxy.proxy.events import DataReceived
from mitmproxy.proxy.layers.http import HttpStream
from mitmproxy.proxy.layers.http import RequestData
from mitmproxy.proxy.layers.http import RequestEndOfMessage
from mitmproxy.proxy.layers.http import RequestHeaders
from mitmproxy.proxy.layers.http import ResponseProtocolError
from mitmproxy.proxy.layers.http import SendHttp
from mitmproxy.proxy.layers.http._base import ReceiveHttp
from mitmproxy.proxy.layers.http._http2 import Http2Client
from mitmproxy.proxy.layers.http._race import MemberState
from mitmproxy.proxy.layers.http._race import RaceGroupError
from mitmproxy.proxy.layers.http._race import RaceRegistry
from test.mitmproxy.proxy.layers.http.test_http2 import decode_frames
from test.mitmproxy.proxy.tutils import Placeholder
from test.mitmproxy.proxy.tutils import Playbook
from test.mitmproxy.proxy.tutils import reply

_WINDOW = 65535
"""The flow control window a connection and each of its streams start with."""


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


def test_register_race_member_registers_the_upstream_stream_id(tctx):
    """Test that a declared member is registered under the id h2 will send on."""
    client = Http2Client(tctx)
    assert list(client.register_race_member(5, RaceGroupSpec("coupons", 2))) == []

    group = client.race_groups.group_for(5)
    assert group is not None
    assert group.id == "coupons"
    assert group.members == {5: MemberState.PENDING}


def test_register_race_member_refuses_a_group_over_the_concurrency_limit(tctx):
    """Test that a group larger than the connection allows is declined, not queued."""
    client = Http2Client(tctx)
    oversized = client.provisional_max_concurrency + 1

    logs = list(client.register_race_member(1, RaceGroupSpec("coupons", oversized)))

    assert len(logs) == 1
    assert "exceed" in logs[0].message
    assert client.race_groups.group_for(1) is None


def _race_playbook(tctx, spec, members=3):
    """Drive an h2 client up to the point where every member has sent its headers."""
    tctx.options.http2_ping_keepalive = 0
    tctx.server.alpn = b"h2"
    playbook = Playbook(Http2Client(tctx), hooks=False)
    req = Request.make("GET", "http://example.com/")
    headers = [Placeholder(bytes) for _ in range(members)]

    playbook << SendData(tctx.server, Placeholder(bytes))  # preamble + settings
    for i in range(members):
        playbook >> RequestHeaders(i + 1, req, end_stream=True, race_group=spec)
        playbook << SendData(tctx.server, headers[i])
    return playbook, headers


def test_race_member_headers_do_not_carry_end_stream(tctx):
    """Test that a member keeps a completion frame of its own to withhold."""
    # A bodyless request would normally finish on its headers, leaving nothing to
    # hold back, so END_STREAM has to be forced off for group members.
    playbook, headers = _race_playbook(tctx, RaceGroupSpec("coupons", 3))
    assert playbook

    for raw in headers:
        (frame,) = decode_frames(raw())
        assert isinstance(frame, hyperframe.frame.HeadersFrame)
        assert "END_STREAM" not in frame.flags


def test_race_group_completions_leave_in_one_send_data(tctx):
    """Test that a full group's completions are written as a single SendData."""
    playbook, _ = _race_playbook(tctx, RaceGroupSpec("coupons", 3))
    released = Placeholder(bytes)

    assert (
        playbook
        # The first two completions are withheld; only the deadline is armed.
        >> RequestEndOfMessage(1)
        << RequestWakeup(10)
        >> RequestEndOfMessage(2)
        >> RequestEndOfMessage(3)
        << SendData(tctx.server, released)
    )

    frames = decode_frames(released())
    assert [f.stream_id for f in frames] == [1, 3, 5]
    assert all(
        isinstance(f, hyperframe.frame.DataFrame) and "END_STREAM" in f.flags
        for f in frames
    )


def test_a_members_final_body_byte_is_withheld(tctx):
    """Test that a member's body goes out one byte short, and that byte completes it."""
    # Sending the whole body and withholding only the empty END_STREAM frame is
    # not enough: a server that completes a message from content-length rather
    # than from END_STREAM would start work as soon as the body landed.
    playbook, _ = _race_playbook(tctx, RaceGroupSpec("coupons", 3))
    body = Placeholder(bytes)
    released = Placeholder(bytes)

    assert (
        playbook
        >> RequestData(1, b"hello")
        << SendData(tctx.server, body)
        >> RequestEndOfMessage(1)
        << RequestWakeup(10)
        >> RequestEndOfMessage(2)
        >> RequestEndOfMessage(3)
        << SendData(tctx.server, released)
    )

    (sent,) = decode_frames(body())
    assert sent.data == b"hell"
    assert "END_STREAM" not in sent.flags

    frames = decode_frames(released())
    assert [(f.stream_id, f.data) for f in frames] == [(1, b"o"), (3, b""), (5, b"")]
    assert all("END_STREAM" in f.flags for f in frames)


def test_only_the_last_byte_of_a_chunked_body_is_withheld(tctx):
    """Test that a later body chunk frees the byte an earlier one held back."""
    playbook, _ = _race_playbook(tctx, RaceGroupSpec("coupons", 1), members=1)
    sent = Placeholder(bytes)
    released = Placeholder(bytes)

    assert (
        playbook
        # Nothing to send yet: this single byte might still be the body's last.
        >> RequestData(1, b"a")
        >> RequestData(1, b"bc")
        << SendData(tctx.server, sent)
        >> RequestEndOfMessage(1)
        << RequestWakeup(10)
        << SendData(tctx.server, released)
    )

    assert decode_frames(sent())[0].data == b"ab"
    assert decode_frames(released())[0].data == b"c"


def test_a_withheld_byte_with_no_window_left_fails_the_group(tctx):
    """Test that a member whose held byte cannot leave fails the group loudly."""
    # The body drains the flow control window exactly, so nothing is buffered,
    # but the held byte still has no room -- unlike the empty END_STREAM frame it
    # replaces, which flow control never applied to.
    playbook, _ = _race_playbook(tctx, RaceGroupSpec("coupons", 3))
    released = Placeholder(bytes)

    assert (
        playbook
        >> RequestData(1, b"x" * (_WINDOW + 1))
        << SendData(tctx.server, Placeholder(bytes))
        >> RequestEndOfMessage(1)
        << RequestWakeup(10)
        >> RequestEndOfMessage(2)
        >> RequestEndOfMessage(3)
        << Log(
            "Race group 'coupons' cannot be released in one write. Releasing "
            "3/3 held members un-raced, 1 still blocked by flow control.",
            WARNING,
        )
        << SendData(tctx.server, released)
    )

    assert [f.stream_id for f in decode_frames(released())] == [3, 5]


def test_withheld_bytes_share_one_connection_window(tctx):
    """Test that held bytes are checked against the window they all draw on."""
    # Each member's byte fits its own stream window, but the three of them do not
    # fit the two bytes of connection window left between them.
    playbook, _ = _race_playbook(tctx, RaceGroupSpec("coupons", 3))
    released = Placeholder(bytes)

    assert (
        playbook
        >> RequestData(1, b"a" * (_WINDOW - 3))  # leaves 4 bytes, holds 1 back
        << SendData(tctx.server, Placeholder(bytes))
        >> RequestData(2, b"bb")
        << SendData(tctx.server, Placeholder(bytes))
        >> RequestData(3, b"cc")
        << SendData(tctx.server, Placeholder(bytes))
        >> RequestEndOfMessage(1)
        << RequestWakeup(10)
        >> RequestEndOfMessage(2)
        >> RequestEndOfMessage(3)
        << Log(
            "Race group 'coupons' cannot be released in one write. Releasing "
            "3/3 held members un-raced, 1 still blocked by flow control.",
            WARNING,
        )
        << SendData(tctx.server, released)
    )

    assert [f.stream_id for f in decode_frames(released())] == [1, 3]


def test_a_member_that_stops_racing_gets_its_withheld_byte_back(tctx):
    """Test that giving up on a group does not truncate a member still in flight."""
    # A member whose body is still arriving when the group is retired goes on as
    # an ordinary request. Its own completion ends the stream and carries no body,
    # so the byte held back from it has to be handed over first.
    playbook, _ = _race_playbook(tctx, RaceGroupSpec("coupons", 2), members=2)
    released = Placeholder(bytes)
    completion = Placeholder(bytes)

    assert (
        playbook
        >> RequestData(1, b"hello")
        << SendData(tctx.server, Placeholder(bytes))
        >> RequestData(2, b"world")
        << SendData(tctx.server, Placeholder(bytes))
        # Only the first member completes, so the deadline gives up on the group
        # while the second is still mid-body.
        >> RequestEndOfMessage(1)
        << RequestWakeup(10)
        >> reply(to=-1)
        << Log(Placeholder(str), WARNING)
        << SendData(tctx.server, released)
        >> RequestEndOfMessage(2)
        << SendData(tctx.server, completion)
    )

    # The first member is completed by its held byte, the second is handed its
    # own back without being completed.
    assert [(f.stream_id, f.data) for f in decode_frames(released())] == [
        (1, b"o"),
        (3, b"d"),
    ]
    assert "END_STREAM" not in decode_frames(released())[1].flags
    (end,) = decode_frames(completion())
    assert (end.stream_id, end.data) == (3, b"")
    assert "END_STREAM" in end.flags


def test_a_lost_members_withheld_byte_is_dropped(tctx):
    """Test that a member that never completes leaves no held byte behind."""
    playbook, _ = _race_playbook(tctx, RaceGroupSpec("coupons", 2), members=2)
    rst = hyperframe.frame.RstStreamFrame(stream_id=1)
    rst.error_code = 8  # CANCEL

    assert (
        playbook
        >> RequestData(1, b"hello")
        << SendData(tctx.server, Placeholder(bytes))
        >> DataReceived(tctx.server, rst.serialize())
        << ReceiveHttp(Placeholder(ResponseProtocolError))
        >> RequestEndOfMessage(2)
        << RequestWakeup(10)
        << Log(
            "Race group 'coupons' lost a member. Releasing 1/2 held members "
            "un-raced, 1 lost to a stream reset.",
            WARNING,
        )
        << SendData(tctx.server, Placeholder(bytes))
    )

    assert playbook.layer._race_tails == {}


def test_race_group_times_out_and_releases_un_raced(tctx):
    """Test that a group missing a member is released normally when the clock runs out."""
    playbook, _ = _race_playbook(tctx, RaceGroupSpec("coupons", 3))
    released = Placeholder(bytes)

    assert (
        playbook
        >> RequestEndOfMessage(1)
        << RequestWakeup(10)
        >> RequestEndOfMessage(2)
        # The third member never arrives and the deadline fires.
        >> reply(to=-2)
        << Log(
            "Race group 'coupons' timed out after 10s -- the rest either never "
            "arrived or went to another connection. Releasing 2/3 held members "
            "un-raced.",
            WARNING,
        )
        << SendData(tctx.server, released)
    )

    frames = decode_frames(released())
    assert [f.stream_id for f in frames] == [1, 3]
    assert all("END_STREAM" in f.flags for f in frames)


def test_race_group_fails_when_a_member_is_stuck_behind_flow_control(tctx):
    """Test that a member whose body is still queued fails the group loudly."""
    # Its completion would be appended to that queue rather than serialised, so it
    # would quietly miss the release. The group must refuse instead.
    playbook, _ = _race_playbook(tctx, RaceGroupSpec("coupons", 3))
    body = Placeholder(bytes)
    released = Placeholder(bytes)

    assert (
        playbook
        # Overshoot the 65535-byte window so a remainder stays buffered.
        >> RequestData(1, b"x" * 70000)
        << SendData(tctx.server, body)
        >> RequestEndOfMessage(1)
        << RequestWakeup(10)
        >> RequestEndOfMessage(2)
        >> RequestEndOfMessage(3)
        << Log(
            "Race group 'coupons' cannot be released in one write. Releasing "
            "3/3 held members un-raced, 1 still blocked by flow control.",
            WARNING,
        )
        << SendData(tctx.server, released)
    )

    # The stuck member is not in the write; the other two complete normally.
    assert [f.stream_id for f in decode_frames(released())] == [3, 5]


def test_race_group_fails_when_a_member_is_reset(tctx):
    """Test that a member lost to a stream reset fails the group rather than hanging."""
    playbook, _ = _race_playbook(tctx, RaceGroupSpec("coupons", 3))
    rst = hyperframe.frame.RstStreamFrame(stream_id=1)
    rst.error_code = 8  # CANCEL
    survivor = Placeholder(bytes)
    latecomer = Placeholder(bytes)

    assert (
        playbook
        >> RequestEndOfMessage(1)
        << RequestWakeup(10)
        >> DataReceived(tctx.server, rst.serialize())
        << ReceiveHttp(Placeholder(ResponseProtocolError))
        # The group is now unwinnable, so the next member to arrive gives up at
        # once rather than holding the survivors until everyone has shown up.
        >> RequestEndOfMessage(2)
        << Log(
            "Race group 'coupons' lost a member. Releasing 1/3 held members "
            "un-raced, 1 lost to a stream reset.",
            WARNING,
        )
        << SendData(tctx.server, survivor)
        # With the group retired, the last member is no longer held at all.
        >> RequestEndOfMessage(3)
        << SendData(tctx.server, latecomer)
    )

    assert [f.stream_id for f in decode_frames(survivor())] == [3]
    assert [f.stream_id for f in decode_frames(latecomer())] == [5]


def test_a_reused_group_id_gets_its_own_deadline(tctx):
    """Test that a second group of the same name is not starved by the first's timer."""
    # A retired group used to leave its deadline behind, so the next group with
    # that name armed none of its own and was then killed by the stale one.
    tctx.options.http2_ping_keepalive = 0
    tctx.server.alpn = b"h2"
    playbook = Playbook(Http2Client(tctx), hooks=False)
    spec = RaceGroupSpec("coupons", 2)
    req = Request.make("GET", "http://example.com/")

    playbook << SendData(tctx.server, Placeholder(bytes))
    for i in (1, 2):
        playbook >> RequestHeaders(i, req, end_stream=True, race_group=spec)
        playbook << SendData(tctx.server, Placeholder(bytes))

    assert (
        playbook
        >> RequestEndOfMessage(1)
        << RequestWakeup(10)
        >> RequestEndOfMessage(2)
        << SendData(tctx.server, Placeholder(bytes))
    )

    # Second group, same name, on the same connection.
    for i in (3, 4):
        playbook >> RequestHeaders(i, req, end_stream=True, race_group=spec)
        playbook << SendData(tctx.server, Placeholder(bytes))

    second = Placeholder(bytes)
    assert (
        playbook
        >> RequestEndOfMessage(3)
        << RequestWakeup(10)  # its own deadline, not the first group's leftover
        >> RequestEndOfMessage(4)
        << SendData(tctx.server, second)
    )
    assert [f.stream_id for f in decode_frames(second())] == [5, 7]


def test_register_race_member_counts_only_free_streams(tctx):
    """Test that a group larger than the remaining capacity is refused."""
    # Members that fit would otherwise hold the connection at capacity while the
    # rest sit in stream_queue waiting for a slot only this group can free.
    tctx.options.http2_ping_keepalive = 0
    tctx.server.alpn = b"h2"
    client = Http2Client(tctx)
    playbook = Playbook(client, hooks=False)
    req = Request.make("GET", "http://example.com/")

    playbook << SendData(tctx.server, Placeholder(bytes))
    for i in range(1, 6):  # five ordinary requests, left open
        playbook >> RequestHeaders(i, req, end_stream=False)
        playbook << SendData(tctx.server, Placeholder(bytes))
    assert playbook

    logs = list(client.register_race_member(99, RaceGroupSpec("coupons", 10)))
    assert len(logs) == 1
    assert "5 of 10 concurrent streams still free" in logs[0].message
    assert client.race_groups.group_for(99) is None


def test_race_members_ready_rejects_queued_trailers(tctx):
    """Test that a member with trailers queued is not treated as releasable."""
    # A guard-rail, not a reachable path: HttpStream refuses a declaration on a
    # request with trailers, so this state cannot occur today. It is poked into
    # place directly. If that refusal is ever relaxed, this is the second line of
    # defence -- so do not read this test as covering the HttpStream check.
    client = Http2Client(tctx)
    group = client.race_groups.register(1, "coupons", 1)
    assert client.race_members_ready(group)

    client.h2_conn.stream_trailers[1] = [(b"x-trailer", b"1")]
    assert not client.race_members_ready(group)


def test_a_request_with_trailers_is_not_raced(tctx):
    """Test that a declared request with trailers is dropped from its group."""
    tctx.server.alpn = b"h2"
    stream = HttpStream(tctx, 1)
    stream.flow = HTTPFlow(tctx.client, tctx.server)
    stream.flow.request = Request.make("POST", "http://example.com/", b"body")
    stream.flow.request.trailers = Headers([(b"x-trailer", b"1")])
    stream.flow.request.race_group = RaceGroupSpec("coupons", 2)

    commands = list(stream.send_buffered_request())

    warning = commands[0]
    assert (
        "a request with trailers cannot have its completion withheld" in warning.message
    )
    headers = next(
        c.event
        for c in commands
        if isinstance(c, SendHttp) and isinstance(c.event, RequestHeaders)
    )
    assert headers.race_group is None


def _declared_stream(tctx, alpn=b"h2", streamed=False):
    """Build an HttpStream whose flow carries a race group declaration."""
    tctx.server.alpn = alpn
    stream = HttpStream(tctx, 1)
    stream.flow = HTTPFlow(tctx.client, tctx.server)
    stream.flow.request = Request.make("POST", "http://example.com/", b"body")
    stream.flow.request.stream = streamed
    stream.flow.request.race_group = RaceGroupSpec("coupons", 2)
    return stream


def test_a_declaration_over_a_non_h2_upstream_is_refused(tctx):
    """Test that declaring a race on an HTTP/1 or HTTP/3 upstream says so."""
    # Only the HTTP/2 client layer can withhold a completion, so anywhere else the
    # declaration would otherwise be ignored without a word.
    stream = _declared_stream(tctx, alpn=b"http/1.1")

    (log,) = list(stream.race_group_for_request())

    assert "needs an HTTP/2 upstream connection" in log.message


def test_a_streamed_request_is_not_raced(tctx):
    """Test that a streamed request explains why it cannot take part."""
    stream = _declared_stream(tctx, streamed=True)

    (log,) = list(stream.race_group_for_request())

    assert "streamed request cannot have its completion withheld" in log.message


def test_an_undeclared_request_is_silent(tctx):
    """Test that a request with no declaration produces no chatter."""
    tctx.server.alpn = b"h2"
    stream = HttpStream(tctx, 1)
    stream.flow = HTTPFlow(tctx.client, tctx.server)
    stream.flow.request = Request.make("GET", "http://example.com/")

    assert list(stream.race_group_for_request()) == []


def test_stage_degrades_instead_of_tearing_down_the_connection(tctx):
    """Test that an illegal state transition sends the request rather than raising."""
    client = Http2Client(tctx)
    client.race_groups.register(1, "coupons", 2)
    list(client.stage_race_member(1))  # legitimate first staging

    logs = list(client.stage_race_member(1))  # cannot stage twice

    assert any("sending this request un-raced" in log.message for log in logs)


def test_a_retired_groups_deadline_fires_harmlessly(tctx):
    """Test that the wakeup left over from a released group does nothing at all."""
    # The wakeup is already scheduled when the first member is held and cannot be
    # unscheduled, so its entry has to stay recognisable. Forgetting it instead
    # would send it to the ping keepalive branch, which reschedules itself -- one
    # permanent extra PING timer per race, and with http2_ping_keepalive=0 a tight
    # loop, because that branch then yields a negative delay.
    playbook, _ = _race_playbook(tctx, RaceGroupSpec("coupons", 3))

    assert (
        playbook
        >> RequestEndOfMessage(1)
        << RequestWakeup(10)
        >> RequestEndOfMessage(2)
        >> RequestEndOfMessage(3)
        << SendData(tctx.server, Placeholder(bytes))
        # The deadline now fires against a group that has already gone.
        >> reply(to=-5)
    )

    assert playbook.layer._race_deadlines == {}


def test_register_race_member_reports_a_contradictory_declaration(tctx):
    """Test that two different sizes for one group id are refused with the reason."""
    client = Http2Client(tctx)
    list(client.register_race_member(1, RaceGroupSpec("coupons", 2)))

    logs = list(client.register_race_member(3, RaceGroupSpec("coupons", 3)))

    assert len(logs) == 1
    assert "expects 2 members, not 3" in logs[0].message


def test_a_repeated_completion_is_sent_un_raced(tctx):
    """Test that a second completion for a staged member is sent rather than raised."""
    playbook, _ = _race_playbook(tctx, RaceGroupSpec("coupons", 2), members=2)
    sent = Placeholder(bytes)

    assert (
        playbook
        >> RequestEndOfMessage(1)
        << RequestWakeup(10)
        # The same member completes again: bookkeeping refuses, but the request
        # must still go out rather than taking the connection down.
        >> RequestEndOfMessage(1)
        << Log(
            "Race group: cannot stage stream 1 from staged; sending this request "
            "un-raced.",
            WARNING,
        )
        << SendData(tctx.server, sent)
    )
    assert [f.stream_id for f in decode_frames(sent())] == [1]


def test_an_un_raced_completion_still_carries_the_withheld_byte(tctx):
    """Test that degrading to an un-raced send does not truncate the body."""
    # The withheld byte is the last byte of the request, so whatever path ends the
    # stream has to send it -- an empty END_STREAM frame would complete the
    # message a byte short.
    playbook, _ = _race_playbook(tctx, RaceGroupSpec("coupons", 2), members=2)
    sent = Placeholder(bytes)

    assert (
        playbook
        >> RequestData(1, b"hello")
        << SendData(tctx.server, Placeholder(bytes))
        >> RequestEndOfMessage(1)
        << RequestWakeup(10)
        >> RequestEndOfMessage(1)
        << Log(
            "Race group: cannot stage stream 1 from staged; sending this request "
            "un-raced.",
            WARNING,
        )
        << SendData(tctx.server, sent)
    )

    (frame,) = decode_frames(sent())
    assert frame.data == b"o"
    assert "END_STREAM" in frame.flags
