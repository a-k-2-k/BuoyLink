"""BuoyLink: a low-overhead transport for the sensor buoy scenario.

    make run SCENARIO=sensor

Design (see the Stage 1 doc), adapted to what the simulator actually charges:
every datagram costs 28 bytes of IP/UDP on top of our own bytes, so the main
goal is to send as few datagrams as possible.

Sender (buoy)
  * Batching. Routine readings wait briefly (until arrivals go quiet, or a
    max hold tied to the message deadline) and go out together in one
    datagram. Alarms (short deadlines) are sent at once, and carry waiting
    routine readings along only while the datagram stays small enough for a
    retry to still beat the alarm's deadline.
  * Compact framing. 1 byte: a 7 bit datagram sequence number, plus a flag
    saying whether the first message id is sent as just its low byte (the
    receiver can tell which id that is from the ones it has seen; otherwise
    the full id follows as a varint). Then entries: usually one byte per message (id delta, and
    the length only when it changes), and a single byte for a run of
    consecutive ids. Messages too big for one datagram are fragmented.
  * Reliability. Every routine datagram gets one small ACK. Lost datagrams
    are found from gaps in the ACK bitmap, or by timeout. On a routine timeout
    we first send an empty "poll" datagram (29 bytes on the wire) instead of
    resending the whole batch: if only the ACK was lost, that is much cheaper.
  * Alarms. When the link looks healthy (low estimated loss), an alarm goes
    alone and "lazy": the receiver doesn't ACK it by itself, and the next
    routine ACK's bitmap confirms it. That saves a 29 byte ACK per 8 byte
    alarm, at the cost of a lost alarm being resent late. When the link looks
    lossy, alarms ask for an ACK, are resent early enough to make their
    deadline, and are sent twice when loss is very high.
  * Exponential backoff during outages, with polls instead of data, so a
    blackout costs a few tiny datagrams rather than repeated full batches.
  * Pacing. Routine datagrams are spaced by their airtime so an alarm never
    queues behind several of them on the slow radio link.
  * Ordering. Alarms first, then the earliest unexpired deadline, then
    messages already past their deadline (newest first).

Receiver (shore station)
  * Delivers each message once, reassembles fragments, and answers every data
    datagram with a tiny ACK: the highest sequence number seen, plus a bitmap
    of the 8 before it only when one of them is missing (so usually 1 byte).
"""

from __future__ import annotations

from transportlab.api import Receiver, Sender

# The scenario your team chose: "leo", "datacenter" or "sensor". Gradescope
# grades your protocol on this scenario, and rejects it while this is empty.
SCENARIO = "sensor"

# ---------------------------------------------------------------------------
# Tunables. Times are wire seconds (the sensor sim runs 60x faster than buoy
# time, so 1 wire second = 60 buoy seconds).
# ---------------------------------------------------------------------------
LINK_BPS = 6000          # buoy radio link rate in the sim (100 bps real x 60)
WIRE_HDR = 28            # IP + UDP bytes the harness charges per datagram
MAX_DGRAM = 300          # cap our datagrams so an alarm never waits long behind one
ALARM_DGRAM = 80         # an alarm only carries other readings up to this size, so a
                         # lost one can still be resent inside its deadline
DEFAULT_LEN = 32         # routine reading size; entries of this size skip the length
IDLE_GAP_S = 0.35        # with a decent batch, flush once arrivals go quiet this long
MIN_BATCH_BYTES = 100    # ... "decent" = this much payload waiting
MAX_HOLD_S = 3.0         # never hold a routine reading longer than this
HOLD_RESERVE_S = 1.5     # ... and leave this much of its deadline for retries
HOLD_FRACTION = 0.6      # ... and never more than this fraction of it
ALARM_DEADLINE_S = 1.5   # deadlines at or under this are treated as alarms
MAX_INFLIGHT = 4         # data datagrams awaiting an ACK at once
RTO_INIT_S = 1.0
RTO_MAX_S = 1.0          # cap: after an outage ends we find out within ~1 s (60 buoy s)
BACKOFF = 1.6
OUTAGE_TIMEOUTS = 3      # this many timeouts in a row = assume an outage, send polls only
ALARM_RETRY_MIN_S = 0.08
LOSSY = 0.30             # above this estimated loss, alarms are sent twice
LAZY_LOSS = 0.12         # below this estimated loss, alarms go without asking for an ACK
LAZY_CONFIRM_S = 12.0    # a lazy datagram is confirmed by a later ACK; poll if none by then
INF = float("inf")


# ---------------------------------------------------------------------------
# Varints (7 bits per byte, high bit = more follows)
# ---------------------------------------------------------------------------
def put_varint(out: bytearray, n: int) -> None:
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)


def get_varint(buf: bytes, i: int) -> tuple[int, int]:
    n = shift = 0
    while True:
        b = buf[i]
        i += 1
        n |= (b & 0x7F) << shift
        if b < 0x80:
            return n, i
        shift += 7


def airtime(nbytes: int) -> float:
    return (nbytes + WIRE_HDR) * 8 / LINK_BPS


# ---------------------------------------------------------------------------
# Sender
# ---------------------------------------------------------------------------
class Unit:
    """One message, or one fragment of a message too big for a datagram."""

    __slots__ = ("msg_id", "offset", "data", "total", "deadline", "alarm",
                 "offered", "inflight", "sent")

    def __init__(self, msg_id, offset, data, total, deadline, alarm, offered):
        self.msg_id = msg_id
        self.offset = offset
        self.data = data
        self.total = total
        self.deadline = deadline      # absolute wire time, or None
        self.alarm = alarm
        self.offered = offered
        self.inflight = 0             # how many unacked datagrams carry it
        self.sent = False             # sent at least once (so a resend goes at once)

    @property
    def key(self):
        return (self.msg_id, self.offset)

    @property
    def is_frag(self):
        return len(self.data) != self.total


def live_alarm(u, now):
    """An alarm still worth rushing: one whose deadline has not passed."""
    return u.alarm and (u.deadline is None or now < u.deadline)


class Dgram:
    """A data datagram (or poll) waiting for its ACK."""

    __slots__ = ("seq", "sent", "units", "alarm", "expires", "expected", "lazy")

    def __init__(self, seq, sent, units, alarm, expires, expected, lazy=False):
        self.lazy = lazy              # sent without asking for an ACK
        self.seq = seq
        self.sent = sent
        self.units = units
        self.alarm = alarm
        self.expires = expires        # INF = parked, waiting on a poll's answer
        self.expected = expected      # queue + airtime part of the round trip


class BuoySender(Sender):
    def on_start(self):
        self.dst = None
        self.units = {}          # key -> Unit, everything not yet acked
        self.pending = []        # Units waiting to be (re)sent
        self.inflight = {}       # full seq -> Dgram
        self.next_seq = 0
        self.srtt = None
        self.rttvar = None
        self.backoff = 0         # consecutive timeouts with no ACK in between
        self.loss = 0.05         # EWMA of datagram loss
        self.next_free = 0.0     # when our radio is free again (pacing)
        self.last_arrival = 0.0
        self.acked_max_id = -1   # highest msg id the receiver has confirmed
        self.sent_max_id = -1    # highest msg id we have ever sent
        self.stats = {"data": 0, "alarm": 0, "poll": 0, "bytes": 0, "units": 0,
                      "resent_units": 0, "timeouts": 0, "gaps": 0}

    # ---- application side -------------------------------------------------
    def on_app_data(self, msg):
        self.dst = msg.dst
        now = self.now()
        alarm = msg.deadline_s is not None and msg.deadline_s <= ALARM_DEADLINE_S
        deadline = None if msg.deadline_s is None else msg.offered_s + msg.deadline_s
        payload = msg.payload
        room = MAX_DGRAM - 12
        for off in range(0, max(len(payload), 1), room):
            u = Unit(msg.msg_id, off, payload[off:off + room], len(payload),
                     deadline, alarm, msg.offered_s)
            self.units[u.key] = u
            self.pending.append(u)
        self.last_arrival = now
        if alarm:
            self._send_now(alarm=True)
        else:
            self._pump()

    # ---- timers -----------------------------------------------------------
    def on_timer(self, name):
        if name == "rto":
            self._check_timeouts()
        self._pump()

    def _arm_rto(self):
        live = [d.expires for d in self.inflight.values() if d.expires != INF]
        if not live:
            self.cancel_timer("rto")
            return
        self.set_timer("rto", max(0.0, min(live) - self.now()))

    def _rto(self, expected):
        """Timeout for a datagram whose send + ACK should take `expected` s.

        srtt/rttvar track the residual: measured RTT minus the airtime we
        already know about, so big and small datagrams share one estimate.
        """
        if self.srtt is None:
            base = max(RTO_INIT_S, expected * 1.5)
        else:
            base = expected + self.srtt + 4 * self.rttvar + 0.02
        return min(max(RTO_MAX_S, expected * 1.5), base * (BACKOFF ** min(self.backoff, 6)))

    def _check_timeouts(self):
        now = self.now()
        expired = [d for d in self.inflight.values() if d.expires <= now + 1e-9]
        if not expired:
            self._arm_rto()
            return
        self.backoff += 1
        self.stats["timeouts"] += len(expired)
        for d in expired:
            if d.lazy:
                # Never confirmed by a later ACK: ask.
                d.expires = INF
            elif d.alarm:
                # Alarm: no time to ask. Resend what it carried.
                del self.inflight[d.seq]
                self._note_loss(True)
                self._requeue(d)
            elif not d.units:
                # A poll got no answer.
                del self.inflight[d.seq]
                self._note_loss(True)
            else:
                # Routine batch: was the data lost, or only its ACK? Park it
                # and ask with a poll; the poll's ACK bitmap answers.
                d.expires = INF
        suspects = any(d.expires == INF for d in self.inflight.values())
        if any(live_alarm(u, now) for u in self.pending):
            self._send_now(alarm=True)       # its ACK answers for the suspects too
        elif suspects and self.pending and self.backoff < OUTAGE_TIMEOUTS:
            self._send_now(alarm=False)      # waiting readings make a better probe
        elif suspects:
            self._send_poll()
        self._arm_rto()

    # ---- network side -----------------------------------------------------
    def on_datagram(self, data, addr):
        if not data:
            return
        now = self.now()
        h = self._full_seq(data[0])
        if h is None:
            return
        bitmap = data[1] if len(data) > 1 else 0xFF
        acked = {h} | {h - 1 - i for i in range(8) if bitmap >> i & 1}
        got_any = False
        for seq in sorted(self.inflight):
            d = self.inflight[seq]
            if seq in acked:
                del self.inflight[seq]
                got_any = True
                self._note_loss(False)
                sample = max(0.0, now - d.sent - d.expected)
                if d.lazy:
                    pass
                elif self.srtt is None:
                    self.srtt, self.rttvar = sample, sample / 2
                else:
                    self.rttvar = 0.75 * self.rttvar + 0.25 * abs(self.srtt - sample)
                    self.srtt = 0.875 * self.srtt + 0.125 * sample
                for u in d.units:
                    u.inflight -= 1
                    self.units.pop(u.key, None)
                    if u.msg_id > self.acked_max_id:
                        self.acked_max_id = u.msg_id
            elif seq < h:
                # Links are FIFO: a later datagram arrived and this one did not.
                self.stats["gaps"] += 1
                del self.inflight[seq]
                self._note_loss(True)
                self._requeue(d)
        if got_any:
            self.backoff = 0
        # Drop acked units that were waiting for a resend.
        self.pending = [u for u in self.pending if u.key in self.units]
        self._arm_rto()
        if any(live_alarm(u, now) for u in self.pending):
            self._send_now(alarm=True)
        else:
            self._pump()

    def on_stop(self):
        # One summary line in runs/<run>/senderN.log, handy when tuning.
        self.log("STATS", self.stats, "unacked", len(self.units),
                 "loss_est", round(self.loss, 3))

    def _full_seq(self, low):
        # The newest sent datagram whose low 6 bits match.
        low &= 0x3F
        for seq in range(self.next_seq - 1, max(-1, self.next_seq - 65), -1):
            if seq & 0x3F == low:
                return seq
        return None

    def _requeue(self, d):
        for u in d.units:
            u.inflight -= 1
            if u.key in self.units and u.inflight <= 0 and u not in self.pending:
                self.pending.append(u)

    def _note_loss(self, lost):
        self.loss = 0.9 * self.loss + 0.1 * (1.0 if lost else 0.0)

    # ---- sending ------------------------------------------------------------
    def _pump(self):
        """Send routine data if it is time, else make sure a timer will."""
        if not self.pending or self.dst is None:
            self.cancel_timer("flush")
            return
        now = self.now()
        if self.backoff >= OUTAGE_TIMEOUTS and self.inflight:
            # Probably an outage: polls on the RTO timer will find out first.
            self.cancel_timer("flush")
            return
        due = self._flush_due(now)
        if due > now + 1e-9:
            self.set_timer("flush", due - now)
            return
        if len(self.inflight) >= MAX_INFLIGHT:
            return  # an ACK or timeout will call us again
        if now < self.next_free - 1e-9:
            self.set_timer("flush", self.next_free - now)
            return
        self._send_now(alarm=False)
        if self.pending:
            self._pump()

    def _flush_due(self, now):
        # Resends and alarms go at once; so does a batch that is already full.
        if any(u.sent or live_alarm(u, now) for u in self.pending):
            return now
        payload = sum(len(u.data) for u in self.pending)
        if payload + 4 * len(self.pending) >= MAX_DGRAM - 40:
            return now
        # A decent batch goes once arrivals go quiet; a small one waits for
        # company, up to each reading's max hold.
        due = INF
        if payload >= MIN_BATCH_BYTES:
            due = self.last_arrival + IDLE_GAP_S
        for u in self.pending:
            hold = MAX_HOLD_S
            if u.deadline is not None:
                budget = u.deadline - u.offered
                hold = max(0.2, min(hold, budget - HOLD_RESERVE_S, HOLD_FRACTION * budget))
            due = min(due, u.offered + hold)
        return due

    def _order(self, now):
        def key(u):
            if live_alarm(u, now):
                return (0, u.deadline or 0.0)
            if u.deadline is not None and u.deadline > now:
                return (1, u.deadline)
            return (2, -u.offered)
        self.pending.sort(key=key)

    def _send_now(self, alarm):
        now = self.now()
        self._order(now)
        # Lazy alarm: when the link looks healthy, send the alarm alone and let
        # the next routine ACK confirm it (its bitmap covers the last 8).
        lazy = (alarm and self.loss < LAZY_LOSS and self.backoff == 0
                and not any(d.expires == INF for d in self.inflight.values()))
        cap = ALARM_DGRAM if alarm else MAX_DGRAM
        chosen, size = [], 1 + 4
        for u in self.pending:
            if lazy and not live_alarm(u, now):
                continue
            add = len(u.data) + 4 + (6 if u.is_frag else 0)
            if chosen and size + add > cap and not live_alarm(u, now):
                continue
            chosen.append(u)
            size += add
        if not chosen:
            return
        for u in chosen:
            self.pending.remove(u)
        copies = 2 if alarm and self.loss > LOSSY else 1
        for _ in range(copies):
            self._transmit(chosen, alarm, now, lazy)

    def _send_poll(self):
        if self.dst is None:
            return
        self._transmit([], False, self.now())

    def _transmit(self, units, alarm, now, lazy=False):
        seq = self.next_seq
        self.next_seq += 1
        pkt = self._encode(seq, units, self._short_ok(units), lazy)
        if units:
            self.sent_max_id = max(self.sent_max_id, max(u.msg_id for u in units))
        self.send_datagram(pkt, to=self.dst)
        st = self.stats
        st["poll" if not units else "alarm" if alarm else "data"] += 1
        st["bytes"] += len(pkt) + WIRE_HDR
        st["units"] += len(units)
        st["resent_units"] += sum(1 for u in units if u.sent)
        for u in units:
            u.inflight += 1
            u.sent = True
        self.next_free = max(now, self.next_free) + airtime(len(pkt))
        # What we already know this exchange takes: our queue, the datagram's
        # airtime and the ACK's.
        expected = (self.next_free - now) + airtime(2)
        rto = self._rto(expected)
        if alarm:
            # Retry early enough to beat the deadline, but not before an ACK
            # could physically be back.
            deadline = min((u.deadline for u in units if live_alarm(u, now)), default=None)
            if deadline is not None:
                rto = min(rto, max(ALARM_RETRY_MIN_S, (deadline - now) * 0.4))
            rto = max(rto, 1.3 * expected + 0.02)
        if lazy:
            rto = LAZY_CONFIRM_S
        self.inflight[seq] = Dgram(seq, now, list(units), alarm, now + rto, expected, lazy)
        self._arm_rto()

    def _short_ok(self, units):
        """Can the first msg id go as its low byte alone?

        The receiver rebuilds it from the highest id it has seen from us, R,
        which lies somewhere in [acked_max_id, sent_max_id]. The low byte is
        unambiguous if the id is within 127 of every possible R.
        """
        if not units or self.acked_max_id < 0:
            return False
        base = min(u.msg_id for u in units)
        return (base - self.acked_max_id <= 127 and
                max(self.sent_max_id, base) - base <= 127 and
                self.acked_max_id - base <= 127)

    @staticmethod
    def _encode(seq, units, short=False, lazy=False):
        """seq byte (6 bit seq; bit 7 = first id is short; bit 6 = lazy, don't
        ACK this one by itself), first msg id
        (its low byte, or a full varint), then entries. Entry = varint X, where
        X = (n << 2) | kind:
          kind 0: one message, id = prev + n, same length as the previous one
          kind 1: one message, id = prev + n, a varint length follows
          kind 2: one fragment, id = prev + n, then varint len, offset, total
          kind 3: n more messages, each id = prev + 1 and the previous length
        Payload bytes follow each entry (all of a run's payloads, back to back).
        """
        out = bytearray([(seq & 0x3F) | (0x80 if short else 0) | (0x40 if lazy else 0)])
        if not units:
            return bytes(out)
        units = sorted(units, key=lambda u: (u.msg_id, u.offset))
        base = units[0].msg_id
        if short:
            out.append(base & 0xFF)
        else:
            put_varint(out, base)
        prev_id, prev_len = base, DEFAULT_LEN
        i = 0
        while i < len(units):
            u = units[i]
            n = len(u.data)
            delta = u.msg_id - prev_id
            if u.is_frag:
                put_varint(out, (delta << 2) | 2)
                put_varint(out, n)
                put_varint(out, u.offset)
                put_varint(out, u.total)
                out += u.data
                prev_id = u.msg_id
                i += 1
                continue
            last = i == len(units) - 1
            if n == prev_len or (last and n < prev_len):
                # Same length as before, or the last entry and shorter than
                # that: the receiver takes the rest of the datagram.
                put_varint(out, delta << 2)
            else:
                put_varint(out, (delta << 2) | 1)
                put_varint(out, n)
            out += u.data
            prev_id, prev_len = u.msg_id, n
            i += 1
            # Fold following consecutive, same-length messages into one run.
            j = i
            while (j < len(units) and not units[j].is_frag
                   and units[j].msg_id == prev_id + (j - i) + 1
                   and len(units[j].data) == prev_len):
                j += 1
            if j - i >= 2:
                put_varint(out, ((j - i) << 2) | 3)
                for k in range(i, j):
                    out += units[k].data
                prev_id = units[j - 1].msg_id
                i = j
        return bytes(out)


# ---------------------------------------------------------------------------
# Receiver
# ---------------------------------------------------------------------------
class PeerState:
    __slots__ = ("highest", "seen", "frags", "max_id")

    def __init__(self):
        self.highest = -1
        self.seen = set()
        self.max_id = -1         # highest msg id decoded from this sender
        self.frags = {}          # msg_id -> {offset: bytes}


class ShoreReceiver(Receiver):
    def on_start(self):
        self.peers_state = {}

    def on_datagram(self, data, addr):
        if not data:
            return
        st = self.peers_state.setdefault(addr, PeerState())
        seq = self._full_seq(st, data[0] & 0x3F)
        st.seen.add(seq)
        if seq > st.highest:
            st.highest = seq
            # Forget anything too old to matter.
            if len(st.seen) > 64:
                st.seen = {s for s in st.seen if s > st.highest - 16}
        try:
            self._unpack(st, data)
        except IndexError:
            pass  # truncated datagram: deliver what we could, still ACK
        if not data[0] & 0x40:
            self._ack(st, addr)       # lazy datagrams are confirmed by the next ACK

    @staticmethod
    def _full_seq(st, low):
        if st.highest < 0:
            return low
        guess = (st.highest & ~0x3F) | low
        # Pick the candidate closest to highest.
        return min((guess - 64, guess, guess + 64), key=lambda s: abs(s - st.highest))

    def _unpack(self, st, data):
        if len(data) == 1:
            return  # a poll
        if data[0] & 0x80:
            low = data[1]
            ref = max(st.max_id, 0)
            guess = (ref & ~0xFF) | low
            msg_id = min((guess - 256, guess, guess + 256), key=lambda c: abs(c - ref))
            i = 2
        else:
            msg_id, i = get_varint(data, 1)
        prev_len = DEFAULT_LEN
        while i < len(data):
            x, i = get_varint(data, i)
            n, kind = x >> 2, x & 3
            if kind == 3:
                for _ in range(n):
                    msg_id += 1
                    chunk = data[i:i + prev_len]
                    i += prev_len
                    if len(chunk) != prev_len:
                        return
                    self._got(msg_id, chunk)
                st.max_id = max(st.max_id, msg_id)
                continue
            msg_id += n
            length = prev_len
            if kind == 0 and len(data) - i < prev_len:
                length = len(data) - i        # last entry, shorter than prev
            if kind in (1, 2):
                length, i = get_varint(data, i)
            if kind == 2:
                off, i = get_varint(data, i)
                total, i = get_varint(data, i)
            chunk = data[i:i + length]
            i += length
            if len(chunk) != length:
                return
            st.max_id = max(st.max_id, msg_id)
            if kind == 2:
                self._frag(st, msg_id, off, total, chunk)
            else:
                prev_len = length
                self._got(msg_id, chunk)

    def _got(self, msg_id, chunk):
        if not self.delivered(msg_id):
            self.deliver(msg_id, chunk)

    def _frag(self, st, msg_id, off, total, chunk):
        if self.delivered(msg_id):
            return
        parts = st.frags.setdefault(msg_id, {})
        parts[off] = chunk
        if sum(len(c) for c in parts.values()) >= total:
            payload = b"".join(parts[k] for k in sorted(parts))[:total]
            del st.frags[msg_id]
            self.deliver(msg_id, payload)

    def _ack(self, st, addr):
        h = st.highest
        bitmap = 0
        for i in range(8):
            if h - 1 - i in st.seen or h - 1 - i < 0:
                bitmap |= 1 << i
        # Nothing missing among the last 8: the bitmap byte is left off.
        ack = bytes([h & 0x3F]) if bitmap == 0xFF else bytes([h & 0x3F, bitmap])
        self.send_datagram(ack, to=addr)


SENDER, RECEIVER = BuoySender, ShoreReceiver
