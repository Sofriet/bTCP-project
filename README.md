# bTCP project, Networks and Security 2023 (Radboud University)

Sending and receiving transport-layer code for bTCP, a simplified TCP that
runs on top of UDP. Written from the course template together with Slavi
Ivanov.

## What's in here

- `btcp/client_socket.py`: the sender. Splits data into segments and sends
  them with a Go-Back-N sliding window: cumulative ACKs and a retransmission
  timeout.
- `btcp/server_socket.py`: the receiver. Checks checksums, ACKs segments and
  passes the data on to `recv()` in order.

Not implemented: the three-way handshake (`connect()` and `accept()` only set
the state) and the FIN termination (`shutdown()` waits until all data is
acknowledged, and the server treats 10 seconds without data as a disconnect).

The rest of the course template and the test framework are not in this repo
yet, so the code can't run on its own. See [TODO.md](TODO.md). Python 3.10 or
newer is needed (the code uses `match` statements).

## Test results

Before the fixes below, the code passed tests 1_1 (ideal), 2_1 (bitflips) and
3_1 (duplication). The test cases are private for the assignment.

TODO: re-run all tests on the fixed code (see [TODO.md](TODO.md)).

## Fixes

After the course the following bugs were fixed.

**Client** (`btcp/client_socket.py`)

- **Deadlock on retransmission.** `retransmit()` checked
  `self._sendbuf.not_empty`, which is a `threading.Condition` object and
  always true, so it blocked forever on an empty send buffer. It also gave
  new data a sequence number that was already in use.
- **Deadlock between the two threads.** `send()` (application thread) and
  the network thread both cycled through the same queue of unacknowledged
  segments with `qsize()`/`get()`/`put()`. If an ACK removed the last
  segment in between, `send()` waited forever. Now only the network thread
  handles the window, ACKs and retransmissions.
- **`send()` waited until everything was acknowledged** (busy-waiting),
  while the template says it shouldn't. It now only puts the data in the
  send buffer (waiting for space if needed), and `shutdown()` waits for the
  ACKs.
- **Wrong timeout.** Retransmission used a separate `TIMEOUT` constant
  instead of the `timeout` (in ms) given to the socket.
- **Crash on large transfers.** Sequence numbers are 16 bits but were never
  wrapped around, so building the header failed after 65535 segments
  (about 66 MB).
- **Missing methods.** Segments received in the `CLOSED` or `FIN_SENT` state
  called methods that don't exist in the client.

**Server** (`btcp/server_socket.py`)

- **Silent data loss.** Segments were acknowledged before being put in the
  receive buffer, so when the buffer was full the data was dropped while the
  client thought it had arrived. Now only stored data gets ACKed.
- **Corrupted output if data arrived before `accept()`.** In the `CLOSED`
  state the raw payload went into the receive buffer, but `recv()` expects
  whole segments. Those segments are now ignored and the client resends
  them.
- **Race between the two threads.** `recv()` also processed segments and
  sent ACKs from the application thread, at the same time as the network
  thread.
- **Crashing helpers.** `_closing_segment_received` was missing `self`, and
  `_other_segment_received` was called with one argument too many.
- `recv()` now returns the data that is available instead of first waiting
  for 10 seconds without new data, and ACKs no longer carry 2 junk bytes.


**How this was checked.** The real test framework isn't available, so the
fixes were tested against a stand-in for the template and an emulation of the
test network: 1% bitflips, 10% duplication, 10% loss, reordering,
100 ms ± 20 ms delay, and all of them combined (500 KB, window 100, timeout
100 ms, repeated with different random seeds), plus a 70 MB transfer. The old
code deadlocked in every scenario. The fixed code delivered all data
correctly in all of them, for example the delay case in about 1 second. The
real tests still need to be re-run.
