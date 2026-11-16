"""bTCP client socket: the sending side.

Application data is split into segments and sent reliably with a Go-Back-N
sliding window: the server sends cumulative ACKs, there is one retransmission
timer for the oldest unacknowledged segment, and when it expires the whole
window is sent again.

There is no connection handshake or termination yet: connect() and shutdown()
only change local state (see README.md).
"""
import collections
import logging
import queue
import time

# TODO: btcp_socket.py, lossy_layer.py and constants.py come from the course
# template and are not in this repo yet, see TODO.md.
from btcp.btcp_socket import BTCPSocket, BTCPStates
from btcp.lossy_layer import LossyLayer
from btcp.constants import *


logger = logging.getLogger(__name__)

# Sequence and acknowledgement numbers are 16-bit header fields.
SEQNUM_MODULO = 1 << 16
# ACK bit in the header's flag byte (see BTCPSocket.build_segment_header).
ACK_FLAG = 0b010
# shutdown() gives up after this many seconds without any ACK progress.
SHUTDOWN_TIMEOUT = 30


class BTCPClientSocket(BTCPSocket):
    """bTCP client socket.

    The application calls connect, send, shutdown and close from its own
    thread. The lossy layer calls lossy_layer_segment_received and
    lossy_layer_tick from the network thread.

    send() only puts data in the send buffer (a thread-safe Queue). Building
    segments, the sliding window, ACK handling and retransmission all happen
    in the network thread, so the window state is never shared between
    threads.
    """

    def __init__(self, window, timeout):
        """Create the socket and start the lossy layer.

        window:  maximum number of unacknowledged segments in flight.
        timeout: retransmission timeout in milliseconds.
        """
        logger.debug("__init__ called")
        super().__init__(window, timeout)
        self._lossy_layer = LossyLayer(self, CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)

        # Chunks of application data waiting to be sent. Filled by send() in
        # the application thread, emptied by the network thread.
        self._sendbuf = queue.Queue(maxsize=1000)

        # Network thread only. The sliding window: one entry per segment that
        # was sent but not acknowledged yet, oldest first, as
        # [seqnum, segment, payload length, time last sent].
        self._unacked = collections.deque()
        # Sequence number of the last segment sent. There is no handshake, so
        # both sides start at 0 and the first data segment gets number 1.
        self.seqnum = 0
        self._retransmit_timeout = timeout / 1000  # ms -> s

        # Progress counters for shutdown(). Each is written by one thread only.
        self._bytes_queued = 0  # application thread (send)
        self._bytes_acked = 0   # network thread (ACK handling)


    ###########################################################################
    ### Network thread: called by the lossy layer                          ###
    ###########################################################################

    def lossy_layer_segment_received(self, segment):
        """Handle a segment from the server.

        Segments with a bad checksum are dropped. In the ESTABLISHED state an
        ACK slides the window; in other states segments are ignored, because
        there is no handshake or termination yet. Afterwards the retransmission
        timer is checked and new data is sent if the window has room.
        """
        logger.debug("lossy_layer_segment_received called")
        if not self.verify_checksum(segment):
            logger.debug("Dropped segment with a bad checksum")
        else:
            _, acknum, flags, *_ = self.unpack_segment_header(segment[:HEADER_SIZE])
            match self._state:
                case BTCPStates.ESTABLISHED:
                    if flags & ACK_FLAG:
                        self._handle_ack(acknum)
                case _:
                    logger.debug("Ignored segment received in state %s",
                                 self._state.name)
        self._retransmit_and_send()


    def lossy_layer_tick(self):
        """Called when no segment arrived for TIMER_TICK ms.

        Makes sure queued data gets sent and timeouts get noticed even when no
        ACKs are coming in.
        """
        logger.debug("lossy_layer_tick called")
        self._retransmit_and_send()


    def _retransmit_and_send(self):
        """Work shared by both network-thread callbacks."""
        if self._state != BTCPStates.ESTABLISHED:
            return
        self._retransmit_on_timeout()
        self._send_new_segments()


    def _handle_ack(self, acknum):
        """Slide the window for a cumulative ACK.

        An ACK for sequence number n acknowledges every segment up to and
        including n. Duplicate and old ACKs are ignored.
        """
        if not self._unacked:
            return
        oldest_seqnum = self._unacked[0][0]
        newly_acked = (acknum - oldest_seqnum + 1) % SEQNUM_MODULO
        if not 0 < newly_acked <= len(self._unacked):
            return
        for _ in range(newly_acked):
            _, _, length, _ = self._unacked.popleft()
            self._bytes_acked += length
        logger.debug("ACK %d, %d segment(s) still unacknowledged",
                     acknum, len(self._unacked))


    def _retransmit_on_timeout(self):
        """If the oldest unacknowledged segment timed out, resend the window.

        Entries are kept in the order they were (re)sent, so the oldest
        segment always has the earliest send time.
        """
        if not self._unacked:
            return
        now = time.monotonic()
        if now - self._unacked[0][3] < self._retransmit_timeout:
            return
        logger.debug("Timeout: resending %d segment(s) starting at %d",
                     len(self._unacked), self._unacked[0][0])
        for entry in self._unacked:
            self._lossy_layer.send_segment(entry[1])
            entry[3] = now


    def _send_new_segments(self):
        """Send queued data as new segments while the window has room."""
        while len(self._unacked) < self._window:
            try:
                chunk = self._sendbuf.get_nowait()
            except queue.Empty:
                return
            self.seqnum = (self.seqnum + 1) % SEQNUM_MODULO
            segment = self.make_segment(chunk, self.seqnum, False, 0)
            self._lossy_layer.send_segment(segment)
            self._unacked.append([self.seqnum, segment, len(chunk), time.monotonic()])
            logger.debug("Sent segment %d (%d bytes)", self.seqnum, len(chunk))


    ###########################################################################
    ### Application thread: the socket API                                  ###
    ###########################################################################

    def connect(self):
        """Mark the connection as established.

        No three-way handshake is implemented, so this returns immediately.
        """
        logger.debug("connect called")
        self._state = BTCPStates.ESTABLISHED


    def send(self, data):
        """Queue data to be sent reliably to the server.

        Waits while the send buffer is full, but never for acknowledgements.
        Returns the number of bytes queued: normally len(data), less only if
        the buffer stayed full for a second, in which case the caller should
        send the rest later.
        """
        logger.debug("send called")
        datalen = len(data)
        sent_bytes = 0
        try:
            while sent_bytes < datalen:
                chunk = data[sent_bytes:sent_bytes + PAYLOAD_SIZE]
                self._sendbuf.put(chunk, timeout=1)
                sent_bytes += len(chunk)
        except queue.Full:
            logger.debug("Send buffer stayed full")
        self._bytes_queued += sent_bytes
        logger.debug("Queued %i of %i bytes", sent_bytes, datalen)
        return sent_bytes


    def shutdown(self):
        """Wait until all data passed to send() is acknowledged, then close.

        There is no FIN handshake yet, so once everything is acknowledged the
        connection is considered closed. Gives up if there is no ACK progress
        for SHUTDOWN_TIMEOUT seconds.
        """
        logger.debug("shutdown called")
        last_acked = self._bytes_acked
        last_progress = time.monotonic()
        while self._bytes_acked < self._bytes_queued:
            time.sleep(0.01)
            if self._bytes_acked != last_acked:
                last_acked = self._bytes_acked
                last_progress = time.monotonic()
            elif time.monotonic() - last_progress > SHUTDOWN_TIMEOUT:
                logger.warning("No ACKs for %d s, giving up with %d of %d bytes "
                               "acknowledged", SHUTDOWN_TIMEOUT,
                               self._bytes_acked, self._bytes_queued)
                break
        else:
            logger.info("All %d bytes acknowledged", self._bytes_queued)
        self._state = BTCPStates.CLOSED
        self.close()


    def close(self):
        """Clean up local resources by destroying the lossy layer.

        Safe to call more than once; also called by the destructor.
        """
        logger.debug("close called")
        if self._lossy_layer is not None:
            self._lossy_layer.destroy()
        self._lossy_layer = None
        self._state = BTCPStates.CLOSED


    def __del__(self):
        """Destructor. Do not modify."""
        logger.debug("__del__ called")
        self.close()
