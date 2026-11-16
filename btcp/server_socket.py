"""bTCP server socket: the receiving side.

The server passes the data of in-order segments to recv() and answers every
segment with a cumulative ACK for the last in-order segment. Segments that
arrive early (but within the window) are kept until the gap before them is
filled, so reordering doesn't force the client to resend them. Duplicate and
corrupted segments are dropped; the client retransmits lost data.

There is no connection handshake or termination yet: accept() only changes
local state, and recv() treats RECV_TIMEOUT seconds without data as a
disconnect (see README.md).
"""
import logging
import queue

# TODO: btcp_socket.py, lossy_layer.py and constants.py come from the course
# template and are not in this repo yet, see TODO.md.
from btcp.btcp_socket import BTCPSocket, BTCPStates
from btcp.lossy_layer import LossyLayer
from btcp.constants import *


logger = logging.getLogger(__name__)

# Sequence and acknowledgement numbers are 16-bit header fields.
SEQNUM_MODULO = 1 << 16
# recv() returns b'' (disconnect) after this many seconds without data.
RECV_TIMEOUT = 10


class BTCPServerSocket(BTCPSocket):
    """bTCP server socket.

    The application calls accept, recv and close from its own thread. The
    lossy layer calls lossy_layer_segment_received and lossy_layer_tick from
    the network thread.

    All segment handling (checking, ACKs, sequence numbers) happens in the
    network thread. Received data reaches the application thread only through
    the receive buffer, a thread-safe Queue.
    """

    def __init__(self, window, timeout):
        """Create the socket and start the lossy layer."""
        logger.debug("__init__ called")
        super().__init__(window, timeout)
        self._lossy_layer = LossyLayer(self, SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT)

        # Data from in-order segments, filled by the network thread and
        # emptied by recv() in the application thread.
        self._recvbuf = queue.Queue(maxsize=1000)
        # No handshake, so both sides start at 0. The server sends no data,
        # so seqnum stays 0; acknum is the sequence number of the last
        # in-order segment received (network thread only).
        self.seqnum = 0
        self.acknum = 0
        # Data of segments that arrived before the next expected one, by
        # sequence number (network thread only, at most `window` entries).
        self._early_segments = {}


    ###########################################################################
    ### Network thread: called by the lossy layer                          ###
    ###########################################################################

    def lossy_layer_segment_received(self, segment):
        """Handle a segment from the client.

        Segments with a bad checksum are dropped without an ACK. Data is only
        accepted in the ESTABLISHED state. Before accept() there is no
        connection to deliver to, so the segment is ignored and the client
        retransmits it later.
        """
        logger.debug("lossy_layer_segment_received called")
        if not self.verify_checksum(segment):
            logger.debug("Dropped segment with a bad checksum")
            return
        seqnum, _, _, _, length, _ = self.unpack_segment_header(segment[:HEADER_SIZE])

        match self._state:
            case BTCPStates.ESTABLISHED:
                data = segment[HEADER_SIZE:HEADER_SIZE + length]
                self._established_segment_received(seqnum, data)
            case _:
                logger.debug("Ignored segment %d received in state %s",
                             seqnum, self._state.name)


    def _established_segment_received(self, seqnum, data):
        """Store the data, pass on everything that is now in order, then ACK.

        Segments within the window ahead of the next expected one are kept
        until the gap before them is filled. Duplicates and segments outside
        the window are dropped.
        """
        expected = (self.acknum + 1) % SEQNUM_MODULO
        if (seqnum - expected) % SEQNUM_MODULO < self._window:
            self._early_segments.setdefault(seqnum, data)
        else:
            logger.debug("Dropped duplicate or out-of-window segment %d", seqnum)

        while expected in self._early_segments:
            try:
                self._recvbuf.put_nowait(self._early_segments[expected])
            except queue.Full:
                # Don't acknowledge data recv() can't take yet; it stays
                # stored and is ACKed once there is room again.
                logger.debug("Receive buffer full, holding segment %d", expected)
                break
            del self._early_segments[expected]
            self.acknum = expected
            expected = (expected + 1) % SEQNUM_MODULO
        self._send_ack()


    def _send_ack(self):
        """Send a cumulative ACK for the last in-order segment."""
        ack = self.make_segment(b'', self.seqnum, True, self.acknum)
        self._lossy_layer.send_segment(ack)
        logger.debug("Sent ACK %d", self.acknum)


    def lossy_layer_tick(self):
        """Called when no segment arrived for TIMER_TICK ms.

        The server only reacts to incoming segments, so there is nothing
        to do here.
        """
        logger.debug("lossy_layer_tick called")


    ###########################################################################
    ### Application thread: the socket API                                  ###
    ###########################################################################

    def accept(self):
        """Mark the connection as established.

        No three-way handshake is implemented, so this returns immediately.
        """
        logger.debug("accept called")
        self._state = BTCPStates.ESTABLISHED


    def recv(self):
        """Return the data received so far, blocking until there is some.

        Returns b'' to signal that the client disconnected when no data
        arrives for RECV_TIMEOUT seconds, because there is no FIN handshake
        yet.
        """
        logger.debug("recv called")
        data = bytearray()
        try:
            # Wait for the first chunk, then take whatever else is buffered.
            data.extend(self._recvbuf.get(timeout=RECV_TIMEOUT))
            while True:
                data.extend(self._recvbuf.get_nowait())
        except queue.Empty:
            pass
        if not data:
            logger.info("No data received for %d seconds, signalling disconnect",
                        RECV_TIMEOUT)
        return bytes(data)


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
