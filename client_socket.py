from btcp.btcp_socket import BTCPSocket, BTCPStates
from btcp.lossy_layer import LossyLayer
from btcp.constants import *

import queue
import logging
import time
logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)


logger = logging.getLogger(__name__)


class BTCPClientSocket(BTCPSocket):
    """bTCP client socket
    A client application makes use of the services provided by bTCP by calling
    connect, send, shutdown, and close.

    You're implementing the transport layer, exposing it to the application
    layer as a (variation on) socket API.

    To implement the transport layer, you also need to interface with the
    network (lossy) layer. This happens by both calling into it
    (LossyLayer.send_segment) and providing callbacks for it
    (BTCPClientSocket.lossy_layer_segment_received, lossy_layer_tick).

    Your implementation will operate in two threads, the network thread,
    where the lossy layer "lives" and where your callbacks will be called from,
    and the application thread, where the application calls connect, send, etc.
    This means you will need some thread-safe information passing between
    network thread and application thread.
    Writing a boolean or enum attribute in one thread and reading it in a loop
    in another thread should be sufficient to signal state changes.
    Lists, however, are not thread safe, so to pass data and segments around
    you probably want to use Queues, or a similar thread safe collection.
    """


    def __init__(self, window, timeout):
        """Constructor for the bTCP client socket. Allocates local resources
        and starts an instance of the Lossy Layer.

        You can extend this method if you need additional attributes to be
        initialized, but do *not* call connect from here.
        """
        logger.debug("__init__ called")
        super().__init__(window, timeout)
        self._lossy_layer = LossyLayer(self, CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)

        # The data buffer used by send() to send data from the application
        # thread into the network thread. Bounded in size.
        self._sendbuf = queue.Queue(maxsize=1000)
        # the following two queues are the segments in the window
        # the queue forall packets sent but not acknowledged
        self._sent_nack = queue.Queue(maxsize=window)
        #because no handshake is implemented, we say that the initial seqnum and achnum are 0
        self.seqnum = 0
        self.acknum = 0
        #a counter for keeping track how many tuples is self._sent_nack
        self._sent_nack_counter = 0
        logger.info("Socket initialized with sendbuf size 1000")


    ###########################################################################
    ### The following section is the interface between the transport layer  ###
    ### and the lossy (network) layer. When a segment arrives, the lossy    ###
    ### layer will call the lossy_layer_segment_received method "from the   ###
    ### network thread". In that method you should handle the checking of   ###
    ### the segment, and take other actions that should be taken upon its   ###
    ### arrival.                                                            ###
    ###                                                                     ###
    ### Of course you can implement this using any helper methods you want  ###
    ### to add.                                                             ###
    ###########################################################################

    # check if timout for not acknowledged segments ran out
    def check_timeout(self):
        #check timeouts
        #logger.info("checking timeouts")
        retransmit = False
        for i in range(self._sent_nack.qsize()):
            (seg, seg_time) = self._sent_nack.get()
            # logger.info("the current time,%d", time.time())
            if(time.time() - seg_time > TIMEOUT):
                retransmit = True
            self._sent_nack.put((seg, seg_time))
        return retransmit
    
    # retransmit segment
    def retransmit(self):
        logger.info("retransmit called")
        for i in range(self._sent_nack.qsize()):
            (resend_seg, _) = self._sent_nack.get()
            resend_sequence,*_ = self.unpack_segment_header(self.get_header(resend_seg))
            logger.info("send segment with seqnum %d", resend_sequence)
            self._lossy_layer.send_segment(resend_seg)
            self._sent_nack.put((resend_seg, time.time()))

        while self._sent_nack_counter < self._window:
            #taking chunk from sendbuf
            if(self._sendbuf.not_empty):
                chunk_to_seg = self._sendbuf.get()
                #send the segments while there is space in the window
                logger.info("send segments while space")
                #increase the sequence number to make segment with new seqnum
                send_seg = self.make_segment(chunk_to_seg, self.seqnum, False, 0)
                self.seqnum += 1
                logger.info("send segment with seqnum %d", self.seqnum)
                self._lossy_layer.send_segment(send_seg)
                self._sent_nack.put((send_seg, time.time())) 
                self._sent_nack_counter += 1
        

    def lossy_layer_segment_received(self, segment):
        """Called by the lossy layer whenever a segment arrives.

        Things you should expect to handle here (or in helper methods called
        from here):
            - checksum verification (and deciding what to do if it fails)
            - receiving syn/ack during handshake
            - receiving ack and registering the corresponding segment as being
              acknowledged
            - receiving fin/ack during termination
            - any other handling of the header received from the server

        Remember, we expect you to implement this *as a state machine!*
        You have quite a bit of freedom in how you do this, but we at least
        expect you to *keep track of the state the protocol is in*,
        *perform the appropriate state transitions based on events*, and
        *alter behaviour based on that state*.

        So when you receive the segment, do the processing that is common
        for all states (verifying the checksum, parsing it into header values
        and data...).
        Then check the protocol state, do appropriate state-based processing
        (e.g. a FIN is not an acceptable segment in ACCEPTING state, whereas a
        SYN is).
        Finally, do post-processing that is common to all states.

        You could e.g. implement the state-specific processing in a helper
        function per state, and simply call the appropriate helper function
        based on which state you are in.
        In that case, it will be very helpful to split your processing into
        smaller helper functions, that you can combine as needed into a larger
        function for each state.

        If you are on Python 3.10, feel free to use the match ... case
        statement.
        If you are on an earlier Python version, an if ... elif ...  elif
        construction can be used; just make sure to check the same variable in
        each elif.
        """
        logger.debug("lossy_layer_segment_received called")
        header = segment[:HEADER_SIZE]

        _, recv_acknum, recv_flag_byte, *_ = self.unpack_segment_header(header)
        self.correct = self.verify_checksum(segment)

        recv_ack_set = bool(recv_flag_byte & 0b00000010)

        match self._state:
            case BTCPStates.CLOSED:
                self._closed_segment_received(segment)
            case BTCPStates.FIN_SENT:
                self._closing_segment_received(segment)
            case _:
                #acknowledge segment and take that segment out of the self._sent_nack queue
                #we do this by taking them all out and putting the ones back that are not acknowledged yet
                # logger.info("start checking")
                # logger.info("bits flipped %d", self.correct)
                # logger.info("recv ack set %d", recv_ack_set)
                if (self.correct & recv_ack_set):
                    #logger.info("checking acknowledgments")
                    for i in range(self._sent_nack.qsize()):
                        (seg, time) = self._sent_nack.get()
                        seg_seqnum,*_ = self.unpack_segment_header(self.get_header(seg))
                        if (seg_seqnum > recv_acknum):
                            # Add the segment back to the queue if its sequence number is greater than recv_acknum
                            self._sent_nack.put((seg, time))
                        else:
                            logger.info("segment that is acknowledged is %d", seg_seqnum)
                    #update the counter of sent_nack
                    self._sent_nack_counter = self._sent_nack.qsize()
                #check the timeouts and retransmit if needed
                if(self.check_timeout()):
                    self.retransmit()






    def lossy_layer_tick(self):
        """Called by the lossy layer whenever no segment has arrived for
        TIMER_TICK milliseconds. Defaults to 100ms, can be set in constants.py.

        NOTE: Will NOT be called if segments are arriving; do not rely on
        simply counting calls to this method for an accurate timeout. If 10
        segments arrive, each 99 ms apart, this method will NOT be called for
        over a second!

        The primary use for this method is to be able to do things in the
        "network thread" even while no segments are arriving -- which would
        otherwise trigger a call to lossy_layer_segment_received.

        For example, checking for timeouts on acknowledgement of previously
        sent segments -- to trigger retransmission -- should work even if no
        segments are being received. Although you can't count these ticks
        themselves for the timeout, you can trigger the check from here.

        You will probably see some code duplication of code that doesn't handle
        the incoming segment among lossy_layer_segment_received and
        lossy_layer_tick. That kind of duplicated code would be a good
        candidate to put in a helper method which can be called from either
        lossy_layer_segment_received or lossy_layer_tick.
        """
        logger.debug("lossy_layer_tick called client")

        # Actually send all chunks available for sending.
        # Relies on an eventual exception to break from the loop when no data
        # is available.
        # You should be checking whether there's space in the window as well,
        # and storing the segments for retransmission somewhere.

        #check the timeouts and retransmit if needed
        if(self.check_timeout()):
            self.retransmit()





    ###########################################################################
    ### You're also building the socket API for the applications to use.    ###
    ### The following section is the interface between the application      ###
    ### layer and the transport layer. Applications call these methods to   ###
    ### connect, shutdown (disconnect), send data, etc. Conceptually, this  ###
    ### happens in "the application thread".                                ###
    ###                                                                     ###
    ### You *can*, from this application thread, send segments into the     ###
    ### lossy layer, i.e. you can call LossyLayer.send_segment(segment)     ###
    ### from these methods without ensuring that happens in the network     ###
    ### thread. However, if you do want to do this from the network thread, ###
    ### you should use the lossy_layer_tick() method above to ensure that   ###
    ### segments can be sent out even if no segments arrive to trigger the  ###
    ### call to lossy_layer_segment_received. When passing segments between ###
    ### the application thread and the network thread, remember to use a    ###
    ### Queue for its inherent thread safety.                               ###
    ###                                                                     ###
    ### Note that because this is the client socket, and our (initial)      ###
    ### implementation of bTCP is one-way reliable data transfer, there is  ###
    ### no recv() method available to the applications. You should still    ###
    ### be able to receive segments on the lossy layer, however, because    ###
    ### of acknowledgements and synchronization. You should implement that  ###
    ### above.                                                              ###
    ###########################################################################

    def connect(self):
        """Perform the bTCP three-way handshake to establish a connection.

        connect should *block* (i.e. not return) until the connection has been
        successfully established or the connection attempt is aborted. You will
        need some coordination between the application thread and the network
        thread for this, because the syn/ack from the server will be received
        in the network thread.

        Hint: assigning to a boolean or enum attribute in thread A and reading
        it in a loop in thread B (preferably with a short sleep to avoid
        wasting a lot of CPU time) ensures that thread B will wait until the
        boolean or enum has the expected value. You can also put some kind of
        "signal" (e.g. BTCPSignals.CONNECT, or BTCPStates.FIN_SENT) in a Queue,
        and use a blocking get() on the other side to receive that signal.

        Since Python uses duck typing, and Queues can handle mixed types,
        you could even use the same queue to send a "connect signal", then
        all data chunks, then a "shutdown signal", into the network thread.
        That will take some tricky handling, however.

        We do not think you will need more advanced thread synchronization in
        this project.
        """
        logger.debug("connect called")
        self._state = BTCPStates.ESTABLISHED
        self.seqnum = 0
        self.acknum = 0


    def send(self, data):
        """Send data originating from the application in a reliable way to the
        server.

        This method should *NOT* block waiting for acknowledgement of the data.


        You are free to implement this however you like, but the following
        explanation may help to understand how sockets *usually* behave and you
        may choose to follow this concept as well:

        The way this usually works is that "send" operates on a "send buffer".
        Once (part of) the data has been successfully put "in the send buffer",
        the send method returns the number of bytes it was able to put in the
        buffer. The actual sending of the data, i.e. turning it into segments
        and sending the segments into the lossy layer, happens *outside* of the
        send method (e.g. in the network thread).
        If the socket does not have enough buffer space available, it is up to
        the application to retry sending the bytes it was not able to buffer
        for sending.

        Again, you should feel free to deviate from how this usually works.
        Note that our rudimentary implementation here already chunks the data
        in maximum 1008-byte bytes objects because that's the maximum a segment
        can carry. If a chunk is smaller we do *not* pad it here, that gets
        done later.
        """
        
        logger.debug("send called")

        # Example with a finite buffer: a queue with at most 1000 chunks,
        # for a maximum of 985KiB data buffered to get turned into packets.
        # See BTCPSocket__init__() in btcp_socket.py for its construction.

        datalen = len(data)
        logger.debug("%i bytes passed to send", datalen)
        sent_bytes = 0
        logger.info("Put data in to big buffer sendbuf")

        #taking the new data and place it in sendbuf
        try:
            while sent_bytes < datalen:
                logger.debug("Cumulative data queued: %i bytes", sent_bytes)
                # Slide over data using sent_bytes. Reassignments to data are
                # too expensive when data is large.
                chunk = data[sent_bytes:sent_bytes+PAYLOAD_SIZE]
                logger.debug("Putting chunk in send queue.")
                self._sendbuf.put_nowait(chunk)
                sent_bytes += len(chunk)
        except queue.Full:
            logger.info("Sendbuf queue full.")
        logger.info("Managed to queue %i out of %i bytes for transmission",
                    sent_bytes,
                    datalen)
        
        #taking data from sendbuf, send and place in window
        while not self._sendbuf.empty():
            try:
                while self._sent_nack_counter < self._window:
                    #taking chunk from sendbuf
                    logger.debug("trying to get item from sendbuf")
                    chunk_to_seg = self._sendbuf.get_nowait()
                    #send the segments while there is space in the window
                    logger.debug("send segments while space")
                    #increase the sequence number to make segment with new seqnum
                    self.seqnum += 1
                    send_seg = self.make_segment(chunk_to_seg, self.seqnum, False, 0)
                    logger.debug("send segment with seqnum %d",self.seqnum)
                    self._lossy_layer.send_segment(send_seg)
                    logger.info("segment sent")
                    self._sent_nack.put((send_seg, time.time()))   
                    self._sent_nack_counter += 1
                #logger.info("Window is full")
            except queue.Empty: 
                logger.info("queue empty")

        #if no data left in the sendbuf, empty the _send_nack
        while not self._sent_nack.empty():
            if(self.check_timeout()):
                self.retransmit()
        
        return sent_bytes


    def shutdown(self):
        """Perform the bTCP three-way finish to shutdown the connection.

        shutdown should *block* (i.e. not return) until the connection has been
        successfully terminated or the disconnect attempt is aborted. You will
        need some coordination between the application thread and the network
        thread for this, because the fin/ack from the server will be received
        in the network thread.

        Hint: assigning to a boolean or enum attribute in thread A and reading
        it in a loop in thread B (preferably with a short sleep to avoid
        wasting a lot of CPU time) ensures that thread B will wait until the
        boolean or enum has the expected value. We do not think you will need
        more advanced thread synchronization in this project.
        """
        logger.info("shutdown called")
        #raise NotImplementedError("No implementation of shutdown present. Read the comments & code of client_socket.py.")
        self.close()

    def close(self):
        """Cleans up any internal state by at least destroying the instance of
        the lossy layer in use. Also called by the destructor of this socket.

        Do not confuse with shutdown, which disconnects the connection.
        close destroys *local* resources, and should only be called *after*
        shutdown.

        Probably does not need to be modified, but if you do, be careful to
        gate all calls to destroy resources with checks that destruction is
        valid at this point -- this method will also be called by the
        destructor itself. The easiest way of doing this is shown by the
        existing code:
            1. check whether the reference to the resource is not None.
                2. if so, destroy the resource.
            3. set the reference to None.
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

