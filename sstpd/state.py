import asyncio
from asyncio import TimerHandle
from enum import Enum
from typing import Callable

from .constants import (
    ATTRIB_STATUS_NEGOTIATION_TIMEOUT,
    ATTRIB_STATUS_RETRY_COUNT_EXCEEDED,
)


class State(Enum):
    SERVER_CALL_DISCONNECTED = "Server_Call_Disconnected"
    SERVER_CONNECT_REQUEST_PENDING = "Server_Connect_Request_Pending"
    SERVER_CALL_CONNECTED_PENDING = "Server_Call_Connected_Pending"
    SERVER_CALL_CONNECTED = "Server_Call_Connected"
    # CALL_DISCONNECT_IN_PROGRESS_1 = "Call_Disconnect_In_Progress_1"
    CALL_DISCONNECT_IN_PROGRESS_2 = "Call_Disconnect_In_Progress_2"
    CALL_DISCONNECT_TIMEOUT_PENDING = "Call_Disconnect_Timeout_Pending"
    CALL_DISCONNECT_ACK_PENDING = "Call_Disconnect_Timeout_Pending"
    # CALL_ABORT_IN_PROGRESS_1 = "Call_Abort_In_Progress_1"
    CALL_ABORT_IN_PROGRESS_2 = "Call_Abort_In_Progress_2"
    CALL_ABORT_TIMEOUT_PENDING = "Call_Abort_Timeout_Pending"
    CALL_ABORT_PENDING = "Call_Abort_Timeout_Pending"


class ServerState:
    def __init__(
        self,
        abort: Callable[[bytes | None], None],
        close: Callable[[], None],
    ) -> None:
        self._abort = abort
        self._close = close
        self._loop = asyncio.get_event_loop()
        self._connect_request_retry_count = 0
        self._timer_short: TimerHandle | None = None
        self._timer_long: TimerHandle | None = None
        self._timer_nego: TimerHandle = self._loop.call_later(60, self._nego_timed_out)
        self.current = State.SERVER_CALL_DISCONNECTED

    def _close_shortly(self):
        if self._timer_long is not None:
            self._timer_long.cancel()
            self._timer_long = None
        if self._timer_short is None:
            self._timer_short = self._loop.call_later(1, self._close)

    def _close_wait_ack(self):
        if self._timer_short is not None and self._timer_long is not None:
            self._timer_long = self._loop.call_later(3, self._close)

    def is_closing(self) -> bool:
        return self.current in (
            State.CALL_ABORT_TIMEOUT_PENDING,
            State.CALL_ABORT_PENDING,
            State.CALL_DISCONNECT_ACK_PENDING,
            State.CALL_DISCONNECT_TIMEOUT_PENDING,
        )

    def http_received(self) -> None:
        assert self.current == State.SERVER_CALL_DISCONNECTED
        self.current = State.SERVER_CONNECT_REQUEST_PENDING
        self._timer_nego.cancel()
        self._timer_nego = self._loop.call_later(60, self._nego_timed_out)

    def _nego_timed_out(self) -> None:
        match self.current:
            case State.SERVER_CALL_DISCONNECTED:
                self._close()  # http timed out
            case State.SERVER_CONNECT_REQUEST_PENDING:
                self._close()  # negotiation timed out before ppp start
            case State.SERVER_CALL_CONNECTED_PENDING:
                self._abort(ATTRIB_STATUS_NEGOTIATION_TIMEOUT)

    def call_connect_request_accepted(self) -> None:
        assert self.current == State.SERVER_CONNECT_REQUEST_PENDING
        self.current = State.SERVER_CALL_CONNECTED_PENDING

    def call_connect_request_rejected(self) -> None:
        assert self.current == State.SERVER_CONNECT_REQUEST_PENDING
        self.connect_request_retry_count += 1
        if self.connect_request_retry_count > 3:
            self._abort(ATTRIB_STATUS_RETRY_COUNT_EXCEEDED)

    def call_connected(self):
        assert self.current == State.SERVER_CALL_CONNECTED_PENDING
        self.current = State.SERVER_CALL_CONNECTED
        self._timer_nego.cancel()

    def call_disconnect_sent(self) -> None:
        self.current = State.CALL_DISCONNECT_ACK_PENDING
        self._close_wait_ack()

    def call_disconnect_asked(self) -> None:
        """They acked us"""
        assert self.current == State.CALL_DISCONNECT_ACK_PENDING
        self._close()

    def call_disconnect_ack_sent(self) -> None:
        """We ack them"""
        self.current = State.CALL_DISCONNECT_TIMEOUT_PENDING
        self._close_shortly()

    def call_abort_acked(self) -> None:
        """They acked us"""
        assert self.current == State.CALL_ABORT_PENDING
        self._close_shortly()

    def call_abort_ack_sent(self) -> None:
        """We ack them"""
        self.current = State.CALL_ABORT_PENDING
        self._close_shortly()

    def call_abort_sent(self) -> None:
        self.current = State.CALL_ABORT_PENDING
        self._close_wait_ack()

    def kill(self) -> None:
        self._timer_nego.cancel()
        if self._timer_short is not None:
            self._timer_short.cancel()
        if self._timer_long is not None:
            self._timer_long.cancel()
