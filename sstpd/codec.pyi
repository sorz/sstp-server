from typing import Callable

class Ppp2Sstp:
    def __init__(self, write_sstp_data: Callable[[bytearray], None]) -> None: ...
    def write(self, data: bytes) -> None: ...
    ctrl_only: bool

def sstp_to_ppp(frames: list[memoryview], full: bool = True) -> bytearray: ...

class Sstp2Ppp:
    def __init__(
        self,
        sstp_control_received: Callable[[bytes], None],
    ) -> None: ...
    def write(self, data: bytes) -> None: ...
    write_ppp_data: Callable[[bytearray], None] | None
    ppp_full_escape: bool
    ppp_ctrl_only: bool
