#!/usr/bin/env python3
import sys
import time


LCP1_EN = (
    b"\x7e\xff\x7d\x23\xc0\x21\x7d\x24\x7d\x20\x7d\x20\x7d\x27\x7d\x2d"
    b"\x7d\x23\x7d\x26\xad\x36\x7e"
)
IP1_EN = (
    b"\x7e\x80\x21\x7d\x22\x7d\x22\x7d\x20\x7d\x2a\x7d\x23\x7d\x26\x7d"
    b"\x2a\x7d\x2a\x20\x7d\x21\x6d\xf9\x7e"
)


def main() -> None:
    if "file" not in sys.argv:
        sys.exit(1)
    with open(sys.argv[1], "r+b", buffering=0) as f:
        f.write(LCP1_EN + LCP1_EN[1:])
        f.flush()
        assert f.read(len(LCP1_EN)) == LCP1_EN
        assert f.read(len(LCP1_EN)) == LCP1_EN

        time.sleep(0.2)  # waiting for auth ok

        f.write(IP1_EN)
        f.flush()
        assert f.read(len(IP1_EN)) == IP1_EN
        f.write(IP1_EN)
        f.flush()

        time.sleep(0.2)


if __name__ == "__main__":
    main()
