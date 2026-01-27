#!/usr/bin/env python3
import os
import timeit

from sstpd.codec import escape, PppDecoder


decoder = PppDecoder()


def get_enscaped() -> bytes:
    frames = [os.urandom(1500) for i in range(2)]
    return b".".join([escape(f) for f in frames])


def prof_unescape() -> float:
    return timeit.timeit(
        "decoder.unescape(data)", setup="data = get_enscaped()", globals=globals()
    )


def codec_test() -> None:
    frame = os.urandom(1500)
    escaped = escape(frame)
    print("escaped: %d bytes " % len(escaped))
    unescaped = PppDecoder().unescape(escaped)
    assert len(unescaped) == 1
    print("unescaped: %d bytes" % len(unescaped[0]))
    assert unescaped[0] == frame


def main() -> None:
    codec_test()
    print("Test unescape...")
    print("\t%f" % prof_unescape())


if __name__ == "__main__":
    main()
