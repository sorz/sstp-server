#!/usr/bin/env python3
import random
import timeit

from sstpd.codec import escape, PppDecoder


random.seed(0)
decoder = PppDecoder()


def get_enscaped() -> bytes:
    frames = [random.randbytes(1500) for i in range(2)]
    return b".".join([escape(f) for f in frames])


def bench_unescape() -> float:
    return timeit.timeit(
        "decoder.unescape(data)", setup="data = get_enscaped()", globals=globals()
    )

def bench_escape() -> float:
    return timeit.timeit(
        "escape(data)", setup="data = random.randbytes(1500)", globals=globals()
    )


def codec_test() -> None:
    frame = random.randbytes(1500)
    escaped = escape(frame)
    print("escaped: %d bytes " % len(escaped))
    unescaped = PppDecoder().unescape(escaped)
    assert len(unescaped) == 1
    print("unescaped: %d bytes" % len(unescaped[0]))
    assert unescaped[0] == frame


def main() -> None:
    codec_test()
    print("Test unescape...")
    print("\tescape:   %f" % bench_escape())
    print("\tunescape: %f" % bench_unescape())


if __name__ == "__main__":
    main()
