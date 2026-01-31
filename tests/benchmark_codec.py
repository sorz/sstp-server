#!/usr/bin/env python3
import random
import timeit

from sstpd.codec import PppDecoder, escape

random.seed(0)
frames = [random.randbytes(1500) for _ in range(2)]
decoder = PppDecoder()


def get_enscaped(full: bool) -> bytes:
    return b".".join([escape(f, full) for f in frames])


def bench_unescape(full: bool) -> float:
    return timeit.timeit(
        "decoder.unescape(data)",
        setup="data = get_enscaped(full)",
        globals=dict(**globals(), full=full),
    )


def bench_escape(full: bool) -> float:
    return timeit.timeit(
        "escape(frames[0], full)",
        globals=dict(**globals(), full=full),
    )


def codec_test() -> None:
    print("escaped: %d bytes " % len(escape(frames[0], False)))
    escaped = escape(frames[0], True)
    print("escaped (full): %d bytes " % len(escaped))
    unescaped = PppDecoder().unescape(bytes(escaped))
    assert len(unescaped) == 1
    print("unescaped: %d bytes" % len(unescaped[0]))
    assert unescaped[0] == frames[0]


def main() -> None:
    codec_test()
    for full in True, False:
        print(f"Benchmark codec (full = {full})...")
        print("\tescape:   %f" % bench_escape(full))
        print("\tunescape: %f" % bench_unescape(full))


if __name__ == "__main__":
    main()
