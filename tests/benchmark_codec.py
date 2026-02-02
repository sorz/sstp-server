#!/usr/bin/env python3
import random
import timeit

from sstpd.codec import PppDecoder, escape

random.seed(0)
frames = [random.randbytes(1500) for _ in range(2)]
decoder = PppDecoder()


def get_escaped(full: bool) -> bytes:
    return b".".join([escape(f, full) for f in frames])


def bench_unescape(full: bool) -> float:
    return timeit.timeit(
        "decoder.unescape(data)",
        setup="data = get_escaped(full)",
        globals=dict(**globals(), full=full),
    )


def bench_escape(full: bool) -> float:
    print("escape")
    return timeit.timeit(
        "escape(frames[0], full)",
        globals=dict(**globals(), full=full),
    )


def codec_test() -> None:
    escaped_full = escape(frames[0], True)
    escaped = escape(frames[0], False)
    print(f"escaped: {len(frames[0])} => {len(escaped)}/{len(escaped_full)} bytes")
    unescaped = PppDecoder().unescape(bytes(escaped))
    assert len(unescaped) == 1
    print("unescaped: %d bytes" % len(unescaped[0]))
    assert unescaped[0] == frames[0]
    unescaped = PppDecoder().unescape(bytes(escaped_full))
    assert unescaped[0] == frames[0]


def main() -> None:
    codec_test()
    for full in True, False:
        print(f"Benchmark codec (full = {full})...")
        print("\tescape:   %f" % bench_escape(full))
        print("\tunescape: %f" % bench_unescape(full))


if __name__ == "__main__":
    main()
