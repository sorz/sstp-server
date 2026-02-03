#!/usr/bin/env python3
import random
import timeit

from sstpd.codec import PppDecoder, escape

random.seed(0)
frames = [random.randbytes(1500) for _ in range(20)]
decoder = PppDecoder()


def get_escaped(full: bool, size) -> bytearray:
    return escape([memoryview(f) for f in frames[:size]], full)


def bench_unescape(full: bool, size: int) -> float:
    return timeit.timeit(
        "decoder.unescape(data)",
        setup="data = bytes(get_escaped(full, size))",
        globals=dict(**globals(), full=full, size=size),
    )


def bench_escape(full: bool) -> float:
    return timeit.timeit(
        "escape(fs, full)",
        setup="fs = [memoryview(frames[0])]",
        globals=dict(**globals(), full=full),
    )


def codec_test() -> None:
    frame = memoryview(frames[0])
    escaped_full = escape([frame], True)
    escaped = escape([frame], False)
    print(f"escaped: {len(frame)} => {len(escaped)}/{len(escaped_full)} bytes")
    unescaped = PppDecoder().unescape(bytes(escaped))
    assert len(unescaped) == 1
    print("unescaped: %d bytes" % len(unescaped[0]))
    assert unescaped[0] == frame
    unescaped = PppDecoder().unescape(bytes(escaped_full))
    assert unescaped[0] == frame


def main() -> None:
    codec_test()
    print("Benchmark codec (full escape)...")
    print("\tescape:    \t%f" % bench_escape(True))
    print("\tunescape/2:\t%f" % (bench_unescape(True, 2) / 2))
    print("Benchmark codec...")
    print("\tescape:    \t%f" % bench_escape(False))
    for n in 1, 2, 8, 20:
        print("\tunescape/%d:\t%f" % (n, (bench_unescape(False, n) / n)))


if __name__ == "__main__":
    main()
