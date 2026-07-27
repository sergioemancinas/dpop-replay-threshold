"""
HdrHistogram reader, plus wrk2 and k6 output ingestion.

WHICH SUBSET OF THE FORMAT IS IMPLEMENTED
=========================================

Supported:

  1. HdrHistogram V2 binary encoding, uncompressed.
     Cookie base 0x1C849303. 40-byte big-endian header (cookie, payload length,
     normalizing index offset, significant digits, lowest discernible value,
     highest trackable value, integer-to-double conversion ratio) followed by a
     ZigZag LEB128 payload where a positive value is a bucket count and a negative
     value is a run of that many empty buckets.
  2. HdrHistogram V2 compressed encoding.
     Cookie base 0x1C849304, 4-byte compressed length, then a zlib (Java Deflater
     default, zlib-wrapped) stream of the uncompressed V2 form above. This is what
     appears base64-encoded in .hlog files.
  3. HdrHistogram interval log files (.hlog).
     `#` comment lines, an optional CSV legend line, and data lines of the form
     `[Tag=name,]start,length,max,base64histogram`.
  4. HdrHistogram `outputPercentileDistribution` text, which is what wrk2 prints
     under "Detailed Percentile spectrum". Four-column table plus the `#[Mean=...]`,
     `#[Max=...]`, `#[Buckets=...]` footer lines.
  5. The wrk2 `--latency` summary block ("Latency Distribution (HdrHistogram -
     <label>)") with us/ms/s/m/h unit suffixes, normalised to milliseconds.
  6. k6 `--out json` newline-delimited output. Not HdrHistogram: k6 emits raw metric
     points. Included because the protocol names k6 as a load generator.

NOT supported, deliberately:

  - V0 and V1 encodings (cookie bases 0x1C849300 through 0x1C849302). Every current
    HdrHistogram release writes V2. A V1 payload raises rather than being silently
    misread.
  - DoubleHistogram and its encodings. `integer_to_double_value_conversion_ratio`
    is parsed and carried, but any value other than 1.0 raises, because applying it
    correctly requires the DoubleHistogram auto-ranging logic that is not here.
  - `normalizing_index_offset` other than 0. Non-zero means a shifted histogram
    (Recorder rebasing); raises rather than returning wrong values.
  - Histogram merging across log intervals with differing lowest/highest/significant
    parameters. `merge()` requires identical parameters.
  - Concurrent, atomic, packed and all-values-recorded variants. Only the plain
    counts array is modelled.
  - Writing anything other than what is needed to build test fixtures. The encoder
    exists so the decoder can be round-trip tested, not as a general writer.

NO REAL MEASUREMENT DATA EXISTS. Nothing in this module has ever been pointed at a
real wrk2 or k6 run for this project. It is validated against histograms this module
encodes itself and against hand-written fixtures, both clearly labelled synthetic.
That is a weaker guarantee than testing against a blob produced by the Java
reference implementation, and it is the honest state of it. See README.md.
"""

from __future__ import annotations

import base64
import gzip
import json
import math
import re
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

import numpy as np

V2_COOKIE_BASE = 0x1C849303
V2_COMPRESSED_COOKIE_BASE = 0x1C849304
V2_HEADER_SIZE = 40
_COOKIE_BASE_MASK = ~0xF0 & 0xFFFFFFFF

# Java writes the cookie with 0x10 in the word-size nibble for V2.
_V2_ENCODING_COOKIE = V2_COOKIE_BASE | 0x10
_V2_COMPRESSED_COOKIE = V2_COMPRESSED_COOKIE_BASE | 0x10

_LEGACY_COOKIE_BASES = {0x1C849300, 0x1C849301, 0x1C849302}


class HdrFormatError(ValueError):
    """Raised for input that is not a supported HdrHistogram encoding."""


# ---------------------------------------------------------------------------
# ZigZag LEB128, as in HdrHistogram's ZigZagEncoding
# ---------------------------------------------------------------------------

def _zigzag_encode(out: bytearray, value: int) -> None:
    v = (value << 1) ^ (value >> 63)
    while v >= 0x80:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v & 0x7F)


def _zigzag_decode(buf: bytes, pos: int) -> tuple[int, int]:
    v = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise HdrFormatError("truncated ZigZag LEB128 value")
        byte = buf[pos]
        pos += 1
        v |= (byte & 0x7F) << shift
        if not byte & 0x80:
            break
        shift += 7
        if shift > 63:
            raise HdrFormatError("ZigZag LEB128 value exceeds 64 bits")
    return (v >> 1) ^ -(v & 1), pos


# ---------------------------------------------------------------------------
# Histogram
# ---------------------------------------------------------------------------

class HdrHistogram:
    """
    A plain HdrHistogram: bucketed counts with a bounded relative error.

    Bucketing follows the reference implementation exactly (unit magnitude, sub
    bucket half count, counts array index mapping) so that percentiles agree with
    what the Java or C library would report for the same counts.
    """

    def __init__(
        self,
        lowest_discernible_value: int = 1,
        highest_trackable_value: int = 3600 * 1000 * 1000,
        significant_figures: int = 3,
    ):
        if lowest_discernible_value < 1:
            raise ValueError("lowest_discernible_value must be >= 1")
        if not 0 <= significant_figures <= 5:
            raise ValueError("significant_figures must be in [0, 5]")
        if highest_trackable_value < 2 * lowest_discernible_value:
            raise ValueError(
                "highest_trackable_value must be >= 2 * lowest_discernible_value"
            )

        self.lowest_discernible_value = int(lowest_discernible_value)
        self.highest_trackable_value = int(highest_trackable_value)
        self.significant_figures = int(significant_figures)

        largest_single_unit = 2 * 10 ** self.significant_figures
        sub_bucket_count_magnitude = int(math.ceil(math.log2(largest_single_unit)))
        self.sub_bucket_half_count_magnitude = max(sub_bucket_count_magnitude, 1) - 1
        self.unit_magnitude = int(math.floor(
            math.log2(self.lowest_discernible_value)))
        self.sub_bucket_count = 1 << (self.sub_bucket_half_count_magnitude + 1)
        self.sub_bucket_half_count = self.sub_bucket_count >> 1
        self.sub_bucket_mask = (self.sub_bucket_count - 1) << self.unit_magnitude
        self._leading_zero_count_base = (
            64 - self.unit_magnitude - self.sub_bucket_half_count_magnitude - 1
        )
        self.bucket_count = self._buckets_needed(self.highest_trackable_value)
        self.counts_len = (self.bucket_count + 1) * self.sub_bucket_half_count
        self.counts = np.zeros(self.counts_len, dtype=np.int64)
        self.total_count = 0

    # -- bucket arithmetic -------------------------------------------------

    def _buckets_needed(self, value: int) -> int:
        smallest_untrackable = self.sub_bucket_count << self.unit_magnitude
        needed = 1
        while smallest_untrackable <= value:
            if smallest_untrackable > (1 << 62):
                return needed + 1
            smallest_untrackable <<= 1
            needed += 1
        return needed

    def _bucket_index(self, value: int) -> int:
        combined = value | self.sub_bucket_mask
        leading_zeros = 64 - combined.bit_length()
        return self._leading_zero_count_base - leading_zeros

    def _sub_bucket_index(self, value: int, bucket_index: int) -> int:
        return value >> (bucket_index + self.unit_magnitude)

    def _counts_index(self, bucket_index: int, sub_bucket_index: int) -> int:
        bucket_base = (bucket_index + 1) << self.sub_bucket_half_count_magnitude
        return bucket_base + sub_bucket_index - self.sub_bucket_half_count

    def counts_index_for(self, value: int) -> int:
        b = self._bucket_index(value)
        return self._counts_index(b, self._sub_bucket_index(value, b))

    def value_from_index(self, index: int) -> int:
        bucket_index = (index >> self.sub_bucket_half_count_magnitude) - 1
        sub_bucket_index = ((index & (self.sub_bucket_half_count - 1))
                            + self.sub_bucket_half_count)
        if bucket_index < 0:
            sub_bucket_index -= self.sub_bucket_half_count
            bucket_index = 0
        return sub_bucket_index << (bucket_index + self.unit_magnitude)

    def size_of_equivalent_value_range(self, value: int) -> int:
        b = self._bucket_index(value)
        s = self._sub_bucket_index(value, b)
        adjusted = b + 1 if s >= self.sub_bucket_count else b
        return 1 << (self.unit_magnitude + adjusted)

    def lowest_equivalent_value(self, value: int) -> int:
        b = self._bucket_index(value)
        s = self._sub_bucket_index(value, b)
        return s << (b + self.unit_magnitude)

    def highest_equivalent_value(self, value: int) -> int:
        return (self.lowest_equivalent_value(value)
                + self.size_of_equivalent_value_range(value) - 1)

    def median_equivalent_value(self, value: int) -> int:
        return (self.lowest_equivalent_value(value)
                + (self.size_of_equivalent_value_range(value) >> 1))

    # -- recording ---------------------------------------------------------

    def record_value(self, value: int, count: int = 1) -> None:
        value = int(value)
        if value < 0:
            raise ValueError("cannot record a negative value")
        if value > self.highest_trackable_value:
            raise ValueError(
                f"value {value} exceeds highest_trackable_value "
                f"{self.highest_trackable_value}"
            )
        index = self.counts_index_for(value)
        if not 0 <= index < self.counts_len:
            raise ValueError(f"value {value} maps outside the counts array")
        self.counts[index] += count
        self.total_count += count

    def record_values(self, values) -> None:
        for v in np.asarray(values).ravel():
            self.record_value(int(v))

    def merge(self, other: "HdrHistogram") -> None:
        """Add another histogram's counts. Requires identical parameters."""
        if (other.lowest_discernible_value != self.lowest_discernible_value
                or other.highest_trackable_value != self.highest_trackable_value
                or other.significant_figures != self.significant_figures):
            raise ValueError(
                "refusing to merge histograms with different parameters; "
                "re-encoding across parameter sets is not implemented"
            )
        self.counts += other.counts
        self.total_count += other.total_count

    # -- queries -----------------------------------------------------------

    def get_value_at_percentile(self, percentile: float) -> int:
        """
        Value at a percentile, using the reference implementation's rule.

        count_at_percentile = floor(p/100 * total + 0.5), at least 1; walk the counts
        array until the cumulative count reaches it, then return the HIGHEST value
        equivalent to that bucket (LOWEST for p = 0). Returning the highest
        equivalent value is what makes HdrHistogram's percentile conservative: the
        reported value is never lower than the true one by more than the bucket
        width.
        """
        if self.total_count == 0:
            return 0
        p = min(max(float(percentile), 0.0), 100.0)
        count_at = int((p / 100.0) * self.total_count + 0.5)
        count_at = max(count_at, 1)
        cumulative = np.cumsum(self.counts)
        idx = int(np.searchsorted(cumulative, count_at, side="left"))
        if idx >= self.counts_len:
            return 0
        value = self.value_from_index(idx)
        if p == 0.0:
            return self.lowest_equivalent_value(value)
        return self.highest_equivalent_value(value)

    def get_percentile_at_or_below_value(self, value: int) -> float:
        if self.total_count == 0:
            return 100.0
        target = self.counts_index_for(min(int(value),
                                           self.highest_trackable_value))
        return 100.0 * float(self.counts[:target + 1].sum()) / self.total_count

    def get_max_value(self) -> int:
        nz = np.nonzero(self.counts)[0]
        if nz.size == 0:
            return 0
        return self.highest_equivalent_value(self.value_from_index(int(nz[-1])))

    def get_min_value(self) -> int:
        nz = np.nonzero(self.counts)[0]
        if nz.size == 0:
            return 0
        return self.lowest_equivalent_value(self.value_from_index(int(nz[0])))

    def get_mean_value(self) -> float:
        if self.total_count == 0:
            return 0.0
        nz = np.nonzero(self.counts)[0]
        mids = np.array([self.median_equivalent_value(self.value_from_index(int(i)))
                         for i in nz], dtype=float)
        return float((mids * self.counts[nz]).sum() / self.total_count)

    def get_stddev(self) -> float:
        if self.total_count == 0:
            return 0.0
        mean = self.get_mean_value()
        nz = np.nonzero(self.counts)[0]
        mids = np.array([self.median_equivalent_value(self.value_from_index(int(i)))
                         for i in nz], dtype=float)
        var = float((((mids - mean) ** 2) * self.counts[nz]).sum()
                    / self.total_count)
        return math.sqrt(var)

    def recorded_values(self) -> list[tuple[int, int]]:
        """(median_equivalent_value, count) for every non-empty bucket."""
        nz = np.nonzero(self.counts)[0]
        return [(self.median_equivalent_value(self.value_from_index(int(i))),
                 int(self.counts[i])) for i in nz]

    # -- encoding ----------------------------------------------------------

    def _relevant_length(self) -> int:
        nz = np.nonzero(self.counts)[0]
        return int(nz[-1]) + 1 if nz.size else 0

    def encode(self, compressed: bool = True) -> bytes:
        """
        Encode to V2, optionally zlib-compressed.

        Exists so the decoder can be round-trip tested and so synthetic fixtures can
        be generated. It is not a general-purpose writer.
        """
        payload = bytearray()
        limit = self._relevant_length()
        i = 0
        while i < limit:
            count = int(self.counts[i])
            i += 1
            if count == 0:
                zeros = 1
                while i < limit and self.counts[i] == 0:
                    zeros += 1
                    i += 1
                _zigzag_encode(payload, -zeros)
            else:
                _zigzag_encode(payload, count)

        header = struct.pack(
            ">iiiiqqd",
            _V2_ENCODING_COOKIE,
            len(payload),
            0,  # normalizing index offset
            self.significant_figures,
            self.lowest_discernible_value,
            self.highest_trackable_value,
            1.0,  # integer to double value conversion ratio
        )
        uncompressed = header + bytes(payload)
        if not compressed:
            return uncompressed
        deflated = zlib.compress(uncompressed)
        return struct.pack(">ii", _V2_COMPRESSED_COOKIE,
                           len(deflated)) + deflated

    def to_base64(self, compressed: bool = True) -> str:
        return base64.b64encode(self.encode(compressed)).decode("ascii")

    def output_percentile_distribution(
        self,
        ticks_per_half_distance: int = 5,
        value_scale: float = 1.0,
    ) -> str:
        """
        Reproduce HdrHistogram's `outputPercentileDistribution` text.

        Same tick schedule as the reference PercentileIterator, so the output is a
        realistic stand-in for what wrk2 prints. Used to build synthetic fixtures.
        """
        lines = ["       Value     Percentile TotalCount 1/(1-Percentile)", ""]
        total = self.total_count
        if total == 0:
            return "\n".join(lines) + "\n"

        cumulative = 0
        level = 0.0
        nz = np.nonzero(self.counts)[0]
        last_index = int(nz[-1])
        for i in range(last_index + 1):
            cumulative += int(self.counts[i])
            if self.counts[i] == 0:
                continue
            pct = 100.0 * cumulative / total
            if pct < level and i != last_index:
                continue
            value = self.highest_equivalent_value(self.value_from_index(i)) / value_scale
            inv = math.inf if pct >= 100.0 else 100.0 / (100.0 - pct)
            inv_text = "inf" if math.isinf(inv) else f"{inv:.2f}"
            lines.append(f"{value:12.3f} {pct / 100.0:14.12f} {cumulative:10d} "
                         f"{inv_text:>12s}")
            if pct >= 100.0:
                break
            ticks = ticks_per_half_distance * (
                2 ** (int(math.log(100.0 / (100.0 - level)) / math.log(2)) + 1)
            )
            level += 100.0 / ticks

        lines.append("")
        lines.append(f"#[Mean    = {self.get_mean_value() / value_scale:14.3f}, "
                     f"StdDeviation   = {self.get_stddev() / value_scale:14.3f}]")
        lines.append(f"#[Max     = {self.get_max_value() / value_scale:14.3f}, "
                     f"Total count    = {total:14d}]")
        lines.append(f"#[Buckets = {self.bucket_count:14d}, "
                     f"SubBuckets     = {self.sub_bucket_count:14d}]")
        return "\n".join(lines) + "\n"

    def __repr__(self) -> str:
        return (f"HdrHistogram(total={self.total_count}, "
                f"min={self.get_min_value()}, max={self.get_max_value()}, "
                f"sig={self.significant_figures})")


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------

def decode_histogram(data) -> HdrHistogram:
    """
    Decode a V2 or V2-compressed HdrHistogram from bytes or a base64 string.

    Raises HdrFormatError on V0/V1 cookies, a non-zero normalizing index offset, or
    a conversion ratio other than 1.0, rather than returning plausible-looking wrong
    numbers.
    """
    if isinstance(data, str):
        data = base64.b64decode(data.strip(), validate=False)
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("expected bytes or a base64 string")
    data = bytes(data)
    if len(data) < 8:
        raise HdrFormatError("input too short to hold a cookie")

    (cookie,) = struct.unpack_from(">i", data, 0)
    base = cookie & _COOKIE_BASE_MASK
    base = base if base <= 0x7FFFFFFF else base - (1 << 32)

    if base == V2_COMPRESSED_COOKIE_BASE:
        (length,) = struct.unpack_from(">i", data, 4)
        if length < 0 or 8 + length > len(data):
            raise HdrFormatError(
                f"compressed length {length} does not fit in {len(data) - 8} bytes"
            )
        data = zlib.decompress(data[8:8 + length])
        (cookie,) = struct.unpack_from(">i", data, 0)
        base = cookie & _COOKIE_BASE_MASK
        base = base if base <= 0x7FFFFFFF else base - (1 << 32)

    if base in _LEGACY_COOKIE_BASES:
        raise HdrFormatError(
            f"cookie base 0x{base:08X} is a V0/V1 encoding; only V2 "
            "(0x1C849303) and V2-compressed (0x1C849304) are implemented"
        )
    if base != V2_COOKIE_BASE:
        raise HdrFormatError(f"unrecognised HdrHistogram cookie 0x{cookie & 0xFFFFFFFF:08X}")

    if len(data) < V2_HEADER_SIZE:
        raise HdrFormatError("input too short to hold a V2 header")
    (_, payload_len, norm_offset, sig_digits, lowest, highest,
     ratio) = struct.unpack_from(">iiiiqqd", data, 0)

    if norm_offset != 0:
        raise HdrFormatError(
            f"normalizing index offset {norm_offset} != 0; shifted histograms "
            "are not implemented"
        )
    if ratio != 1.0:
        raise HdrFormatError(
            f"integer-to-double conversion ratio {ratio} != 1.0; DoubleHistogram "
            "is not implemented"
        )
    payload = data[V2_HEADER_SIZE:V2_HEADER_SIZE + payload_len]
    if len(payload) != payload_len:
        raise HdrFormatError(
            f"payload truncated: header declares {payload_len} bytes, "
            f"{len(payload)} available"
        )

    hist = HdrHistogram(lowest, highest, sig_digits)
    pos = 0
    index = 0
    while pos < payload_len:
        value, pos = _zigzag_decode(payload, pos)
        if value < 0:
            index += -value
            if index > hist.counts_len:
                raise HdrFormatError("zero run overruns the counts array")
        else:
            if index >= hist.counts_len:
                raise HdrFormatError("count index overruns the counts array")
            hist.counts[index] = value
            hist.total_count += value
            index += 1
    return hist


# ---------------------------------------------------------------------------
# .hlog interval log files
# ---------------------------------------------------------------------------

@dataclass
class HlogInterval:
    start_timestamp: float
    length: float
    max_value: float
    tag: str | None
    histogram: HdrHistogram


_HLOG_LEGEND = re.compile(r'^\s*"?StartTimestamp"?\s*,', re.IGNORECASE)


def parse_hlog(source) -> list[HlogInterval]:
    """
    Parse an HdrHistogram interval log.

    Accepts a path or the text itself. Lines starting with `#` are comments (the
    `#[StartTime: ...]` and `#[BaseTime: ...]` preamble included) and are skipped;
    the base time is NOT added to interval start timestamps, so start timestamps are
    returned exactly as written in the file.
    """
    text = _read_text(source)
    intervals: list[HlogInterval] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or _HLOG_LEGEND.match(line):
            continue
        tag = None
        if line.startswith("Tag="):
            tag_part, _, line = line.partition(",")
            tag = tag_part[len("Tag="):]
        fields = line.split(",")
        if len(fields) < 4:
            raise HdrFormatError(f"line {lineno}: expected 4 fields, got {len(fields)}")
        try:
            start, length, max_value = (float(fields[0]), float(fields[1]),
                                        float(fields[2]))
        except ValueError as exc:
            raise HdrFormatError(f"line {lineno}: {exc}") from exc
        payload = fields[3].strip()
        intervals.append(HlogInterval(start, length, max_value, tag,
                                      decode_histogram(payload)))
    return intervals


def merge_hlog(intervals) -> HdrHistogram:
    """Sum the histograms of a list of intervals. Requires identical parameters."""
    intervals = list(intervals)
    if not intervals:
        raise ValueError("no intervals to merge")
    first = intervals[0].histogram
    out = HdrHistogram(first.lowest_discernible_value,
                       first.highest_trackable_value,
                       first.significant_figures)
    for iv in intervals:
        out.merge(iv.histogram)
    return out


# ---------------------------------------------------------------------------
# wrk2 text output
# ---------------------------------------------------------------------------

_SPECTRUM_ROW = re.compile(
    r"^\s*([0-9]+\.?[0-9]*(?:[eE][+-]?[0-9]+)?)\s+"
    r"([01]\.[0-9]+)\s+([0-9]+)\s+(inf|[0-9]+\.?[0-9]*)\s*$"
)
_FOOTER = re.compile(r"#\[(.*?)\]")
_FOOTER_KV = re.compile(r"([A-Za-z ]+?)\s*=\s*([0-9.eE+-]+)")


@dataclass
class PercentileDistribution:
    """Parsed `outputPercentileDistribution` table. Values keep the file's units."""
    values: np.ndarray          # ascending value column
    percentiles: np.ndarray     # fraction in [0, 1], ascending
    total_counts: np.ndarray
    mean: float | None
    stddev: float | None
    max_value: float | None
    total_count: int | None
    buckets: int | None
    sub_buckets: int | None

    def value_at_percentile(self, percentile: float) -> float:
        """
        Value at a percentile in [0, 100], rounded UP to the next tabulated row.

        Step lookup with no interpolation: returns the first tabulated value whose
        percentile is >= the request. Interpolating would invent precision the table
        does not have, and the table is already a step function.

        The percentile spectrum is a re-rendering of a histogram at a fixed
        tick schedule (HdrHistogram's PercentileIterator, five ticks per halving of
        the remaining distance to 100%). Near p99 the tick spacing is about 0.16
        percentile points, so this lookup can land materially above the true p99 when
        the tail is steep. `bracket_at_percentile` reports how coarse the answer
        is. A full histogram (.hlog) preserves this; a percentile dump does not.
        This is a property of the format, not of the parser.
        """
        below, above = self.bracket_at_percentile(percentile)
        return above[1]

    def bracket_at_percentile(
        self, percentile: float
    ) -> tuple[tuple[float, float], tuple[float, float]]:
        """
        Tabulated rows straddling `percentile`, as ((pct_below, value_below),
        (pct_above, value_above)). The true value lies in [value_below,
        value_above]. A wide bracket means the dump is too coarse to answer.
        """
        if not 0.0 <= percentile <= 100.0:
            raise ValueError("percentile must be in [0, 100]")
        target = percentile / 100.0
        idx = int(np.searchsorted(self.percentiles, target, side="left"))
        upper = min(idx, self.values.size - 1)
        lower = max(upper - 1, 0) if self.percentiles[upper] > target else upper
        return ((float(self.percentiles[lower]), float(self.values[lower])),
                (float(self.percentiles[upper]), float(self.values[upper])))

    @property
    def p99(self) -> float:
        return self.value_at_percentile(99.0)


def parse_percentile_distribution(source) -> PercentileDistribution:
    """Parse the HdrHistogram four-column percentile spectrum, plus its footers."""
    text = _read_text(source)
    values, pcts, counts = [], [], []
    footers: dict[str, float] = {}
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            for body in _FOOTER.findall(line):
                for key, val in _FOOTER_KV.findall(body):
                    footers[key.strip().lower()] = float(val)
            continue
        m = _SPECTRUM_ROW.match(line)
        if not m:
            continue
        values.append(float(m.group(1)))
        pcts.append(float(m.group(2)))
        counts.append(int(m.group(3)))
    if not values:
        raise HdrFormatError("no percentile spectrum rows found")

    order = np.argsort(np.asarray(pcts), kind="stable")
    total_count = footers.get("total count")
    return PercentileDistribution(
        values=np.asarray(values, dtype=float)[order],
        percentiles=np.asarray(pcts, dtype=float)[order],
        total_counts=np.asarray(counts, dtype=np.int64)[order],
        mean=footers.get("mean"),
        stddev=footers.get("stddeviation"),
        max_value=footers.get("max"),
        total_count=int(total_count) if total_count is not None else None,
        buckets=int(footers["buckets"]) if "buckets" in footers else None,
        sub_buckets=int(footers["subbuckets"]) if "subbuckets" in footers else None,
    )


_UNIT_TO_MS = {"us": 1e-3, "ms": 1.0, "s": 1e3, "m": 60e3, "h": 3600e3}
_WRK2_BLOCK = re.compile(r"Latency Distribution\s*\(HdrHistogram\s*-\s*([^)]*)\)")
_WRK2_ROW = re.compile(r"^\s*([0-9]+\.?[0-9]*)%\s+([0-9]+\.?[0-9]*)(us|ms|s|m|h)\s*$")


@dataclass
class Wrk2LatencyBlock:
    label: str
    percentile_ms: dict[float, float]

    def value_at_percentile(self, percentile: float) -> float:
        if percentile not in self.percentile_ms:
            raise KeyError(
                f"wrk2 tabulates {sorted(self.percentile_ms)}, not {percentile}; "
                "the summary block is a fixed set of percentiles, use the "
                "detailed spectrum for anything else"
            )
        return self.percentile_ms[percentile]


def parse_wrk2_latency_summary(source) -> list[Wrk2LatencyBlock]:
    """
    Parse wrk2's `--latency` summary blocks, normalising every value to ms.

    wrk2 prints one block for recorded (coordinated-omission corrected) latency and,
    with `-L`, a second for uncorrected latency. Both are returned in file order
    with their labels intact. Which one to analyse is a protocol decision, not a
    parsing one: PROTOCOL.md section 5 commits to the client-side corrected series.
    """
    text = _read_text(source)
    blocks: list[Wrk2LatencyBlock] = []
    current: Wrk2LatencyBlock | None = None
    for line in text.splitlines():
        header = _WRK2_BLOCK.search(line)
        if header:
            current = Wrk2LatencyBlock(header.group(1).strip(), {})
            blocks.append(current)
            continue
        if current is None:
            continue
        m = _WRK2_ROW.match(line)
        if m:
            current.percentile_ms[float(m.group(1))] = (
                float(m.group(2)) * _UNIT_TO_MS[m.group(3)]
            )
        elif line.strip() and not line.startswith(" "):
            current = None  # a non-indented line ends the block
    return blocks


# ---------------------------------------------------------------------------
# k6
# ---------------------------------------------------------------------------

def parse_k6_json_stream(
    source,
    metric: str = "http_req_duration",
    with_time: bool = False,
):
    """
    Read k6 `--out json` newline-delimited output.

    k6 does not emit HdrHistogram. It emits one JSON object per line; the ones that
    matter here are `{"type":"Point","metric":"<name>","data":{"time":...,
    "value":...}}` with value in milliseconds. Returns an array of values, or
    (values, times_seconds) when with_time is set. Times are parsed from RFC3339 and
    returned as seconds since the first point, which is what stationarity.split_half_ks
    wants for a time-based split.

    Non-Point records and other metrics are skipped. Malformed lines raise.
    """
    text = _read_text(source)
    values: list[float] = []
    times: list[float] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {lineno}: not JSON: {exc}") from exc
        if rec.get("type") != "Point" or rec.get("metric") != metric:
            continue
        data = rec.get("data") or {}
        values.append(float(data["value"]))
        if with_time:
            times.append(_rfc3339_seconds(data["time"]))
    if not values:
        raise ValueError(f"no Point records for metric {metric!r}")
    if with_time:
        t = np.asarray(times, dtype=float)
        return np.asarray(values, dtype=float), t - t.min()
    return np.asarray(values, dtype=float)


def _rfc3339_seconds(text: str) -> float:
    from datetime import datetime
    cleaned = text.replace("Z", "+00:00")
    # Python's fromisoformat rejects more than 6 fractional digits; k6 writes 9.
    if "." in cleaned:
        head, _, tail = cleaned.partition(".")
        frac = tail[:len(tail) - 6] if "+" in tail else tail
        digits = "".join(c for c in frac if c.isdigit())[:6]
        offset = tail[len(frac):] if "+" in tail else ""
        cleaned = f"{head}.{digits}{offset}"
    return datetime.fromisoformat(cleaned).timestamp()


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def samples_from_histogram(hist: HdrHistogram) -> np.ndarray:
    """
    Expand a histogram back into one value per recorded observation.

    Each observation gets the median-equivalent value of its bucket. Needed because
    KS and Cliff's delta operate on samples, not on bucket counts.

    This is lossy in a way that matters. Every observation in a bucket becomes the
    same number, so a 10^6-request histogram collapses to a few thousand distinct
    values with enormous tie counts. KS's null distribution assumes continuity, so
    p-values computed on expanded histogram data are wrong in a direction that is
    not easy to sign. Raw per-request samples (k6 JSON) are the accurate input for KS;
    expanding from a percentile dump is lossy and serves as a fallback only when raw
    samples are unavailable.
    """
    pairs = hist.recorded_values()
    if not pairs:
        return np.zeros(0, dtype=float)
    vals = np.array([v for v, _ in pairs], dtype=float)
    cnts = np.array([c for _, c in pairs], dtype=np.int64)
    return np.repeat(vals, cnts)


def _read_text(source) -> str:
    if isinstance(source, (str, Path)) and _looks_like_path(source):
        path = Path(source)
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8") as fh:
                return fh.read()
        return path.read_text(encoding="utf-8")
    if isinstance(source, (bytes, bytearray)):
        return bytes(source).decode("utf-8")
    return str(source)


def _looks_like_path(source) -> bool:
    if isinstance(source, Path):
        return True
    if "\n" in source or len(source) > 4096:
        return False
    try:
        return Path(source).exists()
    except OSError:
        return False
