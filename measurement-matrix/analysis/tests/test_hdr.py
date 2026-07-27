"""
HdrHistogram reader validation.

What is and is not independently validated:

  - Bucket arithmetic (index mapping, equivalent value ranges, percentile lookup) is
    checked against values worked out by hand from the published algorithm, and
    against the library's own precision guarantee: a value read back at percentile p
    must be within `significant_figures` relative error of the true order statistic.
    That is an external contract, not a self-consistency check.
  - ZigZag LEB128 is checked against hand-encoded byte strings taken from the
    encoding definition, not from this module's encoder.
  - The V2 container is checked by round trip through this module's own encoder.
    THAT IS NOT AN INDEPENDENT CHECK. No blob produced by the Java, C or Go
    reference implementation was available offline, so a symmetric bug in the
    encoder and decoder would pass. The header layout is additionally asserted
    field-by-field against the documented byte offsets, which narrows but does not
    close that gap. Recorded in README.md as a known limitation.
"""

import base64
import struct
import zlib
from pathlib import Path

import numpy as np
import pytest

from pipeline import hdr

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# ZigZag LEB128, hand-encoded references
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    (0, b"\x00"),          # zigzag(0) = 0
    (-1, b"\x01"),         # zigzag(-1) = 1
    (1, b"\x02"),          # zigzag(1) = 2
    (-2, b"\x03"),
    (2, b"\x04"),
    (63, b"\x7e"),         # zigzag(63) = 126, single byte
    (-64, b"\x7f"),        # zigzag(-64) = 127, still one byte
    (64, b"\x80\x01"),     # zigzag(64) = 128 -> 0x80 continuation, then 0x01
    (-65, b"\x81\x01"),    # zigzag(-65) = 129
])
def test_zigzag_encode_against_hand_computed_bytes(value, expected):
    out = bytearray()
    hdr._zigzag_encode(out, value)
    assert bytes(out) == expected


@pytest.mark.parametrize("value", [0, 1, -1, 127, 128, -128, 300000, -300000,
                                   2 ** 40, -(2 ** 40)])
def test_zigzag_roundtrip(value):
    out = bytearray()
    hdr._zigzag_encode(out, value)
    got, pos = hdr._zigzag_decode(bytes(out), 0)
    assert got == value
    assert pos == len(out)


def test_zigzag_decode_rejects_truncated():
    with pytest.raises(hdr.HdrFormatError):
        hdr._zigzag_decode(b"\x80", 0)


# ---------------------------------------------------------------------------
# Bucket arithmetic, hand-computed
# ---------------------------------------------------------------------------

def test_histogram_parameters_hand_computed():
    """
    lowest=1, sig=3: largest single-unit value = 2*10^3 = 2000,
    ceil(log2(2000)) = 11, so subBucketHalfCountMagnitude = 10,
    subBucketCount = 2^11 = 2048, unitMagnitude = floor(log2(1)) = 0.
    """
    h = hdr.HdrHistogram(1, 3600 * 1000 * 1000, 3)
    assert h.sub_bucket_count == 2048
    assert h.sub_bucket_half_count == 1024
    assert h.sub_bucket_half_count_magnitude == 10
    assert h.unit_magnitude == 0
    assert h.sub_bucket_mask == 2047
    assert h.counts_len == (h.bucket_count + 1) * 1024


@pytest.mark.parametrize("value,index", [
    (0, 0),
    (1, 1),
    (2047, 2047),
    (2048, 2048),   # first slot of bucket 1: subBucketIndex 1024
    (2050, 2049),   # 2050 >> 1 = 1025 -> 1024 + 1025 - 1024 = 2049
    (4096, 3072),   # bucket 2: 4096 >> 2 = 1024 -> (3<<10) + 0
])
def test_counts_index_hand_computed(value, index):
    h = hdr.HdrHistogram(1, 3600 * 1000 * 1000, 3)
    assert h.counts_index_for(value) == index
    assert h.lowest_equivalent_value(value) == h.value_from_index(index)


def test_value_from_index_inverts_counts_index():
    h = hdr.HdrHistogram(1, 10 ** 7, 3)
    for idx in range(0, h.counts_len, 37):
        value = h.value_from_index(idx)
        assert h.counts_index_for(value) == idx


def test_equivalent_value_range_hand_computed():
    """
    In bucket 0 (values 0..2047) the resolution is 1, so the equivalent range of
    any value is [v, v]. In bucket 1 (2048..4095) it is 2, in bucket 2 it is 4.
    """
    h = hdr.HdrHistogram(1, 10 ** 7, 3)
    assert h.size_of_equivalent_value_range(100) == 1
    assert h.lowest_equivalent_value(100) == 100
    assert h.highest_equivalent_value(100) == 100

    assert h.size_of_equivalent_value_range(2050) == 2
    assert h.lowest_equivalent_value(2050) == 2050
    assert h.highest_equivalent_value(2050) == 2051
    assert h.lowest_equivalent_value(2051) == 2050

    assert h.size_of_equivalent_value_range(4100) == 4
    assert h.lowest_equivalent_value(4100) == 4100
    assert h.highest_equivalent_value(4103) == 4103


def test_percentile_respects_the_precision_guarantee():
    """
    EXTERNAL CONTRACT. HdrHistogram promises that a value read back is within
    1/10^significant_figures relative error of the recorded value. Checked against
    the true order statistics of the input, which the histogram never sees.
    """
    rng = np.random.default_rng(4)
    values = np.round(rng.lognormal(8.0, 0.8, size=200000)).astype(np.int64) + 1
    h = hdr.HdrHistogram(1, int(values.max()) + 1, 3)
    h.record_values(values)

    assert h.total_count == values.size
    for p in (50.0, 90.0, 99.0, 99.9, 99.99):
        truth = np.percentile(values, p, method="lower")
        got = h.get_value_at_percentile(p)
        assert abs(got - truth) / truth <= 1e-3 + 1e-9, (p, got, truth)


def test_percentile_is_conservative_never_below_truth():
    """Reporting the highest equivalent value means the answer never undershoots."""
    rng = np.random.default_rng(5)
    values = rng.integers(1, 500000, size=50000)
    h = hdr.HdrHistogram(1, 10 ** 6, 3)
    h.record_values(values)
    for p in (50.0, 99.0, 99.9):
        assert h.get_value_at_percentile(p) >= np.percentile(values, p,
                                                             method="lower")


def test_percentile_zero_and_hundred():
    h = hdr.HdrHistogram(1, 10 ** 6, 3)
    for v in (5, 10, 20, 40, 80):
        h.record_value(v)
    assert h.get_value_at_percentile(0.0) == 5
    assert h.get_value_at_percentile(100.0) == 80
    assert h.get_max_value() == 80
    assert h.get_min_value() == 5


def test_empty_histogram_is_not_a_crash():
    h = hdr.HdrHistogram(1, 1000, 3)
    assert h.total_count == 0
    assert h.get_value_at_percentile(99.0) == 0
    assert h.get_mean_value() == 0.0
    assert h.get_max_value() == 0
    assert hdr.samples_from_histogram(h).size == 0


def test_record_rejects_out_of_range():
    h = hdr.HdrHistogram(1, 1000, 3)
    with pytest.raises(ValueError):
        h.record_value(-1)
    with pytest.raises(ValueError):
        h.record_value(10 ** 9)


def test_mean_within_precision_of_true_mean():
    rng = np.random.default_rng(6)
    values = rng.integers(1000, 200000, size=100000)
    h = hdr.HdrHistogram(1, 10 ** 6, 3)
    h.record_values(values)
    assert h.get_mean_value() == pytest.approx(values.mean(), rel=1e-3)
    assert h.get_stddev() == pytest.approx(values.std(), rel=2e-3)


# ---------------------------------------------------------------------------
# V2 container
# ---------------------------------------------------------------------------

def _sample_histogram(seed=1, n=20000):
    rng = np.random.default_rng(seed)
    h = hdr.HdrHistogram(1, 10 ** 7, 3)
    h.record_values(np.round(rng.lognormal(7.0, 0.6, size=n)).astype(np.int64) + 1)
    return h


def test_uncompressed_header_layout_matches_the_documented_offsets():
    """Field-by-field, against the byte offsets in the format description."""
    h = _sample_histogram()
    raw = h.encode(compressed=False)
    cookie, payload_len, norm, sig, lowest, highest, ratio = struct.unpack_from(
        ">iiiiqqd", raw, 0)
    assert cookie & ~0xF0 == hdr.V2_COOKIE_BASE
    assert norm == 0
    assert sig == 3
    assert lowest == 1
    assert highest == 10 ** 7
    assert ratio == 1.0
    assert payload_len == len(raw) - hdr.V2_HEADER_SIZE
    assert len(raw) == hdr.V2_HEADER_SIZE + payload_len


def test_compressed_wrapper_is_plain_zlib():
    """Java's Deflater default is zlib-wrapped, so zlib.decompress must work."""
    h = _sample_histogram()
    raw = h.encode(compressed=True)
    cookie, length = struct.unpack_from(">ii", raw, 0)
    assert cookie & ~0xF0 == hdr.V2_COMPRESSED_COOKIE_BASE
    assert length == len(raw) - 8
    inner = zlib.decompress(raw[8:])
    assert struct.unpack_from(">i", inner, 0)[0] & ~0xF0 == hdr.V2_COOKIE_BASE


@pytest.mark.parametrize("compressed", [False, True])
def test_v2_roundtrip_preserves_every_count(compressed):
    """
    NOT an independent check, see the module docstring. It does prove the payload
    encoding is self-consistent and that zero-run elision is lossless.
    """
    h = _sample_histogram(seed=2)
    back = hdr.decode_histogram(h.encode(compressed))
    assert back.total_count == h.total_count
    assert np.array_equal(back.counts, h.counts)
    assert back.lowest_discernible_value == h.lowest_discernible_value
    assert back.highest_trackable_value == h.highest_trackable_value
    assert back.significant_figures == h.significant_figures
    for p in (50.0, 90.0, 99.0, 99.99):
        assert back.get_value_at_percentile(p) == h.get_value_at_percentile(p)


def test_base64_roundtrip():
    h = _sample_histogram(seed=3)
    assert np.array_equal(hdr.decode_histogram(h.to_base64()).counts, h.counts)


def test_base64_prefix_matches_real_hlog_files():
    """
    Weak external check. Compressed V2 blobs in real .hlog files always begin
    'HISTFAAA', because the first bytes are cookie 0x1C849314 followed by a
    four-byte length whose top bits are zero. Getting the cookie or the byte order
    wrong changes this prefix, so it catches the most likely container mistake even
    though it says nothing about the payload.
    """
    assert _sample_histogram(seed=3).to_base64().startswith("HISTFAAA")


def test_sparse_histogram_encodes_zero_runs():
    """A histogram with two far-apart values must not encode the whole array."""
    h = hdr.HdrHistogram(1, 10 ** 9, 3)
    h.record_value(1)
    h.record_value(900_000_000)
    raw = h.encode(compressed=False)
    payload = len(raw) - hdr.V2_HEADER_SIZE
    assert payload < 40, f"zero-run elision failed, payload {payload} bytes"
    assert np.array_equal(hdr.decode_histogram(raw).counts, h.counts)


def test_decode_rejects_v1_cookie():
    body = struct.pack(">iiiiqqd", 0x1C849301 | 0x10, 0, 0, 3, 1, 1000, 1.0)
    with pytest.raises(hdr.HdrFormatError, match="V0/V1"):
        hdr.decode_histogram(body)


def test_decode_rejects_unknown_cookie():
    with pytest.raises(hdr.HdrFormatError, match="unrecognised"):
        hdr.decode_histogram(struct.pack(">iiiiqqd", 0x0BADF00D, 0, 0, 3, 1,
                                         1000, 1.0))


def test_decode_rejects_nonzero_normalizing_offset():
    body = struct.pack(">iiiiqqd", hdr._V2_ENCODING_COOKIE, 0, 7, 3, 1, 1000, 1.0)
    with pytest.raises(hdr.HdrFormatError, match="normalizing"):
        hdr.decode_histogram(body)


def test_decode_rejects_double_histogram_ratio():
    body = struct.pack(">iiiiqqd", hdr._V2_ENCODING_COOKIE, 0, 0, 3, 1, 1000, 0.5)
    with pytest.raises(hdr.HdrFormatError, match="DoubleHistogram"):
        hdr.decode_histogram(body)


def test_decode_rejects_truncated_payload():
    h = _sample_histogram(seed=4)
    raw = h.encode(compressed=False)
    with pytest.raises(hdr.HdrFormatError, match="truncated"):
        hdr.decode_histogram(raw[:-5])


# ---------------------------------------------------------------------------
# .hlog
# ---------------------------------------------------------------------------

def test_parse_hlog_synthetic_fixture():
    intervals = hdr.parse_hlog(FIXTURES / "SYNTHETIC_NOT_A_MEASUREMENT.hlog")
    assert len(intervals) == 3
    assert [iv.tag for iv in intervals] == ["SYNTHETIC", "SYNTHETIC", "SYNTHETIC"]
    assert intervals[0].start_timestamp == pytest.approx(0.0)
    assert intervals[1].length == pytest.approx(1.0)
    assert all(iv.histogram.total_count == 5000 for iv in intervals)

    merged = hdr.merge_hlog(intervals)
    assert merged.total_count == 15000
    assert merged.get_value_at_percentile(99.0) > 0


def test_parse_hlog_without_tags():
    h = hdr.HdrHistogram(1, 100000, 3)
    for v in (10, 20, 30):
        h.record_value(v)
    text = f"#[SYNTHETIC]\n0.000,1.000,30.0,{h.to_base64()}\n"
    intervals = hdr.parse_hlog(text)
    assert len(intervals) == 1 and intervals[0].tag is None
    assert intervals[0].histogram.total_count == 3


def test_parse_hlog_skips_legend_and_comments():
    h = hdr.HdrHistogram(1, 1000, 3)
    h.record_value(5)
    text = (
        "#[SYNTHETIC FIXTURE]\n"
        "#[StartTime: 1441812723.000 (seconds since epoch)]\n"
        '"StartTimestamp","Interval_Length","Interval_Max","Interval_Compressed_Histogram"\n'
        f"0.0,1.0,5.0,{h.to_base64()}\n"
    )
    assert len(hdr.parse_hlog(text)) == 1


def test_parse_hlog_rejects_short_line():
    with pytest.raises(hdr.HdrFormatError, match="expected 4 fields"):
        hdr.parse_hlog("0.0,1.0,5.0\n")


def test_merge_rejects_mismatched_parameters():
    a = hdr.HdrHistogram(1, 1000, 3)
    b = hdr.HdrHistogram(1, 1000, 2)
    with pytest.raises(ValueError, match="different parameters"):
        a.merge(b)


# ---------------------------------------------------------------------------
# wrk2 text
# ---------------------------------------------------------------------------

def test_percentile_distribution_roundtrips_through_the_text_format():
    """
    Generate the reference text format from a known histogram, parse it back, and
    require the p99 to agree. This validates the parser against the histogram, not
    against itself.
    """
    h = _sample_histogram(seed=7, n=50000)
    text = h.output_percentile_distribution()
    parsed = hdr.parse_percentile_distribution(text)
    assert parsed.total_count == h.total_count
    assert parsed.mean == pytest.approx(h.get_mean_value(), rel=1e-3)
    assert parsed.max_value == pytest.approx(h.get_max_value(), rel=1e-3)
    assert parsed.sub_buckets == h.sub_bucket_count

    truth = h.get_value_at_percentile(99.0)
    below, above = parsed.bracket_at_percentile(99.0)
    assert below[1] <= truth <= above[1], (below, truth, above)
    # The lookup rounds up to the next tick, so it never understates, and on a
    # smoothly tailed distribution the overshoot stays inside a few percent.
    assert parsed.p99 >= truth
    assert parsed.p99 == pytest.approx(truth, rel=0.05)


def test_percentile_distribution_step_lookup_is_not_interpolated():
    text = (
        "       Value     Percentile TotalCount 1/(1-Percentile)\n"
        "\n"
        "       1.000 0.000000000000          1         1.00\n"
        "       5.000 0.500000000000         50         2.00\n"
        "      20.000 0.990000000000         99       100.00\n"
        "      99.000 1.000000000000        100          inf\n"
        "#[Mean    =         6.000, StdDeviation   =         3.000]\n"
        "#[Max     =        99.000, Total count    =            100]\n"
    )
    d = hdr.parse_percentile_distribution(text)
    assert d.value_at_percentile(50.0) == 5.0
    assert d.value_at_percentile(75.0) == 20.0   # next tabulated row, not 12.5
    assert d.p99 == 20.0
    assert d.value_at_percentile(100.0) == 99.0
    assert d.total_count == 100
    assert d.bracket_at_percentile(75.0) == ((0.5, 5.0), (0.99, 20.0))
    assert d.bracket_at_percentile(50.0) == ((0.5, 5.0), (0.5, 5.0))


def test_percentile_distribution_rejects_empty():
    with pytest.raises(hdr.HdrFormatError, match="no percentile spectrum"):
        hdr.parse_percentile_distribution("nothing to see here\n")


def test_parse_wrk2_summary_fixture():
    blocks = hdr.parse_wrk2_latency_summary(
        FIXTURES / "SYNTHETIC_NOT_A_MEASUREMENT_wrk2.txt")
    labels = [b.label for b in blocks]
    assert labels == ["Recorded Latency", "Uncorrected Latency"]

    recorded = blocks[0]
    # The fixture is built so these order statistics are exact: the 50000th value is
    # 1050 us and the 99000th is 12340 us, which HdrHistogram reports as the top of
    # its bucket, 12343 us. See tests/fixtures/make_fixtures.py.
    assert recorded.value_at_percentile(50.0) == pytest.approx(1.05)
    assert recorded.value_at_percentile(99.0) == pytest.approx(12.34)
    assert recorded.value_at_percentile(100.0) == pytest.approx(30.02)
    # Uncorrected is lower, which is what coordinated-omission correction exists to
    # surface: the corrected series must not be quietly discarded.
    assert blocks[1].value_at_percentile(99.0) < recorded.value_at_percentile(99.0)


def test_parse_wrk2_unit_conversion():
    text = (
        "  Latency Distribution (HdrHistogram - Recorded Latency)\n"
        " 50.000%  750.00us\n"
        " 90.000%    1.50ms\n"
        " 99.000%    2.00s\n"
        " 99.900%    1.00m\n"
    )
    b = hdr.parse_wrk2_latency_summary(text)[0]
    assert b.percentile_ms == pytest.approx(
        {50.0: 0.75, 90.0: 1.5, 99.0: 2000.0, 99.9: 60000.0})


def test_wrk2_block_rejects_untabulated_percentile():
    text = ("  Latency Distribution (HdrHistogram - Recorded Latency)\n"
            " 50.000%    1.00ms\n")
    with pytest.raises(KeyError):
        hdr.parse_wrk2_latency_summary(text)[0].value_at_percentile(99.0)


def test_wrk2_fixture_also_carries_a_parsable_detailed_spectrum():
    """
    The fixture's true p99 is 12.343 ms by construction. The detailed spectrum can
    only bracket it, because its tick schedule has no row at exactly 99.000%.
    """
    d = hdr.parse_percentile_distribution(
        FIXTURES / "SYNTHETIC_NOT_A_MEASUREMENT_wrk2.txt")
    assert d.total_count == 100000
    below, above = d.bracket_at_percentile(99.0)
    assert below[1] <= 12.343 <= above[1], (below, above)
    assert above[1] / below[1] < 1.15, "bracket unexpectedly wide"


# ---------------------------------------------------------------------------
# k6
# ---------------------------------------------------------------------------

def test_parse_k6_json_stream():
    values = hdr.parse_k6_json_stream(
        FIXTURES / "SYNTHETIC_NOT_A_MEASUREMENT_k6.json")
    assert values.tolist() == pytest.approx([1.5, 2.25, 3.0, 90.125])


def test_parse_k6_json_stream_with_time():
    values, times = hdr.parse_k6_json_stream(
        FIXTURES / "SYNTHETIC_NOT_A_MEASUREMENT_k6.json", with_time=True)
    assert times.size == values.size
    assert times[0] == pytest.approx(0.0)
    assert np.all(np.diff(times) >= 0)


def test_parse_k6_ignores_other_metrics_and_types():
    text = (
        '{"type":"Metric","metric":"http_req_duration","data":{"name":"x"}}\n'
        '{"type":"Point","metric":"vus","data":{"time":"2026-01-01T00:00:00Z","value":5}}\n'
        '{"type":"Point","metric":"http_req_duration","data":{"time":"2026-01-01T00:00:00Z","value":7.5}}\n'
    )
    assert hdr.parse_k6_json_stream(text).tolist() == [7.5]


def test_parse_k6_raises_when_metric_absent():
    text = ('{"type":"Point","metric":"vus",'
            '"data":{"time":"2026-01-01T00:00:00Z","value":5}}\n')
    with pytest.raises(ValueError, match="no Point records"):
        hdr.parse_k6_json_stream(text)


def test_parse_k6_rejects_malformed_line():
    with pytest.raises(ValueError, match="not JSON"):
        hdr.parse_k6_json_stream("{oops\n")


# ---------------------------------------------------------------------------
# Sample expansion
# ---------------------------------------------------------------------------

def test_samples_from_histogram_preserves_count_and_quantiles():
    h = _sample_histogram(seed=9, n=30000)
    samples = hdr.samples_from_histogram(h)
    assert samples.size == h.total_count
    # Expanded samples use median-equivalent values, so quantiles agree to within
    # the bucket width, not exactly.
    assert np.percentile(samples, 99) == pytest.approx(
        h.get_value_at_percentile(99.0), rel=2e-3)


def test_samples_from_histogram_is_heavily_tied():
    """Documents the quantisation problem that makes KS on expanded data suspect."""
    h = _sample_histogram(seed=10, n=100000)
    samples = hdr.samples_from_histogram(h)
    distinct = np.unique(samples).size
    assert distinct < samples.size / 20, (distinct, samples.size)
