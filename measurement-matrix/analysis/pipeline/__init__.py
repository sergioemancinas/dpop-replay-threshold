"""
Statistical pipeline for the pre-registered DPoP-versus-mTLS cost comparison.

NO REAL MEASUREMENT DATA EXISTS. The condition matrix in PROTOCOL.md section 3 has
not been executed. Every number this package has ever produced came from the
synthetic generators in `pipeline.synthetic` or from test fixtures. The package is
here so that the analysis is fixed and validated before any data is collected,
which is the point of a pre-registration.

Implements exactly the plan in PREREGISTRATION.md, "Statistical analysis plan":

  bca.py           bootstrap BCa 95% CI for median p99, plus the replication-count
                   rule targeting a CI half-width of <= 5% of median p99
  stationarity.py  Kolmogorov-Smirnov on split halves of a measurement window
  omnibus.py       Kruskal-Wallis omnibus, Dunn post-hoc, Holm correction
  effect_size.py   Cliff's delta with Romano-Kromrey magnitude thresholds
  hdr.py           HdrHistogram reader (documented subset) and wrk2/k6 ingestion
  synthetic.py     synthetic generators, for validating the pipeline only
  report.py        glue that runs the above in the pre-registered order
"""

__all__ = [
    "bca",
    "effect_size",
    "hdr",
    "omnibus",
    "report",
    "stationarity",
    "synthetic",
]

NO_REAL_DATA_BANNER = (
    "SYNTHETIC INPUT ONLY. No measurement of the condition matrix has been run. "
    "Numbers below are not results."
)
