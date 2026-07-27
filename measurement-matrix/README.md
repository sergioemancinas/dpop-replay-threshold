# Measurement Matrix

**Status: correctness conditions executed. Latency matrix not executed.**

This directory is a placeholder for the full condition matrix described in `PROTOCOL.md`:
C0 bearer baseline, D1 single-node DPoP, D2 three-replica Redis-backed DPoP, D4
server-provided nonces, M1 mTLS certificate-bound tokens, and X1/X2 for correct and broken
X-Forwarded-Client-Cert propagation.

Each subdirectory has been run against live services; outputs are under `results/`:

| Directory | Condition | Outcome |
|---|---|---|
| `d2-distributed-cache/` | D2 | 11 passed default cache, 12 passed Redis shared cache |
| `baseline-and-mtls/` | C0, M1 | 24 passed |
| `xfcc-silent-binding/` | X1, X2 | 25 passed |
| `d4-nonces/` | D4 | live nonce flow |
| `analysis/` | statistical pipeline | 145 tests, synthetic data only |

What remains unexecuted is the **latency** comparison and hypotheses H1 through H4 in
`PREREGISTRATION.md`. No outcome for them is claimed anywhere.

Running this matrix requires infrastructure the single-host demonstration deliberately
omits: a Redis cluster, three resource-server replicas behind NGINX, mTLS client
certificates with a terminating proxy, and a two-host network path. It also requires the
statistical pipeline in `PROTOCOL.md` section 5, which the binary single-host outcome does
not need.

When this work is executed, results land here and the pre-registration deviation log in
`docs/DEVIATIONS.md` records any departure from the committed analysis plan.
