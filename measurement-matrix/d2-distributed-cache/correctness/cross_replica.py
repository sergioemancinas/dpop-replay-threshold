"""
Cross-replica DPoP proof replay, condition D2.

Two facts, both binary, no latency measurement.

  Fact 1, dpop.jti.cache=default
    Spring Security's JtiClaimValidator is backed by a static LinkedHashMap private to the
    JVM. Behind a round-robin proxy, the same proof presented again lands on a replica that
    has never seen it and is accepted. This holds at any rate: the sequence below is paced
    at 1 req/s, roughly 1/17 of the single-node bounded-cache threshold R* from D1, so no
    eviction is involved. This is spring-projects/spring-security#18120.

  Fact 2, dpop.jti.cache=redis
    With a shared jti cache installed through
    DPoPProofJwtDecoderFactory.setJwtValidatorFactory, the first presentation wins and every
    later one is rejected, on whichever replica it lands.

The proof is presented verbatim each time, same jti and same iat. Presentations go through
the proxy on one URL, so htu is identical for all of them and a rejection can only come from
the jti check.

Assertions are stated over the observed (status, node) sequence rather than over an assumed
round-robin order, so a scheduling artefact shows up as INCONCLUSIVE, never as PASS.
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path

import httpx

# Same primitives as the single-host validation. Copying them would let the two conditions
# drift apart in how a proof is built.
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "single-host-validation" / "load"))
from dpop import DPoPKey, decode_claims, fetch_token  # noqa: E402

results = []


def record(name, ok, detail=""):
    status = "PASS" if ok else "FAIL"
    results.append((status, name, detail))
    print(f"  {status}  {name:56s} {detail}")
    return ok


def inconclusive(name, reason):
    results.append(("INCONCLUSIVE", name, reason))
    print(f"  ????  {name:56s} {reason}")


def skip(name, reason):
    results.append(("SKIP", name, reason))
    print(f"  SKIP  {name:56s} {reason}")


def present(client, url, token, proof):
    """Send one presentation and return (status, node, cache_mode)."""
    response = client.get(url, headers={"Authorization": f"DPoP {token}", "DPoP": proof},
                          timeout=15.0)
    return (response.status_code,
            response.headers.get("X-Node-Id", "?"),
            response.headers.get("X-Jti-Cache", "?"))


def wait_for_stack(url, token, key, timeout):
    """Block until the proxy answers with a DPoP 200 from some replica."""
    deadline = time.monotonic() + timeout
    last = None
    with httpx.Client() as client:
        while time.monotonic() < deadline:
            try:
                status, node, cache = present(
                    client, url, token, key.proof("GET", url, access_token=token))
                if status == 200:
                    return cache
                last = f"HTTP {status} from {node}"
            except httpx.HTTPError as exc:
                last = str(exc)
            time.sleep(1.0)
    raise RuntimeError(f"stack not ready after {timeout}s: {last}")


def run(args):
    url = f"{args.base_url}/api/resource"
    key = DPoPKey()
    token_response = fetch_token(args.token_endpoint, key, args.client_id,
                                 args.username, args.password)
    token = token_response["access_token"]

    print("\nPreconditions")
    record("token_type is DPoP", token_response.get("token_type") == "DPoP",
           f"got {token_response.get('token_type')}")
    jkt = decode_claims(token).get("cnf", {}).get("jkt")
    record("access token carries cnf.jkt bound to client key", jkt == key.thumbprint,
           f"got {jkt}")

    reported_mode = wait_for_stack(url, token, key, args.wait)
    record(f"stack reports jti cache mode '{args.mode}'", reported_mode == args.mode,
           f"replicas report '{reported_mode}'")
    if reported_mode != args.mode:
        print("\naborting: the stack is not in the mode this run claims to test")
        return False

    with httpx.Client() as client:
        # Every request below carries a distinct jti unless stated otherwise.
        probe = [present(client, url, token, key.proof("GET", url, access_token=token))
                 for _ in range(6)]
        nodes = {node for _, node, _ in probe}
        fanout_ok = record("proxy fans out over 3 distinct replicas", len(nodes) == 3,
                           f"saw {sorted(nodes)}")
        record("unique proofs accepted on every replica",
               all(status == 200 for status, _, _ in probe),
               f"statuses {[s for s, _, _ in probe]}")
        if not fanout_ok:
            print("\naborting: cross-replica claims are meaningless without 3 replicas")
            return False

        # The proof under test. Built once, presented verbatim args.presentations times.
        iat = int(time.time())
        jti = f"d2-probe-{iat}"
        held = key.proof("GET", url, jti=jti, iat=iat, access_token=token)

        print(f"\nReplay sequence: {args.presentations} presentations of one proof, "
              f"{args.pace:g} s apart ({1 / args.pace:g} req/s)")
        sequence = []
        for i in range(args.presentations):
            if i:
                time.sleep(args.pace)
            status, node, _ = present(client, url, token, held)
            sequence.append((status, node))
            print(f"    #{i + 1} HTTP {status} from {node}")

        age = int(time.time()) - iat
        record("whole sequence stayed inside the 60 s iat window", age < 60,
               f"probe age {age} s at the last presentation")

        first_status, first_node = sequence[0]
        record("first presentation accepted", first_status == 200,
               f"HTTP {first_status} from {first_node}")

        later = sequence[1:]
        accepted_elsewhere = [(s, n) for s, n in later if s == 200 and n != first_node]
        rejected_elsewhere = [(s, n) for s, n in later if s == 401 and n != first_node]
        distinct_acceptors = {n for s, n in sequence if s == 200}

        print()
        if args.mode == "default":
            record("replay ACCEPTED on a replica that never saw the proof",
                   bool(accepted_elsewhere),
                   f"{len(accepted_elsewhere)} of {len(later)} later presentations")
            record("every replica admitted the same proof", len(distinct_acceptors) == 3,
                   f"admitted by {sorted(distinct_acceptors)}")
            repeats = [(s, n) for s, n in later if n == first_node]
            if repeats:
                record("rejected only once the proof returns to a replica that saw it",
                       all(s == 401 for s, n in repeats),
                       f"statuses on {first_node}: {[s for s, _ in repeats]}")
            else:
                inconclusive("rejected on return to the first replica",
                             f"no presentation came back to {first_node}")
            record("admission is rate independent", bool(accepted_elsewhere),
                   f"observed at {1 / args.pace:g} req/s, well below R* ~= 17 req/s")
        else:
            record("exactly one presentation accepted", len(distinct_acceptors) == 1,
                   f"accepted by {sorted(distinct_acceptors)}")
            record("replay REJECTED on a replica that never saw the proof",
                   bool(rejected_elsewhere),
                   f"{len(rejected_elsewhere)} of {len(later)} later presentations")
            record("every later presentation rejected",
                   all(s == 401 for s, _ in later),
                   f"statuses {[s for s, _ in later]}")

        print("\nShared-cache partition behaviour")
        if not args.with_redis_outage:
            skip("Redis unavailable fails closed",
                 "needs --with-redis-outage, which stops the redis container")
        elif args.mode != "redis":
            skip("Redis unavailable fails closed", "only meaningful in redis mode")
        else:
            check_fail_closed(client, url, token, key, args)

    failed = sum(1 for r in results if r[0] == "FAIL")
    passed = sum(1 for r in results if r[0] == "PASS")
    unclear = sum(1 for r in results if r[0] == "INCONCLUSIVE")
    skipped = sum(1 for r in results if r[0] == "SKIP")
    print(f"\n{passed} passed, {failed} failed, {unclear} inconclusive, {skipped} skipped")
    if failed:
        print("\nFAILURES")
        for status, name, detail in results:
            if status == "FAIL":
                print(f"  {name}: {detail}")
    return failed == 0


def compose(args, *argv):
    subprocess.run(["docker", "compose", "-f", args.compose_file, *argv],
                   check=True, capture_output=True)


def check_fail_closed(client, url, token, key, args):
    """Stop Redis, assert a fresh unique proof is refused, restart, assert recovery."""
    compose(args, "stop", "redis")
    try:
        # Give Lettuce a moment to notice; the connect timeout is 500 ms.
        time.sleep(2.0)
        statuses = [present(client, url, token,
                            key.proof("GET", url, access_token=token))[0]
                    for _ in range(3)]
        record("fresh unique proof refused while Redis is down",
               all(s == 401 for s in statuses), f"statuses {statuses}")
    finally:
        compose(args, "start", "redis")
    deadline = time.monotonic() + 30
    recovered = False
    while time.monotonic() < deadline:
        time.sleep(1.0)
        status, _, _ = present(client, url, token,
                               key.proof("GET", url, access_token=token))
        if status == 200:
            recovered = True
            break
    record("service recovers once Redis returns", recovered)


def main():
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["default", "redis"], required=True,
                        help="the jti cache the stack was started with")
    parser.add_argument("--base-url", default="http://localhost:8190")
    parser.add_argument("--token-endpoint",
                        default="http://localhost:8180/realms/dpop-demo/protocol/openid-connect/token")
    parser.add_argument("--client-id", default="demo-client")
    parser.add_argument("--username", default="testuser")
    parser.add_argument("--password", default="testpass")
    # Six presentations at one per second visit each of three replicas twice and finish
    # 5 s after the proof was minted, far inside the 60 s iat window.
    parser.add_argument("--presentations", type=int, default=6)
    parser.add_argument("--pace", type=float, default=1.0)  # seconds between presentations
    parser.add_argument("--wait", type=float, default=180.0)
    parser.add_argument("--with-redis-outage", action="store_true")
    parser.add_argument("--compose-file", default=str(here.parent / "docker-compose.yml"))
    args = parser.parse_args()
    if args.pace <= 0:
        parser.error("--pace must be > 0; the rate independence claim needs a stated rate")
    return 0 if run(args) else 1


if __name__ == "__main__":
    sys.exit(main())
