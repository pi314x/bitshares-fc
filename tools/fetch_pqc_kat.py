#!/usr/bin/env python3
"""Refresh the FIPS 203 / 204 known-answer vectors in tests/crypto/pqc_kat/.

Downloads NIST's ACVP vectors and writes back the subsets the conformance test reads,
verbatim apart from dropping unused fields. Run it to move to a newer ACVP revision, then
update the commit hash recorded in tests/crypto/pqc_kat/SOURCE.md.

    python3 tools/fetch_pqc_kat.py

Only the parameter sets this project uses are extracted: ML-KEM-768 and ML-DSA-65.
"""

import json
import os
import sys
import urllib.request

RAW = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files"
API = "https://api.github.com/repos/usnistgov/ACVP-Server/commits/master"

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, os.pardir, "tests", "crypto", "pqc_kat")

# (output file, ACVP directory, parameter set, group predicate, fields kept)
WANTED = [
    ("ml-kem-768-keygen.json", "ML-KEM-keyGen-FIPS203", "ML-KEM-768",
     lambda g: g.get("testType") == "AFT",
     ("tcId", "d", "z", "ek", "dk")),
    ("ml-kem-768-encap.json", "ML-KEM-encapDecap-FIPS203", "ML-KEM-768",
     lambda g: g.get("function") == "encapsulation",
     ("tcId", "ek", "m", "c", "k")),
    ("ml-kem-768-decap.json", "ML-KEM-encapDecap-FIPS203", "ML-KEM-768",
     lambda g: g.get("function") == "decapsulation",
     ("tcId", "dk", "c", "k", "reason")),
    ("ml-dsa-65-keygen.json", "ML-DSA-keyGen-FIPS204", "ML-DSA-65",
     lambda g: g.get("testType") == "AFT",
     ("tcId", "seed", "pk", "sk")),
    # the external / pure group, which is what crypto_sign_verify_ctx implements
    ("ml-dsa-65-sigver.json", "ML-DSA-sigVer-FIPS204", "ML-DSA-65",
     lambda g: (g.get("signatureInterface") == "external"
                and g.get("preHash") == "pure"
                and not g.get("externalMu")),
     ("tcId", "pk", "message", "context", "signature", "testPassed", "reason")),
    # sigGen, external/pure like sigVer. Split into the two groups rather than merged,
    # because they differ in exactly the field that makes signing reproducible:
    # deterministic fixes the hedging randomness at all zeros and carries no "rnd" per case,
    # hedged supplies one. "deterministic" itself is a GROUP property and lands in the meta.
    ("ml-dsa-65-siggen-det.json", "ML-DSA-sigGen-FIPS204", "ML-DSA-65",
     lambda g: (g.get("signatureInterface") == "external"
                and g.get("preHash") == "pure"
                and not g.get("externalMu")
                and g.get("deterministic") is True),
     ("tcId", "sk", "message", "context", "signature")),
    ("ml-dsa-65-siggen-hedged.json", "ML-DSA-sigGen-FIPS204", "ML-DSA-65",
     lambda g: (g.get("signatureInterface") == "external"
                and g.get("preHash") == "pure"
                and not g.get("externalMu")
                and g.get("deterministic") is False),
     ("tcId", "sk", "message", "context", "signature", "rnd")),
]


def fetch(url):
    with urllib.request.urlopen(url, timeout=180) as r:
        return r.read()


def main():
    try:
        sha = json.loads(fetch(API))["sha"]
    except Exception as e:                      # noqa: BLE001 - provenance is advisory here
        print("warning: could not read ACVP commit sha (%s)" % e, file=sys.stderr)
        sha = "unknown"
    print("ACVP-Server master:", sha)

    cache = {}
    for name, directory, param_set, pred, fields in WANTED:
        if directory not in cache:
            url = "%s/%s/internalProjection.json" % (RAW, directory)
            print("fetching", url)
            cache[directory] = json.loads(fetch(url))
        doc = cache[directory]

        group = next((g for g in doc["testGroups"]
                      if g.get("parameterSet") == param_set and pred(g)), None)
        if group is None:
            raise SystemExit("no matching group for %s in %s" % (param_set, directory))

        # Missing fields are a schema change, not something to paper over with a default:
        # a silently-empty vector would make the conformance test pass on nothing.
        tests = []
        for t in group["tests"]:
            missing = [f for f in fields if f not in t]
            if missing:
                raise SystemExit("tcId %s in %s is missing %s"
                                 % (t.get("tcId"), directory, missing))
            tests.append({f: t[f] for f in fields})

        meta = {"source": "NIST ACVP-Server gen-val/json-files",
                "algorithm": doc.get("algorithm"),
                "mode": doc.get("mode"),
                "parameterSet": param_set,
                "vectorSetId": doc.get("vsId"),
                "tgId": group["tgId"],
                "acvpCommit": sha}
        for key in ("signatureInterface", "preHash", "deterministic"):
            if key in group:
                meta[key] = group[key]

        path = os.path.join(OUT, name)
        with open(path, "w") as f:
            json.dump(dict(meta, tests=tests), f, indent=1)
        print("  wrote %-28s %3d tests" % (name, len(tests)))

    print("\nUpdate the commit hash in tests/crypto/pqc_kat/SOURCE.md to", sha)


if __name__ == "__main__":
    main()
