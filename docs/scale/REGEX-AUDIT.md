# Regular expression audit

Report, 2026-11-26, for [#255](https://github.com/bawbel/gate/issues/255) (GATE-44). Report only: no code, no test, no
DESIGN.md change, no dependency added, and nothing decided. It lists every pattern the gate runs on caller or upstream data, times
each on adversarial input of growing length, and says which ones grow faster than their input.

Every statement about code carries a file and line, read on 2026-11-26 from `develop` at `b9d76a9` (paths under `src/bawbel_gate/`).
A statement without one is UNVERIFIED. Every timing is VERIFIED: run on one machine, one run per cell taking the best of three.

```
machine: Linux-6.8.0-147-generic-x86_64-with-glibc2.39 | 11th Gen Intel(R) Core(TM) i7-1185G7 @ 3.00GHz | 8 logical CPUs | 31820 MiB RAM | Python 3.12.3
seed:    20261126 (for the random strings). The adversarial strings are built from fixed units, so they do not depend on it
```

## 1. Where patterns run on data

| Pattern | Where | Run on |
|---|---|---|
| Five secret patterns (AWS key, GitLab token, Vault token, PEM header, JWT) | `policy/manifest.py:270-274`, called by `_secret_scan` (`:280-287`) | every string value in a call's arguments, when a manifest has an argument guard with the scan on, which is its default (`:92`, `:131-138`) |
| Shannon entropy of the whole value | `policy/manifest.py:285`, `:290-295` | the same strings. It is a count, not a pattern, and is timed here because it shares the 5 ms budget |
| `fnmatch` glob, written by the manifest author | `policy/manifest.py:36` (a condition's `pattern`, matched against `str(value)` of an argument) and `:96` (`applies_to`, matched against the tool name) | caller-supplied strings. `fnmatch` compiles the glob to a regular expression |
| Approval prompt redaction | `policy/approval.py:20`, `:34` | calls `_secret_scan` on an argument string, so it has the same cost |
| Route patterns | `hub/server.py:34-35`, `console/server.py:236-237` | URL paths on the Hub and the console: anchored, with one character class. Not timed: they cannot backtrack across a delimiter (UNVERIFIED by run) |

No other `re` or `fnmatch` call exists under `src/` on caller or upstream data: `git grep -n "re\.\(compile\|search\|match\|sub\|findall\)"` and `fnmatch`
over `src/` finds only the lines above (`cli.py:238` is a file glob over a directory, not data). The JSON parse of every line is not a pattern.

## 2. Results

Time in milliseconds for one scan of a string of the given length, best of three, and `skip` where an earlier size had already taken more than 2 s.
The log-log slope between the smallest and largest timed sizes is about 1.0 for linear growth and 2.0 for quadratic.

| Pattern, input | 1 KiB | 10 KiB | 100 KiB | 1 MiB | First over 5 ms | Slope |
|---|---|---|---|---|---|---|
| AWS key, `AKIA` plus 15 characters then a break, repeated | 0.004 | 0.039 | 0.354 | 4.04 | not reached | 1.01 |
| GitLab token, `glpat-` plus 19 then a space, repeated | 0.002 | 0.015 | 0.135 | 1.38 | not reached | 1.00 |
| GitLab token, `glpat-` repeated | 0.001 | 0.010 | 0.099 | 1.02 | not reached | 1.01 |
| Vault token, `hvs.` plus 23 then a break, repeated | 0.002 | 0.018 | 0.140 | 1.44 | not reached | 1.00 |
| PEM header, `-----BEGIN ` then one long run | 0.002 | 0.015 | 0.148 | 1.51 | not reached | 0.95 |
| PEM header, `-----BEGIN A` repeated | 0.001 | 0.014 | 0.140 | 1.31 | not reached | 0.98 |
| **JWT, `eyJ` repeated, no dot** | **0.238** | **23.75** | **2,530** | skip | **between 4 KiB (3.76 ms) and 10 KiB** | **2.01** |
| JWT, `eyJ` and two segments, repeated | 0.002 | 0.021 | 0.205 | 2.03 | not reached | 0.99 |
| Entropy, random alphanumeric | 0.029 | 0.240 | 3.27 | 34.3 | between 100 KiB and 400 KiB | 1.05 |
| Entropy, one repeated character | 0.026 | 0.260 | 2.70 | 27.3 | between 100 KiB and 400 KiB | 1.00 |
| `_secret_scan` on benign prose (all patterns and entropy) | 0.028 | 0.260 | 3.11 | 31.8 | between 100 KiB and 400 KiB | 1.04 |
| **`_secret_scan` on `eyJ` repeated, no dot** | **0.284** | **25.05** | **2,716** | skip | **between 4 KiB (4.15 ms) and 10 KiB** | **1.99** |
| `fnmatch`, `*a*a*a*a*a*c`, `*a*...*c` with nine stars, and `a*` twelve times then `c`, each against a run of `a` with and without a final `b` | 0.001 | 0.004 | 0.039 | 0.39 | not reached | 0.91 to 1.01 |

Every cell is in `regex_audit.py` output on the machine above. The 256 B to 1 MiB grid has eight sizes, and the cells above are the ones at 1 KiB, 10 KiB, 100 KiB and 1 MiB.

## 3. What it shows

1. **One pattern grows quadratically: the JWT pattern** `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}` (`policy/manifest.py:274`). Its
   first segment starts with a literal that is itself made of the segment's characters, so on a string of repeated `eyJ` with no dot, each start position
   scans to the end of the string before failing. DERIVED from the pattern and confirmed by the slope of 2.01. At 40 KiB it took 390 ms, and at 100 KiB 2.5 s.
   Through `_secret_scan` it is the same (2.7 s at 100 KiB). It passes 5 ms between 4 KiB and 10 KiB.
2. **Nothing bounds the input by default.** A call's string argument has no size cap unless a manifest sets `max_outbound_bytes` (`policy/manifest.py:93`,
   `:225`, check at `:135`), and the gate runs on one thread (GATE-42, `mux/proxy.py:88`). A string of repeated `eyJ` of 100 KiB therefore holds the request loop for
   about 2.7 s, and the arguments are chosen by the caller. The byte cap, when set, is checked before the scan within a value (`:135-138`), so a cap below about 4 KiB
   keeps this pattern under 5 ms. That is a consequence of the byte cap and not a mitigation anyone has chosen.
3. **The other four secret patterns are linear** on every input tried, up to 1 MiB, with slopes between 0.95 and 1.01. The AWS pattern reaches 4.0 ms at 1 MiB.
4. **The entropy count is linear but is not free:** 3.3 ms for 100 KiB and 34 ms for 1 MiB, so a single large string exceeds the 5 ms budget by itself.
   `_shannon_entropy` runs on the whole value, whereas DESIGN.md 11.2 says "entropy windows run only on outbound string arguments over 24 chars".
   The code computes one value over the whole string (`policy/manifest.py:285`), not a window. That is a difference between DESIGN.md and the code, not changed here.
5. **`fnmatch` did not grow faster than its input** on the three globs tried, which have repeated stars. That does not cover every glob: the patterns are written by
   whoever writes the manifest, and a manifest was not fuzzed here (UNVERIFIED beyond the three).

## 4. Recommendations, per pattern

Options, not decisions. Adding a dependency is a decision for the maintainer and none is proposed to be added without it.

| Pattern | Recommendation | Needs a dependency |
|---|---|---|
| JWT (`manifest.py:274`) | Rewrite so the first segment cannot swallow the next start: require the literal `eyJ` to start a token (a lookbehind that the previous character is not in the class), or search for `eyJ` with `str.find` and test each hit with a bounded pattern, `\beyJ[A-Za-z0-9_-]{10,}\.` then the two segments, and stop at the first dot-less run. Either should be linear and needs only `re` (DERIVED from the pattern, not run). A fixed upper bound on each segment (for example 4,096) is a second option and changes what is detected | no |
| AWS, GitLab, Vault, PEM | Keep. Linear on every input tried | no |
| Entropy | Cap the length that is scanned (for example the first and last 4 KiB of a long value) or move to windows as DESIGN.md says. Either changes what is flagged, so it needs a decision | no |
| `fnmatch` globs | Keep, and add a test that runs each manifest glob against long `a` runs in `lint` | no |
| Any of the above, if a pattern cannot be rewritten | A linear-time engine would remove the class of problem. The standard library has none. This is the only place a dependency could be needed, and the JWT pattern can be fixed without one | yes, if chosen |

Independent of any rewrite: a size cap on a value before the scan, with a deny reason, bounds every pattern at once. DESIGN.md has no such limit today
and that is the GATE-45 question.

## 5. Not done

- No code, no test and no dependency. Nothing was rewritten.
- A manifest's own globs and condition patterns were not fuzzed, only three globs with repeated stars.
- The JWT result was timed in CPython 3.12.3 only. The `re` engine differs between versions and was not compared.
- One run per cell, best of three. Variance was not measured.
- The route patterns of the Hub and the console were not timed.
- No fix was run, so the effect of the recommended rewrite is not measured.

## Sources

`src/bawbel_gate/policy/manifest.py`, `policy/approval.py`, `hub/server.py`, `console/server.py`, `cli.py`, `mux/proxy.py` on `develop` `b9d76a9`;
DESIGN.md 11.2; `docs/hub/THREAT-MODEL.md` for the 5 ms budget context. GitHub's guidance on rewriting risky patterns and preferring
linear-time engines is the source the plan names, and it was not re-read for this report.
