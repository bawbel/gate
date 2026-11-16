# Verifying a release

bawbel-gate releases on PyPI carry signed build provenance. This page shows how to check it,
what a pass and a failure look like, and what a pass does not tell you.

The examples were run on 2026-11-16 against bawbel-gate 0.1.0 with `pypi-attestations` 0.0.31.
Replace the version and file name with the release you are checking. Both checks need network
access.

## 1. Check the provenance

The provenance is a signed statement, published with the release, that this exact file was
built and published by the `publish.yml` workflow in the `bawbel/gate` repository. Check it
with PyPI's attestation tool:

```bash
pip install pypi-attestations
pypi-attestations verify pypi --repository https://github.com/bawbel/gate \
  pypi:bawbel_gate-0.1.0-py3-none-any.whl
```

A pass prints one line and exits 0:

```text
OK: bawbel_gate-0.1.0-py3-none-any.whl
```

The source distribution is checked the same way (`pypi:bawbel_gate-0.1.0.tar.gz`) and printed
`OK: bawbel_gate-0.1.0.tar.gz`. To check a file you already downloaded, give its path instead
of `pypi:<name>`: the tool then compares that file's digest with the signed statement.

```bash
pypi-attestations verify pypi --repository https://github.com/bawbel/gate \
  ./bawbel_gate-0.1.0-py3-none-any.whl
```

### What a failure looks like

Any exit code other than 0 means the check did not pass. Do not install the file. Two failures,
as printed:

A file that is not the one that was signed (here, a copy of the wheel with one byte appended):

```text
Verification failed for bawbel_gate-0.1.0-py3-none-any.whl: Verification failed: subject does not match distribution digest
```

A provenance signed by a different repository than the one you named (here, the 0.1.0 wheel
checked against `bawbel/scanner`):

```text
Verification failed: provenance was signed by repository "bawbel/gate", expected "bawbel/scanner"
```

A file PyPI does not have gives `Could not find the artifact '<name>' on PyPI` and exit 1.

### Where the provenance lives

PyPI's JSON API (`https://pypi.org/pypi/bawbel-gate/json`) has no `provenance` entry for either
0.1.0 file, so a tool that reads only that API reports no provenance. The attestation is served
by PyPI's integrity endpoint:

```bash
curl -s -H 'Accept: application/vnd.pypi.integrity.v1+json' \
  https://pypi.org/integrity/bawbel-gate/0.1.0/bawbel_gate-0.1.0-py3-none-any.whl/provenance
```

It returned HTTP 200 for the wheel and for the sdist. The publisher recorded in the wheel's
attestation is `kind: GitHub`, `repository: bawbel/gate`, `workflow: publish.yml`,
`environment: pypi`, and its subject is the wheel's SHA-256.

## 2. Compare the hash

The hash tells you the file you hold is byte-for-byte the file PyPI serves. Get it from PyPI's
JSON API or from the file's page on pypi.org, and compute it for your copy:

```bash
python -m pip hash bawbel_gate-0.1.0-py3-none-any.whl
# --hash=sha256:2ca4bc0531d6510e87b8833501a6a92a66118cd71ea521dedce96b2ca3ef174e
```

To make `pip` refuse anything else, pin the hash in a requirements file:

```text
bawbel-gate==0.1.0 --hash=sha256:2ca4bc0531d6510e87b8833501a6a92a66118cd71ea521dedce96b2ca3ef174e
```

```bash
pip install --no-deps --require-hashes -r requirements.txt
```

With a wrong hash, `pip` stops with `ERROR: THESE PACKAGES DO NOT MATCH THE HASHES FROM THE
REQUIREMENTS FILE` and prints the expected and the actual value.

`--no-deps` is there because without it `pip` stops at the first dependency that is not pinned:
`ERROR: In --require-hashes mode, all requirements must have their versions pinned with ==.`
Pin each dependency with its own hash if you want the whole install pinned.

A hash taken from PyPI comes from the same place as the file, so a match shows the download
was intact. It does not show who built the file. Check 1 does that.

## What a pass does not show

- It does not show the code is free of defects, or that anyone reviewed it. It shows that the
  file came from the named workflow in the named repository and has not been changed since.
- It covers the files you check. Check each release you install; a pass for 0.1.0 says nothing
  about another version. As of 2026-11-16, 0.1.0 is the only release on PyPI.
