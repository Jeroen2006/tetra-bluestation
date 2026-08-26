# `tetra-crypto`

Dependency-free Rust primitives for TETRA air-interface encryption (AIE) and
the TAA1 key-management primitives:

- TEA1 and TEA3 keystream generation;
- air-interface IV construction;
- HURDLE, TA11/12/21/31/32/41/51/52/61/71/81/82/91/92;
- TB4, TB5, TB6 and TB7.

TEA2 is bewust niet opgenomen: de huidige SC2-scope vraagt om TEA1 en TEA3.
Voeg TEA2 alleen toe wanneer een expliciete interoperability-eis dat vereist.

The crate deliberately does **not** hold keys, decide ciphering policy, send
OTAR messages or encrypt an air-interface block. It provides pure primitives
only, so key lifecycle and protocol state stay in their respective layers.

## Test locally

Run only this crate and its embedded reference vectors:

```powershell
cargo test -p tetra-crypto
```

This command builds without SoapySDR or other radio DLLs. A full workspace
build may still fail on a development host where the required native radio
DLLs/libraries are not installed; that is unrelated to this crate.

## Provenance and licence

This is a Rust port of the Apache-2.0 licensed reference implementation in
[MidnightBlueLabs/TETRA_crypto](https://github.com/MidnightBlueLabs/TETRA_crypto),
at commit `defed030f6155ac70ff5d8bea97b348cb92ee1f6`. The crate is licensed
Apache-2.0; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

No cipher key, test-network secret or production credential may be committed
to this crate or its tests.
