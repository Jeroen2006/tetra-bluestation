# Shared protocol patch

`common-scch-v43.patch` updates
`tetra-network-domain/crates/tetra-swmi-protocol/src/lib.rs` from protocol v42
to v43. The shared workspace has no Git metadata here, so the BS commit
retains the patch instead of leaving this dependency change unversioned.

Apply from the shared workspace root, where `crates/tetra-swmi-protocol`
exists. Check first with `git apply --check /path/to/common-scch-v43.patch`.
The LF-normalised base source SHA256 is
`2244f478ffbba2b00a63acb3180254d820098fe16bf28c67d4b223ec7b685edf`.
Already-updated sources will fail that forward check; use
`git apply --reverse --check` to verify that they include this change.

Build the BS and SwMI against the same shared sources. Tests in this patch
cover v43 SCCH fields, invalid allocations and v41/v42 registration/SYSINFO
compatibility. The BS and SwMI implementations must be deployed together
before enabling a positive common SCCH count.
