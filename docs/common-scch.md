# Common secondary control channels

Configure `common_scch_count = 0`, `1` or `2` in `[cell_info]`, or change
**Cell configuration → Control channels → Common SCCH count** in the BS UI.
The default is zero. MCCH remains on TS1; SCCH1 uses TS2 and SCCH2 uses TS3.
With two SCCHs there is one remaining slot for voice/packet data. Minimum
mode is not advertised while common SCCH resources are present.

The dashboard shows requested/advertised counts, transition status and the
number of terminals assigned to each control channel. Terminal details show
SCCH support, MS_SCCH and the derived control timeslot. Counts include active
registrations and registrations awaiting their acceptance ACK, each once.

## Radio procedures

- At registration, capable radios get an MS_SCCH value from 0 to 11 for the
  least populated channel. Departures and roaming remove their occupancy.
  Radios without known support remain on MCCH; the SwMI caches capability
  for subsequent registrations and roaming. Missing capability is requested
  using D-LOCATION UPDATE COMMAND when SCCHs are operating.
- D-LOCATION UPDATE ACCEPT and its BL-ACK stay on the request's CCCH. The
  new assignment becomes the downlink route only after acceptance is ACKed.
  The SCCH information IE has a four-bit MS_SCCH and zero distribution on
  frame 18 (minimum mode is not used).
- On a SYSINFO N_SCCH change, the radio derives its new channel as
  `1 + MS_SCCH % (N_SCCH + 1)`. Existing radios do not need forced registration.
- New SCCHs wait for current voice/PD allocations to release naturally.
  The allocator fences requested resources against new allocations before
  expanding. Physical SCCH operation starts before SYSINFO advertises it.
- On decrease, advertise the lower N_SCCH first. SYSINFO is sent on every
  frame-18 slot, with additional broadcasts on the remaining CCCHs. The old
  resources remain control channels for at least 72 frames, longer for an
  active EE period, and until queues and previously granted uplink drain.
- Each CCCH has common-control AACH, reserved/random access and its own
  load controller. LMAC recognises common uplink bursts on all these slots.
- Ordinary acknowledged signalling tries the assigned CCCH, then plausible
  voice/PD listener channels, then the other CCCHs. Registration, explicit
  response routes and PD procedures retain their protocol-bound channel.
  Common-channel ACKs use SCH/F rather than FACCH. With SCCHs disabled the
  existing delivery behaviour is retained.
- Group common signalling covers MCCH and all operating SCCHs, including
  scanning listeners; existing traffic/PD listener copies remain in use.
  Group SDS therefore always retains its MCCH copy. EE replays use the
  appropriate assigned common slot. Event labels are discarded when an idle
  terminal changes physical control slot; active PDCH labels are retained.

## SwMI and protocol

The BS and SwMI need protocol v43. Registration messages carry the optional
SCCH capability; a CommonControlReport confirms allocation after the air ACK.
The SwMI accepts reports only from the current serving BS with its exact
registration generation. These generations are BS-local command IDs and
must not be compared as globally increasing numbers. Capability and the
last serving-cell assignment are stored in `terminal_common_control` for
same-cell recovery. A roaming target makes its own load-based assignment.

The shared `../tetra-network-domain` directory has no Git repository in this
checkout. Its reviewed source change is preserved in
`contrib/protocol/common-scch-v43.patch`. Apply it from that directory with
`git apply --check <path-to-patch>` and `git apply <path-to-patch>` (Git can
apply this patch outside a repository). The patch is for the v42 source
recorded in the adjacent README. Both build machines need that shared change.
The SwMI also accepts v42/v41 sessions during deployment; their registration
layout does not contain the new byte and their radios remain on MCCH.

## Standards and verification

Normative sources are in `docs/tetra/`:

- TS 100 392-2 V3.10.1: 16.10.45–46; 23.3.1.2.1.2 (mapping/configuration
  order); 23.4 (event labels); 23.5.1.3.2 (response channel); 23.7.6 (EE).
- TTR 001-01 V7.0.0: 6.3–6.4 and Figure 3 (capability, acceptance ACK,
  roaming, MS_SCCH and frame-18 distribution); 14.1.11 (minimum mode).
- TTR 001-12: service interactions and current-channel response rules.

Tests cover least-load allocation after departure, pending registration
counting, capability fallback, MS_SCCH wire bits, common-channel AACH/access,
ordered delivery and ingress ACKs, live expansion without preemption and
SYSINFO-before-release ordering, persistence and protocol v41/v42 compatibility.
Live RF verification should include registrations across TS1/2/3, SDS in both
directions, scan-list groups, voice/PD and roaming, and a decrease with sleeping
radios and outstanding grants.
