```
░▀█▀░█▀▀░▀█▀░█▀▄░█▀█░░░░░█▀▄░█░░░█░█░█▀▀░█▀▀░▀█▀░█▀█░▀█▀░▀█▀░█▀█░█▀█
░░█░░█▀▀░░█░░█▀▄░█▀█░▄▄▄░█▀▄░█░░░█░█░█▀▀░▀▀█░░█░░█▀█░░█░░░█░░█░█░█░█
░░▀░░▀▀▀░░▀░░▀░▀░▀░▀░░░░░▀▀░░▀▀▀░▀▀▀░▀▀▀░▀▀▀░░▀░░▀░▀░░▀░░▀▀▀░▀▀▀░▀░▀
```

This is a FOSS TETRA stack aimed at providing an extensible basis for TETRA experimentation and research. At this point, it's alpha code. The stack serves a downlink base station signal, and a properly configured MS is able to receive the emitted downlink signal, connect to it, and attach to talkgroups. Voice calls are partially supported. Connectivity through Brew with the larger BrandMeister network is also optionally available. Lots of other functionality is currently not implemented, although parsing code for most TETRA protocol messages is already present. 

## Local BS dashboard

`bluestation-bs` includes a read-only dashboard for system, radio, terminal, Random Access and SwMI status. Add this section to the BS TOML configuration, then restart the BS:

```toml
[web]
enabled = true
bind_address = "0.0.0.0"
port = 8080
```

Open `http://<bs-address>:8080/`. The dashboard is disabled when `[web]` is absent or `enabled = false`. Its assets are included in the BS binary; no separate web server or internet connection is needed. The most recent 15 minutes of charts are held in memory and restart with the BS. The page has no authentication; choose an appropriate interface or network for the listener.

The JSON status is available at `/api/v1/snapshot` and `/api/v1/history`. Unknown measurements are `null` rather than zero. `--check-config` validates the web settings without opening a listener.

The Cell tab shows the effective broadcast identity, carrier, SYSINFO and service flags, plus a one-second snapshot of the downlink hyperframe/multiframe/frame/timeslot counters. Its chart counts allocated slots per type (control, voice, packet data and network), not individual transmitted bursts, on a fixed 0–4 axis. The same colours are used for slots throughout the dashboard: blue control, orange voice, purple packet data, pink network and grey free.

Configuration → Cell includes a live Enable TX switch, persisted as `[phy_io].tx_enabled` (default `true`). Disabling it stops transmission while reception and SwMI stay active. Enabling it still requires the usual network radio permission; it does not override provisioning or recovery gates.

## Documentation

Project documentation for tetra-bluestation is maintained in a separate repository, as a wiki.

https://github.com/MidnightBlueLabs/tetra-bluestation-docs/wiki

The documentation repository contains:
- Hardware and SDR considerations 
- Configuration file reference and examples  
- Build and runtime instructions   
- Practical notes 

Contributions to the documentation follow the same pull-request-based workflow as the main codebase, see the appropriate "Contributions" chapter.

## Acknowledgements

- Thanks to Harald Welte and the osmocom crew for their amazing initial work on osmocom-tetra, without which this project would not have existed. 
- Many thanks to Tatu Peltola, who graciously augmented rust-soapysdr with the required timestamping functionality to facilitate robust rx/tx, and also provided a rust-native Viterbi encoder/decoder class used in the LMAC.
- Many thanks to the awesome contributers helping to make BlueStation as stable, fancy and feature-rich as can be. 
- Thanks to Stichting NLnet, who agreed on allocating a part of the [RETETRA3 project](https://nlnet.nl/project/RETETRA3/) grant to the implementation of FOSS software for TETRA. 
