# xBGPsec: Extended BGP Security Protocol

## Overview

xBGPsec is an extended BGP security protocol designed to address the limitations of BGPsec while providing robust security guarantees for interdomain routing. This repository contains a prototype implementation that demonstrates feasibility and benefits.

> Note: This project is under active development. More comprehensive documentation, implementation details, and evaluation results will be added upon publication of our research paper.

## Key Features

- AS path integrity protection (cryptographic verification)
- Route leak detection
- Partial deployment support
- Offloaded cryptographic operations (centralized validation)
- Legacy compatibility with existing BGP infrastructure

## Architecture

This prototype extends a GoBGP router with xBGPsec capabilities and integrates with a modified NIST-BGP-SRx framework to demonstrate deployment feasibility and performance.

## Repository structure

- `GoBGPSRx/` — Modified GoBGP implementation with xBGPsec support
- `NIST-BGP-SRx/` — Enhanced NIST framework supporting xBGPsec validation
- `docs/` — Documentation (to be expanded upon publication)

## Requirements

- Linux-based OS
- Go 1.16+ (module-aware; Go 1.18+ recommended)
- Build tools and dependencies required by NIST-BGP-SRx

## Installation

### GoBGP (GoBGPSRx)
Run from repository root:
```bash
cd gobgp
# with Go modules, go install will build and install binaries
go install ./...
```

Notes:
- If you use GOPATH (legacy), ensure binaries path is in your PATH (`$GOPATH/bin`).
- `go build [Projects](http://_vscodecontentref_/0).` is optional for a local build; `go install` is sufficient to build+install.

### NIST-BGP-SRx

If you are on a recent Ubuntu release, helper.sh tries to install required packages:
```bash
cd NIST-BGP-SRx
# helper script tested on Ubuntu (may need adjustments on other distros)
./helper.sh
```

General build (may require additional manual fixes depending on OS):
```bash
./buildBGP-SRx.sh -A -SRxSnP
```
The build script can produce errors depending on OS and package versions; see `NIST-BGP-SRx/README` or open an issue if you hit platform-specific failures.

## Usage

Example: run SRx server demo (from NIST-BGP-SRx binaries directory)
```bash
cd NIST-BGP-SRx/local-6.3.3/bin
sudo ./srx_server -f demo.conf
```

Run GoBGP (installed to your Go bin directory, e.g. `~/go/bin`):
```bash
sudo gobgpd -f path/to/router_config.conf
```
Adjust IPs and config paths to your environment.

## Troubleshooting

- If builds fail, check Go version, module settings, and install required system packages.
- For permission issues when binding BGP ports, run with sudo or use appropriate capabilities.

## License

Please add a LICENSE file to this repository. If none is present, specify the intended license (e.g., MIT, Apache-2.0).

## Contributing

Open issues or PRs for bugs, documentation or improvements. Add developer setup instructions as needed.

## Citation

If you use this software in research, please cite the forthcoming paper (details to be added on publication).

## Contact

For implementation or research questions, open an issue in this repository.
