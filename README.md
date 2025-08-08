# xBGPsec: Extended BGP Security Protocol

## Overview

xBGPsec is an extended BGP security protocol designed to address the limitations of BGPsec while providing robust security guarantees for interdomain routing. This repository contains a prototype implementation that demonstrates the feasibility and benefits of our approach.

> **Note**: This project is under active development. More comprehensive documentation, detailed implementation guidelines, and evaluation results will be made available upon publication of our research paper.

## Key Features

- **AS Path Integrity Protection**: Cryptographic verification of the AS path to prevent path manipulation attacks
- **Route Leak Detection**: Integrated mechanisms to identify and prevent route leaks
- **Partial Deployment Support**: Functions effectively in environments with mixed participation
- **Offloaded Cryptographic Operations**: Reduces router computational burden through a centralized validation architecture
- **Legacy Compatibility**: Maintains interoperability with existing BGP infrastructure

## Architecture

This prototype extends the GoBGP router with xBGPsec capabilities and integrates with a modified version of the NIST-BGP-SRx framework. The implementation demonstrates how xBGPsec can be deployed in practical network environments while maintaining performance and security.

## Repository Structure

- `/GoBGPSRx`: Modified GoBGP implementation with xBGPsec support
- `/NIST-BGP-SRx`: Enhanced NIST framework supporting xBGPsec validation
- `/docs`: Detailed documentation and implementation details will be provided upon paper publication

## Installation

Detailed installation instructions will be provided upon paper publication. Currently, the prototype requires:

1. A Linux-based operating system
2. Go 1.16 or higher
3. NIST-BGP-SRx dependencies

## Usage

Basic usage examples will be expanded in future updates. 

## Citation

If you use this software in your research, please cite our forthcoming paper (details to be added upon publication).

## Contact

For questions regarding the implementation or research, please open an issue in this repository.
