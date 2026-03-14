# ProofVote

<img align="right" width="192px" src="./resources/logo.png" alt="ProofVote Logo">

<a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License"></a> <a href="https://www.buymeacoffee.com/gabrielzschmitz" target="_blank"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee" style="height: 20px !important;width: 87px;" ></a> <a href="https://github.com/gabrielzschmitz/proofvote"><img src="https://img.shields.io/github/stars/gabrielzschmitz/proofvote?style=social" alt="Give me a Star"></a>

**ProofVote** is a decentralized, permissioned blockchain voting system
designed for secure and transparent elections.
It enables organizations to conduct elections where votes are cryptographically
verifiable while maintaining voter privacy.

This repository contains the **ProofVote core system** and example workflows
demonstrating its use for benchmarking elections and case studies.

---

## Quick Start

### 1. Clone the repository

```sh
git clone https://github.com/gabrielzschmitz/ProofVote.git
cd ProofVote
```

### 2. Build and run

Follow the platform-specific build and run instructions in
[INSTALL.md](INSTALL.md).

### 3. Explore the examples

* **`src/core`** — Core blockchain nodes, clients, and consensus engine
* **`src/nodes`** — Leader and client executable implementations
* **`examples`** — Benchmark elections and university rector case study
* **`resources`** — Assets such as certificates for TLS connections

---

## Features

* Decentralized voting system using a permissioned blockchain
* Clients submit transactions (register members, create elections, cast votes)
* Leaders run a consensus engine ensuring correct vote ordering
* Metrics tracking (TPS, latency, throughput) for benchmarking
* Case study demonstration for university elections

<!-- <p align="center"> -->
<!--   <img src="./resources/demo.gif" alt="ProofVote Demo" style="border-radius: 8px;"> -->
<!-- </p> -->
<!-- <p align="center"> -->
<!--   <em>ProofVote can process hundreds of votes in real-time while ensuring -->
<!--   correctness and auditability.</em> -->
<!-- </p> -->

---

## Usage

ProofVote allows you to run secure elections for organizations or simulated
case studies.

* Start leader nodes and client nodes according to [INSTALL.md](INSTALL.md)
  instructions.
* Submit transactions through clients to register voters, create elections, and
  cast votes.
* View metrics and election outcomes via the client console.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file
for details.
