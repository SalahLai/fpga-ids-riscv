# FPGA-Accelerated Network IDS with RISC-V Co-Processor Integration

Bachelor's graduation project — Institute of Electrical and Electronic Engineering,
M'Hamed Bougara University of Boumerdes, Algeria (2026)

**Authors:** Salah Eddine Laifa & Youcef Slimani
**Supervisor:** Dr. Touzzout Walid

---

## Project Overview

A hardware-accelerated Intrusion Detection System implemented in VHDL on a
MicroPhase Z7-Lite (Zynq-7020 FPGA), with RISC-V co-processor integration
for adaptive threat management.

## IDS Pipeline
RMII RX → Ethernet Parser → IPv4 Parser → IPv4 Checker (R1–R12)
→ TCP Parser  → TCP Checker  (T1–T5)
→ UDP Parser  → UDP Checker  (U1–U3)
→ Scoring Engine → RISC-V

## Implemented Detection Rules

### IPv4 Layer (12 rules)
| Rule | Condition | Attack |
|------|-----------|--------|
| R1 | ip_version ≠ 4 | Malformed packet |
| R2 | ip_ihl < 5 | Invalid header length |
| R3 | ip_length < 20 | Impossible packet size |
| R4 | ip_ttl ≤ threshold | Traceroute / low TTL probe |
| R5 | ip_frag_off > 0 | Fragmentation attack |
| R6 | ip_src = 0.0.0.0 | Spoofed source address |
| R7 | ip_src = ip_dst | Land attack |
| R8 | ip_src = 127.x.x.x | Bogon loopback source |
| R9 | ip_src = 169.254.x.x | Bogon link-local source |
| R10 | ip_src = 224–239.x.x.x | Bogon multicast source |
| R11 | ip_ihl > 5 | IP options present |
| R12 | ip_flags[0] = 1 | Reserved bit set |

### TCP Layer (5 rules)
| Rule | Condition | Attack |
|------|-----------|--------|
| T1 | SYN + FIN | Invalid flag combination |
| T2 | SYN + RST | Invalid flag combination |
| T3 | flags = 0x00 | NULL scan |
| T4 | flags = 0xFF | XMAS scan |
| T5 | dst_port ∈ forbidden table | Forbidden service access |

### UDP Layer (3 rules)
| Rule | Condition | Attack |
|------|-----------|--------|
| U1 | dst_port ∈ forbidden table | Forbidden UDP service |
| U2 | udp_length < 8 | Invalid UDP length |
| U3 | udp_length = 0 | Zero-length UDP |

## Hardware

- **Board:** MicroPhase Z7-Lite (Xilinx Zynq-7020)
- **Language:** VHDL
- **Tool:** Vivado ML Standard 2025.2
- **Clock:** 50 MHz (PL fabric)

## Repository Structure
sources_1/new/     ← VHDL design files
sim_1/new/         ← VHDL testbenches
## RISC-V Co-Processor

The BigDCore RV32I pipelined processor (designed by Youcef Slimani) 
interfaces with the IDS through a memory-mapped register bank at 
addresses 0x400–0x5FF in its data memory space.

See [BigDCore repository](LINK_HERE) for the processor implementation.