# Kali-Linux Lab

![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)
![Focus](https://img.shields.io/badge/Focus-Low%20Level%20Engineering-red?style=for-the-badge)
![Code](https://img.shields.io/badge/Code-Python%20%7C%20C%20%7C%20Assembly-blue?style=for-the-badge)

## Overview

This repository serves as a centralized research lab. The projects housed here focus on Defense Engineering, Kernel-Level Monitoring, and Malware Analysis at the binary level.All tools are developed and stress-tested in a Kali Linux environment, utilizing frameworks like `eBPF`, `Qiling`, `Triton`, and `YARA`.

## Project Index

### Defensive Engineering & Forensics
| Project | Tech Stack | Description |
| :--- | :--- | :--- |
| [YARA Malware Scanner](./YARA_Malware_Scanner) | `Python` `YARA` | Automated Threat Triage System. Scans file systems for malware artifacts based on custom signature rules and automatically quarantines threats. |
| [eBPF EDR](./eBPF_EDR) | `C` `Python` `BCC` | Kernel-Level Endpoint Detection. Hooks into system calls using eBPF to monitor process execution and detect rootkits invisible to standard tools. |
| [Process Integrity Scanner](./Process%20Integrity%20Scanner) | `Python` `Linux API` | Memory Forensics Tool. Hunts for fileless malware and code injection by analyzing `/proc` memory maps for suspicious RWX (Read-Write-Execute) regions. |

### Malware Analysis & Reverse Engineering
| Project | Tech Stack | Description |
| :--- | :--- | :--- |
| [Malware Unpacker](./Malware_Unpacker) | `Python` `Qiling` | Dynamic Unpacking Engine. Uses binary emulation to execute packed malware in a sandbox, identifying the Original Entry Point and dumping the clean payload. |
| [De-virtualization Tool](./De-virtualization%20%26%20Symbolic%20Execution%20Tool) | `Python` `Triton` `Z3` | Obfuscation Defeater. Utilizes Symbolic Execution and SMT Solvers to simplify virtualized code and solve complex logical constraints in binaries. |

## Technologies & Frameworks

This laboratory relies on the following engines:

* [Qiling Framework](https://qiling.io/): Advanced binary emulation and instrumentation.
* [eBPF (Extended Berkeley Packet Filter)](https://ebpf.io/): For safe and efficient kernel instrumentation.
* [YARA](https://virustotal.github.io/yara/): Pattern matching and malware classification.
* [Triton](https://triton-library.github.io/): Dynamic binary analysis (DBA) and symbolic execution.

## Getting Started

Feel free to explore and improve any projects

```bash
git clone [https://github.com/uusrajaminyak/Kali-Linux.git]
```