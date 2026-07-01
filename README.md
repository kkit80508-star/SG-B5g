# Cryptographic Scheme Implementation and Comparative Analysis

## Overview

This project presents an implementation of a cryptographic scheme using two different approaches:

- **Python-based implementation** for high-level prototyping and functional validation.  
- **C-based implementation** using the **PBC (Pairing-Based Cryptography) library** and **OpenSSL** for performance-oriented and low-level cryptographic operations.  

The goal is to analyze correctness, efficiency, and performance trade-offs between a high-level interpreted environment and a low-level optimized cryptographic stack.

---

## Requirements

### Python Environment
- Python 3.8+
- hashlib
- secrets
- time

### C Environment
- GCC / Clang
- PBC library
- OpenSSL
- Make
