# Rev-Dojo

[*Rev-Dojo*](https://dylan-liew.github.io/rev-dojo/) is my personal journey in learning the foundations of reverse engineering and binary exploitation. 

This documentation serves as both my learning notes and a resource for others interested in these fields.

## Learning Path

### 1. Foundations
- C Programming Essentials 
- Compilation Process   
- Assembly Basics     
- Memory Management

### 2. Reverse Engineering
**Static Analysis:**
- Disassemblers (IDA Pro/Ghidra)
- Control Flow & Function Analysis
- String & Symbol Analysis

**Dynamic Analysis:**
- GDB + PEDA/Pwndbg
- Debugging Techniques
- Binary Patching

**Symbolic Execution (Z3/angr)**

### 3. Binary Exploitation
**Fundamentals:**
- Introduction to pwntools
- Buffer Overflows
- Shellcode Development

**Memory Corruption:**
- Format String Attacks
- Array Indexing Vulnerabilities
- Integer Overflow

**Protection Bypasses:**
- Understanding Mitigations (ASLR, NX, Stack Canaries, PIE)
- Stack Canary Bypass
- Return-to-libc Attacks

**Advanced Exploitation:**
- ROP (Return Oriented Programming)
- Heap Exploitation
- Modern Techniques (Tcache Poisoning)

## Getting Started

The documentation is built with MkDocs Material. To run locally:

```bash
pip install mkdocs-material
mkdocs serve
```



