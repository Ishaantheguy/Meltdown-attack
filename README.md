# Molten Walk – Speculative Execution Attack

This repository demonstrates a **Meltdown-style speculative execution attack** used to leak protected kernel memory through a **cache timing side channel**.

The exploit was developed for the **pwn.college Molten Walk challenge**, where the objective is to walk kernel page tables and recover a secret value from kernel memory.

---

## Attack Overview

Modern CPUs use **speculative and out-of-order execution** to improve performance.  
When a faulting instruction occurs, the CPU eventually rolls back architectural state. However, **microarchitectural effects such as cache state remain**.

This exploit abuses that behavior to leak data from privileged memory.

### Attack Steps

1. **Flush the cache** for a probe buffer.
2. Trigger **speculative execution** using a faulting memory access.
3. Use the **secret byte as an index** into the probe buffer.
4. Measure **cache access time** to determine which index was loaded.
5. Repeat the process multiple times to reliably recover the byte.

---

## Core Technique – Flush + Reload

A probe buffer is allocated:

```c
buffer[256 * 4096];
