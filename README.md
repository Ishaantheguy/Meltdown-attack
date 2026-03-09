```markdown
# Molten Walk – Speculative Execution Attack

![Language](https://img.shields.io/badge/language-C-blue)
![Platform](https://img.shields.io/badge/platform-x86__64-orange)
![Category](https://img.shields.io/badge/category-Speculative%20Execution-red)
![Purpose](https://img.shields.io/badge/purpose-Educational-green)

This repository demonstrates a **Meltdown-style speculative execution attack** used to leak protected kernel memory using a **cache timing side channel**.

The exploit was developed for the **pwn.college Molten Walk challenge**, where the goal is to recover a secret value by walking kernel page tables and leaking memory byte-by-byte.

---

## Overview

Modern CPUs use **out-of-order and speculative execution** to improve performance.  
When a faulting instruction occurs, the CPU eventually rolls back the architectural state.

However, **microarchitectural side effects (such as cache state) remain**.

This exploit abuses that behavior to leak data from privileged memory.

---

## Attack Flow

The attack works in the following stages:

1. **Flush the cache** for a probe buffer.
2. Trigger **speculative execution** using a faulting memory access.
3. Use the **secret byte as an index** into the probe buffer.
4. The accessed cache line becomes **cached**.
5. Measure **memory access time** to determine which index was loaded.
6. Repeat the process multiple times to recover the byte reliably.

---

## Core Technique – Flush + Reload

A probe buffer is allocated:

```c
buffer[256 * 4096];
```

Each possible byte value maps to a separate cache line.

During speculative execution, the secret value is used as an index:

```c
buffer[secret_byte * 4096];
```

If this memory is accessed transiently, the corresponding cache line becomes **hot**.

Later, the attacker measures access times to identify the cached entry and recover the secret byte.

---

## Speculative Execution Gadget

The exploit intentionally triggers a fault:

```asm
mov rax, [rax]   ; segmentation fault
```

Before the CPU handles the fault, the processor speculatively executes subsequent instructions which encode the secret into the cache.

After the fault is handled, the program resumes execution while the **cache state still contains the leaked information**.

---

## Cache Timing Measurement

Cache hits are detected using the CPU timestamp counter:

```c
uint64_t start = __rdtsc();
*(volatile uint64_t *)addr;
uint64_t end = __rdtsc();
```

Typical timing behavior:

| Access Type | Cycles |
| ----------- | ------ |
| Cached      | ~60    |
| Uncached    | ~200+  |

---

## Kernel Memory Walk

The exploit interacts with the challenge interface:

```
/proc/pwncollege
```

Two ioctl operations are used:

```
31337 → leak kernel pointer
1337  → trigger speculative access
```

Using leaked pointers, the exploit walks the kernel page tables:

```
PGD → PUD → PMD → PTE
```

This allows translation of virtual addresses to physical pages and eventually reveals the location of the secret.

---

## Flag Extraction

Once the final physical page is located, the exploit repeatedly performs speculative reads to recover each byte of the flag.

To improve reliability, the attack:

* performs multiple measurements
* uses statistical voting to determine the most likely byte value

---

