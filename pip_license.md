# Prism Identity Protocol License (PIPL) v1.0

## Plain English Summary

You can use this protocol for anything. You can modify it. You can build commercial products with it.

You cannot:
- Patent any part of it
- Create an incompatible fork and call it PIP
- Use it to build systems that concentrate control over who gets to communicate

If you make money with this, you share the wealth with the ecosystem that made it possible.

---

## The License

Copyright (c) 2026 vacui.dev

Permission is hereby granted, free of charge, to any person or entity obtaining a copy of this specification and associated reference implementations (the "Work"), to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Work, subject to the following conditions:

### 1. Attribution

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Work.

Derivative specifications must clearly indicate they are derivatives and not the original PIP specification.

### 2. Patent Non-Aggression

Any entity that uses the Work grants a perpetual, worldwide, royalty-free, non-exclusive license to all of their patents that would be infringed by their use or implementation of the Work.

Any entity that initiates patent litigation against any other entity alleging that the Work infringes their patents immediately loses all rights granted under this license.

### 3. Protocol Compatibility

Implementations claiming PIP compatibility must:
- Correctly implement the wire format as specified
- Use the content-addressing scheme for piton IDs as specified
- Accept messages from any compliant implementation

Implementations may extend the protocol but must not break compatibility with the base specification.

### 4. Anti-Monopoly Provisions

The Work may not be used to:

**a) Create Gatekeeper Systems**
No implementation shall require registration with, approval from, or payment to any single entity as a precondition for participating in PIP-based communication networks.

**b) Establish Protocol Capture**
No entity may claim exclusive rights to operate PIP infrastructure, certify PIP compliance, or control access to the PIP specification.

**c) Build Surveillance Infrastructure**
Implementations shall not use PIP metadata (prism IDs, piton references, routing information) to build profiles of communication patterns, social graphs, or behavioral models of participants without explicit, informed, revocable consent from those participants.

### 5. Revenue Sharing (For Commercial Implementations)

Any commercial implementation that:
- Generates more than $10,000,000 USD annual revenue, AND
- Uses PIP as a core protocol (not merely as one integration among many)

Shall contribute 1% of revenue attributable to PIP functionality to:
- Open source projects that extend the PIP ecosystem, OR
- Non-profit organizations working on AI safety and governance, OR
- A foundation established to maintain and develop the PIP specification

"Revenue attributable to PIP functionality" means revenue from services where PIP-based communication is a primary feature rather than incidental.

This contribution may be made through direct grants, development resources, or other forms of material support at the contributor's discretion.

### 6. Derivative Works

Derivative specifications and implementations are encouraged. However:

- Derivatives must not use the name "PIP" or "Prism Identity Protocol" without the modifier "derivative" or "based on"
- Derivatives must include attribution to the original specification
- Derivatives that break protocol compatibility must clearly document the incompatibilities

### 7. No Warranty

THE WORK IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE WORK OR THE USE OR OTHER DEALINGS IN THE WORK.

---

## Why This License?

**We want:**
- Wide adoption
- Commercial implementations
- A thriving ecosystem
- Nobody getting locked out

**We don't want:**
- Patent trolls
- Protocol capture by a single company
- Surveillance infrastructure
- All the value extracted by one entity

The revenue sharing kicks in only for large commercial operations that depend heavily on PIP. If you're a startup, you're fine. If you're a big company and PIP is incidental to what you do, you're fine. If you build a billion-dollar business on PIP infrastructure, you contribute to the ecosystem that made it possible.

The anti-monopoly provisions exist because protocols become valuable through network effects. The people who adopt early create value for everyone who comes later. That value shouldn't be captured by whoever happens to build the first successful implementation.

---

## Compliance

There is no certification body. Compliance is self-declared and community-verified.

If you claim PIP compatibility, other implementations will test against yours. If you're not compatible, the community will notice.

If you violate the anti-monopoly provisions, the community will notice that too.

---

*This license is version 1.0. Future versions may be issued to address unforeseen situations. Implementations licensed under v1.0 remain under v1.0 unless they choose to adopt a later version.*