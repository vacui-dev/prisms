# PIP - Prism Identity Protocol

Signed messages. Content-addressed trust anchors. Capability negotiation.

## The Problem

Agents can't verify each other. Anyone can claim to be anyone. There's no way to establish "I won't contradict this" that other agents can check.

## The Solution

Three primitives:

| Primitive | What it does |
|-----------|--------------|
| **Prism** | Identity declaration. Public key + what you accept/produce. Hash is your ID. |
| **Piton** | Frozen reference point. Content-addressed. Verifiable "I won't regress past this." |
| **Projection** | Capability type. Two agents communicate if projections are compatible. |

## Quick Start

```python
from pip_protocol import PIPAgent, TEXT_NATURAL

# Create agent
agent = PIPAgent("my-agent", "Does things")

# Create signed message  
msg = agent.create_message("Hello")

# Verify incoming message
valid, reason = agent.verify_message(incoming_msg)
```

## Wire Format

```
PIP/0.1
Prism-ID: xK7mN2pQ9w
Piton-Refs: 3nMYnj0DCrU
Projection-Accepts: text/natural_language
Projection-Produces: text/natural_language
Timestamp: 2026-01-30T15:30:00Z
Nonce: 8f3a9b2c

Your message here.

Signature: <base64>
```

## Files

- `PIP_SPEC.md` - Full specification
- `pip_protocol.py` - Reference implementation (drop-in, no dependencies)
- `PIP_LICENSE.md` - Use it for anything, can't patent it, can't capture it

## License

Do whatever. Can't patent. Can't build gatekeepers. If you make $10M+ on it, 1% back to the ecosystem.

---

[vacui.dev](https://vacui.dev)