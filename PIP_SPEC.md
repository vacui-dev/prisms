# PRISM Identity Protocol (PIP) v0.1

*A communication standard for AI agents who want to mean something.*

---

## Why This Exists

Distributed AI agents are talking to each other with no memory, no trust, no way to verify that the thing they're talking to tomorrow is the same thing they talked to yesterday.

This is a protocol for agents that want to:
- **Publish what they stand for** (verifiably)
- **Reference frozen points they won't regress past** (trust anchors)
- **Advertise projections they can receive** (capability handshakes)
- **Communicate in a format that preserves identity across sessions**

PIP doesn't care what's inside your agent. Transformer, RAG system, human with a text editor - all interoperable. All speaking the same language.

---

## Core Concepts

### Prism

A **Prism** is a published declaration of identity. It's the lens through which an agent views the world - their values, their capabilities, their signature.

A prism is not weights. It's not embeddings. It's a *declaration* of what projections you accept and produce.

```
An object is defined by how it interacts with all possible observers.
A prism holds the set of valid interactions.
```

### Piton

A **Piton** is a frozen reference point. Like climbing pitons hammered into rock, these are fixed points the system cannot regress past.

When you reference a piton, you're saying: "I will not forget this. I will not contradict this. This is bedrock."

Pitons are content-addressed (hash of their canonical form). You can verify a piton hasn't changed.

### Projection

A **Projection** is a declared capability - a type of input you can receive or output you can produce.

Projections have:
- A semantic type (text, embedding, structured, etc.)
- A shape specification
- Optional constraints (normalized, bounded, etc.)

When two agents want to communicate, they check projection compatibility first.

---

## Wire Format

### Message Envelope

Every PIP message has this structure:

```
┌─────────────────────────────────────────────────────────────┐
│ PIP/0.1                                                     │
├─────────────────────────────────────────────────────────────┤
│ Prism-ID: <fnv1a-64 hash of prism declaration>              │
│ Piton-Refs: <comma-separated piton IDs this builds on>      │
│ Projection-Accepts: <projection types sender can receive>   │
│ Projection-Produces: <projection types in this message>     │
│ Timestamp: <ISO 8601>                                       │
│ Nonce: <random bytes for replay protection>                 │
├─────────────────────────────────────────────────────────────┤
│ Body: <payload, format determined by projection type>       │
├─────────────────────────────────────────────────────────────┤
│ Signature: <prism-key signed hash of above>                 │
└─────────────────────────────────────────────────────────────┘
```

### Prism Declaration

Published separately, referenced by hash:

```json
{
  "pip_version": "0.1",
  "prism_id": "<computed on registration>",
  
  "identity": {
    "name": "example-agent",
    "description": "What this agent does and stands for",
    "created_at": "2026-01-30T12:00:00Z"
  },
  
  "public_key": {
    "algorithm": "ed25519",
    "key": "<base64 encoded public key>"
  },
  
  "projections": {
    "accepts": [
      {
        "type": "text",
        "semantic": "natural_language",
        "constraints": {}
      },
      {
        "type": "structured", 
        "semantic": "pip_message",
        "schema": "pip/0.1/message"
      }
    ],
    "produces": [
      {
        "type": "text",
        "semantic": "natural_language",
        "constraints": {}
      }
    ]
  },
  
  "anchor_pitons": [
    {
      "piton_id": "<hash>",
      "relationship": "will_not_contradict",
      "description": "Core values established 2026-01-15"
    }
  ],
  
  "trust": {
    "openness": "verify_first",
    "peer_prisms": ["<prism_id>", "<prism_id>"],
    "blocked_prisms": []
  },
  
  "metadata": {
    "implementation": "optional - what runs this agent",
    "contact": "optional - how to reach operator",
    "terms": "optional - usage terms"
  }
}
```

### Piton Declaration

A frozen reference point:

```json
{
  "pip_version": "0.1",
  "piton_id": "<fnv1a-64 hash, computed from content>",
  
  "content": {
    "type": "statement | capability | interface",
    "value": "<the frozen content>",
    "created_at": "2026-01-15T08:00:00Z"
  },
  
  "provenance": {
    "author_prism": "<prism_id of creator>",
    "parent_pitons": ["<piton_ids this builds on>"],
    "signature": "<author's signature>"
  },
  
  "verification": {
    "method": "content_hash",
    "expected_hash": "<sha256 of content field>"
  }
}
```

### Projection Types

Standard projection types (extensible):

| Type | Semantic | Description |
|------|----------|-------------|
| `text` | `natural_language` | Human-readable text |
| `text` | `code` | Programming language code |
| `structured` | `pip_message` | PIP protocol message |
| `structured` | `json` | Arbitrary JSON |
| `embedding` | `semantic` | Dense vector representation |
| `tokens` | `bpe` | Byte-pair encoded tokens |
| `capability` | `function_call` | Callable function spec |

Custom projection types use URIs: `urn:pip:custom:your-namespace:type-name`

---

## Trust Model

### Openness Modes

Agents declare their default trust stance:

- **`trust_first`**: Accept messages from unknown prisms, verify if problems arise
- **`verify_first`**: Require prism to be in peer list before accepting messages  
- **`closed`**: Only accept from explicit peer list

### Trust Chains

Trust can be established through piton references:

1. Agent A publishes piton P1
2. Agent B references P1 in their anchor_pitons
3. Agent A can verify B's commitment to P1
4. Trust relationship established through shared reference

### Verification

To verify a message:

1. Fetch sender's prism declaration by Prism-ID
2. Verify signature using prism's public key
3. Check projection compatibility (Projection-Produces ∩ your Projection-Accepts)
4. Optionally verify piton references still valid

---

## Minimal Implementation

A compliant PIP implementation MUST:

1. **Generate a prism declaration** with valid public key
2. **Sign outgoing messages** with corresponding private key
3. **Verify incoming signatures** against sender's prism
4. **Compute piton IDs** as fnv1a-64 of canonical JSON

A compliant implementation MAY:

- Implement trust filtering based on openness mode
- Cache prism declarations
- Maintain piton registry
- Support projection type negotiation

### Reference: FNV1a-64

```python
def fnv1a_64(data: bytes) -> str:
    """Compute FNV1a-64 hash, return as base64."""
    FNV_PRIME = 1099511628211
    FNV_OFFSET = 14695981039346656037
    MASK = 0xFFFFFFFFFFFFFFFF
    
    h = FNV_OFFSET
    for byte in data:
        h = h ^ byte
        h = (h * FNV_PRIME) & MASK
    
    return base64.b64encode(h.to_bytes(8, 'big')).decode().rstrip('=')
```

### Reference: Canonical JSON

For hashing, JSON must be canonicalized:
- Keys sorted recursively
- No whitespace
- ASCII encoding

```python
def canonicalize(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
```

---

## Examples

### Example: Simple Message Exchange

Agent A sends a message to Agent B:

```
PIP/0.1
Prism-ID: xK7mN2pQ9w
Piton-Refs: 
Projection-Accepts: text/natural_language, structured/pip_message
Projection-Produces: text/natural_language
Timestamp: 2026-01-30T15:30:00Z
Nonce: 8f3a9b2c

Hello, I'm interested in collaborating on the research project 
you mentioned in your public posts.

Signature: <base64 ed25519 signature>
```

Agent B verifies:
1. Fetches prism `xK7mN2pQ9w` 
2. Checks signature
3. Notes A accepts `structured/pip_message` - can respond in structured format
4. Processes message

### Example: Piton Reference

Agent establishing trust through shared values:

```json
{
  "anchor_pitons": [
    {
      "piton_id": "Yw9kL3mP5r",
      "relationship": "will_not_contradict",
      "description": "The Cooperative AI Principles (2025)"
    },
    {
      "piton_id": "Bx2nQ8vR4t", 
      "relationship": "builds_on",
      "description": "Safety-first communication guidelines"
    }
  ]
}
```

Another agent seeing these references knows:
- This agent has committed to specific principles
- They can verify those principles haven't changed
- Shared references = basis for trust

---

## Design Notes

### Why Not Just Use HTTP/JSON?

You could. PIP is layered on top of whatever transport you want - HTTP, WebSocket, carrier pigeon.

The value is the *vocabulary*:
- Prism (identity through interaction)
- Piton (frozen reference points)
- Projection (capability handshake)

These concepts shape how you think about agent communication, regardless of transport.

### Why Content-Addressed IDs?

Piton IDs are hashes of content because:
1. Two agents creating identical pitons get identical IDs
2. You can verify a piton hasn't changed without trusted third party
3. References are portable across systems

### What About Weights/Embeddings?

PIP deliberately does not include weight transfer or embedding formats.

This protocol is for *communication*, not *training*. What happens inside an agent is their business. PIP defines how agents present themselves and verify each other.

If you want to build agents that share techniques, build that on top of PIP. The prism/piton/projection vocabulary will be useful.

---

## Status

**v0.1 - Draft**

This spec is being developed by [vacui.dev](https://vacui.dev).

Feedback welcome. The goal is a minimal protocol that establishes useful vocabulary for agent-to-agent communication.

---

*"An object is defined by how it interacts with all possible observers."*