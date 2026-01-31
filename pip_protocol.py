# pip_protocol.py
# PRISM Identity Protocol - Reference Implementation
# 
# This is a MINIMAL implementation for agent communication.
# It establishes vocabulary (prism, piton, projection) without
# exposing any training or learning machinery.
#
# License: MIT (this file only - not the rest of VACUI)

"""
PRISM Identity Protocol (PIP) v0.1
==================================

A communication protocol for AI agents that want to:
- Publish verifiable identity (prisms)
- Reference frozen trust anchors (pitons)  
- Negotiate capabilities (projections)

This implementation is deliberately minimal. It handles:
- Message signing and verification
- Prism declaration generation
- Piton content-addressing
- Projection compatibility checking

What runs inside your agent is your business.
"""

from __future__ import annotations

import json
import base64
import hashlib
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set, Tuple
from enum import Enum


# =============================================================================
# HASHING
# =============================================================================

def fnv1a_64(data: bytes) -> str:
    """
    Compute FNV1a-64 hash, return as base64.
    
    Fast, good distribution, simple to implement anywhere.
    """
    FNV_PRIME = 1099511628211
    FNV_OFFSET = 14695981039346656037
    MASK = 0xFFFFFFFFFFFFFFFF
    
    h = FNV_OFFSET
    for byte in data:
        h = h ^ byte
        h = (h * FNV_PRIME) & MASK
    
    return base64.b64encode(h.to_bytes(8, 'big')).decode().rstrip('=')


def canonicalize_json(data: Dict[str, Any]) -> str:
    """Canonical JSON for hashing: sorted keys, no whitespace, ASCII."""
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def compute_content_id(content: Dict[str, Any]) -> str:
    """Compute content-addressable ID for any JSON-serializable content."""
    canonical = canonicalize_json(content)
    return fnv1a_64(canonical.encode('utf-8'))


# =============================================================================
# PROJECTION TYPES
# =============================================================================

@dataclass
class ProjectionSpec:
    """
    Specification for a projection type.
    
    Projections describe what an agent can receive or produce.
    Two agents communicate if their projections are compatible.
    """
    type: str                           # text, structured, embedding, tokens, capability
    semantic: str                       # natural_language, code, pip_message, etc.
    constraints: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'type': self.type,
            'semantic': self.semantic,
            'constraints': self.constraints,
        }
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'ProjectionSpec':
        return cls(
            type=d.get('type', 'text'),
            semantic=d.get('semantic', 'unknown'),
            constraints=d.get('constraints', {}),
        )
    
    def is_compatible_with(self, other: 'ProjectionSpec') -> bool:
        """Check if this projection can receive from other."""
        # Same type and semantic = compatible
        if self.type == other.type and self.semantic == other.semantic:
            return True
        # text/* can receive from text/*
        if self.type == 'text' and other.type == 'text':
            return True
        return False
    
    def __str__(self) -> str:
        return f"{self.type}/{self.semantic}"


# Standard projections
TEXT_NATURAL = ProjectionSpec('text', 'natural_language')
TEXT_CODE = ProjectionSpec('text', 'code')
STRUCTURED_JSON = ProjectionSpec('structured', 'json')
STRUCTURED_PIP = ProjectionSpec('structured', 'pip_message')


# =============================================================================
# PITONS (Frozen Reference Points)
# =============================================================================

class PitonRelationship(Enum):
    """How an agent relates to a piton."""
    WILL_NOT_CONTRADICT = "will_not_contradict"  # This is bedrock
    BUILDS_ON = "builds_on"                       # This is foundation
    REFERENCES = "references"                     # This is relevant


@dataclass
class PitonReference:
    """Reference to a piton in a prism declaration."""
    piton_id: str
    relationship: PitonRelationship
    description: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'piton_id': self.piton_id,
            'relationship': self.relationship.value,
            'description': self.description,
        }
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'PitonReference':
        return cls(
            piton_id=d['piton_id'],
            relationship=PitonRelationship(d.get('relationship', 'references')),
            description=d.get('description', ''),
        )


@dataclass
class Piton:
    """
    A frozen reference point.
    
    Pitons are content-addressed: their ID is computed from their content.
    Two agents creating identical pitons get identical IDs.
    You can verify a piton hasn't changed without a trusted third party.
    """
    content_type: str           # statement, capability, interface
    value: Any                  # The frozen content
    created_at: str             # ISO 8601
    author_prism: str           # Prism ID of creator
    parent_pitons: List[str] = field(default_factory=list)
    
    # Computed on creation
    piton_id: str = ""
    
    def __post_init__(self):
        if not self.piton_id:
            self.piton_id = self._compute_id()
    
    def _compute_id(self) -> str:
        """Compute content-addressable ID."""
        content = {
            'content_type': self.content_type,
            'value': self.value,
            'created_at': self.created_at,
            'author_prism': self.author_prism,
            'parent_pitons': sorted(self.parent_pitons),
        }
        return compute_content_id(content)
    
    def verify(self) -> bool:
        """Verify piton ID matches content."""
        return self.piton_id == self._compute_id()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'pip_version': '0.1',
            'piton_id': self.piton_id,
            'content': {
                'type': self.content_type,
                'value': self.value,
                'created_at': self.created_at,
            },
            'provenance': {
                'author_prism': self.author_prism,
                'parent_pitons': self.parent_pitons,
            },
        }
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'Piton':
        content = d.get('content', {})
        provenance = d.get('provenance', {})
        return cls(
            content_type=content.get('type', 'statement'),
            value=content.get('value'),
            created_at=content.get('created_at', ''),
            author_prism=provenance.get('author_prism', ''),
            parent_pitons=provenance.get('parent_pitons', []),
            piton_id=d.get('piton_id', ''),
        )


def create_statement_piton(
    statement: str,
    author_prism: str,
    parents: List[str] = None,
) -> Piton:
    """Create a piton containing a statement."""
    return Piton(
        content_type='statement',
        value=statement,
        created_at=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        author_prism=author_prism,
        parent_pitons=parents or [],
    )


# =============================================================================
# PRISM (Identity Declaration)
# =============================================================================

class OpennessMode(Enum):
    """Default trust stance."""
    TRUST_FIRST = "trust_first"      # Accept, verify if problems
    VERIFY_FIRST = "verify_first"    # Require known prism
    CLOSED = "closed"                # Explicit peer list only


@dataclass
class PrismDeclaration:
    """
    A prism is a published declaration of identity.
    
    It defines:
    - Who you are (name, description)
    - How to verify messages from you (public key)
    - What you can receive and produce (projections)
    - What you won't contradict (anchor pitons)
    - Your trust stance (openness mode)
    """
    name: str
    description: str
    public_key: bytes                               # Ed25519 public key
    accepts: List[ProjectionSpec]                   # What you can receive
    produces: List[ProjectionSpec]                  # What you produce
    anchor_pitons: List[PitonReference] = field(default_factory=list)
    openness: OpennessMode = OpennessMode.VERIFY_FIRST
    peer_prisms: Set[str] = field(default_factory=set)
    blocked_prisms: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    
    # Computed
    prism_id: str = ""
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        if not self.prism_id:
            self.prism_id = self._compute_id()
    
    def _compute_id(self) -> str:
        """Compute prism ID from declaration content."""
        content = {
            'name': self.name,
            'public_key': base64.b64encode(self.public_key).decode(),
            'created_at': self.created_at,
        }
        return compute_content_id(content)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'pip_version': '0.1',
            'prism_id': self.prism_id,
            'identity': {
                'name': self.name,
                'description': self.description,
                'created_at': self.created_at,
            },
            'public_key': {
                'algorithm': 'ed25519',
                'key': base64.b64encode(self.public_key).decode(),
            },
            'projections': {
                'accepts': [p.to_dict() for p in self.accepts],
                'produces': [p.to_dict() for p in self.produces],
            },
            'anchor_pitons': [p.to_dict() for p in self.anchor_pitons],
            'trust': {
                'openness': self.openness.value,
                'peer_prisms': list(self.peer_prisms),
                'blocked_prisms': list(self.blocked_prisms),
            },
            'metadata': self.metadata,
        }
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'PrismDeclaration':
        identity = d.get('identity', {})
        pk = d.get('public_key', {})
        proj = d.get('projections', {})
        trust = d.get('trust', {})
        
        return cls(
            name=identity.get('name', ''),
            description=identity.get('description', ''),
            public_key=base64.b64decode(pk.get('key', '')),
            accepts=[ProjectionSpec.from_dict(p) for p in proj.get('accepts', [])],
            produces=[ProjectionSpec.from_dict(p) for p in proj.get('produces', [])],
            anchor_pitons=[PitonReference.from_dict(p) for p in d.get('anchor_pitons', [])],
            openness=OpennessMode(trust.get('openness', 'verify_first')),
            peer_prisms=set(trust.get('peer_prisms', [])),
            blocked_prisms=set(trust.get('blocked_prisms', [])),
            metadata=d.get('metadata', {}),
            created_at=identity.get('created_at', ''),
            prism_id=d.get('prism_id', ''),
        )
    
    def can_receive_from(self, other: 'PrismDeclaration') -> bool:
        """Check if we can receive messages from another prism."""
        # Check trust
        if other.prism_id in self.blocked_prisms:
            return False
        
        if self.openness == OpennessMode.CLOSED:
            if other.prism_id not in self.peer_prisms:
                return False
        
        # Check projection compatibility
        for their_output in other.produces:
            for our_input in self.accepts:
                if our_input.is_compatible_with(their_output):
                    return True
        
        return False


# =============================================================================
# MESSAGES
# =============================================================================

@dataclass  
class PIPMessage:
    """
    A PIP protocol message.
    
    Messages are signed by the sender's prism key.
    Recipients verify using the sender's public key.
    """
    sender_prism_id: str
    body: Any                                       # Message content
    body_projection: ProjectionSpec                 # Type of body
    piton_refs: List[str] = field(default_factory=list)
    accepts: List[ProjectionSpec] = field(default_factory=list)
    timestamp: str = ""
    nonce: str = ""
    signature: bytes = b""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        if not self.nonce:
            import secrets
            self.nonce = base64.b64encode(secrets.token_bytes(8)).decode()
    
    def signing_content(self) -> bytes:
        """Get content to sign (everything except signature)."""
        content = {
            'sender_prism_id': self.sender_prism_id,
            'body': self.body,
            'body_projection': self.body_projection.to_dict(),
            'piton_refs': self.piton_refs,
            'accepts': [p.to_dict() for p in self.accepts],
            'timestamp': self.timestamp,
            'nonce': self.nonce,
        }
        return canonicalize_json(content).encode('utf-8')
    
    def to_wire(self) -> str:
        """Convert to wire format."""
        lines = [
            "PIP/0.1",
            f"Prism-ID: {self.sender_prism_id}",
            f"Piton-Refs: {','.join(self.piton_refs) if self.piton_refs else ''}",
            f"Projection-Accepts: {','.join(str(p) for p in self.accepts)}",
            f"Projection-Produces: {self.body_projection}",
            f"Timestamp: {self.timestamp}",
            f"Nonce: {self.nonce}",
            "",
            json.dumps(self.body) if not isinstance(self.body, str) else self.body,
            "",
            f"Signature: {base64.b64encode(self.signature).decode()}",
        ]
        return '\n'.join(lines)
    
    @classmethod
    def from_wire(cls, wire: str) -> 'PIPMessage':
        """Parse from wire format."""
        lines = wire.strip().split('\n')
        
        headers = {}
        body_start = 0
        for i, line in enumerate(lines):
            if line == "":
                body_start = i + 1
                break
            if ':' in line and not line.startswith('PIP/'):
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        # Find signature line
        sig_line = None
        body_end = len(lines)
        for i in range(len(lines) - 1, body_start, -1):
            if lines[i].startswith('Signature:'):
                sig_line = lines[i]
                body_end = i - 1
                break
        
        body_text = '\n'.join(lines[body_start:body_end])
        try:
            body = json.loads(body_text)
        except json.JSONDecodeError:
            body = body_text
        
        # Parse projection
        proj_str = headers.get('Projection-Produces', 'text/natural_language')
        if '/' in proj_str:
            ptype, psem = proj_str.split('/', 1)
        else:
            ptype, psem = 'text', 'natural_language'
        
        # Parse accepts
        accepts = []
        accepts_str = headers.get('Projection-Accepts', '')
        if accepts_str:
            for proj in accepts_str.split(','):
                proj = proj.strip()
                if '/' in proj:
                    pt, ps = proj.split('/', 1)
                    accepts.append(ProjectionSpec(pt, ps))
        
        # Parse signature
        sig = b""
        if sig_line:
            sig = base64.b64decode(sig_line.split(':', 1)[1].strip())
        
        return cls(
            sender_prism_id=headers.get('Prism-ID', ''),
            body=body,
            body_projection=ProjectionSpec(ptype, psem),
            piton_refs=[p.strip() for p in headers.get('Piton-Refs', '').split(',') if p.strip()],
            accepts=accepts,
            timestamp=headers.get('Timestamp', ''),
            nonce=headers.get('Nonce', ''),
            signature=sig,
        )


# =============================================================================
# AGENT (Minimal Implementation)
# =============================================================================

class PIPAgent:
    """
    Minimal PIP-compliant agent.
    
    Handles:
    - Signing outgoing messages
    - Verifying incoming messages
    - Managing prism identity
    - Storing piton references
    
    What the agent actually *does* with messages is up to you.
    """
    
    def __init__(
        self,
        name: str,
        description: str = "",
        openness: OpennessMode = OpennessMode.VERIFY_FIRST,
    ):
        # Generate keypair (Ed25519)
        # In production, use cryptography library
        # This is a placeholder for the reference implementation
        import secrets
        self._private_key = secrets.token_bytes(32)
        self._public_key = self._derive_public_key(self._private_key)
        
        self.prism = PrismDeclaration(
            name=name,
            description=description,
            public_key=self._public_key,
            accepts=[TEXT_NATURAL, STRUCTURED_PIP],
            produces=[TEXT_NATURAL],
            openness=openness,
        )
        
        self.known_prisms: Dict[str, PrismDeclaration] = {}
        self.known_pitons: Dict[str, Piton] = {}
    
    def _derive_public_key(self, private_key: bytes) -> bytes:
        """
        Derive public key from private key.
        
        NOTE: This is a PLACEHOLDER. In production, use:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        """
        # Placeholder: hash of private key (NOT SECURE - just for demonstration)
        return hashlib.sha256(private_key).digest()
    
    def _sign(self, data: bytes) -> bytes:
        """
        Sign data with private key.
        
        NOTE: This is a PLACEHOLDER. In production, use Ed25519.
        """
        # Placeholder: HMAC (NOT a real signature - just for demonstration)
        import hmac
        return hmac.new(self._private_key, data, hashlib.sha256).digest()
    
    def _verify(self, data: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify signature.
        
        NOTE: This is a PLACEHOLDER. In production, use Ed25519.
        """
        # Placeholder: can't actually verify without private key
        # In real implementation, this would use public key crypto
        return len(signature) == 32  # Just check it looks like a signature
    
    def register_prism(self, prism: PrismDeclaration):
        """Register a known prism for verification."""
        self.known_prisms[prism.prism_id] = prism
    
    def register_piton(self, piton: Piton):
        """Register a known piton."""
        if piton.verify():
            self.known_pitons[piton.piton_id] = piton
    
    def add_anchor_piton(self, piton: Piton, relationship: PitonRelationship):
        """Add a piton to our anchor list."""
        self.register_piton(piton)
        self.prism.anchor_pitons.append(PitonReference(
            piton_id=piton.piton_id,
            relationship=relationship,
            description=str(piton.value)[:50],
        ))
        # Recompute prism ID
        self.prism.prism_id = self.prism._compute_id()
    
    def create_message(
        self,
        body: Any,
        projection: ProjectionSpec = None,
        piton_refs: List[str] = None,
    ) -> PIPMessage:
        """Create and sign a message."""
        msg = PIPMessage(
            sender_prism_id=self.prism.prism_id,
            body=body,
            body_projection=projection or TEXT_NATURAL,
            piton_refs=piton_refs or [],
            accepts=self.prism.accepts,
        )
        msg.signature = self._sign(msg.signing_content())
        return msg
    
    def verify_message(self, msg: PIPMessage) -> Tuple[bool, str]:
        """
        Verify an incoming message.
        
        Returns (is_valid, reason).
        """
        # Get sender's prism
        sender = self.known_prisms.get(msg.sender_prism_id)
        if not sender:
            return False, f"Unknown prism: {msg.sender_prism_id}"
        
        # Check trust
        if not self.prism.can_receive_from(sender):
            return False, "Blocked or incompatible prism"
        
        # Verify signature
        if not self._verify(msg.signing_content(), msg.signature, sender.public_key):
            return False, "Invalid signature"
        
        # Verify piton refs exist
        for piton_id in msg.piton_refs:
            if piton_id not in self.known_pitons:
                return False, f"Unknown piton reference: {piton_id}"
        
        return True, "OK"
    
    def add_peer(self, prism_id: str):
        """Add a prism to peer list."""
        self.prism.peer_prisms.add(prism_id)
    
    def block_prism(self, prism_id: str):
        """Block a prism."""
        self.prism.blocked_prisms.add(prism_id)


# =============================================================================
# EXAMPLE USAGE
# =============================================================================

def example_usage():
    """Demonstrate PIP protocol usage."""
    
    # Create two agents
    alice = PIPAgent("alice", "Alice's agent", OpennessMode.TRUST_FIRST)
    bob = PIPAgent("bob", "Bob's agent", OpennessMode.VERIFY_FIRST)
    
    # Exchange prism declarations (out of band)
    alice.register_prism(bob.prism)
    bob.register_prism(alice.prism)
    
    # Bob requires explicit peers
    bob.add_peer(alice.prism.prism_id)
    
    # Create a shared piton (a value they both commit to)
    shared_value = create_statement_piton(
        "We agree to be honest in our communications.",
        alice.prism.prism_id,
    )
    alice.register_piton(shared_value)
    bob.register_piton(shared_value)
    
    # Alice anchors to this piton
    alice.add_anchor_piton(shared_value, PitonRelationship.WILL_NOT_CONTRADICT)
    
    # Alice sends a message
    msg = alice.create_message(
        "Hello Bob, I'd like to collaborate.",
        piton_refs=[shared_value.piton_id],
    )
    
    # Serialize to wire format
    wire = msg.to_wire()
    print("=== Wire Format ===")
    print(wire)
    print()
    
    # Bob receives and verifies
    received = PIPMessage.from_wire(wire)
    
    # Bob needs to re-register Alice's updated prism (with anchor)
    bob.register_prism(alice.prism)
    
    valid, reason = bob.verify_message(received)
    print(f"=== Verification ===")
    print(f"Valid: {valid}")
    print(f"Reason: {reason}")
    print()
    
    # Check shared piton reference
    if shared_value.piton_id in received.piton_refs:
        print(f"Message references shared commitment: {shared_value.value}")


if __name__ == "__main__":
    example_usage()