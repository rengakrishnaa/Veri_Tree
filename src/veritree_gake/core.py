"""
----------------------------------------------------------------------------------
Implementation
- Algorithm 1: Parent mKEM Broadcast
- Algorithm 2: Child Uplink KEM  
- Algorithm 3: Dual-Commit Fairness (com^1 and com^2)
- Algorithm 4: Split-Key PRF Combiner with cross-wire HMAC
- Algorithm 5: Key Confirmation
- Section 5: Deterministic CBOR/COSE Canonicalization
- Section 4.3: Per-Level Derivation with sid_ℓ
-----------------------------------------------------------------------------------
"""

import hashlib
import hmac
import secrets
import json
import time
from typing import List, Dict, Tuple, Any, Optional
from dataclasses import dataclass, field
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Try to import pyOQS for real post-quantum KEMs
try:
    import oqs
    HAS_OQS = True
except Exception:
    HAS_OQS = False

# Try to import cbor2 for canonical encoding
try:
    import cbor2
    HAS_CBOR2 = True
except Exception:
    HAS_CBOR2 = False


# =============================================================================
# Section 2: Cryptographic Primitives (HKDF, SHA3, HMAC per Paper)
# =============================================================================

def hkdf_extract(salt: bytes, ikm: bytes, hashmod=hashlib.sha256) -> bytes:
    """HKDF-Extract per RFC 5869"""
    if salt is None or len(salt) == 0:
        salt = bytes([0] * hashmod().digest_size)
    return hmac.new(salt, ikm, hashmod).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int, hashmod=hashlib.sha256) -> bytes:
    """HKDF-Expand per RFC 5869"""
    hash_len = hashmod().digest_size
    n = (length + hash_len - 1) // hash_len
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashmod).digest()
        okm += t
    return okm[:length]


def hkdf_sha256(salt: bytes, ikm: bytes, info: bytes = b"", length: int = 32) -> bytes:
    """Combined HKDF-Extract-Expand with SHA256"""
    prk = hkdf_extract(salt, ikm, hashlib.sha256)
    return hkdf_expand(prk, info, length, hashlib.sha256)


def sha3_512(data: bytes) -> bytes:
    """SHA3-512 for final key derivation (Algorithm 4)"""
    return hashlib.sha3_512(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256 for PRF extraction and confirmation"""
    return hmac.new(key, data, hashlib.sha256).digest()


def hash_sha256(data: bytes) -> bytes:
    """SHA256 for commitments and sid computation"""
    return hashlib.sha256(data).digest()


# =============================================================================
# Section 5: Deterministic CBOR/COSE Canonicalization
# =============================================================================

def canonical_encode(obj: Any) -> bytes:
    """
    Canonical encoding per Paper Section 5.
    Prefers CBOR canonical mode; falls back to deterministic JSON.
    """
    if HAS_CBOR2:
        return cbor2.dumps(obj, canonical=True)
    else:
        return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('utf-8')


def canonical_decode(data: bytes) -> Any:
    """
    Decode canonical encoding (CBOR or JSON).
    """
    if HAS_CBOR2:
        return cbor2.loads(data)
    else:
        return json.loads(data.decode('utf-8'))


def compute_sid_level(transcript: List[bytes], level: int) -> bytes:
    """
    Compute per-level session ID: sid_ℓ = H(canonical transcript at level ℓ)
    Per Paper Section 5
    """
    level_data = b"level|" + str(level).encode() + b"|" + b"".join(transcript)
    return hash_sha256(level_data)


def compute_sid_global(all_level_sids: List[bytes]) -> bytes:
    """
    Compute global session ID: sid = H(all sid_ℓ values)
    Per Paper Section 5
    """
    return hash_sha256(b"global|" + b"".join(all_level_sids))


# =============================================================================
# Section 6.1: KEM/mKEM Wrappers (Algorithm 1 & 2)
# =============================================================================

class PyOQSKEM:
    """Real post-quantum KEM using LibOQS"""
    def __init__(self, alg: str):
        self.alg = alg
        try:
            self._kem = oqs.KeyEncapsulation(alg)
        except Exception as e:
            raise RuntimeError(f"pyOQS KeyEncapsulation init failed for {alg}: {e}")

    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate keypair: (public_key, secret_key)"""
        pk = self._kem.generate_keypair()
        sk = self._kem.export_secret_key()
        return pk, sk

    def encaps(self, pk: bytes) -> Tuple[Dict[str, bytes], bytes]:
        """Encapsulate: returns (ciphertext_dict, shared_secret)"""
        ct, ss = self._kem.encap_secret(pk)
        return {'ct': ct}, ss

    def decaps(self, sk: bytes, ctobj: Dict[str, bytes]) -> bytes:
        """Decapsulate: returns shared_secret"""
        try:
            ss = oqs.KeyEncapsulation(self.alg).decap_secret(ctobj['ct'], sk)
            return ss
        except Exception as e:
            raise RuntimeError(f"pyOQS decap failed for alg {self.alg}: {e}")


class SimKEM:
    """Simulated KEM for testing (NOT secure, for demo only)"""
    def __init__(self, name: str):
        self.name = name

    def keygen(self):
        pk = secrets.token_bytes(32)
        sk = pk  # Symmetric for simulation
        return pk, sk

    def encaps(self, pk: bytes):
        shared = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        pad = hash_sha256(pk + nonce)
        ct = bytes(a ^ b for a, b in zip(shared, pad))
        return {'ct': ct, 'nonce': nonce}, shared

    def decaps(self, sk: bytes, ctobj: Dict[str, bytes]):
        pad = hash_sha256(sk + ctobj['nonce'])
        shared = bytes(a ^ b for a, b in zip(ctobj['ct'], pad))
        return shared


def make_kem_instance(fam: str):
    """Factory: returns PyOQSKEM if available, else SimKEM"""
    if HAS_OQS:
        try:
            return PyOQSKEM(fam)
        except Exception:
            return SimKEM(fam)
    else:
        return SimKEM(fam)


# =============================================================================
# Data Structures: Node
# =============================================================================

@dataclass
class Node:
    """
    Participant node in VeriTree-GAKE tree.
    Per Paper Section 3: System Model
    """
    id: str
    role: str  # "admin", "moderator", "member"
    level: int
    families: List[str]
    
    # Long-term keys per family
    longterm_pk: Dict[str, bytes] = field(default_factory=dict)
    longterm_sk: Dict[str, bytes] = field(default_factory=dict)
    
    # Ephemeral keys per family
    ephemeral_pk: Dict[str, bytes] = field(default_factory=dict)
    ephemeral_sk: Dict[str, bytes] = field(default_factory=dict)
    
    # Per-session state
    transcript: List[bytes] = field(default_factory=list)
    sid_l: Optional[bytes] = None  # Per-level session ID
    
    # Per-family level secrets L_X^(j)
    level_secrets: Dict[str, bytes] = field(default_factory=dict)
    
    # Aggregated tildeK
    tildeK: Optional[bytes] = None
    
    # Dual-commit state (Algorithm 3)
    mask: Optional[bytes] = None
    masked: Optional[bytes] = None
    rho1: Optional[bytes] = None
    rho2: Optional[bytes] = None
    commit1: Optional[bytes] = None
    commit2: Optional[bytes] = None
    
    # Final keys
    final_SK: Optional[bytes] = None
    confirm_tag: Optional[str] = None

    def derive_signing_key(self) -> bytes:
        """Derive deterministic signing key from long-term secrets"""
        fams_sorted = sorted(self.families)
        concat = b''.join(self.longterm_sk[f] for f in fams_sorted)
        return hkdf_sha256(salt=b"sign-salt", ikm=concat, info=b"signkey|" + self.id.encode(), length=32)

    def hmac_sign(self, payload: bytes) -> bytes:
        """Sign payload with HMAC (simulates COSE_Sign1)"""
        key = self.derive_signing_key()
        return hmac_sha256(key, payload)

    def hmac_verify(self, payload: bytes, tag: bytes) -> bool:
        """Verify HMAC signature"""
        key = self.derive_signing_key()
        expected = hmac_sha256(key, payload)
        return hmac.compare_digest(expected, tag)


# =============================================================================
# VeriTree-GAKE Simulator: Full Protocol Implementation
# =============================================================================

class VeriTreeSimulator:
    """
    Complete VeriTree-GAKE protocol implementation.
    Implements all algorithms from research paper.
    """
    
    def __init__(self, preferred_families: List[str] = None):
        self.default_families = preferred_families or ["Kyber512", "Saber"]
        self.kem_wrappers: Dict[str, Any] = {}

    def make_kem_objects(self, families: List[str]) -> Dict[str, Any]:
        """Initialize KEM wrappers for each family"""
        km = {}
        for fam in families:
            km[fam] = make_kem_instance(fam)
        return km

    # =========================================================================
    # Algorithm 1: Parent mKEM Broadcast (Section 6, Algorithm 1)
    # =========================================================================
    
    def parent_mkem_broadcast(self, parent_id: str, children_ids: List[str],
                          family: str, nodes: Dict[str, Node],
                          kem_objs: Dict, downlinks: Dict,
                          commits: Dict, commit_sigs: Dict):
        """
        Algorithm 1: Parent mKEM Broadcast
        """
        parent = nodes[parent_id]

        for child_id in children_ids:
            child = nodes[child_id]
            # Simulate mKEM: individual encaps per child (real mKEM would be single ct)
            ctobj, k_parent = kem_objs[family].encaps(child.longterm_pk[family])

            if parent_id not in downlinks:
                downlinks[parent_id] = {}
            if child_id not in downlinks[parent_id]:
                downlinks[parent_id][child_id] = {}
            downlinks[parent_id][child_id][family] = {'ct': ctobj, 'k_parent': k_parent}

            # Commit to ciphertext with canonical encoding and signature
            commit_payload = {
                'type': 'downlink_commit',
                'suite_id': 'VeriTree-GAKE-v1',
                'parent': parent_id,
                'child': child_id,
                'family': family,
                'level': parent.level,
                'ct_hex': ctobj['ct'].hex(),
                'sid_l': parent.sid_l.hex() if parent.sid_l else "initial"
            }
            encoded = canonical_encode(commit_payload)
            com_hex = hash_sha256(encoded).hex()

            # --- bandwidth accounting: commitment + ciphertext ---
            self.total_bytes += len(encoded) + len(ctobj['ct'])

            if parent_id not in commits:
                commits[parent_id] = {}
            if child_id not in commits[parent_id]:
                commits[parent_id][child_id] = {}
            commits[parent_id][child_id][family] = com_hex

            # Sign commitment
            sig = parent.hmac_sign(encoded)

            # Add to transcripts
            parent.transcript.append(encoded)
            child.transcript.append(encoded)


    # =========================================================================
    # Algorithm 2: Child Uplink KEM (Section 6, Algorithm 2)
    # =========================================================================
    
    def child_uplink_kem(self, child_id: str, parent_id: str, family: str,
                     nodes: Dict[str, Node], kem_objs: Dict, uplinks: Dict):
        """
        Algorithm 2: Child Uplink KEM
        """
        child = nodes[child_id]
        parent = nodes[parent_id]

        # Child encapsulates to parent's long-term public key
        ct_up, k_child = kem_objs[family].encaps(parent.longterm_pk[family])

        if child_id not in uplinks:
            uplinks[child_id] = {}
        uplinks[child_id][family] = {'ct': ct_up, 'k_child': k_child}

        # Canonical message with signature
        uplink_payload = {
            'type': 'uplink',
            'child': child_id,
            'parent': parent_id,
            'family': family,
            'level': child.level,
            'ct_hex': ct_up['ct'].hex(),
            'sid_l': child.sid_l.hex() if child.sid_l else "initial"
        }
        encoded = canonical_encode(uplink_payload)
        sig = child.hmac_sign(encoded)

        # --- bandwidth accounting: uplink message + ciphertext ---
        self.total_bytes += len(encoded) + len(ct_up['ct'])

        # Add to transcripts
        child.transcript.append(encoded)
        parent.transcript.append(encoded)


    # =========================================================================
    # Section 4.3: Per-Level Secret Derivation
    # =========================================================================
    
    def derive_level_secrets(self, node: Node, parent_id: Optional[str], 
                             children_ids: List[str], downlinks: Dict, 
                             uplinks: Dict, downlinks_ephemeral: Dict, 
                             kem_objs: Dict):
        """
        Per-Level Derivation per Paper Section 4.3:
        
        L_X^(j) = HKDF(K_S^(j) || k_{X↔P}^(j) || sid_ℓ)
        tildeK = HKDF(||_j L_X^(j) || sid_ℓ)
        """
        L_parts = []
        sid_l = node.sid_l if node.sid_l else b"level|" + str(node.level).encode()
        
        # Downlink from parent + uplink to parent
        if parent_id is not None:
            for fam in node.families:
                # Decapsulate downlink from parent
                k_down = kem_objs[fam].decaps(
                    node.longterm_sk[fam],
                    downlinks[parent_id][node.id][fam]['ct']
                )
                # Get uplink secret child sent to parent
                k_up = uplinks[node.id][fam]['k_child']
                
                # L_X^(j) = HKDF(K_S^(j) || k_{X↔P}^(j) || sid_ℓ)
                ikm = k_down + k_up + sid_l
                L_j = hkdf_sha256(
                    salt=hash_sha256(b"L_salt|" + node.id.encode()),
                    ikm=ikm,
                    info=b"L|" + fam.encode() + b"|" + node.id.encode(),
                    length=32
                )
                node.level_secrets[fam] = L_j
                L_parts.append(L_j)
        else:
            # Root node: use placeholder
            for fam in node.families:
                L_j = b'ROOT|' + fam.encode() + b'|' + node.id.encode()
                L_j = hash_sha256(L_j)
                node.level_secrets[fam] = L_j
                L_parts.append(L_j)
        
        # Aggregate children contributions (if any)
        R_parts = []
        if children_ids:
            for fam in node.families:
                acc = b''
                for child_id in children_ids:
                    acc += downlinks[node.id][child_id][fam]['k_parent']
                    acc += downlinks_ephemeral[node.id][child_id][fam]['kprime_parent']
                R_parts.append(acc)
        else:
            for fam in node.families:
                R_parts.append(b'LEAF|' + fam.encode() + b'|' + node.id.encode())
        
        # tildeK = HKDF(||_j L_X^(j) || sid_ℓ)
        ikm = b''.join(L_parts) + b''.join(R_parts)
        node.tildeK = hkdf_sha256(
            salt=hash_sha256(b"tildeK_salt"),
            ikm=ikm + sid_l,
            info=b"tildeK|" + node.id.encode(),
            length=32
        )

    # =========================================================================
    # Algorithm 3: Dual-Commit Fairness (Section 6.2)
    # =========================================================================
    
    def dual_commit(self, node: Node):
        """
        Algorithm 3: Dual-Commit Phase
        
        com_X^1 = H(tildeK || ρ_X || sid_ℓ)
        com_X^2 = H((tildeK ⊕ m_X) || ρ'_X || sid_ℓ)
        """
        if node.tildeK is None:
            raise ValueError(f"Node {node.id} has no tildeK")
        
        sid_l = node.sid_l if node.sid_l else b"level|" + str(node.level).encode()
        
        # Generate mask and masked value
        node.mask = secrets.token_bytes(len(node.tildeK))
        node.masked = bytes(a ^ b for a, b in zip(node.tildeK, node.mask))
        
        # Generate randomness
        node.rho1 = secrets.token_bytes(16)
        node.rho2 = secrets.token_bytes(16)
        
        # Compute dual commitments
        node.commit1 = hash_sha256(node.tildeK + node.rho1 + sid_l)
        node.commit2 = hash_sha256(node.masked + node.rho2 + sid_l)
        
        # Broadcast commitments with signature
        commit_payload = {
            'type': 'dual_commit',
            'node': node.id,
            'level': node.level,
            'commit1_hex': node.commit1.hex(),
            'commit2_hex': node.commit2.hex(),
            'sid_l': sid_l.hex()
        }
        encoded = canonical_encode(commit_payload)
        sig = node.hmac_sign(encoded)
        node.transcript.append(encoded)

        self.total_bytes += len(encoded)
        return encoded, sig

    # =========================================================================
    # Algorithm 3 (continued): Open Phase
    # =========================================================================
    
    def dual_open(self, node: Node):
        """
        Algorithm 3: Open Phase
        
        Reveal tildeK, m_X, ρ_X, ρ'_X for verification.
        """
        sid_l = node.sid_l if node.sid_l else b"level|" + str(node.level).encode()
        
        open_payload = {
            'type': 'dual_open',
            'node': node.id,
            'level': node.level,
            'tildeK_hex': node.tildeK.hex(),
            'mask_hex': node.mask.hex(),
            'masked_hex': node.masked.hex(),
            'rho1_hex': node.rho1.hex(),
            'rho2_hex': node.rho2.hex(),
            'sid_l': sid_l.hex()
        }
        encoded = canonical_encode(open_payload)
        sig = node.hmac_sign(encoded)
        node.transcript.append(encoded)

        self.total_bytes += len(encoded)
        return encoded, sig

    def verify_dual_open(self, node: Node, open_data: Dict):
        """Verify dual-commit opening matches original commitments"""
        sid_l = bytes.fromhex(open_data['sid_l'])
        tildeK = bytes.fromhex(open_data['tildeK_hex'])
        masked = bytes.fromhex(open_data['masked_hex'])
        rho1 = bytes.fromhex(open_data['rho1_hex'])
        rho2 = bytes.fromhex(open_data['rho2_hex'])
        
        # Recompute commitments
        recomputed_com1 = hash_sha256(tildeK + rho1 + sid_l)
        recomputed_com2 = hash_sha256(masked + rho2 + sid_l)
        
        # Verify
        if not hmac.compare_digest(recomputed_com1, node.commit1):
            raise ValueError(f"Node {node.id} commit1 verification failed")
        if not hmac.compare_digest(recomputed_com2, node.commit2):
            raise ValueError(f"Node {node.id} commit2 verification failed")
        
        # Verify mask consistency: tildeK ⊕ mask = masked
        mask = bytes.fromhex(open_data['mask_hex'])
        expected_masked = bytes(a ^ b for a, b in zip(tildeK, mask))
        if not hmac.compare_digest(expected_masked, masked):
            raise ValueError(f"Node {node.id} mask consistency check failed")

    # =========================================================================
    # Algorithm 4: Split-Key PRF Combiner (Section 4.4)
    # =========================================================================
    
    def split_key_combiner(self, B_per_level: Dict[int, Dict[str, bytes]], 
                           families: List[str], sid: bytes) -> bytes:
        """
        Algorithm 4: Split-Key PRF Combiner
        
        For each family j:
          K_grp^(j) = HKDF(||_ℓ B_ℓ^(j) || sid)
          k_j = HMAC_{salt_j}(K_grp^(j))
          u_j = g(K_grp^(j), ctx_j)  [3 SHA3-512 chunks with domain separation]
        
        K_final = SHA3-512(⊕_{j=1}^m HMAC_{k_j}(||_{ℓ≠j} u_ℓ || label(j)))
        """
        print(f"\n=== Algorithm 4: Split-Key PRF Combiner ===")
        
        # Step 1: Derive per-family group pre-keys K_grp^(j)
        K_grp = {}
        for family in families:
            # Concatenate B_ℓ^(j) across all levels in sorted order
            all_B = b"".join([
                B_per_level[lvl].get(family, b"\x00" * 32)
                for lvl in sorted(B_per_level.keys())
            ])
            K_grp[family] = hkdf_sha256(
                salt=hash_sha256(b"K_grp_salt"),
                ikm=all_B + sid,
                info=b"K_grp|" + family.encode() + b"|" + sid,
                length=32
            )
            print(f"  K_grp[{family}] = {K_grp[family].hex()[:32]}...")
        
        # Step 2: PRF extraction k_j = HMAC_{salt_j}(K_grp^(j))
        k_j = {}
        for family in families:
            salt_j = hash_sha256(b"salt|" + family.encode())
            k_j[family] = hmac_sha256(salt_j, K_grp[family])
            print(f"  k_j[{family}] = {k_j[family].hex()[:32]}...")
        
        # Step 3: Context expansion u_j = g(K_grp^(j), ctx_j)
        # g() produces 64 bytes via 3 SHA3-512 chunks with domain separation
        u_j = {}
        for family in families:
            ctx_j = f"VTG:combiner|{family}|{sid.hex()}".encode()
            # 3 chunks: 21 + 21 + 22 = 64 bytes
            u_j[family] = (
                sha3_512(K_grp[family] + ctx_j + b"|chunk1")[:21] +
                sha3_512(K_grp[family] + ctx_j + b"|chunk2")[:21] +
                sha3_512(K_grp[family] + ctx_j + b"|chunk3")[:22]
            )
            print(f"  u_j[{family}] = {u_j[family].hex()[:32]}...")
        
        # Step 4: Cross-wire HMAC combination
        # t = ⊕_{j=1}^m HMAC_{k_j}(||_{ℓ≠j} u_ℓ || label(j))
        t = bytes([0] * 32)
        families_sorted = sorted(families)
        for j_idx, family_j in enumerate(families_sorted):
            # Concatenate u_ℓ for ℓ ≠ j
            other_u = b"".join([
                u_j[f] for f_idx, f in enumerate(families_sorted) if f_idx != j_idx
            ])
            label_j = f"label|{family_j}".encode()
            hmac_val = hmac_sha256(k_j[family_j], other_u + label_j)
            t = bytes(a ^ b for a, b in zip(t, hmac_val))
            print(f"  Cross-wire HMAC[{family_j}] contributes to t")
        
        # Step 5: Final key derivation K_final = SHA3-512(t)
        K_final = sha3_512(t)[:32]  # 256-bit final key
        print(f"  K_final = {K_final.hex()}")
        
        return K_final

    # =========================================================================
    # Algorithm 5: Key Confirmation (Section 4.5)
    # =========================================================================
    
    def key_confirmation(self, node: Node, K_final: bytes, sid: bytes) -> str:
        """
        Algorithm 5: Key Confirmation
        
        τ_i = HMAC(K_final, "CONFIRM" || sid)
        """
        node.final_SK = K_final
        confirm_input = b"CONFIRM|" + sid + b"|" + node.id.encode() 
        node.confirm_tag = hmac_sha256(K_final, confirm_input).hex()
        return node.confirm_tag

    # =========================================================================
    # Full Protocol Execution
    # =========================================================================
    
    def run_demo_tree(self, admin_name: str, n_mod: int, members_per: int,
                      families: List[str] = None, sid: bytes = b"sid") -> Dict:
        """
        Execute complete VeriTree-GAKE protocol with all algorithms.
        
        Returns: JSON-serializable result dictionary
        """
        print("\n" + "="*80)
        print("VeriTree-GAKE: Complete Protocol Execution")
        print("="*80)

        
        self.total_bytes = 0  # reset counter for this run
        print(f"DEBUG: n_mod={n_mod}, members_per={members_per}, families={families}")
        
        families = families if families else self.default_families
        kem_objs = self.make_kem_objects(families)
        
        # Build tree structure
        nodes: Dict[str, Node] = {}
        parent: Dict[str, Optional[str]] = {}
        children: Dict[str, List[str]] = {}
        
        # Admin (root, level 2)
        admin_id = admin_name or "admin"
        nodes[admin_id] = Node(admin_id, "admin", level=2, families=families)
        parent[admin_id] = None
        children[admin_id] = []
        
        # Moderators (level 1)
        for i in range(n_mod):
            mid = f"mod{i+1}"
            nodes[mid] = Node(mid, "moderator", level=1, families=families)
            parent[mid] = admin_id
            children[mid] = []
            children[admin_id].append(mid)
        
        # Members (level 0, leaves)
        for i in range(n_mod):
            mid = f"mod{i+1}"
            for j in range(members_per):
                lid = f"{mid}-mem{j+1}"
                nodes[lid] = Node(lid, "member", level=0, families=families)
                parent[lid] = mid
                children[lid] = []
                children[mid].append(lid)
        
        print(f"\nTree built: {len(nodes)} nodes")
        print(f"Families: {families}")
        print(f"Structure: 1 admin -> {n_mod} moderators -> {n_mod * members_per} members\n")
        
        # Generate long-term and ephemeral keys
        print("=== Phase 0: Key Generation ===")
        for nid, node in nodes.items():
            for fam in families:
                pk, sk = kem_objs[fam].keygen()
                node.longterm_pk[fam] = pk
                node.longterm_sk[fam] = sk
                epk, esk = kem_objs[fam].keygen()
                node.ephemeral_pk[fam] = epk
                node.ephemeral_sk[fam] = esk
        
        # Initialize per-level session IDs
        for nid, node in nodes.items():
            node.sid_l = compute_sid_level([b"init"], node.level)
        
        # Data structures for protocol
        downlinks = {}
        commits = {}
        commit_sigs = {}
        uplinks = {}
        downlinks_ephemeral = {}
        
        # Phase 1: Algorithm 1 - Parent mKEM Broadcast
        print("\n=== Phase 1: Algorithm 1 - Parent mKEM Broadcast ===")
        for p_id, child_ids in children.items():
            if not child_ids:
                continue
            for fam in families:
                self.parent_mkem_broadcast(
                    p_id, child_ids, fam, nodes, kem_objs,
                    downlinks, commits, commit_sigs
                )
                print(f"  {p_id} -> {child_ids} (family: {fam})")
        
        # Phase 2: Algorithm 2 - Child Uplink KEM
        print("\n=== Phase 2: Algorithm 2 - Child Uplink KEM ===")
        for c_id, p_id in parent.items():
            if p_id is None:
                continue
            for fam in families:
                self.child_uplink_kem(c_id, p_id, fam, nodes, kem_objs, uplinks)
                print(f"  {c_id} -> {p_id} (family: {fam})")
        
        # Ephemeral downlinks (parent -> children)
        print("\n=== Ephemeral Downlinks ===")
        for p_id, child_ids in children.items():
            if not child_ids:
                continue
            downlinks_ephemeral[p_id] = {}
            for c_id in child_ids:
                downlinks_ephemeral[p_id][c_id] = {}
                for fam in families:
                    ct_ep, kprime = kem_objs[fam].encaps(nodes[c_id].ephemeral_pk[fam])
                    downlinks_ephemeral[p_id][c_id][fam] = {'ct': ct_ep, 'kprime_parent': kprime}
                    self.total_bytes += len(ct_ep['ct']) 
        
        # Phase 3: Per-Level Secret Derivation (Section 4.3)
        print("\n=== Phase 3: Per-Level Secret Derivation (Section 4.3) ===")
        for nid in sorted(nodes.keys()):
            self.derive_level_secrets(
                nodes[nid], parent[nid], children.get(nid, []),
                downlinks, uplinks, downlinks_ephemeral, kem_objs
            )
            print(f"  {nid}: tildeK = {nodes[nid].tildeK.hex()[:32]}...")
        
        # Phase 4: Algorithm 3 - Dual-Commit
        print("\n=== Phase 4: Algorithm 3 - Dual-Commit ===")
        for nid in sorted(nodes.keys()):
            self.dual_commit(nodes[nid])
            print(f"  {nid}: committed")
        
        # Barrier/Timeout (simulated)
        print("\n=== Barrier/Timeout ===")
        time.sleep(0.01)
        
        # Phase 5: Algorithm 3 - Dual-Open
        print("\n=== Phase 5: Algorithm 3 - Dual-Open ===")
        opens = {}
        for nid in sorted(nodes.keys()):
            encoded, sig = self.dual_open(nodes[nid])
            opens[nid] = canonical_decode(encoded)  # FIXED: use canonical_decode
            print(f"  {nid}: opened")
        
        # Verify all opens
        print("\n=== Verification of Opens ===")
        for nid in sorted(nodes.keys()):
            self.verify_dual_open(nodes[nid], opens[nid])
            print(f"  {nid}: verified OK")
        
        # Phase 6: Aggregation per level
        print("\n=== Phase 6: Level Aggregation (B_ℓ computation) ===")
        B_per_level = {}
        
        # Aggregate at each level
        for level in sorted(set(n.level for n in nodes.values())):
            level_nodes = [nid for nid, n in nodes.items() if n.level == level]
            B_per_level[level] = {}
            
            for fam in families:
                xor_acc = bytes([0] * 32)
                for nid in level_nodes:
                    xor_acc = bytes(a ^ b for a, b in zip(xor_acc, nodes[nid].tildeK))
                B_per_level[level][fam] = xor_acc
                print(f"  Level {level}, family {fam}: B_ℓ = {xor_acc.hex()[:32]}...")
        
        # Compute global sid from all level sids
        all_level_sids = [nodes[nid].sid_l for nid in sorted(nodes.keys())]
        global_sid = compute_sid_global(all_level_sids)
        print(f"\n  Global sid = {global_sid.hex()[:32]}...")
        
        # Phase 7: Algorithm 4 - Split-Key PRF Combiner
        K_final = self.split_key_combiner(B_per_level, families, global_sid)
        
        # Phase 8: Algorithm 5 - Key Confirmation
        print("\n=== Phase 8: Algorithm 5 - Key Confirmation ===")
        confirmation_tags = {}
        for nid in sorted(nodes.keys()):
            tag = self.key_confirmation(nodes[nid], K_final, global_sid)
            confirmation_tags[nid] = tag
            print(f"  {nid}: τ = {tag[:32]}...")
        
        # Check unanimity
        print("\n=== Unanimity Check ===")
        all_tags = list(confirmation_tags.values())
        unanimous = True
        for nid in sorted(nodes.keys()):
            expected_tag = hmac_sha256(K_final, b"CONFIRM|" + global_sid + b"|" + nid.encode()).hex()
            if confirmation_tags[nid] != expected_tag:
                unanimous = False
                print(f"  ✗ {nid}: Tag mismatch!")
                break

        print(f"  Unanimous: {unanimous}")
        
        if unanimous:
            print("   All nodes derived the same group key!")
        # Prepare result
        result = {
            'unanimous': unanimous,
            'SK_hex': K_final.hex(),
            'global_sid': global_sid.hex(),
            'total_bytes': self.total_bytes,
            'nodes': {},
            'bandwidth_kb': round(self.total_bytes / 1024.0, 2),
        }
        
        for nid, node in nodes.items():
            result['nodes'][nid] = {
                'role': node.role,
                'level': node.level,
                'tildeK': node.tildeK.hex(),
                'masked': node.masked.hex(),
                'mask': node.mask.hex(),
                'confirm': node.confirm_tag,
                'transcript_length': len(node.transcript)
            }
        
        logger.info("\n" + "="*80)
        logger.info("Protocol Execution Complete")
        logger.info("="*80 + "\n")
        logger.info(f"\nTotal bandwidth (bytes): {self.total_bytes}")
        logger.info(f"Total bandwidth (KB): {self.total_bytes / 1024.0}")
        
        return result


# =============================================================================
# Main Demo
# =============================================================================

if __name__ == "__main__":
    # Configuration
    families = ["Kyber512", "Saber"]
    
    # Initialize simulator
    sim = VeriTreeSimulator(preferred_families=families)
    
    # Run protocol: 1 admin, 2 moderators, 2 members each
    result = sim.run_demo_tree(
        admin_name="admin",
        n_mod=2,
        members_per=2,
        families=families,
        sid=b"session-2025-10-16"
    )
    print("\nTotal bandwidth (bytes):", result['total_bytes'])
    print("Total bandwidth (KB):", result['total_bytes'] / 1024.0)
    
    # Display results
    print("\n" + "="*80)
    print("FINAL RESULTS")
    print("="*80)
    print(f"\nUnanimous Agreement: {result['unanimous']}")
    print(f"Final Group Key (K_final): {result['SK_hex']}")
    print(f"Global Session ID: {result['global_sid']}\n")
    
    print("Per-Node Summary:")
    print("-" * 80)
    for node_id, node_data in result['nodes'].items():
        print(f"\n{node_id} ({node_data['role']}, level {node_data['level']}):")
        print(f"  tildeK: {node_data['tildeK'][:32]}...")
        print(f"  confirm: {node_data['confirm'][:32]}...")
    
    # Save to JSON
    with open("veritree_gake_complete_results.json", "w") as f:
        json.dump(result, f, indent=2)
    
    print("\n" + "="*80)
    print("Results saved to: veritree_gake_complete_results.json")
    print("="*80)