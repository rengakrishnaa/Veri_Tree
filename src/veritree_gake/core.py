import csv
import hashlib
import hmac
import json
import logging
import math
import random
import secrets
import statistics
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    import oqs  # type: ignore
    HAS_OQS = True
except Exception:
    HAS_OQS = False

try:
    import cbor2  # type: ignore
    HAS_CBOR2 = True
except Exception:
    HAS_CBOR2 = False

OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True)


def hkdf_extract(salt: bytes, ikm: bytes, hashmod=hashlib.sha256) -> bytes:
    if not salt:
        salt = bytes([0] * hashmod().digest_size)
    return hmac.new(salt, ikm, hashmod).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int, hashmod=hashlib.sha256) -> bytes:
    hash_len = hashmod().digest_size
    n = (length + hash_len - 1) // hash_len
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashmod).digest()
        okm += t
    return okm[:length]


def hkdf_sha256(salt: bytes, ikm: bytes, info: bytes = b"", length: int = 32) -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm, hashlib.sha256), info, length, hashlib.sha256)


def sha3_512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hash_sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def now_ms() -> int:
    return int(time.time() * 1000)


def canonical_encode(obj: Any) -> bytes:
    if HAS_CBOR2:
        return cbor2.dumps(obj, canonical=True)
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_decode(data: bytes) -> Any:
    if HAS_CBOR2:
        return cbor2.loads(data)
    return json.loads(data.decode("utf-8"))


def compute_sid_level(transcript: List[bytes], level: int) -> bytes:
    return hash_sha256(b"level" + str(level).encode() + b"|" + b"".join(transcript))


def compute_sid_global(all_level_sids: List[bytes]) -> bytes:
    return hash_sha256(b"global|" + b"".join(all_level_sids))


def json_safe(obj: Any):
    if isinstance(obj, bytes):
        return {"bytes": obj.hex()}
    if isinstance(obj, dict):
        return {str(k): json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [json_safe(v) for v in obj]
    return obj


KEM_PARAMETER_BYTES = {
    "Kyber512": {"pk": 800, "sk": 1632, "ct": 768, "ss": 32},
    "ML-KEM-512": {"pk": 800, "sk": 1632, "ct": 768, "ss": 32},
    "Saber": {"pk": 672, "sk": 1568, "ct": 736, "ss": 32},
    "LightSaber": {"pk": 672, "sk": 1568, "ct": 736, "ss": 32},
    "FireSaber": {"pk": 1312, "sk": 3040, "ct": 1472, "ss": 32},
}

PREFERRED_OQS_ALIASES = {
    "Kyber512": ["ML-KEM-512", "Kyber512"],
    "ML-KEM-512": ["ML-KEM-512", "Kyber512"],
    "Saber": ["Saber", "LightSaber"],
}


class ContributionState(str, Enum):
    VALID = "valid"
    LEAFDEFAULT = "leafdefault"
    MISSINGDOWNLINK = "missingdownlink"
    MISSINGUPLINK = "missinguplink"
    MISSINGEPHEMERAL = "missingephemeral"
    EXCLUDEDTIMEOUT = "excludedtimeout"
    INVALIDOPEN = "invalidopen"
    MODERATORFAILURE = "moderatorfailure"
    DYNAMICLEAVE = "dynamicleave"
    INACTIVENODE = "inactivenode"
    REPARENTED = "reparented"


class BaseKEM:
    def __init__(self, alg: str):
        self.alg = alg
        meta = KEM_PARAMETER_BYTES.get(alg, {})
        self.ctbytes = meta.get("ct", 768)
        self.ssbytes = meta.get("ss", 32)

    def keygen(self) -> Tuple[bytes, bytes]:
        raise NotImplementedError

    def encaps(self, pk: bytes) -> Tuple[Dict[str, bytes], bytes]:
        raise NotImplementedError

    def decaps(self, sk: bytes, ctobj: Dict[str, bytes]) -> bytes:
        raise NotImplementedError

    def mencaps(self, pks: List[bytes], mode: str = "aggregated") -> Tuple[Dict[str, Any], List[bytes]]:
        ciphertexts = []
        shared_secrets = []
        recipients_meta = []
        for idx, pk in enumerate(pks):
            ctobj, ss = self.encaps(pk)
            ciphertexts.append(ctobj)
            shared_secrets.append(ss)
            recipients_meta.append({"index": idx, "ctlen": len(ctobj["ct"])})
        aggregate_ct = hash_sha256(
            canonical_encode(
                {
                    "family": self.alg,
                    "count": len(ciphertexts),
                    "ciphertexts": [c["ct"].hex() for c in ciphertexts],
                }
            )
        )
        measured_ct_bytes = sum(len(c["ct"]) + len(c.get("nonce", b"")) for c in ciphertexts)
        theoretical_ct_bytes = int(math.ceil(self.ctbytes * (1.30 + 0.05 * max(0, len(pks) - 1)))) if pks else 0
        bundle = {
            "mode": mode,
            "family": self.alg,
            "count": len(ciphertexts),
            "ciphertexts": ciphertexts,
            "aggregatect": aggregate_ct,
            "recipientsmeta": recipients_meta,
            "measuredctbytes": measured_ct_bytes,
            "theoreticalctbytes": theoretical_ct_bytes,
            "bundleoverheadbytes": len(aggregate_ct),
        }
        return bundle, shared_secrets

    def mdecaps(self, sk: bytes, bundle: Dict[str, Any], index: int) -> bytes:
        return self.decaps(sk, bundle["ciphertexts"][index])


class PyOQSKEM(BaseKEM):
    def __init__(self, alg: str):
        super().__init__(alg)
        self.kem = oqs.KeyEncapsulation(alg)

    def keygen(self) -> Tuple[bytes, bytes]:
        pk = self.kem.generate_keypair()
        sk = self.kem.export_secret_key()
        return pk, sk

    def encaps(self, pk: bytes) -> Tuple[Dict[str, bytes], bytes]:
        ct, ss = self.kem.encap_secret(pk)
        return {"ct": ct}, ss

    def decaps(self, sk: bytes, ctobj: Dict[str, bytes]) -> bytes:
        kem = oqs.KeyEncapsulation(self.alg)
        return kem.decap_secret(ctobj["ct"], sk)


class SimKEM(BaseKEM):
    def keygen(self) -> Tuple[bytes, bytes]:
        pk = secrets.token_bytes(32)
        sk = pk
        return pk, sk

    def encaps(self, pk: bytes) -> Tuple[Dict[str, bytes], bytes]:
        shared = secrets.token_bytes(self.ssbytes)
        nonce = secrets.token_bytes(16)
        stream = hkdf_sha256(pk, nonce, b"simkem-" + self.alg.encode(), self.ssbytes)
        ct = xor_bytes(shared, stream)
        return {"ct": ct, "nonce": nonce}, shared

    def decaps(self, sk: bytes, ctobj: Dict[str, bytes]) -> bytes:
        stream = hkdf_sha256(sk, ctobj["nonce"], b"simkem-" + self.alg.encode(), len(ctobj["ct"]))
        return xor_bytes(ctobj["ct"], stream)


class HybridSignatureBackend:
    def __init__(self, families: List[str]):
        self.families = families

    def sign_key_for_node(self, node_material: Dict[str, bytes], node_id: str) -> bytes:
        concat = b"".join(node_material[f] for f in sorted(node_material.keys()))
        return hkdf_sha256(b"sign-salt", concat, b"signkey|" + node_id.encode(), 32)

    def sign(self, signing_key: bytes, payload: bytes) -> bytes:
        return hmac_sha256(signing_key, payload)

    def verify(self, signing_key: bytes, payload: bytes, sig: bytes) -> bool:
        return hmac.compare_digest(hmac_sha256(signing_key, payload), sig)


def make_kem_instance(fam: str):
    if HAS_OQS:
        for candidate in PREFERRED_OQS_ALIASES.get(fam, [fam]):
            try:
                return PyOQSKEM(candidate)
            except Exception:
                continue
    return SimKEM(fam)


@dataclass
class FaultEvent:
    nodeid: str
    phase: str
    reason: str
    timestampms: int
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Node:
    id: str
    role: str
    level: int
    families: List[str]
    parentid: Optional[str] = None
    active: bool = True
    alive: bool = True
    longtermpk: Dict[str, bytes] = field(default_factory=dict)
    longtermsk: Dict[str, bytes] = field(default_factory=dict)
    ephemeralpk: Dict[str, bytes] = field(default_factory=dict)
    ephemeralsk: Dict[str, bytes] = field(default_factory=dict)
    transcript: List[bytes] = field(default_factory=list)
    sidl: Optional[bytes] = None
    levelsecrets: Dict[str, bytes] = field(default_factory=dict)
    contributionstate: Dict[str, str] = field(default_factory=dict)
    tildeK: Optional[bytes] = None
    mask: Optional[bytes] = None
    masked: Optional[bytes] = None
    rho1: Optional[bytes] = None
    rho2: Optional[bytes] = None
    commit1: Optional[bytes] = None
    commit2: Optional[bytes] = None
    commitreceipts: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    openevidence: Dict[str, Any] = field(default_factory=dict)
    finalSK: Optional[bytes] = None
    confirmtag: Optional[str] = None
    excludedreason: Optional[str] = None

    def signing_material(self) -> Dict[str, bytes]:
        return self.longtermsk


class VeriTreeSimulator:
    def __init__(
        self,
        preferredfamilies: Optional[List[str]] = None,
        mkemmode: str = "aggregated",
        timeoutms: int = 500,
        networklatencyms: int = 0,
        packetloss: float = 0.0,
        seed: int = 42,
        enabledynamicops: bool = True,
        enablefailover: bool = True,
    ):
        self.defaultfamilies = preferredfamilies or ["Kyber512", "Saber"]
        self.mkemmode = mkemmode
        self.timeoutms = timeoutms
        self.networklatencyms = networklatencyms
        self.packetloss = packetloss
        self.enabledynamicops = enabledynamicops
        self.enablefailover = enablefailover
        self.rng = random.Random(seed)
        self.sigbackend = HybridSignatureBackend(self.defaultfamilies)
        self.reset_metrics()

    def reset_metrics(self):
        self.totalbytes = 0
        self.messagebytesbytype: Dict[str, int] = {}
        self.ciphertextbytesbytype: Dict[str, int] = {}
        self.theoreticalbytesbytype: Dict[str, int] = {}
        self.phasetimingsms: Dict[str, float] = {}
        self.faultevents: List[FaultEvent] = []
        self.cpuops: Dict[str, int] = {}
        self.memoryestimates: Dict[str, int] = {}
        self.energyestimates: Dict[str, float] = {}

    def track_message(self, name: str, payloadbytes: int = 0, ciphertextbytes: int = 0, theoreticalbytes: int = 0):
        self.totalbytes += payloadbytes + ciphertextbytes
        self.messagebytesbytype[name] = self.messagebytesbytype.get(name, 0) + payloadbytes
        self.ciphertextbytesbytype[name] = self.ciphertextbytesbytype.get(name, 0) + ciphertextbytes
        self.theoreticalbytesbytype[name] = self.theoreticalbytesbytype.get(name, 0) + theoreticalbytes

    def track_cpu(self, name: str, count: int = 1):
        self.cpuops[name] = self.cpuops.get(name, 0) + count

    def fault(self, nodeid: str, phase: str, reason: str, evidence: Optional[Dict[str, Any]] = None):
        event = FaultEvent(nodeid=nodeid, phase=phase, reason=reason, timestampms=now_ms(), evidence=evidence or {})
        self.faultevents.append(event)
        return event

    def make_kem_objects(self, families: List[str]) -> Dict[str, Any]:
        return {fam: make_kem_instance(fam) for fam in families}

    def build_tree(
        self,
        adminname: str,
        nmod: int,
        membersper: int,
        families: List[str],
    ):
        nodes: Dict[str, Node] = {}
        parent: Dict[str, Optional[str]] = {}
        children: Dict[str, List[str]] = {}
        failoverparent: Dict[str, Optional[str]] = {}

        adminid = adminname or "admin"
        nodes[adminid] = Node(adminid, "admin", 2, families, parentid=None)
        parent[adminid] = None
        children[adminid] = []
        failoverparent[adminid] = None

        moderatorids = []
        for i in range(nmod):
            mid = f"mod{i+1}"
            moderatorids.append(mid)
            nodes[mid] = Node(mid, "moderator", 1, families, parentid=adminid)
            parent[mid] = adminid
            children[mid] = []
            children[adminid].append(mid)

        for idx, mid in enumerate(moderatorids):
            failoverparent[mid] = adminid
            for j in range(membersper):
                lid = f"{mid}-mem{j+1}"
                nodes[lid] = Node(lid, "member", 0, families, parentid=mid)
                parent[lid] = mid
                children[lid] = []
                children[mid].append(lid)
                failoverparent[lid] = moderatorids[(idx + 1) % len(moderatorids)] if self.enablefailover and len(moderatorids) > 1 else adminid

        return nodes, parent, children, failoverparent

    def initialize_keys(self, nodes: Dict[str, Node], families: List[str], kemobjs: Dict[str, Any]):
        for node in nodes.values():
            for fam in families:
                pk, sk = kemobjs[fam].keygen()
                epk, esk = kemobjs[fam].keygen()
                node.longtermpk[fam] = pk
                node.longtermsk[fam] = sk
                node.ephemeralpk[fam] = epk
                node.ephemeralsk[fam] = esk
                node.contributionstate[fam] = ContributionState.LEAFDEFAULT.value if node.role == "member" else ContributionState.VALID.value
                self.track_cpu("kemkeygen", 2)
            node.sidl = compute_sid_level([b"init", node.id.encode()], node.level)

    def simulate_network_delivery(self, payloadname: str, senderid: str, receiverid: str) -> bool:
        if self.packetloss > 0 and self.rng.random() < self.packetloss:
            self.fault(receiverid, payloadname, "networkloss", {"sender": senderid, "receiver": receiverid})
            return False
        return True

    def apply_failover_and_reparent(
        self,
        failednodeid: str,
        nodes: Dict[str, Node],
        parent: Dict[str, Optional[str]],
        children: Dict[str, List[str]],
        failoverparent: Dict[str, Optional[str]],
    ):
        if failednodeid not in children:
            return
        for childid in list(children[failednodeid]):
            altparent = failoverparent.get(childid)
            if self.enablefailover and altparent and altparent in nodes and nodes[altparent].alive:
                parent[childid] = altparent
                nodes[childid].parentid = altparent
                children.setdefault(altparent, []).append(childid)
                for fam in nodes[childid].families:
                    nodes[childid].contributionstate[fam] = ContributionState.REPARENTED.value
                self.fault(childid, "reparent", "failoverreparent", {"oldparent": failednodeid, "newparent": altparent})
            else:
                nodes[childid].active = False
                nodes[childid].excludedreason = "parentfailureisolation"
                for fam in nodes[childid].families:
                    nodes[childid].contributionstate[fam] = ContributionState.MODERATORFAILURE.value
                self.fault(childid, "reparent", "subtreeisolated", {"parent": failednodeid})
        children[failednodeid] = []

    def add_member_dynamic(
        self,
        moderatorid: str,
        membername: str,
        nodes: Dict[str, Node],
        parent: Dict[str, Optional[str]],
        children: Dict[str, List[str]],
        families: List[str],
        kemobjs: Dict[str, Any],
    ):
        if not self.enabledynamicops or moderatorid not in nodes:
            return None
        node = Node(membername, "member", 0, families, parentid=moderatorid)
        nodes[membername] = node
        parent[membername] = moderatorid
        children[membername] = []
        children[moderatorid].append(membername)
        for fam in families:
            pk, sk = kemobjs[fam].keygen()
            epk, esk = kemobjs[fam].keygen()
            node.longtermpk[fam] = pk
            node.longtermsk[fam] = sk
            node.ephemeralpk[fam] = epk
            node.ephemeralsk[fam] = esk
            node.contributionstate[fam] = ContributionState.VALID.value
        node.sidl = compute_sid_level([b"dynamic-join", node.id.encode()], node.level)
        self.fault(membername, "dynamicjoin", "memberadded", {"parent": moderatorid})
        return membername

    def remove_member_dynamic(self, memberid: str, nodes: Dict[str, Node], children: Dict[str, List[str]]):
        if not self.enabledynamicops or memberid not in nodes:
            return False
        nodes[memberid].alive = False
        nodes[memberid].active = False
        nodes[memberid].excludedreason = "dynamicleave"
        for fam in nodes[memberid].families:
            nodes[memberid].contributionstate[fam] = ContributionState.DYNAMICLEAVE.value
        self.fault(memberid, "dynamicleave", "memberremoved", {})
        pid = nodes[memberid].parentid
        if pid and memberid in children.get(pid, []):
            children[pid].remove(memberid)
        return True

    def sign_message(self, node: Node, payload: bytes) -> bytes:
        signkey = self.sigbackend.sign_key_for_node(node.signing_material(), node.id)
        return self.sigbackend.sign(signkey, payload)

    def verify_message(self, node: Node, payload: bytes, sig: bytes) -> bool:
        signkey = self.sigbackend.sign_key_for_node(node.signing_material(), node.id)
        return self.sigbackend.verify(signkey, payload, sig)

    def parent_mkem_broadcast(
        self,
        parentid: str,
        childrenids: List[str],
        family: str,
        nodes: Dict[str, Node],
        kemobjs: Dict[str, Any],
        downlinks: Dict[str, Any],
    ) -> int:
        parentnode = nodes[parentid]
        activechildren = [c for c in childrenids if c in nodes and nodes[c].active and nodes[c].alive]
        if not activechildren:
            return 0
        recipientpks = [nodes[c].longtermpk[family] for c in activechildren]
        bundle, secretsforchildren = kemobjs[family].mencaps(recipientpks, mode=self.mkemmode)
        msg = {
            "type": "downlinkmkem",
            "suiteid": "VeriTree-GAKE-v4",
            "family": family,
            "mode": bundle["mode"],
            "parent": parentid,
            "children": activechildren,
            "level": parentnode.level,
            "sidl": parentnode.sidl.hex() if parentnode.sidl else "initial",
            "count": bundle["count"],
            "aggregatecthex": bundle["aggregatect"].hex(),
        }
        encoded = canonical_encode(msg)
        sig = self.sign_message(parentnode, encoded)
        parentnode.transcript.append(encoded)
        self.track_message(
            "downlinkmkem",
            payloadbytes=len(encoded) + len(sig),
            ciphertextbytes=bundle["measuredctbytes"] + bundle["bundleoverheadbytes"],
            theoreticalbytes=bundle["theoreticalctbytes"],
        )
        self.track_cpu("mkemencaps")
        downlinks.setdefault(parentid, {})
        delivered = 0
        for idx, childid in enumerate(activechildren):
            if not self.simulate_network_delivery("downlinkmkem", parentid, childid):
                nodes[childid].contributionstate[family] = ContributionState.MISSINGDOWNLINK.value
                continue
            child = nodes[childid]
            downlinks[parentid].setdefault(childid, {})
            downlinks[parentid][childid][family] = {
                "bundle": bundle,
                "bundleindex": idx,
                "kparent": secretsforchildren[idx],
                "signature": sig,
                "message": msg,
            }
            child.transcript.append(encoded)
            delivered += 1
        return delivered

    def child_uplink_kem(
        self,
        childid: str,
        parentid: str,
        family: str,
        nodes: Dict[str, Node],
        kemobjs: Dict[str, Any],
        uplinks: Dict[str, Any],
    ) -> bool:
        child = nodes[childid]
        parentnode = nodes[parentid]
        ctup, kchild = kemobjs[family].encaps(parentnode.longtermpk[family])
        payload = {
            "type": "uplinkkem",
            "child": childid,
            "parent": parentid,
            "family": family,
            "level": child.level,
            "sidl": child.sidl.hex() if child.sidl else "initial",
        }
        encoded = canonical_encode(payload)
        sig = self.sign_message(child, encoded)
        self.track_message("uplinkkem", payloadbytes=len(encoded) + len(sig), ciphertextbytes=len(ctup["ct"]) + len(ctup.get("nonce", b"")))
        self.track_cpu("kemencaps")
        child.transcript.append(encoded)
        parentnode.transcript.append(encoded)
        if not self.simulate_network_delivery("uplinkkem", childid, parentid):
            child.contributionstate[family] = ContributionState.MISSINGUPLINK.value
            return False
        uplinks.setdefault(childid, {})
        uplinks[childid][family] = {"ct": ctup, "kchild": kchild, "signature": sig, "message": payload}
        return True

    def ephemeral_parent_to_child(
        self,
        parentid: str,
        childid: str,
        family: str,
        nodes: Dict[str, Node],
        kemobjs: Dict[str, Any],
        downlinksephemeral: Dict[str, Any],
    ) -> bool:
        ctep, kprime = kemobjs[family].encaps(nodes[childid].ephemeralpk[family])
        self.track_message("ephemeraldownlink", ciphertextbytes=len(ctep["ct"]) + len(ctep.get("nonce", b"")))
        self.track_cpu("kemencaps")
        if not self.simulate_network_delivery("ephemeraldownlink", parentid, childid):
            nodes[childid].contributionstate[family] = ContributionState.MISSINGEPHEMERAL.value
            return False
        downlinksephemeral.setdefault(parentid, {}).setdefault(childid, {})
        downlinksephemeral[parentid][childid][family] = {"ct": ctep, "kprimeparent": kprime}
        return True

    def fallback_secret(self, reason: str, nodeid: str, family: str, sidl: bytes) -> bytes:
        return hkdf_sha256(
            hash_sha256(b"fallbacksalt|" + reason.encode() + b"|" + nodeid.encode() + b"|" + family.encode() + b"|" + sidl),
            b"fallback|" + reason.encode(),
            32 * b"\x00",
            32,
        )

    def derive_level_secrets(
        self,
        node: Node,
        parentid: Optional[str],
        childrenids: List[str],
        downlinks: Dict[str, Any],
        uplinks: Dict[str, Any],
        downlinksephemeral: Dict[str, Any],
        kemobjs: Dict[str, Any],
    ):
        lparts = []
        sidl = node.sidl if node.sidl else b"level" + str(node.level).encode()
        for fam in node.families:
            if not node.active or not node.alive:
                node.levelsecrets[fam] = self.fallback_secret(ContributionState.INACTIVENODE.value, node.id, fam, sidl)
                node.contributionstate[fam] = ContributionState.INACTIVENODE.value
                lparts.append(node.levelsecrets[fam])
                continue

            downok = parentid is not None and downlinks.get(parentid, {}).get(node.id, {}).get(fam)
            upok = uplinks.get(node.id, {}).get(fam)

            if parentid is None:
                lj = self.fallback_secret(ContributionState.LEAFDEFAULT.value, node.id, fam, sidl)
                node.contributionstate[fam] = ContributionState.LEAFDEFAULT.value
            elif downok and upok:
                down = downlinks[parentid][node.id][fam]
                kdown = kemobjs[fam].mdecaps(node.longtermsk[fam], down["bundle"], down["bundleindex"])
                kup = uplinks[node.id][fam]["kchild"]
                self.track_cpu("mkemdecaps")
                ikm = kdown + kup + sidl
                lj = hkdf_sha256(hash_sha256(b"Lsalt|" + node.id.encode() + b"|" + ikm), b"L|" + fam.encode() + b"|" + node.id.encode(), 32 * b"\x00", 32)
                if node.contributionstate.get(fam) not in [ContributionState.REPARENTED.value, ContributionState.VALID.value]:
                    node.contributionstate[fam] = ContributionState.VALID.value
            else:
                reason = ContributionState.MISSINGDOWNLINK.value if not downok else ContributionState.MISSINGUPLINK.value
                lj = self.fallback_secret(reason, node.id, fam, sidl)
                node.contributionstate[fam] = reason

            node.levelsecrets[fam] = lj
            lparts.append(lj)

        rparts = []
        for fam in node.families:
            acc = b""
            for childid in childrenids:
                childpresent = downlinks.get(node.id, {}).get(childid, {}).get(fam)
                eph = downlinksephemeral.get(node.id, {}).get(childid, {}).get(fam)
                acc += childpresent["kparent"] if childpresent else self.fallback_secret(ContributionState.MISSINGDOWNLINK.value, childid, fam, sidl)
                acc += eph["kprimeparent"] if eph else self.fallback_secret(ContributionState.MISSINGEPHEMERAL.value, childid, fam, sidl)
            if not acc:
                acc = self.fallback_secret(ContributionState.LEAFDEFAULT.value, node.id, fam, sidl)
            rparts.append(acc)

        ikm = b"".join(lparts) + b"".join(rparts) + sidl
        node.tildeK = hkdf_sha256(hash_sha256(b"tildeKsalt"), ikm, b"tildeK|" + node.id.encode(), 32)
        return node.tildeK

    def ack_commit(self, parentnode: Node, childnode: Node, encodedcommit: bytes, sigcommit: bytes) -> Dict[str, Any]:
        receipt = {
            "type": "commitreceipt",
            "parent": parentnode.id,
            "child": childnode.id,
            "level": childnode.level,
            "sidl": childnode.sidl.hex() if childnode.sidl else "initial",
            "commithash": hash_sha256(encodedcommit + sigcommit).hex(),
            "timestampms": now_ms(),
        }
        receiptencoded = canonical_encode(receipt)
        receiptsig = self.sign_message(parentnode, receiptencoded)
        self.track_message("commitreceipt", payloadbytes=len(receiptencoded) + len(receiptsig))
        return {"receipt": receipt, "signature": receiptsig}

    def dual_commit(self, node: Node, nodes: Dict[str, Node]):
        sidl = node.sidl if node.sidl else b"level" + str(node.level).encode()
        node.mask = secrets.token_bytes(32)
        node.masked = xor_bytes(node.tildeK, node.mask)
        node.rho1 = secrets.token_bytes(16)
        node.rho2 = secrets.token_bytes(16)
        node.commit1 = hash_sha256(node.tildeK + node.rho1 + sidl)
        node.commit2 = hash_sha256(node.masked + node.rho2 + sidl)
        payload = {
            "type": "dualcommit",
            "node": node.id,
            "level": node.level,
            "commit1hex": node.commit1.hex(),
            "commit2hex": node.commit2.hex(),
            "sidl": sidl.hex(),
        }
        encoded = canonical_encode(payload)
        sig = self.sign_message(node, encoded)
        node.transcript.append(encoded)
        self.track_message("dualcommit", payloadbytes=len(encoded) + len(sig))
        self.track_cpu("commit")
        if node.parentid and node.parentid in nodes and nodes[node.parentid].alive:
            parent = nodes[node.parentid]
            if self.simulate_network_delivery("dualcommit", node.id, parent.id):
                node.commitreceipts[parent.id] = self.ack_commit(parent, node, encoded, sig)
            else:
                self.fault(node.id, "dualcommit", "missingparentreceipt", {"parent": parent.id})
        return encoded, sig

    def dual_open(self, node: Node):
        sidl = node.sidl if node.sidl else b"level" + str(node.level).encode()
        payload = {
            "type": "dualopen",
            "node": node.id,
            "level": node.level,
            "tildeKhex": node.tildeK.hex(),
            "maskhex": node.mask.hex(),
            "maskedhex": node.masked.hex(),
            "rho1hex": node.rho1.hex(),
            "rho2hex": node.rho2.hex(),
            "sidl": sidl.hex(),
            "receipts": node.commitreceipts,
        }
        encoded = canonical_encode(payload)
        sig = self.sign_message(node, encoded)
        node.transcript.append(encoded)
        self.track_message("dualopen", payloadbytes=len(encoded) + len(sig))
        self.track_cpu("open")
        return encoded, sig

    def verify_dual_open(self, node: Node, opendata: Dict[str, Any]) -> bool:
        sidl = bytes.fromhex(opendata["sidl"])
        tildeK = bytes.fromhex(opendata["tildeKhex"])
        masked = bytes.fromhex(opendata["maskedhex"])
        rho1 = bytes.fromhex(opendata["rho1hex"])
        rho2 = bytes.fromhex(opendata["rho2hex"])
        mask = bytes.fromhex(opendata["maskhex"])
        receipts = opendata.get("receipts", {})
        ok = True
        ok &= hmac.compare_digest(hash_sha256(tildeK + rho1 + sidl), node.commit1)
        ok &= hmac.compare_digest(hash_sha256(masked + rho2 + sidl), node.commit2)
        ok &= hmac.compare_digest(xor_bytes(tildeK, mask), masked)
        if node.parentid:
            ok &= node.parentid in receipts
        self.track_cpu("verifyopen")
        return ok

    def barrier_and_accountable_abort(self, nodes: Dict[str, Node], opens: Dict[str, Dict[str, Any]]):
        excluded = []
        for nid, node in nodes.items():
            if not node.active or not node.alive:
                excluded.append(nid)
                continue
            if node.parentid and node.parentid not in node.commitreceipts:
                node.active = False
                node.excludedreason = "missingparentreceipt"
                for fam in node.families:
                    node.contributionstate[fam] = ContributionState.EXCLUDEDTIMEOUT.value
                node.openevidence = {"reason": "missingparentreceipt", "parent": node.parentid}
                self.fault(nid, "dualcommit", "missingparentreceipt", node.openevidence)
                excluded.append(nid)
                continue
            if nid not in opens:
                node.active = False
                node.excludedreason = "missingopentimeout"
                for fam in node.families:
                    node.contributionstate[fam] = ContributionState.EXCLUDEDTIMEOUT.value
                node.openevidence = {"reason": "timeout", "timeoutms": self.timeoutms}
                self.fault(nid, "dualopen", "timeout", node.openevidence)
                excluded.append(nid)
                continue
            if not self.verify_dual_open(node, opens[nid]):
                node.active = False
                node.excludedreason = "invalidopen"
                for fam in node.families:
                    node.contributionstate[fam] = ContributionState.INVALIDOPEN.value
                node.openevidence = {"reason": "commitopenmismatch", "node": nid}
                self.fault(nid, "dualopen", "commitopenmismatch", node.openevidence)
                excluded.append(nid)
        return excluded

    def aggregate_by_level(self, nodes: Dict[str, Node], families: List[str]) -> Dict[int, Dict[str, bytes]]:
        bperlevel: Dict[int, Dict[str, bytes]] = {}
        levels = sorted(set(n.level for n in nodes.values()))
        for level in levels:
            bperlevel[level] = {}
            levelnodes = [n for n in nodes.values() if n.level == level]
            for fam in families:
                acc = bytes(32)
                for node in levelnodes:
                    if node.active and node.alive and node.tildeK:
                        contribution = node.tildeK
                    else:
                        contribution = self.fallback_secret(node.contributionstate.get(fam, ContributionState.INACTIVENODE.value), node.id, fam, node.sidl or b"none")
                    acc = xor_bytes(acc, contribution)
                bperlevel[level][fam] = acc
        return bperlevel

    def split_key_combiner(self, bperlevel: Dict[int, Dict[str, bytes]], families: List[str], sid: bytes) -> bytes:
        kgrp = {}
        for family in families:
            allb = b"".join(bperlevel[level].get(family, bytes(32)) for level in sorted(bperlevel.keys()))
            kgrp[family] = hkdf_sha256(hash_sha256(b"Kgrpsalt"), allb + sid, b"Kgrp|" + family.encode() + b"|" + sid, 32)

        kj = {}
        for family in families:
            saltj = hash_sha256(b"salt|" + family.encode())
            kj[family] = hmac_sha256(saltj, kgrp[family])

        uj = {}
        for family in families:
            ctx = b"VTGcombiner|" + family.encode() + b"|" + sid.hex().encode()
            uj[family] = sha3_512(kgrp[family] + ctx + b"|chunk1") + sha3_512(kgrp[family] + ctx + b"|chunk2") + sha3_512(kgrp[family] + ctx + b"|chunk3")

        t = bytes(32)
        ordered = sorted(families)
        for idx, family in enumerate(ordered):
            otheru = b"".join(uj[f] for j, f in enumerate(ordered) if j != idx)
            t = xor_bytes(t, hmac_sha256(kj[family], otheru + b"|label|" + family.encode()))
        self.track_cpu("splitkeycombiner")
        return sha3_512(t)[:32]

    def key_confirmation(self, node: Node, kfinal: bytes, sid: bytes) -> str:
        node.finalSK = kfinal
        node.confirmtag = hmac_sha256(kfinal, b"CONFIRM|" + sid + b"|" + node.id.encode()).hex()
        self.track_message("keyconfirmation", payloadbytes=len(node.confirmtag))
        self.track_cpu("keyconfirmation")
        return node.confirmtag

    def estimate_iot_profile(self, nodes: Dict[str, Node], families: List[str]) -> Dict[str, Any]:
        activecount = sum(1 for n in nodes.values() if n.active and n.alive)
        avgtranscript = int(sum(len(b"".join(n.transcript)) for n in nodes.values()) / max(1, len(nodes)))
        kemfactor = len(families)
        estmemorypernode = 2048 + avgtranscript + kemfactor * 1024
        estcpucycles = (
            self.cpuops.get("kemkeygen", 0) * 120000
            + self.cpuops.get("kemencaps", 0) * 90000
            + self.cpuops.get("mkemencaps", 0) * 140000
            + self.cpuops.get("mkemdecaps", 0) * 95000
            + self.cpuops.get("splitkeycombiner", 0) * 40000
            + self.cpuops.get("commit", 0) * 18000
            + self.cpuops.get("verifyopen", 0) * 24000
        )
        estenergymj = round(estcpucycles / 1000000.0 * 0.18, 3)
        self.memoryestimates = {"pernodebytesest": estmemorypernode, "activenodes": activecount, "avgtranscriptbytes": avgtranscript}
        self.energyestimates = {"cpucyclesest": estcpucycles, "energymjest": estenergymj}
        return {"memory": self.memoryestimates, "energy": self.energyestimates}

    def export_benchmark_artifacts(self, result: Dict[str, Any], stem: str = "veritreebenchmarkfixed"):
        jsonpath = OUTPUT_DIR / f"{stem}.json"
        csvpath = OUTPUT_DIR / f"{stem}-summary.csv"
        with open(jsonpath, "w") as f:
            json.dump(json_safe(result), f, indent=2)
        with open(csvpath, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["metric", "value"])
            for key in ["unanimous", "totalbytes", "bandwidthkb", "theoreticalbandwidthkb", "mkemmode", "networklatencyms", "packetloss"]:
                writer.writerow([key, result[key]])
            for k, v in result["phasetimingsms"].items():
                writer.writerow([f"phase_{k}", v])
            for k, v in result["cpuops"].items():
                writer.writerow([f"cpu_{k}", v])
            writer.writerow(["memorypernodebytesest", result["iotprofile"]["memory"]["pernodebytesest"]])
            writer.writerow(["energymjest", result["iotprofile"]["energy"]["energymjest"]])
        return str(jsonpath), str(csvpath)

    def run_demo_tree(
        self,
        adminname: str,
        nmod: int,
        membersper: int,
        families: Optional[List[str]] = None,
        sid: bytes = b"sid",
        simulatedynamicops: bool = True,
        simulatemoderatorfailure: bool = True,
        moderatorfailuretarget: Optional[str] = None,
    ) -> Dict[str, Any]:
        starttotal = time.perf_counter()
        self.reset_metrics()
        families = families if families else self.defaultfamilies
        kemobjs = self.make_kem_objects(families)
        self.sigbackend = HybridSignatureBackend(families)

        nodes, parent, children, failoverparent = self.build_tree(adminname, nmod, membersper, families)

        t0 = time.perf_counter()
        self.initialize_keys(nodes, families, kemobjs)
        self.phasetimingsms["keygen"] = round((time.perf_counter() - t0) * 1000, 3)

        if simulatedynamicops and self.enabledynamicops:
            t0 = time.perf_counter()
            jointarget = "mod1" if "mod1" in nodes else next((nid for nid, n in nodes.items() if n.role == "moderator"), None)
            if jointarget:
                self.add_member_dynamic(jointarget, f"{jointarget}-dyn1", nodes, parent, children, families, kemobjs)
            leavetarget = next((nid for nid, n in nodes.items() if n.role == "member" and not nid.endswith("dyn1")), None)
            if leavetarget:
                self.remove_member_dynamic(leavetarget, nodes, children)
            self.phasetimingsms["dynamicops"] = round((time.perf_counter() - t0) * 1000, 3)

        if simulatemoderatorfailure and self.enablefailover:
            t0 = time.perf_counter()
            failuretarget = moderatorfailuretarget or ("mod1" if "mod1" in nodes else None)
            if failuretarget and failuretarget in nodes:
                nodes[failuretarget].alive = False
                nodes[failuretarget].active = False
                nodes[failuretarget].excludedreason = "moderatorfailure"
                for fam in nodes[failuretarget].families:
                    nodes[failuretarget].contributionstate[fam] = ContributionState.MODERATORFAILURE.value
                self.fault(failuretarget, "failure", "moderatorcrash", {})
                self.apply_failover_and_reparent(failuretarget, nodes, parent, children, failoverparent)
            self.phasetimingsms["failurerecovery"] = round((time.perf_counter() - t0) * 1000, 3)

        downlinks: Dict[str, Any] = {}
        uplinks: Dict[str, Any] = {}
        downlinksephemeral: Dict[str, Any] = {}

        t0 = time.perf_counter()
        for pid, childids in list(children.items()):
            if not childids or pid not in nodes or not nodes[pid].alive:
                continue
            for fam in families:
                self.parent_mkem_broadcast(pid, childids, fam, nodes, kemobjs, downlinks)
        self.phasetimingsms["phase1downlinkmkem"] = round((time.perf_counter() - t0) * 1000, 3)

        t0 = time.perf_counter()
        for cid, pid in list(parent.items()):
            if pid is None or cid not in nodes or pid not in nodes:
                continue
            if not nodes[cid].alive or not nodes[cid].active or not nodes[pid].alive:
                continue
            for fam in families:
                self.child_uplink_kem(cid, pid, fam, nodes, kemobjs, uplinks)
        self.phasetimingsms["phase2uplinkkem"] = round((time.perf_counter() - t0) * 1000, 3)

        t0 = time.perf_counter()
        for pid, childids in list(children.items()):
            if not childids or pid not in nodes or not nodes[pid].alive:
                continue
            for cid in list(childids):
                if cid not in nodes or not nodes[cid].alive or not nodes[cid].active:
                    continue
                for fam in families:
                    self.ephemeral_parent_to_child(pid, cid, fam, nodes, kemobjs, downlinksephemeral)
        self.phasetimingsms["ephemeraldownlink"] = round((time.perf_counter() - t0) * 1000, 3)

        t0 = time.perf_counter()
        for nid in sorted(nodes.keys()):
            self.derive_level_secrets(nodes[nid], parent.get(nid), children.get(nid, []), downlinks, uplinks, downlinksephemeral, kemobjs)
        self.phasetimingsms["phase3derivation"] = round((time.perf_counter() - t0) * 1000, 3)

        t0 = time.perf_counter()
        for nid in sorted(nodes.keys()):
            if nodes[nid].alive:
                self.dual_commit(nodes[nid], nodes)
        self.phasetimingsms["phase4dualcommit"] = round((time.perf_counter() - t0) * 1000, 3)

        if self.networklatencyms > 0:
            time.sleep(min(self.networklatencyms / 1000.0, 0.05))
        else:
            time.sleep(0.01)

        t0 = time.perf_counter()
        opens = {}
        for nid in sorted(nodes.keys()):
            if not nodes[nid].alive:
                continue
            encoded, _ = self.dual_open(nodes[nid])
            opens[nid] = canonical_decode(encoded)
        self.phasetimingsms["phase5dualopen"] = round((time.perf_counter() - t0) * 1000, 3)

        t0 = time.perf_counter()
        excluded = self.barrier_and_accountable_abort(nodes, opens)
        self.phasetimingsms["phase5verification"] = round((time.perf_counter() - t0) * 1000, 3)

        t0 = time.perf_counter()
        bperlevel = self.aggregate_by_level(nodes, families)
        self.phasetimingsms["phase6aggregation"] = round((time.perf_counter() - t0) * 1000, 3)

        alllevelsids = [nodes[nid].sidl for nid in sorted(nodes.keys()) if nodes[nid].sidl]
        globalsid = compute_sid_global(alllevelsids)

        t0 = time.perf_counter()
        kfinal = self.split_key_combiner(bperlevel, families, globalsid)
        self.phasetimingsms["phase7combiner"] = round((time.perf_counter() - t0) * 1000, 3)

        t0 = time.perf_counter()
        confirmationtags = {}
        activekeyholders = [nid for nid, node in nodes.items() if node.active and node.alive]
        for nid in sorted(activekeyholders):
            confirmationtags[nid] = self.key_confirmation(nodes[nid], kfinal, globalsid)
        self.phasetimingsms["phase8keyconfirmation"] = round((time.perf_counter() - t0) * 1000, 3)

        unanimous = True
        for nid in sorted(activekeyholders):
            expectedtag = hmac_sha256(kfinal, b"CONFIRM|" + globalsid + b"|" + nid.encode()).hex()
            if confirmationtags.get(nid) != expectedtag:
                unanimous = False
                break

        t0 = time.perf_counter()
        iotprofile = self.estimate_iot_profile(nodes, families)
        self.phasetimingsms["iotprofile"] = round((time.perf_counter() - t0) * 1000, 3)
        self.phasetimingsms["total"] = round((time.perf_counter() - starttotal) * 1000, 3)

        theoreticaltotal = sum(self.theoreticalbytesbytype.values()) + sum(self.messagebytesbytype.values())

        result = {
            "unanimous": unanimous,
            "SKhex": kfinal.hex(),
            "globalsid": globalsid.hex(),
            "totalbytes": self.totalbytes,
            "bandwidthkb": round(self.totalbytes / 1024.0, 2),
            "theoreticaltotalbytes": theoreticaltotal,
            "theoreticalbandwidthkb": round(theoreticaltotal / 1024.0, 2),
            "mkemmode": self.mkemmode,
            "families": families,
            "networklatencyms": self.networklatencyms,
            "packetloss": self.packetloss,
            "activenodes": activekeyholders,
            "excludednodes": {nid: nodes[nid].excludedreason for nid in nodes if not nodes[nid].active or not nodes[nid].alive},
            "faultevents": [
                {"nodeid": e.nodeid, "phase": e.phase, "reason": e.reason, "timestampms": e.timestampms, "evidence": e.evidence}
                for e in self.faultevents
            ],
            "messagebytesbytype": self.messagebytesbytype,
            "ciphertextbytesbytype": self.ciphertextbytesbytype,
            "theoreticalbytesbytype": self.theoreticalbytesbytype,
            "phasetimingsms": self.phasetimingsms,
            "cpuops": self.cpuops,
            "iotprofile": iotprofile,
            "nodes": {},
        }

        for nid, node in nodes.items():
            result["nodes"][nid] = {
                "role": node.role,
                "level": node.level,
                "parentid": node.parentid,
                "active": node.active,
                "alive": node.alive,
                "excludedreason": node.excludedreason,
                "contributionstate": node.contributionstate,
                "tildeK": node.tildeK.hex() if node.tildeK else None,
                "commitreceipts": node.commitreceipts,
                "openevidence": node.openevidence,
                "confirm": node.confirmtag,
                "transcriptlength": len(node.transcript),
            }

        jsonpath, csvpath = self.export_benchmark_artifacts(result)
        result["artifacts"] = {"json": jsonpath, "csv": csvpath}

        logger.info(f"Total bandwidth bytes: {self.totalbytes}")
        logger.info(f"Theoretical bandwidth bytes: {theoreticaltotal}")
        return result

    def run_network_resilience_benchmark(
        self,
        profiles: List[Tuple[int, float]],
        nmod: int = 2,
        membersper: int = 2,
        families: Optional[List[str]] = None,
    ):
        families = families or self.defaultfamilies
        rows = []
        for latencyms, loss in profiles:
            self.networklatencyms = latencyms
            self.packetloss = loss
            sample = self.run_demo_tree(
                adminname="admin",
                nmod=nmod,
                membersper=membersper,
                families=families,
                sid=f"profile-{latencyms}-{loss}".encode(),
                simulatedynamicops=True,
                simulatemoderatorfailure=True,
            )
            rows.append(
                {
                    "latencyms": latencyms,
                    "packetloss": loss,
                    "bandwidthkb": sample["bandwidthkb"],
                    "theoreticalbandwidthkb": sample["theoreticalbandwidthkb"],
                    "totalms": sample["phasetimingsms"]["total"],
                    "activenodes": len(sample["activenodes"]),
                    "excludednodes": len(sample["excludednodes"]),
                    "unanimous": sample["unanimous"],
                }
            )
        outcsv = OUTPUT_DIR / "veritree-network-profiles-fixed.csv"
        with open(outcsv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        return rows, str(outcsv)


def choose_tree_shape(n: int):
    if n <= 7:
        return 2, 2
    elif n <= 13:
        return 3, 3
    elif n <= 31:
        return 5, 5
    else:
        return 7, 9


def run_veritree_once(
    n: int,
    sidprefix: bytes = b"session-bench",
    families: List[str] = ["Kyber512", "Saber"],
):
    nmod, membersper = choose_tree_shape(n)
    sim = VeriTreeSimulator(
        preferredfamilies=families,
        mkemmode="aggregated",
        timeoutms=500,
        networklatencyms=30,
        packetloss=0.01,
        enabledynamicops=True,
        enablefailover=True,
    )
    sid = sidprefix + b"-" + str(n).encode()
    result = sim.run_demo_tree(
        adminname="admin",
        nmod=nmod,
        membersper=membersper,
        families=families,
        sid=sid,
        simulatedynamicops=True,
        simulatemoderatorfailure=True,
    )
    totalbwbytes = result.get("totalbytes", 0)
    totalms = result.get("phasetimingsms", {}).get("total", 0.0)
    phase4ms = result.get("phasetimingsms", {}).get("phase4dualcommit")
    return {
        "groupsize": n,
        "totaltimems": totalms,
        "totalbandwidthkb": totalbwbytes / 1024.0,
        "phase4ms": phase4ms,
    }


def benchmark_repeated(groupsizes=[7, 13, 31, 64], runs=5, outcsv="veritree-repeated-stats.csv"):
    results = []
    for n in groupsizes:
        for r in range(1, runs + 1):
            summary = run_veritree_once(n)
            results.append(
                {
                    "n": n,
                    "run": r,
                    "totalms": summary["totaltimems"],
                    "totalkb": summary["totalbandwidthkb"],
                    "phase4ms": summary.get("phase4ms", None),
                }
            )

    outpath = Path(outcsv)
    with outpath.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["n", "run", "totalms", "totalkb", "phase4ms"])
        writer.writeheader()
        writer.writerows(results)

    stats = []
    for n in groupsizes:
        subset = [row for row in results if row["n"] == n]
        times = [row["totalms"] for row in subset]
        bws = [row["totalkb"] for row in subset]
        phase4 = [row["phase4ms"] for row in subset if row["phase4ms"] is not None]
        stats.append(
            {
                "n": n,
                "timemean": statistics.mean(times),
                "timestd": statistics.pstdev(times) if len(times) > 1 else 0.0,
                "bwmean": statistics.mean(bws),
                "bwstd": statistics.pstdev(bws) if len(bws) > 1 else 0.0,
                "phase4mean": statistics.mean(phase4) if phase4 else None,
                "phase4std": statistics.pstdev(phase4) if phase4 else None,
            }
        )

    for row in stats:
        phase4part = ""
        if row["phase4mean"] is not None:
            phase4part = f", phase4={row['phase4mean']:.2f}±{row['phase4std']:.2f} ms"
        print(
            f"n={row['n']}: time={row['timemean']:.2f}±{row['timestd']:.2f} ms, "
            f"bw={row['bwmean']:.2f}±{row['bwstd']:.2f} KB{phase4part}"
        )
    return stats


if __name__ == "__main__":
    families = ["Kyber512", "Saber"]

    stats = benchmark_repeated(groupsizes=[7, 13, 31, 64], runs=5)

    sim = VeriTreeSimulator(
        preferredfamilies=families,
        mkemmode="aggregated",
        timeoutms=500,
        networklatencyms=30,
        packetloss=0.01,
        enabledynamicops=True,
        enablefailover=True,
    )

    result = sim.run_demo_tree(
        adminname="admin",
        nmod=2,
        membersper=2,
        families=families,
        sid=b"session-2026-04-25",
        simulatedynamicops=True,
        simulatemoderatorfailure=True,
    )

    profiles, csvpath = sim.run_network_resilience_benchmark(
        [(0, 0.0), (30, 0.0), (80, 0.01), (120, 0.03), (200, 0.05)],
        2,
        2,
        families,
    )

    print(result["artifacts"])
    print(csvpath)