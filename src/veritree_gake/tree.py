from typing import Any, Dict, List, Optional

from .core import VeriTreeSimulator


class VeriTreeManager:
    def __init__(self, families: Optional[List[str]] = None, mkem_mode: str = "aggregated"):
        self.simulator = VeriTreeSimulator(
            preferredfamilies=families or ["Kyber512", "Saber"],
            mkemmode=mkem_mode,
        )

    def create_org_tree(
        self,
        admin_name: str,
        moderators: List[str],
        members_per_mod: int = 1,
        sid: Optional[bytes] = None,
        simulate_dynamic_ops: bool = True,
        simulate_moderator_failure: bool = True,
    ) -> Dict[str, Any]:
        raw_result = self.simulator.run_demo_tree(
            admin_name=admin_name,
            n_mod=len(moderators),
            members_per=members_per_mod,
            families=self.simulator.default_families,
            sid=sid or b"org-chat-2026",
            simulate_dynamic_ops=simulate_dynamic_ops,
            simulate_moderator_failure=simulate_moderator_failure,
        )
        return {
            "tree_id": f"{admin_name}-{len(moderators)}mods-{members_per_mod}mems",
            "group_key": raw_result["SK_hex"],
            "global_sid": raw_result["global_sid"],
            "bandwidth_bytes": raw_result["total_bytes"],
            "theoretical_bandwidth_bytes": raw_result["theoretical_total_bytes"],
            "unanimous": raw_result["unanimous"],
            "active_nodes": raw_result["active_nodes"],
            "excluded_nodes": raw_result["excluded_nodes"],
            "fault_events": raw_result["fault_events"],
            "phase_timings_ms": raw_result["phase_timings_ms"],
            "artifacts": raw_result.get("artifacts", {}),
            "raw_result": raw_result,
        }
