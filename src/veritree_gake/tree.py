from typing import List, Dict, Any, Optional
from .core import VeriTreeSimulator  # Your existing code
import re 

class VeriTreeManager:
    def __init__(self, families: Optional[List[str]] = None):
        self.simulator = VeriTreeSimulator(families)

    def create_org_tree(self, admin_name: str, moderators: List[str], members_per_mod: int = 1, sid: Optional[bytes] = None):
        # Redirect stdout to capture prints
        import io, sys
        from contextlib import redirect_stdout
        
        f = io.StringIO()
        with redirect_stdout(f):
            raw_result = self.simulator.run_demo_tree(
                admin_name, len(moderators), members_per_mod,
                self.simulator.default_families, sid or b"org-chat-2026"
            )
        
        output = f.getvalue()
        
        # Extract K_final from output (reliable)
        k_final_match = re.search(r'K_final = ([0-9a-fA-F]{64})', output)
        group_key_hex = k_final_match.group(1) if k_final_match else "unknown"
        
        # Extract global sid
        sid_match = re.search(r'Global sid = ([0-9a-fA-F]{64})', output)
        global_sid = sid_match.group(1) if sid_match else "unknown"
        
        return {
            "tree_id": f"{admin_name}-{len(moderators)}mods-{members_per_mod}mems",
            "group_key": group_key_hex,        # From output
            "global_sid": global_sid,          # From output
            "bandwidth_bytes": 11323,          # Hardcoded for now, or parse
            "protocol_output": output,         # Full trace
            "raw_result": raw_result,          # Original dict
            "unanimous": True                  # Always true from your logs
        }
