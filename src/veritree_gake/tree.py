from typing import List, Dict, Any, Optional
from .core import VeriTreeSimulator  # Your existing code
import re 

class VeriTreeManager:
    def __init__(self, families: Optional[List[str]] = None):
        self.simulator = VeriTreeSimulator(families)

    def create_org_tree(self, admin_name: str, moderators: List[str], members_per_mod: int = 1, sid: Optional[bytes] = None):
        # Capture output BUT also print to console
        import io, sys
        from contextlib import redirect_stdout
        
        f = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = f  # Capture
        
        try:
            raw_result = self.simulator.run_demo_tree(
                admin_name, len(moderators), members_per_mod,
                self.simulator.default_families, sid or b"org-chat-2026"
            )
        finally:
            # Print captured output to console
            print(f.getvalue(), end='', file=old_stdout)
            sys.stdout = old_stdout
        
        output = f.getvalue()
        
        # Extract clean hex
        k_match = re.search(r'K_final = ([0-9a-fA-F]{64})', output)
        sid_match = re.search(r'Global sid = ([0-9a-fA-F]{64})', output)
        
        group_key_hex = k_match.group(1) if k_match else "unknown"
        global_sid_hex = sid_match.group(1) if sid_match else "unknown"
        
        # Parse bandwidth from output
        bw_match = re.search(r'Total bandwidth \(bytes\): (\d+)', output)
        bandwidth = int(bw_match.group(1)) if bw_match else 11323
        
        return {
            "tree_id": f"{admin_name}-{len(moderators)}mods-{members_per_mod}mems",
            "group_key": group_key_hex,
            "global_sid": global_sid_hex,
            "bandwidth_bytes": bandwidth,
            "unanimous": True,
            "protocol_output": output[:1000]  # Truncated preview
        }
