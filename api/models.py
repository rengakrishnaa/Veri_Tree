from pydantic import BaseModel
from typing import List

class TreeRequest(BaseModel):
    admin_name: str
    moderators: List[str]
    members: List[dict]  # [{"moderator": "mod1", "name": "member1"}]

class TreeResponse(BaseModel):
    tree_id: str
    group_key: str  # Hex only!
    global_sid: str
    bandwidth_bytes: int
    unanimous: bool
