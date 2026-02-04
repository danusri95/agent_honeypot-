from pydantic import BaseModel
from typing import List, Optional

class Issue(BaseModel):
    code: str
    message: str

class DetectionResult(BaseModel):
    address: str
    score: int  # 0 (safe) - 100 (very risky) — simple heuristic score
    issues: List[Issue]
    details: Optional[dict] = None