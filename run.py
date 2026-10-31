import json
import os
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

# ==========================================
# 1. ĐỊNH NGHĨA SCHEMAS BẰNG PYDANTIC
# ==========================================
class NISTMapping(BaseModel):
    category_id: str
    description: str

class TechnicalMitigation(BaseModel):
    control_id: str
    description: str
    discount_weight: float = Field(..., ge=0.0, le=1.0)

class RiskItem(BaseModel):
    risk_id: str
    risk_name: str
    nist_mappings: List[NISTMapping]
    attack_scenario: str
    base_likelihood: int = Field(..., ge=1, le=5)
    base_impact: int = Field(..., ge=1, le=5)
    technical_mitigations: List[TechnicalMitigation]

class ComponentKnowledge(BaseModel):
    display_name: str
    aliases: List[str]
    risks: List[RiskItem]

class SeverityThreshold(BaseModel):
    min: int
    max: int
    action: str

class KBMetadata(BaseModel):
    version: str
    project: str
    standards: List[str]

class KnowledgeBaseDocument(BaseModel):
    metadata: KBMetadata
    severity_thresholds: Dict[str, SeverityThreshold]
    components: Dict[str, ComponentKnowledge]

class EvaluatedRiskResult(BaseModel):
    source_component: str
    risk_id: str
    risk_name: str
    nist_categories: List[str]
    inherent_score: int
    residual_likelihood: int
    residual_impact: int
    residual_score: int
    severity_level: str
    recommended_action: str
    missing_mitigations: List[str]

# ==========================================
# 2. BỘ QUẢN LÝ CƠ SỞ TRI THỨC (KB MANAGER)
# ==========================================
class KnowledgeBaseManager:
    def __init__(self, json_path: str):
        self.json_path = json_path
        self.kb = self._load_and_validate()
        self._alias_lookup = self._build_alias_lookup()

    def _load_and_validate(self) -> KnowledgeBaseDocument:
        with open(self.json_path, "r", encoding="utf-8") as f:
            return KnowledgeBaseDocument(**json.load(f))

    def _build_alias_lookup(self) -> Dict[str, str]:
        lookup = {}
        for canonical_key, comp_data in self.kb.components.items():
            lookup[canonical_key.lower()] = canonical_key
            for alias in comp_data.aliases:
                lookup[alias.strip().lower()] = canonical_key
        return lookup

    def classify_severity(self, score: int) -> tuple:
        for level, threshold in self.kb.severity_thresholds.items():
            if threshold.min <= score <= threshold.max:
                return level, threshold.action
        return "Unknown", "Không xác định."

    def evaluate_node(self, raw_type: str, controls: List[str], is_public: bool) -> List[EvaluatedRiskResult]:
        comp_key = self._alias_lookup.get(raw_type.strip().lower())
        if not comp_key:
            return []
        
        comp_kb = self.kb.components[comp_key]
        active_set = {c.strip().upper() for c in controls}
        results = []

        for risk in comp_kb.risks:
            L_base = risk.base_likelihood
            I_base = risk.base_impact
            
            total_discount = sum(
                m.discount_weight for m in risk.technical_mitigations 
                if m.control_id.upper() in active_set
            )
            total_discount = min(total_discount, 0.80)
            
            missing = [
                f"[{m.control_id}] {m.description}" 
                for m in risk.technical_mitigations 
                if m.control_id.upper() not in active_set
            ]

            context_L = L_base if is_public else max(1, L_base - 1)
            L_final = max(1, round(context_L * (1.0 - total_discount)))
            I_final = I_base
            residual_score = L_final * I_final
            severity_level, action = self.classify_severity(residual_score)

            results.append(EvaluatedRiskResult(
                source_component=comp_kb.display_name,
                risk_id=risk.risk_id,
                risk_name=risk.risk_name,
                nist_categories=[f"{n.category_id}" for n in risk.nist_mappings],
                inherent_score=L_base * I_base,
                residual_likelihood=L_final,
                residual_impact=I_final,
                residual_score=residual_score,
                severity_level=severity_level,
                recommended_action=action,
                missing_mitigations=missing
            ))
        return results

# ==========================================
# 3. HÀM MAIN - CHẠY DEMO
# ==========================================
def main():
    print("*" * 80)
    print(" HỆ THỐNG ĐÁNH GIÁ RỦI RO BẢO MẬT AI (OWASP LLM & NIST AI RMF) - DEMO PROJECT 1")
    print("*" * 80)
    
    # Khởi tạo Engine
    print("[+] Đang nạp Cơ sở tri thức (rule_store.json)...")
    kb_manager = KnowledgeBaseManager("rule_store.json")
    
    # Đọc cấu trúc đầu vào
    print("[+] Đang đọc cấu trúc hệ thống (input_architecture.json)...\n")
    with open("input_architecture.json", "r", encoding="utf-8") as f:
        architecture = json.load(f)

    all_results = []
    for node in architecture:
        results = kb_manager.evaluate_node(
            raw_type=node["node_type"],
            controls=node.get("controls", []),
            is_public=node.get("is_public", True)
        )
        all_results.extend(results)

    # In kết quả
    for idx, r in enumerate(all_results, 1):
        print(f"[{idx}] Node: {r.source_component}")
        print(f"    - Mối đe dọa   : {r.risk_id} - {r.risk_name}")
        print(f"    - Ánh xạ NIST  : {', '.join(r.nist_categories)}")
        print(f"    - Điểm Inherent: {r.inherent_score}/25")
        print(f"    - Điểm Residual: {r.residual_score}/25 (L={r.residual_likelihood} x I={r.residual_impact}) -> {r.severity_level.upper()}")
        print(f"    - Khuyến nghị  : {r.recommended_action}")
        if r.missing_mitigations:
            print("    ! Yêu cầu bổ sung kiểm soát:")
            for m in r.missing_mitigations:
                print(f"      + {m}")
        print("-" * 80)

    if all_results:
        max_score = max(r.residual_score for r in all_results)
        overall_level, _ = kb_manager.classify_severity(max_score)
        print(f"\n=> CHỈ SỐ RỦI RO TỔNG THỂ CỦA KIẾN TRÚC: {max_score}/25 - NGƯỠNG: {overall_level.upper()}\n")

if __name__ == '__main__':
    main()
