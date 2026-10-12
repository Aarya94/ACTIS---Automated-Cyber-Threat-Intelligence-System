"""
ACTIS Hierarchical Explainability Tree Subsystem
Automated Cyber Threat Intelligence System — Milestone Day 22

Provides a structured, deterministic, bounded tree representation of detection
decisions. Traces raw input characteristics, static analysis metrics, heuristic rules,
ML predictions, and threat intelligence provenance directly to intermediate layer scores,
dynamic weight renormalizations, mutual confirmation adjustments, and the final risk score.
"""

import math
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


# Safety bounds
MAX_TREE_DEPTH = 5
MAX_TOTAL_NODES = 100
MAX_SNIPPET_LENGTH = 256

# Sensitive string redaction pattern
SECRET_PATTERN = re.compile(
    r'(?:api[_-]?key|secret|token|password|bearer|auth)[\s:=]+([a-zA-Z0-9_\-\.]{8,})',
    re.IGNORECASE
)


def mask_sensitive_value(value: Any) -> Any:
    """Recursively masks sensitive tokens and credentials from string values."""
    if isinstance(value, str):
        if len(value) > MAX_SNIPPET_LENGTH:
            value = value[:MAX_SNIPPET_LENGTH] + "... [truncated]"

        def _repl(m):
            secret = m.group(1)
            masked = f"{secret[:2]}****{secret[-2:]}" if len(secret) > 4 else "****"
            return m.group(0).replace(secret, masked)

        return SECRET_PATTERN.sub(_repl, value)
    elif isinstance(value, dict):
        return {k: mask_sensitive_value(v) for k, v in value.items()}
    elif isinstance(value, (list, tuple)):
        return [mask_sensitive_value(v) for v in value]
    return value


class NodeCategory(str, Enum):
    """Functional category of an explainability tree node."""
    ROOT = "ROOT"
    INPUT_ANALYSIS = "INPUT_ANALYSIS"
    STATIC_ANALYSIS = "STATIC_ANALYSIS"
    RULE_ENGINE = "RULE_ENGINE"
    MACHINE_LEARNING = "MACHINE_LEARNING"
    THREAT_INTELLIGENCE = "THREAT_INTELLIGENCE"
    EVIDENCE_AGGREGATION = "EVIDENCE_AGGREGATION"
    RISK_CALCULATION = "RISK_CALCULATION"
    FINAL_DECISION = "FINAL_DECISION"
    FINDING = "FINDING"
    METRIC = "METRIC"
    LIMITATION = "LIMITATION"


class NodeStatus(str, Enum):
    """Observational evaluation status of an explanation node."""
    EVALUATED = "EVALUATED"
    NO_FINDINGS = "NO_FINDINGS"
    NOT_EVALUATED = "NOT_EVALUATED"
    UNAVAILABLE = "UNAVAILABLE"
    TIMED_OUT = "TIMED_OUT"
    CONFIRMED_THREAT = "CONFIRMED_THREAT"
    SUSPICIOUS = "SUSPICIOUS"
    BENIGN = "BENIGN"
    MUTUAL_CONFIRMATION = "MUTUAL_CONFIRMATION"
    MITIGATED = "MITIGATED"
    OVERRIDDEN = "OVERRIDDEN"


@dataclass
class ExplainabilityNode:
    """
    Individual structured node within the hierarchical explainability tree.
    Represents an input property, analytical finding, layer evaluation, or calculation step.
    """
    node_id: str
    category: NodeCategory
    title: str
    description: str
    status: NodeStatus
    score_contribution: float = 0.0
    weight: float = 0.0
    source: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    children: List["ExplainabilityNode"] = field(default_factory=list)

    def add_child(self, child: "ExplainabilityNode", current_total_nodes: int = 0) -> bool:
        """Appends a child node while enforcing maximum node count bounds."""
        if current_total_nodes >= MAX_TOTAL_NODES:
            return False
        self.children.append(child)
        return True

    def count_nodes(self) -> int:
        """Computes the total number of nodes in this subtree."""
        total = 1
        for child in self.children:
            total += child.count_nodes()
        return total

    def max_depth(self) -> int:
        """Computes the maximum depth of this subtree."""
        if not self.children:
            return 1
        return 1 + max(child.max_depth() for child in self.children)

    def find_nodes_by_category(self, category: NodeCategory) -> List["ExplainabilityNode"]:
        """Recursively discovers all nodes matching the given category."""
        matched = []
        if self.category == category:
            matched.append(self)
        for child in self.children:
            matched.extend(child.find_nodes_by_category(category))
        return matched

    def find_node(self, node_id: str) -> Optional["ExplainabilityNode"]:
        """Locates a specific node by its stable identifier."""
        if self.node_id == node_id:
            return self
        for child in self.children:
            found = child.find_node(node_id)
            if found:
                return found
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the node and its children to a clean JSON-compatible dictionary."""
        return {
            "node_id": self.node_id,
            "category": self.category.value if isinstance(self.category, NodeCategory) else str(self.category),
            "title": self.title,
            "description": mask_sensitive_value(self.description),
            "status": self.status.value if isinstance(self.status, NodeStatus) else str(self.status),
            "score_contribution": round(float(self.score_contribution), 2),
            "weight": round(float(self.weight), 4),
            "source": self.source,
            "metadata": mask_sensitive_value(self.metadata),
            "children": [child.to_dict() for child in self.children]
        }


@dataclass
class ScoreTraceability:
    """
    Mathematical provenance detailing the exact computation from individual layers to final score.
    Eliminates discrepancies between explained contributions and authoritative risk scoring.
    """
    active_layers: List[str]
    configured_weights: Dict[str, float]
    normalized_weights: Dict[str, float]
    layer_scores: Dict[str, float]
    layer_contributions: Dict[str, float]
    weighted_sum: float
    mutual_confirmation_boost: bool
    boost_multiplier: float
    mitigation_adjustment: float
    raw_composite: float
    final_score: float
    is_override: bool
    override_reason: Optional[str] = None
    pre_override_score: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "active_layers": list(self.active_layers),
            "configured_weights": {k: round(v, 4) for k, v in self.configured_weights.items()},
            "normalized_weights": {k: round(v, 4) for k, v in self.normalized_weights.items()},
            "layer_scores": {k: round(v, 2) for k, v in self.layer_scores.items()},
            "layer_contributions": {k: round(v, 2) for k, v in self.layer_contributions.items()},
            "weighted_sum": round(self.weighted_sum, 2),
            "mutual_confirmation_boost": self.mutual_confirmation_boost,
            "boost_multiplier": round(self.boost_multiplier, 2),
            "mitigation_adjustment": round(self.mitigation_adjustment, 2),
            "raw_composite": round(self.raw_composite, 2),
            "final_score": round(self.final_score, 2),
            "is_override": self.is_override,
            "override_reason": self.override_reason
        }
        if self.pre_override_score is not None:
            d["pre_override_score"] = round(self.pre_override_score, 2)
        return d


@dataclass
class ExplainabilityTree:
    """
    Authoritative hierarchical explainability model for a detection decision.
    Binds the root node, mathematical traceability, and human-readable formatting.
    """
    target_identifier: str
    input_type: str
    final_score: float
    risk_level: str
    detection_status: str
    confidence: float
    root: ExplainabilityNode
    traceability: ScoreTraceability
    summary_reasons: List[str] = field(default_factory=list)

    @property
    def total_nodes(self) -> int:
        return self.root.count_nodes()

    @property
    def tree_depth(self) -> int:
        return self.root.max_depth()

    def find_node(self, node_id: str) -> Optional[ExplainabilityNode]:
        return self.root.find_node(node_id)

    def find_nodes_by_category(self, category: NodeCategory) -> List[ExplainabilityNode]:
        return self.root.find_nodes_by_category(category)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the complete tree and audit trail."""
        return {
            "target_identifier": self.target_identifier,
            "input_type": self.input_type,
            "final_score": round(self.final_score, 2),
            "risk_level": self.risk_level,
            "detection_status": self.detection_status,
            "confidence": round(self.confidence, 4),
            "total_nodes": self.total_nodes,
            "tree_depth": self.tree_depth,
            "summary_reasons": list(self.summary_reasons),
            "traceability": self.traceability.to_dict(),
            "root": self.root.to_dict()
        }

    def render_ascii(self) -> str:
        """Renders the hierarchical tree into a human-readable ASCII / Unicode tree format."""
        lines = [
            f"ACTIS Explainability Tree [{self.risk_level} / Score: {self.final_score:.1f} / Conf: {self.confidence:.2f}]",
            f"Target: {self.target_identifier} ({self.input_type})",
            "─" * 70
        ]

        def _render_node(node: ExplainabilityNode, prefix: str = "", is_last: bool = True):
            connector = "└── " if is_last else "├── "
            status_tag = f"[{node.status.value}]"
            score_tag = f" (Score Contrib: +{node.score_contribution:.1f})" if node.score_contribution > 0 else ""
            lines.append(f"{prefix}{connector}{node.title} {status_tag}{score_tag}")

            desc_prefix = prefix + ("    " if is_last else "│   ")
            if node.description:
                # Wrap long descriptions
                lines.append(f"{desc_prefix}: {node.description}")

            child_prefix = prefix + ("    " if is_last else "│   ")
            for idx, child in enumerate(node.children):
                child_is_last = (idx == len(node.children) - 1)
                _render_node(child, child_prefix, child_is_last)

        _render_node(self.root)
        lines.append("─" * 70)
        lines.append(
            f"Traceability: Active Layers: {', '.join(self.traceability.active_layers) or 'None'} | "
            f"Raw: {self.traceability.raw_composite:.1f} -> Final: {self.traceability.final_score:.1f}"
        )
        return "\n".join(lines)
