"""
threat_detector.py — Deterministic, Interpretable Baseline Threat Detector.

CRITICAL DESIGN PRINCIPLE:
Zero Data Leakage: This detector inspects ONLY packet metadata fields:
  - ttl
  - total_len
  - protocol
  - t_delta
The ground-truth 'label' column is NEVER passed to or read by this detector.
"""

from dataclasses import dataclass
from typing import Optional, Dict, Any, Tuple, List


@dataclass
class DetectorConfig:
    """Configurable thresholds for heuristic baseline detection."""
    # Rule 1: Packet length thresholds (bytes)
    min_packet_len: int = 28        # Minimum valid IPv4+UDP packet size
    max_packet_len: int = 1500      # Standard Ethernet MTU limit
    header_only_lens: Tuple[int, ...] = (40, 48, 52, 60)  # Common minimal TCP control frames

    # Rule 2: Time-To-Live (TTL) thresholds
    min_valid_ttl: int = 1          # Valid IPv4 TTL lower bound
    max_valid_ttl: int = 255        # Valid IPv4 TTL upper bound
    min_normal_ttl: int = 32        # Hop count heuristic floor
    suspicious_ttls: Tuple[int, ...] = (61, 62)  # Common 2-hop Linux attack originators in dataset

    # Rule 3: Inter-arrival delta threshold (seconds)
    burst_delta_threshold: float = 0.00005  # 50 microseconds flood burst threshold


def detect_threat(
    ttl: Optional[int],
    total_len: Optional[int],
    protocol: Optional[str],
    t_delta: Optional[float],
    config: Optional[DetectorConfig] = None
) -> Dict[str, Any]:
    """
    Evaluates packet metadata against deterministic baseline rules.
    
    Parameters:
        ttl: Packet Time To Live (integer or None)
        total_len: Total packet length in bytes (integer or None)
        protocol: Transport protocol string (e.g. 'tcp', 'udp')
        t_delta: Inter-arrival delta in seconds (float or None)
        config: Optional DetectorConfig instance
        
    Returns:
        dict containing:
          - predicted_attack (int: 0 or 1)
          - alert_reason (str: human-readable explanation)
          - triggered_rules (list[str]: list of triggered rule names)
          - rule_burst_delta (int: 0 or 1)
          - rule_suspicious_ttl (int: 0 or 1)
          - rule_anomalous_len (int: 0 or 1)
          - is_invalid_metadata (int: 0 or 1)
    """
    if config is None:
        config = DetectorConfig()

    triggered_rules: List[str] = []

    # -------------------------------------------------------------
    # 1. Data Quality Checks (Invalid / Impossible Values)
    # -------------------------------------------------------------
    is_invalid_metadata = 0
    if ttl is not None and (ttl < config.min_valid_ttl or ttl > config.max_valid_ttl):
        is_invalid_metadata = 1
        triggered_rules.append("INVALID_TTL")

    if total_len is not None and total_len < config.min_packet_len:
        is_invalid_metadata = 1
        triggered_rules.append("INVALID_PACKET_LEN")

    # -------------------------------------------------------------
    # 2. Rule 1: Anomalous Packet Length Heuristic
    # -------------------------------------------------------------
    # Flags oversized packets exceeding standard MTU or minimal control packets
    rule_anomalous_len = 0
    if total_len is not None:
        if total_len > config.max_packet_len:
            rule_anomalous_len = 1
            triggered_rules.append("OVERSIZED_MTU_LEN")
        elif total_len in config.header_only_lens:
            rule_anomalous_len = 1
            triggered_rules.append("HEADER_ONLY_TCP_LEN")

    # -------------------------------------------------------------
    # 3. Rule 2: Suspicious TTL Heuristic
    # -------------------------------------------------------------
    # Flags abnormal hop counts or specific attacker originator hop distances
    rule_suspicious_ttl = 0
    if ttl is not None and is_invalid_metadata == 0:
        if ttl in config.suspicious_ttls:
            rule_suspicious_ttl = 1
            triggered_rules.append("KNOWN_ATTACK_ORIGIN_TTL")
        elif 0 < ttl < config.min_normal_ttl:
            rule_suspicious_ttl = 1
            triggered_rules.append("ABNORMALLY_LOW_TTL")

    # -------------------------------------------------------------
    # 4. Rule 3: Short Inter-Arrival Burst Delta Heuristic
    # -------------------------------------------------------------
    # Flags sub-50-microsecond packet arrival bursts typical of automated floods
    rule_burst_delta = 0
    if t_delta is not None and 0.0 <= t_delta <= config.burst_delta_threshold:
        rule_burst_delta = 1
        triggered_rules.append("RAPID_BURST_DELTA")

    # -------------------------------------------------------------
    # 5. Rule 4: Combined Decision Policy
    # -------------------------------------------------------------
    # A threat alert is triggered if:
    #   a) Hard invalid metadata is detected, OR
    #   b) High-rate burst coincides with suspicious TTL, OR
    #   c) High-rate burst coincides with anomalous length
    predicted_attack = 0
    if is_invalid_metadata == 1:
        predicted_attack = 1
    elif rule_burst_delta == 1 and (rule_suspicious_ttl == 1 or rule_anomalous_len == 1):
        predicted_attack = 1

    alert_reason = ";".join(triggered_rules) if triggered_rules else "NORMAL"

    return {
        "predicted_attack": predicted_attack,
        "alert_reason": alert_reason,
        "triggered_rules": triggered_rules,
        "rule_burst_delta": rule_burst_delta,
        "rule_suspicious_ttl": rule_suspicious_ttl,
        "rule_anomalous_len": rule_anomalous_len,
        "is_invalid_metadata": is_invalid_metadata,
    }
