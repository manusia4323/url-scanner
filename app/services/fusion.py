"""Fusion service - combines scores from all three modules."""

import logging
from typing import Dict, Any, List
from app.config import settings

logger = logging.getLogger(__name__)

# Tolerance threshold for dangerous verdict
DEFAULT_TOLERANCE = 70


def calculate_final_score(
    skor_prediksi: float,
    skor_kerentanan: float,
    skor_reputasi: float
) -> float:
    """
    Calculate final fused score using weighted average.

    Args:
        skor_prediksi: Prediction score (0-100)
        skor_kerentanan: Vulnerability score (0-100)
        skor_reputasi: Reputation score (0-100)

    Returns:
        Final fused score (0-100)
    """
    weight_p = settings.weight_prediction
    weight_v = settings.weight_vulnerability
    weight_r = settings.weight_reputation

    final_score = (
        (weight_p * skor_prediksi) +
        (weight_v * skor_kerentanan) +
        (weight_r * skor_reputasi)
    )

    return round(final_score, 2)


def determine_verdict(skor_final: float, toleransi: int = None) -> str:
    """
    Determine verdict based on final score and tolerance.

    Args:
        skor_final: Final fused score
        toleransi: Tolerance threshold (default from settings)

    Returns:
        "AMAN" or "BERBAHAYA"
    """
    if toleransi is None:
        toleransi = settings.default_tolerance

    return "BERBAHAYA" if skor_final > toleransi else "AMAN"


def generate_reasons(
    prediksi_result: Dict[str, Any],
    kerentanan_result: Dict[str, Any],
    reputasi_result: Dict[str, Any]
) -> List[str]:
    """
    Combine reasons from all scoring modules.

    Args:
        prediksi_result: Result from prediction module
        kerentanan_result: Result from vulnerability module
        reputasi_result: Result from reputation module

    Returns:
        List of combined reasons
    """
    reasons = []

    # Add prediction reasons
    if prediksi_result.get("reasons"):
        reasons.extend(prediksi_result["reasons"])

    # Add vulnerability reasons
    if kerentanan_result.get("reasons"):
        reasons.extend(kerentanan_result["reasons"])

    # Add reputation reasons
    if reputasi_result.get("reasons"):
        reasons.extend(reputasi_result["reasons"])

    # Deduplicate while preserving order
    seen = set()
    unique_reasons = []
    for reason in reasons:
        if reason not in seen:
            seen.add(reason)
            unique_reasons.append(reason)

    return unique_reasons


def fuse_results(
    prediksi_result: Dict[str, Any],
    kerentanan_result: Dict[str, Any],
    reputasi_result: Dict[str, Any],
    toleransi: int = None
) -> Dict[str, Any]:
    """
    Fuse results from all three scoring modules into final verdict.

    Args:
        prediksi_result: Result from prediction module
        kerentanan_result: Result from vulnerability module
        reputasi_result: Result from reputation module
        toleransi: Tolerance threshold

    Returns:
        Dictionary with fused results
    """
    skor_prediksi = prediksi_result.get("score", 0)
    skor_kerentanan = kerentanan_result.get("score", 0)
    skor_reputasi = reputasi_result.get("score", 0)

    # Calculate final score
    skor_final = calculate_final_score(skor_prediksi, skor_kerentanan, skor_reputasi)

    # Determine verdict
    keputusan = determine_verdict(skor_final, toleransi)

    # Generate combined reasons
    alasan = generate_reasons(prediksi_result, kerentanan_result, reputasi_result)

    return {
        "skor_prediksi": skor_prediksi,
        "skor_kerentanan": skor_kerentanan,
        "skor_reputasi": skor_reputasi,
        "skor_final": skor_final,
        "keputusan": keputusan,
        "alasan": alasan,
    }