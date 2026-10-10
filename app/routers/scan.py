"""Router for URL scanning endpoints."""

import asyncio
import logging
from typing import List
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.schemas import ScanRequest, ScanResponse, SkorResponse
from app.models import ScanVerdict
from app.services.prediction import score_prediction
from app.services.vulnerability import score_vulnerability
from app.services.reputation import score_reputation
from app.services.fusion import fuse_results
from app.utils.url_parser import (
    normalize_url,
    extract_domain,
    is_localhost,
    is_private_ip,
    get_url_hash,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scan", tags=["scan"])

# Semaphore for concurrent scans
_concurrent_scan_semaphore = None


def get_semaphore() -> asyncio.Semaphore:
    """Get or create the concurrent scan semaphore."""
    global _concurrent_scan_semaphore
    if _concurrent_scan_semaphore is None:
        _concurrent_scan_semaphore = asyncio.Semaphore(settings.max_concurrent_scans)
    return _concurrent_scan_semaphore


@router.post("", response_model=ScanResponse)
async def scan_url(
    request: ScanRequest,
    db: Session = Depends(get_db)
):
    """
    Scan a URL for security threats.

    Runs three scoring modules concurrently and fuses results.
    """
    # Normalize and validate URL
    url = normalize_url(request.url)
    domain = extract_domain(url)

    if not domain:
        raise HTTPException(
            status_code=400,
            detail={"detail": "Invalid URL format", "code": "INVALID_URL"}
        )

    # Check for localhost/private IPs (SSRF protection)
    if is_localhost(url) or (domain and is_private_ip(domain)):
        raise HTTPException(
            status_code=400,
            detail={"detail": "URL points to internal/private network", "code": "PRIVATE_NETWORK"}
        )

    # Limit concurrent scans
    semaphore = get_semaphore()
    async with semaphore:
        try:
            # Run all three scoring modules concurrently
            prediksi_task = score_prediction(url)
            kerentanan_task = score_vulnerability(url)
            reputasi_task = score_reputation(url, db)

            prediksi_result, kerentanan_result, reputasi_result = await asyncio.gather(
                prediksi_task,
                kerentanan_task,
                reputasi_task
            )

            # Fuse results
            fusion_result = fuse_results(
                prediksi_result,
                kerentanan_result,
                reputasi_result
            )

            # Save to database
            url_hash = get_url_hash(url)
            verdict = ScanVerdict(
                url=url,
                url_hash=url_hash,
                skor_prediksi=fusion_result["skor_prediksi"],
                skor_kerentanan=fusion_result["skor_kerentanan"],
                skor_reputasi=fusion_result["skor_reputasi"],
                skor_final=fusion_result["skor_final"],
                keputusan=fusion_result["keputusan"],
            )
            db.add(verdict)
            db.commit()
            db.refresh(verdict)

            # Build response
            response = ScanResponse(
                url=url,
                url_hash=url_hash,
                skor=SkorResponse(
                    prediksi=fusion_result["skor_prediksi"],
                    kerentanan=fusion_result["skor_kerentanan"],
                    reputasi=fusion_result["skor_reputasi"],
                    final=fusion_result["skor_final"],
                ),
                keputusan=fusion_result["keputusan"],
                toleransi=settings.default_tolerance,
                alasan=fusion_result["alasan"],
                waktu=verdict.waktu,
            )

            return response

        except Exception as e:
            logger.error(f"Scan error: {e}")
            db.rollback()
            raise HTTPException(
                status_code=500,
                detail={"detail": f"Scan failed: {str(e)}", "code": "SCAN_ERROR"}
            )


@router.get("/health")
async def health_check(db: Session = Depends(get_db)):
    """Health check endpoint."""
    from sqlalchemy import text

    db_status = "ok"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        db_status = "error"

    return {
        "status": "ok" if db_status == "ok" else "degraded",
        "db": db_status
    }