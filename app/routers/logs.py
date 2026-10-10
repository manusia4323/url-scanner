"""Router for scan logs endpoints."""

import logging
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.database import get_db
from app.models import ScanVerdict
from app.schemas import LogsResponse, LogItem, ErrorResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/logs", tags=["logs"])


@router.get("", response_model=LogsResponse)
def list_logs(
    page: int = Query(default=1, ge=1, description="Page number"),
    size: int = Query(default=20, ge=1, le=100, description="Items per page"),
    keputusan: Optional[str] = Query(default=None, description="Filter by verdict (AMAN|BERBAHAYA)"),
    since: Optional[datetime] = Query(default=None, description="Filter by time (ISO format)"),
    db: Session = Depends(get_db)
):
    """
    List scan verdict logs with pagination and filtering.
    """
    query = db.query(ScanVerdict)

    # Apply verdict filter
    if keputusan:
        if keputusan not in ("AMAN", "BERBAHAYA"):
            raise HTTPException(
                status_code=400,
                detail={"detail": "keputusan must be AMAN or BERBAHAYA", "code": "INVALID_FILTER"}
            )
        query = query.filter(ScanVerdict.keputusan == keputusan)

    # Apply time filter
    if since:
        query = query.filter(ScanVerdict.waktu >= since)

    # Get total count
    total = query.count()

    # Apply pagination
    offset = (page - 1) * size
    items = query.order_by(ScanVerdict.waktu.desc()).offset(offset).limit(size).all()

    return LogsResponse(
        total=total,
        page=page,
        size=size,
        items=[
            LogItem(
                id=item.id,
                url=item.url,
                url_hash=item.url_hash,
                skor_prediksi=item.skor_prediksi,
                skor_kerentanan=item.skor_kerentanan,
                skor_reputasi=item.skor_reputasi,
                skor_final=item.skor_final,
                keputusan=item.keputusan,
                waktu=item.waktu,
            )
            for item in items
        ]
    )


@router.get("/stats")
def get_scan_stats(
    since: Optional[datetime] = Query(default=None, description="Filter by time (ISO format)"),
    db: Session = Depends(get_db)
):
    """
    Get scan statistics summary.
    """
    query = db.query(ScanVerdict)

    if since:
        query = query.filter(ScanVerdict.waktu >= since)

    total = query.count()
    aman = query.filter(ScanVerdict.keputusan == "AMAN").count()
    berbahaya = query.filter(ScanVerdict.keputusan == "BERBAHAYA").count()

    # Get average scores
    avg_result = query.with_entities(
        func.avg(ScanVerdict.skor_final).label("avg_final"),
        func.avg(ScanVerdict.skor_prediksi).label("avg_prediksi"),
        func.avg(ScanVerdict.skor_kerentanan).label("avg_kerentanan"),
        func.avg(ScanVerdict.skor_reputasi).label("avg_reputasi"),
    ).first()

    return {
        "total_scans": total,
        "aman_count": aman,
        "berbahaya_count": berbahaya,
        "danger_rate": round((berbahaya / total * 100) if total > 0 else 0, 2),
        "average_scores": {
            "final": round(avg_result.avg_final or 0, 2),
            "prediksi": round(avg_result.avg_prediksi or 0, 2),
            "kerentanan": round(avg_result.avg_kerentanan or 0, 2),
            "reputasi": round(avg_result.avg_reputasi or 0, 2),
        }
    }


@router.get("/{log_id}", response_model=LogItem, responses={404: {"model": ErrorResponse}})
def get_log(log_id: int, db: Session = Depends(get_db)):
    """
    Get a specific scan log entry by ID.
    """
    item = db.query(ScanVerdict).filter(ScanVerdict.id == log_id).first()
    if not item:
        raise HTTPException(
            status_code=404,
            detail={"detail": "Log entry not found", "code": "NOT_FOUND"}
        )

    return LogItem(
        id=item.id,
        url=item.url,
        url_hash=item.url_hash,
        skor_prediksi=item.skor_prediksi,
        skor_kerentanan=item.skor_kerentanan,
        skor_reputasi=item.skor_reputasi,
        skor_final=item.skor_final,
        keputusan=item.keputusan,
        waktu=item.waktu,
    )


@router.delete("/{log_id}", status_code=204, responses={404: {"model": ErrorResponse}})
def delete_log(log_id: int, db: Session = Depends(get_db)):
    """
    Delete a scan log entry.
    """
    item = db.query(ScanVerdict).filter(ScanVerdict.id == log_id).first()
    if not item:
        raise HTTPException(
            status_code=404,
            detail={"detail": "Log entry not found", "code": "NOT_FOUND"}
        )

    db.delete(item)
    db.commit()

    logger.info(f"Deleted log entry {log_id}")

    return None


@router.delete("/clear")
def clear_all_logs(
    before: Optional[datetime] = Query(default=None, description="Delete logs before this date"),
    db: Session = Depends(get_db)
):
    """
    Clear scan logs. If 'before' is specified, only delete logs older than that date.
    """
    query = db.query(ScanVerdict)

    if before:
        query = query.filter(ScanVerdict.waktu < before)

    count = query.count()
    query.delete()
    db.commit()

    logger.info(f"Cleared {count} log entries")

    return {"deleted": count}