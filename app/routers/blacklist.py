"""Router for blacklist management endpoints."""

import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models import UrlBlacklist
from app.schemas import BlacklistCreate, BlacklistResponse, BlacklistItem, ErrorResponse
from app.utils.url_parser import normalize_url, extract_domain, get_url_hash

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/blacklist", tags=["blacklist"])


@router.get("", response_model=BlacklistResponse)
def list_blacklist(
    page: int = Query(default=1, ge=1, description="Page number"),
    size: int = Query(default=20, ge=1, le=100, description="Items per page"),
    domain: Optional[str] = Query(default=None, description="Filter by domain"),
    db: Session = Depends(get_db)
):
    """
    List all blacklisted URLs with pagination and filtering.
    """
    query = db.query(UrlBlacklist)

    # Apply domain filter if provided
    if domain:
        query = query.filter(UrlBlacklist.domain.ilike(f"%{domain}%"))

    # Get total count
    total = query.count()

    # Apply pagination
    offset = (page - 1) * size
    items = query.order_by(UrlBlacklist.created_at.desc()).offset(offset).limit(size).all()

    return BlacklistResponse(
        total=total,
        page=page,
        size=size,
        items=[
            BlacklistItem(
                id=item.id,
                url_hash=item.url_hash,
                url=item.url,
                domain=item.domain,
                risiko=item.risiko,
                toleransi=item.toleransi,
                sumber=item.sumber,
                created_at=item.created_at,
            )
            for item in items
        ]
    )


@router.get("/{item_id}", response_model=BlacklistItem, responses={404: {"model": ErrorResponse}})
def get_blacklist_item(item_id: int, db: Session = Depends(get_db)):
    """
    Get a specific blacklist entry by ID.
    """
    item = db.query(UrlBlacklist).filter(UrlBlacklist.id == item_id).first()
    if not item:
        raise HTTPException(
            status_code=404,
            detail={"detail": "Blacklist item not found", "code": "NOT_FOUND"}
        )

    return BlacklistItem(
        id=item.id,
        url_hash=item.url_hash,
        url=item.url,
        domain=item.domain,
        risiko=item.risiko,
        toleransi=item.toleransi,
        sumber=item.sumber,
        created_at=item.created_at,
    )


@router.post("", response_model=BlacklistItem, status_code=201, responses={409: {"model": ErrorResponse}})
def add_to_blacklist(item: BlacklistCreate, db: Session = Depends(get_db)):
    """
    Add a URL to the blacklist.
    """
    # Normalize URL
    url = normalize_url(item.url)
    domain = extract_domain(url)

    if not domain:
        raise HTTPException(
            status_code=400,
            detail={"detail": "Invalid URL format", "code": "INVALID_URL"}
        )

    # Generate hash
    url_hash = get_url_hash(url)

    # Check for duplicate
    existing = db.query(UrlBlacklist).filter(UrlBlacklist.url_hash == url_hash).first()
    if existing:
        raise HTTPException(
            status_code=409,
            detail={"detail": "URL already exists in blacklist", "code": "DUPLICATE"}
        )

    # Create new entry
    blacklist_item = UrlBlacklist(
        url_hash=url_hash,
        url=url,
        domain=domain,
        risiko=item.risiko,
        toleransi=item.toleransi,
        sumber=item.sumber,
    )

    db.add(blacklist_item)
    db.commit()
    db.refresh(blacklist_item)

    logger.info(f"Added {url} to blacklist (risiko={item.risiko})")

    return BlacklistItem(
        id=blacklist_item.id,
        url_hash=blacklist_item.url_hash,
        url=blacklist_item.url,
        domain=blacklist_item.domain,
        risiko=blacklist_item.risiko,
        toleransi=blacklist_item.toleransi,
        sumber=blacklist_item.sumber,
        created_at=blacklist_item.created_at,
    )


@router.delete("/{item_id}", status_code=204, responses={404: {"model": ErrorResponse}})
def remove_from_blacklist(item_id: int, db: Session = Depends(get_db)):
    """
    Remove a URL from the blacklist.
    """
    item = db.query(UrlBlacklist).filter(UrlBlacklist.id == item_id).first()
    if not item:
        raise HTTPException(
            status_code=404,
            detail={"detail": "Blacklist item not found", "code": "NOT_FOUND"}
        )

    db.delete(item)
    db.commit()

    logger.info(f"Removed item {item_id} from blacklist")

    return None


@router.get("/check/{url:path}")
def check_url_in_blacklist(url: str, db: Session = Depends(get_db)):
    """
    Check if a URL is in the blacklist.
    """
    normalized_url = normalize_url(url)
    url_hash = get_url_hash(normalized_url)

    item = db.query(UrlBlacklist).filter(UrlBlacklist.url_hash == url_hash).first()

    if item:
        return {
            "found": True,
            "risiko": item.risiko,
            "toleransi": item.toleransi,
            "sumber": item.sumber,
        }

    return {"found": False}