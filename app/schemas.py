"""Pydantic schemas for request/response validation."""

from pydantic import BaseModel, HttpUrl, Field, field_validator
from typing import Optional, List
from datetime import datetime


class ScanRequest(BaseModel):
    """Request body for URL scanning."""

    url: str = Field(..., min_length=1, max_length=2048, description="URL to scan")

    @field_validator("url")
    @classmethod
    def validate_url_format(cls, v: str) -> str:
        """Validate URL format and scheme."""
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


class SkorResponse(BaseModel):
    """Response structure for individual scores."""

    prediksi: float = Field(..., description="Prediction score (0-100)")
    kerentanan: float = Field(..., description="Vulnerability score (0-100)")
    reputasi: float = Field(..., description="Reputation score (0-100)")
    final: float = Field(..., description="Final fused score (0-100)")


class ScanResponse(BaseModel):
    """Response body for successful scan."""

    url: str
    url_hash: str
    skor: SkorResponse
    keputusan: str = Field(..., description="AMAN or BERBAHAYA")
    toleransi: int
    alasan: List[str] = Field(default_factory=list)
    waktu: datetime


class BlacklistItem(BaseModel):
    """Single blacklist entry."""

    id: int
    url_hash: str
    url: str
    domain: str
    risiko: str
    toleransi: int
    sumber: str
    created_at: datetime

    model_config = {"from_attributes": True}


class BlacklistCreate(BaseModel):
    """Request body for adding to blacklist."""

    url: str = Field(..., min_length=1, max_length=2048)
    risiko: str = Field(..., pattern="^(low|medium|high)$")
    toleransi: int = Field(default=70, ge=0, le=100)
    sumber: str = Field(default="manual", pattern="^(manual|gsb|virustotal|urlhaus)$")


class BlacklistResponse(BaseModel):
    """Response for blacklist list endpoint."""

    total: int
    page: int
    size: int
    items: List[BlacklistItem]


class LogItem(BaseModel):
    """Single scan log entry."""

    id: int
    url: str
    url_hash: str
    skor_prediksi: float
    skor_kerentanan: float
    skor_reputasi: float
    skor_final: float
    keputusan: str
    waktu: datetime

    model_config = {"from_attributes": True}


class LogsResponse(BaseModel):
    """Response for logs list endpoint."""

    total: int
    page: int
    size: int
    items: List[LogItem]


class HealthResponse(BaseModel):
    """Response for health check endpoint."""

    status: str
    db: str


class ErrorResponse(BaseModel):
    """Standard error response."""

    detail: str
    code: Optional[str] = None