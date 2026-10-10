"""SQLAlchemy database models."""

from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Index
from sqlalchemy.sql import func
from app.database import Base


class UrlBlacklist(Base):
    """Model for blacklisted URLs."""

    __tablename__ = "url_blacklist"

    id = Column(Integer, primary_key=True, autoincrement=True)
    url_hash = Column(String(64), unique=True, nullable=False, index=True)
    url = Column(Text, nullable=False)
    domain = Column(String(512), nullable=False, index=True)
    risiko = Column(String(20), nullable=False)  # low, medium, high
    toleransi = Column(Integer, default=70)
    sumber = Column(String(50), nullable=False)  # manual, gsb, virustotal, urlhaus
    created_at = Column(DateTime, server_default=func.current_timestamp())

    def __repr__(self):
        return f"<UrlBlacklist(id={self.id}, domain='{self.domain}', risiko='{self.risiko}')>"


class ScanVerdict(Base):
    """Model for scan verdict records."""

    __tablename__ = "scan_verdict"

    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(Text, nullable=False)
    url_hash = Column(String(64), nullable=False, index=True)
    skor_prediksi = Column(Float, nullable=False)
    skor_kerentanan = Column(Float, nullable=False)
    skor_reputasi = Column(Float, nullable=False)
    skor_final = Column(Float, nullable=False)
    keputusan = Column(String(20), nullable=False)  # AMAN, BERBAHAYA
    waktu = Column(DateTime, server_default=func.current_timestamp(), index=True)

    def __repr__(self):
        return f"<ScanVerdict(id={self.id}, url='{self.url}', keputusan='{self.keputusan}')>"


# Define indexes for better query performance
Index('idx_scan_waktu', ScanVerdict.waktu.desc())
Index('idx_scan_hash', ScanVerdict.url_hash)
Index('idx_blacklist_domain', UrlBlacklist.domain)