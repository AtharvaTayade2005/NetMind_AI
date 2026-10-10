"""NetMind AI - Threats & Anomalies Monitoring API Router."""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from netmind.src.backend.database import get_db
from netmind.src.backend.repository import AnomalyRepository, SecurityEventRepository
from netmind.src.backend.schemas import (
    AnomalyRead,
    PaginatedResponse,
    ReviewEventRequest,
    SecurityEventRead,
)

router = APIRouter(prefix="/api", tags=["Threats & Anomalies"])


@router.get("/threats", response_model=PaginatedResponse)
def list_threats(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    severity: Optional[str] = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    event_type: Optional[str] = Query(None, description="Filter by event type (DoS, Port Scan, etc.)"),
    db: Session = Depends(get_db),
) -> PaginatedResponse:
    """Retrieve security threats and intrusion events with pagination and filtering."""
    repo = SecurityEventRepository(db)
    skip = (page - 1) * page_size
    items, total = repo.list_events(skip=skip, limit=page_size, severity=severity, event_type=event_type)

    pydantic_items = [SecurityEventRead.model_validate(item) for item in items]
    total_pages = (total + page_size - 1) // page_size if total > 0 else 0

    return PaginatedResponse(
        total=total,
        page=page,
        page_size=page_size,
        pages=total_pages,
        items=pydantic_items,
    )


@router.get("/anomalies", response_model=PaginatedResponse)
def list_anomalies(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    status: Optional[str] = Query(None, description="Filter by status: open, investigating, resolved"),
    db: Session = Depends(get_db),
) -> PaginatedResponse:
    """Retrieve unsupervised zero-day anomaly detections with pagination and status filtering."""
    repo = AnomalyRepository(db)
    skip = (page - 1) * page_size
    items, total = repo.list_anomalies(skip=skip, limit=page_size, status=status)

    pydantic_items = [AnomalyRead.model_validate(item) for item in items]
    total_pages = (total + page_size - 1) // page_size if total > 0 else 0

    return PaginatedResponse(
        total=total,
        page=page,
        page_size=page_size,
        pages=total_pages,
        items=pydantic_items,
    )


@router.post("/events/{event_id}/review", response_model=SecurityEventRead)
def review_security_event(
    event_id: int,
    review_req: ReviewEventRequest,
    db: Session = Depends(get_db),
) -> SecurityEventRead:
    """Acknowledge, resolve, or mark a security threat incident as false positive."""
    repo = SecurityEventRepository(db)
    event = repo.get_by_id(event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event with ID {event_id} not found",
        )

    # Append review notes to description
    reviewer_note = f" [Reviewed by {review_req.reviewed_by}: {review_req.status.upper()}"
    if review_req.notes:
        reviewer_note += f" - {review_req.notes}"
    reviewer_note += "]"

    event.description = f"{event.description}{reviewer_note}"
    db.commit()
    db.refresh(event)

    return SecurityEventRead.model_validate(event)
