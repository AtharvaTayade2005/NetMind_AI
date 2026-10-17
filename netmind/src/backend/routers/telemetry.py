"""NetMind AI - Live NIC Telemetry & Flow Ingestion API Router."""

from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from netmind.src.ingestion.nic_sniffer import LiveNICCapture

router = APIRouter(prefix="/api/telemetry", tags=["Live NIC Telemetry"])


class InterfaceSwitchRequest(BaseModel):
    interface_name: str


@router.get("/live")
def get_live_telemetry() -> Dict[str, Any]:
    """Retrieve sliding window time-series and instantaneous packet rates from hardware NIC."""
    capture = LiveNICCapture.get_instance()
    return {
        "current": capture.get_current_metrics(),
        "series": capture.get_telemetry_series(),
    }


@router.get("/interfaces")
def get_available_interfaces() -> Dict[str, Any]:
    """List all physical and virtual network interface cards available on the host."""
    capture = LiveNICCapture.get_instance()
    return {
        "interfaces": capture.available_interfaces,
        "active": capture.active_interface,
    }


@router.post("/interface")
def switch_interface(req: InterfaceSwitchRequest) -> Dict[str, Any]:
    """Switch the actively monitored network interface."""
    capture = LiveNICCapture.get_instance()
    success = capture.set_interface(req.interface_name)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to switch network interface")
    return {
        "status": "success",
        "active": capture.active_interface,
    }


@router.get("/flows")
def get_live_flows(limit: int = 25) -> List[Dict[str, Any]]:
    """Retrieve real-time network flow socket table captured directly from the host system."""
    capture = LiveNICCapture.get_instance()
    return capture.get_live_flows(limit=limit)
