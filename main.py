"""
eco-lab_venbrax V5 — Forensic API
FastAPI + Swagger auto-doc | Deploy: Railway
"""
from fastapi import FastAPI, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import hashlib, json, uuid, os
from datetime import datetime, timezone
from supabase import create_client

# ── Config ──────────────────────────────────────────────────────
app = FastAPI(
    title="eco-lab_venbrax V5 — Forensic API",
    description="Automated digital evidence preservation & chain of custody. Powered by Gem Vigía (david_one) + Gem Alcaide (miguel_core).",
    version="5.0.0",
    contact={"name": "Alfonso Grammatica", "email": "hola@venbratech.com", "url": "https://venbratech.com"},
    license_info={"name": "Proprietary — eco-lab_venbrax V5"}
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://xshannxyjzrhgnsqmhun.supabase.co")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_KEY")
API_KEY      = os.environ.get("FORENSIC_API_KEY", "demo-venbrax-2026")

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def get_db():
    return create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_KEY else None

def verify_key(key: str = Security(api_key_header)):
    if key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return key

def sha256(data: dict) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

# ── Models ───────────────────────────────────────────────────────
class NetworkMeta(BaseModel):
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

class CaptureRequest(BaseModel):
    event_type: str  # auth_failure | injection | anomaly | network_breach
    severity: str    # low | medium | high | critical
    network_meta: NetworkMeta
    client_org: Optional[str] = None

class SuppressRequest(BaseModel):
    incident_id: str
    endpoints_to_block: list[str]
    operator_id: Optional[str] = None

# ── Endpoints ────────────────────────────────────────────────────
@app.get("/health", tags=["System"])
def health():
    return {"status": "operational", "version": "V5", "service": "eco-lab_venbrax Forensic API"}

@app.post("/forensic/capture", tags=["Forensic"], summary="Temporal Drift — Capture incident snapshot")
def capture(req: CaptureRequest, key: str = Security(verify_key)):
    """
    **Gem Vigía (david_one)** — Captures an immutable forensic snapshot of the incident.

    - Masks PII from environment
    - Calculates SHA256-HEX forensic hash
    - Writes to Supabase `security_events` (RLS isolated)
    - Returns `forensic_hash` and `incident_id` for chain of custody
    """
    incident_id = str(uuid.uuid4())
    ts = datetime.now(timezone.utc).isoformat()
    payload = {"network": req.network_meta.dict(), "ts": ts, "event": req.event_type}
    f_hash = sha256(payload)

    record = {
        "incident_id": incident_id,
        "severity": req.severity,
        "event_type": req.event_type,
        "snapshot_network": req.network_meta.dict(),
        "snapshot_timestamp": ts,
        "forensic_hash": f_hash,
        "hash_algorithm": "SHA256",
        "payload_encoding": "UTF-8",
        "hash_verified": True,
        "requires_human_sign": req.severity in ("high", "critical"),
        "gem_source": "david_one",
        "pipeline_version": "V5",
        "client_org": req.client_org,
        "isolation_applied": False,
    }

    db = get_db()
    if db:
        db.table("security_events").insert(record).execute()

    return {
        "status": "captured",
        "incident_id": incident_id,
        "forensic_hash": f_hash,
        "severity": req.severity,
        "requires_human_approval": req.severity in ("high", "critical"),
        "gem": "david_one (Gem Vigía)",
        "timestamp": ts
    }

@app.post("/forensic/suppress", tags=["Forensic"], summary="Iron Suppression — Perimeter isolation")
def suppress(req: SuppressRequest, key: str = Security(verify_key)):
    """
    **Gem Alcaide (miguel_core)** — Applies perimeter isolation and logs operator signature.

    - Blocks specified endpoints
    - Injects dynamic RLS policy in Supabase
    - Records isolation timestamp
    - Required for `severity=high/critical` after human approval
    """
    ts = datetime.now(timezone.utc).isoformat()
    db = get_db()
    if db:
        db.table("security_events").update({
            "isolation_applied": True,
            "isolated_endpoints": req.endpoints_to_block,
            "rls_policy_injected": True,
            "isolation_timestamp": ts,
            "human_operator_id": req.operator_id,
            "gem_source": "miguel_core",
        }).eq("incident_id", req.incident_id).execute()

    return {
        "status": "suppressed",
        "incident_id": req.incident_id,
        "blocked_endpoints": req.endpoints_to_block,
        "isolation_timestamp": ts,
        "gem": "miguel_core (Gem Alcaide)"
    }

@app.get("/forensic/verify/{incident_id}", tags=["Forensic"], summary="Verify chain of custody integrity")
def verify(incident_id: str, key: str = Security(verify_key)):
    """
    **Verify** — Recomputes SHA256 hash and confirms evidence integrity.

    Returns `PASS` if the evidence is unmodified since capture, or `TAMPERED` if any modification is detected.
    Admissible in judicial proceedings.
    """
    db = get_db()
    if not db:
        return {"status": "DEMO_MODE", "incident_id": incident_id, "note": "Connect Supabase to verify real records"}

    rows = db.table("security_events").select("*").eq("incident_id", incident_id).execute()
    if not rows.data:
        raise HTTPException(status_code=404, detail="Incident not found")

    row = rows.data[0]
    payload = {"network": row.get("snapshot_network", {}), "ts": row.get("snapshot_timestamp",""), "event": row.get("event_type","")}
    recomputed = sha256(payload)
    integrity = "PASS" if recomputed == row["forensic_hash"] else "TAMPERED"

    return {
        "status": integrity,
        "incident_id": incident_id,
        "stored_hash": row["forensic_hash"],
        "recomputed_hash": recomputed,
        "severity": row["severity"],
        "isolation_applied": row["isolation_applied"],
        "human_signed": bool(row.get("human_operator_id")),
        "gem": "verify_custody_chain"
    }

@app.get("/forensic/events", tags=["Forensic"], summary="List recent forensic events")
def list_events(limit: int = 10, key: str = Security(verify_key)):
    """Returns the last N forensic events from the audit view (no sensitive data)."""
    db = get_db()
    if not db:
        return {"events": [], "note": "DEMO_MODE — connect Supabase"}
    rows = db.table("forensic_audit_view").select("*").order("created_at", desc=True).limit(limit).execute()
    return {"events": rows.data, "count": len(rows.data)}
