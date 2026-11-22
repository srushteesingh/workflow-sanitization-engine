from collections import Counter
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field, ValidationError, field_validator

app = FastAPI(
    title="Workflow Sanitization & Guardrail Engine",
    description="Deduplicates, validates, and quarantines malformed webhook or LLM payloads.",
    version="1.0.0",
)

quarantine_store: list[dict[str, Any]] = []


class LeadRecord(BaseModel):
    name: str
    email: str
    score: int = Field(ge=0, le=100)

    @field_validator("name")
    @classmethod
    def normalize_name(cls, v: str) -> str:
        return v.strip().title()

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if "@" not in v:
            raise ValueError("Missing @ symbol")
        return v.strip().lower()


class BatchPayload(BaseModel):
    records: list[dict[str, Any]]

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "records": [
                        {"name": " ethan carter ", "email": "ETHAN@company.io", "score": "92"},
                        {"name": "Ethan Carter", "email": "ethan@company.io", "score": 92},
                        {"name": "Marcus", "email": "invalid-email", "score": "150"},
                    ]
                }
            ]
        }
    }


@app.post("/v1/ingest-leads")
async def ingest_leads(payload: BatchPayload) -> dict[str, Any]:
    accepted: list[dict[str, Any]] = []
    seen_emails: set[str] = set()
    duplicates_skipped = 0
    quarantined_now = 0

    for raw in payload.records:
        try:
            clean = LeadRecord.model_validate(raw)
            if clean.email in seen_emails:
                duplicates_skipped += 1
                continue
            seen_emails.add(clean.email)
            accepted.append(clean.model_dump())
        except ValidationError as err:
            quarantined_now += 1
            quarantine_store.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "raw_payload": raw,
                "errors": [
                    {
                        "field": str(e["loc"][0]) if e["loc"] else "payload",
                        "type": e["type"],
                        "msg": e["msg"],
                    }
                    for e in err.errors()
                ],
            })

    return {
        "status": "processed",
        "accepted_count": len(accepted),
        "duplicates_skipped": duplicates_skipped,
        "quarantined_count": quarantined_now,
        "clean_records": accepted,
    }


@app.get("/v1/quarantine")
async def inspect_quarantine() -> dict[str, Any]:
    error_clusters = Counter(
        f"{err['field']}:{err['type']}"
        for item in quarantine_store
        for err in item["errors"]
    )
    return {
        "total_quarantined": len(quarantine_store),
        "error_clusters": dict(error_clusters),
        "records": quarantine_store,
    }