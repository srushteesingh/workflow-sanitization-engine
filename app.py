from collections import Counter
import csv
from datetime import datetime, timezone
import io
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ValidationError, field_validator

app = FastAPI(
    title="Workflow Sanitization & Guardrail Engine",
    description="Deduplicates, validates, and quarantines malformed CSV or webhook payloads.",
    version="1.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_ROWS_PER_UPLOAD = 500
quarantine_store: list[dict[str, Any]] = []


class LeadRecord(BaseModel):
    name: str
    email: str
    score: int = Field(ge=0, le=100)

    @field_validator("name")
    @classmethod
    def normalize_name(cls, v: str) -> str:
        cleaned = v.strip().title()
        if not cleaned:
            raise ValueError("Name cannot be empty")
        return cleaned

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if "@" not in v or "." not in v.split("@")[-1]:
            raise ValueError("Invalid email format")
        return v.strip().lower()


class BatchPayload(BaseModel):
    records: list[dict[str, Any]]


def run_sanitization(raw_records: list[dict[str, Any]]) -> dict[str, Any]:
    accepted: list[dict[str, Any]] = []
    quarantined_batch: list[dict[str, Any]] = []
    seen_emails: set[str] = set()
    duplicates_skipped = 0

    for row_num, raw in enumerate(raw_records, start=1):
        try:
            clean = LeadRecord.model_validate(raw)
            if clean.email in seen_emails:
                duplicates_skipped += 1
                continue
            seen_emails.add(clean.email)
            accepted.append(clean.model_dump())
        except ValidationError as err:
            entry = {
                "row_number": row_num,
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
            }
            quarantined_batch.append(entry)
            quarantine_store.append(entry)

    error_clusters = Counter(
        f"{err['field']}:{err['type']}"
        for item in quarantined_batch
        for err in item["errors"]
    )

    return {
        "status": "processed",
        "accepted_count": len(accepted),
        "duplicates_skipped": duplicates_skipped,
        "quarantined_count": len(quarantined_batch),
        "error_clusters": dict(error_clusters),
        "clean_records": accepted,
        "quarantined_records": quarantined_batch,
    }


@app.get("/")
async def health_check() -> dict[str, str]:
    return {"status": "ok", "max_rows_per_upload": str(MAX_ROWS_PER_UPLOAD)}


@app.post("/v1/ingest-leads")
async def ingest_leads(payload: BatchPayload) -> dict[str, Any]:
    if len(payload.records) > MAX_ROWS_PER_UPLOAD:
        raise HTTPException(
            status_code=400,
            detail=f"Row limit exceeded ({len(payload.records)} rows). Max {MAX_ROWS_PER_UPLOAD} allowed.",
        )
    return run_sanitization(payload.records)


@app.post("/v1/clean-csv")
async def clean_csv(file: UploadFile = File(...)) -> dict[str, Any]:
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Please upload a valid .csv file.")

    contents = await file.read()
    try:
        decoded = contents.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="CSV must be UTF-8 encoded.")

    reader = csv.DictReader(io.StringIO(decoded))
    if not reader.fieldnames:
        raise HTTPException(status_code=400, detail="CSV file has no header row.")

    normalized_rows: list[dict[str, Any]] = []
    for row in reader:
        cleaned_row = {
            k.strip().lower(): (v.strip() if isinstance(v, str) else v)
            for k, v in row.items()
            if k is not None
        }
        if any(cleaned_row.values()):
            normalized_rows.append(cleaned_row)

    if not normalized_rows:
        raise HTTPException(status_code=400, detail="CSV file contains no data rows.")

    if len(normalized_rows) > MAX_ROWS_PER_UPLOAD:
        raise HTTPException(
            status_code=400,
            detail=f"Upload has {len(normalized_rows)} rows. Maximum {MAX_ROWS_PER_UPLOAD} rows allowed per upload.",
        )

    return run_sanitization(normalized_rows)


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