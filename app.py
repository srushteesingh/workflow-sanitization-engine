from collections import Counter, deque
import csv
from datetime import datetime, timezone
import io
import os
import re
import time
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ValidationError, field_validator

app = FastAPI(
    title="Universal CSV Cleaner & Sanitization Engine",
    description="Cleans, formats, deduplicates, and validates any CSV spreadsheet.",
    version="2.2.0",
)

# Configurable CORS: defaults to "*" for setup; set ALLOWED_ORIGINS on Render once Vercel is live
raw_origins = os.getenv("ALLOWED_ORIGINS", "*").strip()
allowed_origins = (
    ["*"]
    if raw_origins == "*"
    else [origin.strip() for origin in raw_origins.split(",") if origin.strip()]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

MAX_ROWS_PER_UPLOAD = 500
MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # 2 MB cap
CHUNK_SIZE_BYTES = 64 * 1024           # 64 KB streaming chunks

RATE_LIMIT_MAX_REQUESTS = 30
RATE_LIMIT_WINDOW_SECONDS = 60
MAX_TRACKED_IPS = 5000

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
NUMERIC_REGEX = re.compile(r"^[+-]?\d+(?:,\d{3})*(?:\.\d+)?$")
SIMPLE_PHONE_REGEX = re.compile(r"^\+\d[\d\s]{5,18}\d$")

EMAIL_HEADER_HINTS = ("email", "e-mail", "mail")
NAME_HEADER_HINTS = ("name", "first_name", "last_name", "firstname", "lastname", "contact")
NON_NUMERIC_HEADER_HINTS = ("phone", "tel", "mobile", "zip", "postal", "id", "code", "date", "time")

# Bounded in-memory stores to prevent unbounded RAM growth
quarantine_store: deque[dict[str, Any]] = deque(maxlen=1000)
ip_request_log: dict[str, deque[float]] = {}


# --- Legacy Webhook Models ---
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
        if not EMAIL_REGEX.match(v.strip()):
            raise ValueError("Invalid email format")
        return v.strip().lower()


class BatchPayload(BaseModel):
    records: list[dict[str, Any]]


# --- Security & Parsing Helpers ---
def enforce_rate_limit(request: Request) -> None:
    forwarded = request.headers.get("x-forwarded-for", "")
    client_ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "unknown")
    )

    now = time.monotonic()
    window_start = now - RATE_LIMIT_WINDOW_SECONDS

    if len(ip_request_log) >= MAX_TRACKED_IPS and client_ip not in ip_request_log:
        stale_ips = [
            ip for ip, times in ip_request_log.items() if not times or times[-1] < window_start
        ]
        for ip in stale_ips:
            del ip_request_log[ip]
        if len(ip_request_log) >= MAX_TRACKED_IPS:
            ip_request_log.clear()

    timestamps = ip_request_log.setdefault(client_ip, deque())
    while timestamps and timestamps[0] < window_start:
        timestamps.popleft()

    if len(timestamps) >= RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(
            status_code=429,
            detail="Too many uploads in a short time. Please wait a minute and try again.",
        )

    timestamps.append(now)


async def read_file_with_limit(file: UploadFile, max_bytes: int) -> bytes:
    buffer = bytearray()
    while True:
        chunk = await file.read(CHUNK_SIZE_BYTES)
        if not chunk:
            break
        buffer.extend(chunk)
        if len(buffer) > max_bytes:
            raise HTTPException(
                status_code=413,
                detail="This file is larger than 2 MB. Please upload a smaller CSV file.",
            )
    return bytes(buffer)


def decode_csv_bytes(contents: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return contents.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise HTTPException(
        status_code=400,
        detail="We couldn't read this file's text encoding. Please save it as a standard CSV (UTF-8).",
    )


def detect_delimiter(sample_text: str) -> str:
    try:
        dialect = csv.Sniffer().sniff(sample_text[:4096], delimiters=",;\t|")
        return dialect.delimiter
    except csv.Error:
        return ","


def is_email_column(header: str) -> bool:
    low = header.strip().lower()
    return any(hint in low for hint in EMAIL_HEADER_HINTS)


def is_name_column(header: str) -> bool:
    low = header.strip().lower()
    if is_email_column(low) or any(word in low for word in ("company", "file", "domain", "user")):
        return False
    return any(hint in low for hint in NAME_HEADER_HINTS)


def clean_whitespace(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def detect_numeric_columns(
    headers: list[str],
    raw_rows: list[list[str]],
    email_cols: set[str],
    name_cols: set[str],
) -> list[str]:
    numeric_cols: list[str] = []
    for idx, col in enumerate(headers):
        low = col.lower()
        if col in email_cols or col in name_cols:
            continue
        if any(hint in low for hint in NON_NUMERIC_HEADER_HINTS):
            continue

        non_empty = 0
        numeric_hits = 0
        for row in raw_rows:
            if idx >= len(row):
                continue
            val = clean_whitespace(row[idx])
            if not val:
                continue
            non_empty += 1
            if NUMERIC_REGEX.match(val):
                numeric_hits += 1

        # Treat as a numeric column if at least 3 values exist and >= 60% are valid numbers
        if non_empty >= 3 and (numeric_hits / non_empty) >= 0.6:
            numeric_cols.append(col)

    return numeric_cols


def neutralize_formula_injection(value: str) -> tuple[str, bool]:
    if not value:
        return value, False

    first_char = value[0]
    if first_char in ("=", "@"):
        return f"'{value}", True

    if first_char in ("+", "-"):
        if NUMERIC_REGEX.match(value) or SIMPLE_PHONE_REGEX.match(value):
            return value, False
        return f"'{value}", True

    return value, False


# --- Core Universal Cleaning Engine ---
def run_universal_csv_cleaning(
    headers: list[str],
    raw_rows: list[list[str]],
    dedupe_by: str = "auto",
    fix_name_casing: bool = True,
    flag_invalid_emails: bool = True,
    flag_invalid_numbers: bool = True,
    flag_missing_values: bool = False,
) -> dict[str, Any]:
    clean_headers: list[str] = []
    header_counts: Counter[str] = Counter()
    for idx, raw_h in enumerate(headers):
        base = clean_whitespace(raw_h) or f"Column {idx + 1}"
        header_counts[base] += 1
        final_name = base if header_counts[base] == 1 else f"{base} ({header_counts[base]})"
        clean_headers.append(final_name)

    email_cols = [h for h in clean_headers if is_email_column(h)]
    name_cols = [h for h in clean_headers if is_name_column(h)]
    numeric_cols = detect_numeric_columns(
        clean_headers, raw_rows, set(email_cols), set(name_cols)
    )

    if dedupe_by == "auto":
        active_dedupe_mode = email_cols[0] if email_cols else "exact_row"
    elif dedupe_by == "exact_row":
        active_dedupe_mode = "exact_row"
    elif dedupe_by in clean_headers:
        active_dedupe_mode = dedupe_by
    else:
        active_dedupe_mode = "exact_row"

    clean_records: list[dict[str, str]] = []
    flagged_records: list[dict[str, Any]] = []
    seen_keys: set[Any] = set()

    blank_rows_removed = 0
    duplicates_removed = 0
    cells_fixed = 0
    formulas_neutralized = 0

    for row_num, raw_cells in enumerate(raw_rows, start=2):
        if not any(cell.strip() for cell in raw_cells):
            blank_rows_removed += 1
            continue

        row_issues: list[str] = []
        raw_dict: dict[str, str] = {}
        cleaned_dict: dict[str, str] = {}

        if len(raw_cells) > len(clean_headers):
            extra_values = [c.strip() for c in raw_cells[len(clean_headers) :] if c.strip()]
            if extra_values:
                row_issues.append("This row has extra values that don't match the column headings")

        for idx, col in enumerate(clean_headers):
            original_val = raw_cells[idx] if idx < len(raw_cells) else ""
            raw_dict[col] = original_val

            val = clean_whitespace(original_val)

            if not val:
                if flag_missing_values:
                    row_issues.append(f'"{col}" is blank')
            elif col in email_cols:
                val = val.lower()
                if flag_invalid_emails and not EMAIL_REGEX.match(val):
                    row_issues.append(f'"{col}" does not look like a valid email address')
            elif col in numeric_cols:
                if flag_invalid_numbers and not NUMERIC_REGEX.match(val):
                    row_issues.append(f'"{col}" should be a number (found "{val}")')
            elif fix_name_casing and col in name_cols:
                if val.islower() or val.isupper():
                    val = val.title()

            val, was_formula = neutralize_formula_injection(val)
            if was_formula:
                formulas_neutralized += 1
                row_issues.append(
                    f'"{col}" contains a suspicious spreadsheet formula and was neutralized for safety'
                )

            if val != original_val:
                cells_fixed += 1

            cleaned_dict[col] = val

        if row_issues:
            flagged_records.append(
                {
                    "row_number": row_num,
                    "raw_payload": raw_dict,
                    "cleaned_preview": cleaned_dict,
                    "reasons": row_issues,
                }
            )
            continue

        if active_dedupe_mode == "exact_row":
            dedupe_key: Any = tuple(cleaned_dict[c].lower() for c in clean_headers)
        else:
            key_val = cleaned_dict.get(active_dedupe_mode, "").lower()
            dedupe_key = (
                ("col", key_val)
                if key_val
                else ("row", tuple(cleaned_dict[c].lower() for c in clean_headers))
            )

        if dedupe_key in seen_keys:
            duplicates_removed += 1
            continue

        seen_keys.add(dedupe_key)
        clean_records.append(cleaned_dict)

    return {
        "status": "processed",
        "columns": clean_headers,
        "detected_email_columns": email_cols,
        "detected_name_columns": name_cols,
        "detected_numeric_columns": numeric_cols,
        "dedupe_mode_used": active_dedupe_mode,
        "total_rows_scanned": len(raw_rows),
        "clean_count": len(clean_records),
        "duplicates_removed": duplicates_removed,
        "blank_rows_removed": blank_rows_removed,
        "flagged_count": len(flagged_records),
        "cells_fixed": cells_fixed,
        "formulas_neutralized": formulas_neutralized,
        "clean_records": clean_records,
        "flagged_records": flagged_records,
    }


# --- API Routes ---
@app.get("/")
async def health_check() -> dict[str, str]:
    return {
        "status": "ok",
        "version": "2.2.0",
        "max_rows_per_upload": str(MAX_ROWS_PER_UPLOAD),
        "max_file_size_mb": "2",
    }


@app.post("/v1/clean-csv")
async def clean_csv(
    request: Request,
    file: UploadFile = File(...),
    dedupe_by: str = Form(default="auto"),
    fix_name_casing: bool = Form(default=True),
    flag_invalid_emails: bool = Form(default=True),
    flag_invalid_numbers: bool = Form(default=True),
    flag_missing_values: bool = Form(default=False),
) -> dict[str, Any]:
    enforce_rate_limit(request)

    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=400,
            detail="Please choose a standard CSV spreadsheet file (.csv).",
        )

    contents = await read_file_with_limit(file, MAX_FILE_SIZE_BYTES)
    if not contents.strip():
        raise HTTPException(
            status_code=400,
            detail="This file is empty. Please upload a CSV with data.",
        )

    decoded = decode_csv_bytes(contents)
    delimiter = detect_delimiter(decoded)
    rows = list(csv.reader(io.StringIO(decoded), delimiter=delimiter))

    while rows and not any(cell.strip() for cell in rows[0]):
        rows.pop(0)

    if not rows:
        raise HTTPException(
            status_code=400,
            detail="This file has no column headings or data.",
        )

    headers = rows[0]
    data_rows = rows[1:]

    non_empty_count = sum(1 for r in data_rows if any(c.strip() for c in r))
    if non_empty_count == 0:
        raise HTTPException(
            status_code=400,
            detail="This file only has headings and no data rows.",
        )

    if non_empty_count > MAX_ROWS_PER_UPLOAD:
        raise HTTPException(
            status_code=400,
            detail=f"Your file has {non_empty_count} rows. Free uploads support up to {MAX_ROWS_PER_UPLOAD} rows at a time.",
        )

    return run_universal_csv_cleaning(
        headers=headers,
        raw_rows=data_rows,
        dedupe_by=dedupe_by,
        fix_name_casing=fix_name_casing,
        flag_invalid_emails=flag_invalid_emails,
        flag_invalid_numbers=flag_invalid_numbers,
        flag_missing_values=flag_missing_values,
    )


@app.post("/v1/ingest-leads")
async def ingest_leads(request: Request, payload: BatchPayload) -> dict[str, Any]:
    enforce_rate_limit(request)

    if len(payload.records) > MAX_ROWS_PER_UPLOAD:
        raise HTTPException(
            status_code=400,
            detail=f"Row limit exceeded ({len(payload.records)} rows). Max {MAX_ROWS_PER_UPLOAD} allowed.",
        )

    accepted: list[dict[str, Any]] = []
    quarantined_batch: list[dict[str, Any]] = []
    seen_emails: set[str] = set()
    duplicates_skipped = 0

    for row_num, raw in enumerate(payload.records, start=1):
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


@app.get("/v1/quarantine")
async def inspect_quarantine() -> dict[str, Any]:
    records = list(quarantine_store)
    error_clusters = Counter(
        f"{err['field']}:{err['type']}"
        for item in records
        for err in item["errors"]
    )
    return {
        "total_quarantined": len(records),
        "error_clusters": dict(error_clusters),
        "records": records,
    }