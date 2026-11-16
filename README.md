# ⚡ Deterministic Workflow Sanitization Engine (`Python`)

A lightweight, zero-dependency data sanitization and deduplication layer designed to clean messy operational payloads **before** database insertion (`PostgreSQL` / `Supabase`) or LLM prompt ingestion.

---

### 🏗️ Engineering Highlights
- **$O(1)$ Hash-Set Deduplication:** Uses Python `set()` hashing (`seen_emails`) to strip duplicate records in linear $O(n)$ total time instead of $O(n^2)$ list scans.
- **Deterministic Normalization:** Enforces lowercase email keys, title-cased names, and safe integer coercion without external dependencies.
- **Pre-Ingestion Guardrail:** Prevents malformed rows from polluting downstream SQL tables or wasting LLM token budgets.

---

### 🔄 Working Output: Before vs. After

#### ❌ Raw Unsanitized Input (4 Rows — Duplicates & Broken Data)
```json
[
  {"name": " ethan carter ", "email": "ETHAN@company.io", "score": "92"},
  {"name": "olivia bennett", "email": "olivia@company.io", "score": "88"},
  {"name": "ethan carter", "email": "ethan@company.io", "score": "92"},
  {"name": "marcus reed", "email": "", "score": ""}
]
```

#### ✅ Sanitized Output (`python sanitizer.py`)
```json
{
  "total_raw": 4,
  "valid": 2,
  "avg_score": 90.0,
  "data": [
    {
      "name": "Ethan Carter",
      "email": "ethan@company.io",
      "score": 92
    },
    {
      "name": "Olivia Bennett",
      "email": "olivia@company.io",
      "score": 88
    }
  ]
}
```
