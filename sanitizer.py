from typing import List, Dict, Any

def clean_workflow_data(raw_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    seen_emails: set[str] = set()
    clean_rows: List[Dict[str, Any]] = []

    for row in raw_rows:
        email = str(row.get("email", "")).strip().lower()
        if not email or email in seen_emails:
            continue

        seen_emails.add(email)
        score = str(row.get("score", "0")).strip()

        clean_rows.append({
            "name": str(row.get("name", "Unknown")).strip().title(),
            "email": email,
            "score": int(score) if score.isdigit() else 0
        })

    avg = round(sum(r["score"] for r in clean_rows) / len(clean_rows), 1) if clean_rows else 0
    return {"total_raw": len(raw_rows), "valid": len(clean_rows), "avg_score": avg, "data": clean_rows}

if __name__ == "__main__":
    sample_input = [
        {"name": " ethan carter ", "email": "ETHAN@company.io", "score": "92"},
        {"name": "olivia bennett", "email": "olivia@company.io", "score": "88"},
        {"name": "ethan carter", "email": "ethan@company.io", "score": "92"},  # Duplicate
        {"name": "marcus reed", "email": "", "score": ""},  # Broken row
    ]
    print(clean_workflow_data(sample_input))