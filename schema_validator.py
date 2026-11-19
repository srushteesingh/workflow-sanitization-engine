from pydantic import BaseModel, Field, ValidationError, field_validator

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

# 1. Auto-cleans messy strings and converts "92" -> int 92
valid_lead = LeadRecord(name=" ethan carter ", email="ETHAN@company.io", score="92")
print("Clean:", valid_lead.model_dump())

# 2. Instantly blocks corrupted payload (bad email + score over 100)
try:
    LeadRecord(name="Marcus", email="invalid-email", score="150")
except ValidationError as err:
    print("Blocked:", err.error_count(), "corrupted fields rejected")
    