from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")


class Settings(BaseModel):
    harness_backend: str = Field(default="mock", pattern=r"^(mock|konsole)$")
    harness_base_url: str = ""
    harness_api_key: str = ""
    harness_model: str = "mock-dpr-v1"
    harness_fallback_model: str = ""
    default_region: str = "in"
    database_path: Path = ROOT / "adhikar.db"
    token_map_key: str = "replace-for-production"

    @classmethod
    def from_env(cls) -> "Settings":
        db_value = os.getenv("DATABASE_PATH", "adhikar.db")
        db_path = Path(db_value)
        if not db_path.is_absolute():
            db_path = ROOT / db_path
        return cls(
            harness_backend=os.getenv("HARNESS_BACKEND", "mock").lower(),
            harness_base_url=os.getenv("HARNESS_BASE_URL", ""),
            harness_api_key=os.getenv("HARNESS_API_KEY", ""),
            harness_model=os.getenv("HARNESS_MODEL", "mock-dpr-v1"),
            harness_fallback_model=os.getenv("HARNESS_FALLBACK_MODEL", ""),
            default_region=os.getenv("DEFAULT_REGION", "in"),
            database_path=db_path,
            token_map_key=os.getenv("TOKEN_MAP_KEY", "replace-for-production"),
        )


settings = Settings.from_env()

