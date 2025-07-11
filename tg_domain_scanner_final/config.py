import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()

@dataclass
class Settings:
    TG_TOKEN: str
    DNS_TIMEOUT: int = 5
    HTTP_TIMEOUT: int = 6
    CONCURRENCY: int = 20

settings = Settings(
    TG_TOKEN=os.getenv("TG_TOKEN", ""),
    DNS_TIMEOUT=int(os.getenv("DNS_TIMEOUT", 5)),
    HTTP_TIMEOUT=int(os.getenv("HTTP_TIMEOUT", 6)),
    CONCURRENCY=int(os.getenv("CONCURRENCY", 20)),
)
