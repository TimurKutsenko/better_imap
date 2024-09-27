from __future__ import annotations

from pydantic import BaseModel
from datetime import datetime


class EmailMessage(BaseModel):
    subject: str | None = None
    text: str
    sender: str | None = None
    receiver: str | None = None
    date: datetime
