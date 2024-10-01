from typing import Sequence
import datetime

from pydantic import BaseModel


class Service(BaseModel):
    name: str | None = None
    host: str
    folders: Sequence[str] = ("INBOX", )
    domains: Sequence[str]
    encoding: str | None = "UTF-8"  # "US-ASCII"


class EmailMessage(BaseModel):
    subject:  str | None = None
    text:     str
    sender:   str | None = None
    receiver: str | None = None
    date: datetime
