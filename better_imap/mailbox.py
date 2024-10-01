import asyncio
from datetime import datetime, timedelta
from typing import Literal, Sequence
from email import message_from_bytes
from email.utils import parsedate_to_datetime
import re

import pytz
import aioimaplib
from better_proxy import Proxy

from .proxy import IMAP4_SSL_PROXY
from .errors import IMAPSearchTimeout
from .errors import IMAPLoginFailed
from .models import EmailMessage
from .models import Service
from .utils import extract_email_text


class MailBox:
    def __init__(
        self,
        service: Service,
        address: str,
        password: str,
        *,
        proxy: Proxy = None,
        timeout: float = 10,
    ):
        if service.host == "imap.rambler.ru" and "%" in password:
            raise IMAPLoginFailed(f"IMAP password contains '%' character. Change your password."
                                  f" It's a specific rambler.ru error")

        self._address = address
        self._password = password
        self._service = service
        self._connected = False
        self._imap = IMAP4_SSL_PROXY(
            host=service.host,
            proxy=proxy,
            timeout=timeout,
        )

    async def __aenter__(self):
        await self._connect()
        return self

    async def __aexit__(self, *args):
        await self._imap.logout()

    async def _connect(self):
        if self._connected:
            return

        await self._imap.wait_hello_from_server()

        try:
            await self._imap.login(self._address, self._password)
            self._connected = True
        except aioimaplib.Abort as exc:
            if "command SELECT illegal in state NONAUTH" in str(exc):
                raise IMAPLoginFailed(f"Email account banned"
                                      f" or login/password incorrect"
                                      f" or IMAP not enabled: {exc}")

            raise IMAPLoginFailed(f"IMAP login failed: {exc}")

    async def check_email(self, folders: Sequence[str] = None):
        await self._connect()

        folders = folders or self._service.folders

        for mailbox in folders:
            await self._imap.select(mailbox=mailbox)

        await self._imap.logout()

    async def fetch_messages(
            self,
            folder: str,
            *,
            search_criteria: Literal["ALL", "UNSEEN"] = "ALL",
            since: datetime = None,
            allowed_senders: Sequence[str] = None,
            allowed_receivers: Sequence[str] = None,
            sender_regex: str | re.Pattern[str] = None,
    ) -> list[EmailMessage]:
        await self._connect()

        await self._imap.select(mailbox=folder)

        if since:
            date_filter = since.strftime("%d-%b-%Y")
            search_criteria += f" SINCE {date_filter}"

        if allowed_senders:
            senders_criteria = ' '.join([f'FROM "{sender}"' for sender in allowed_senders])
            search_criteria += f" {senders_criteria}"

        if allowed_receivers:
            receivers_criteria = ' '.join([f'TO "{receiver}"' for receiver in allowed_receivers])
            search_criteria += f" {receivers_criteria}"

        status, data = await self._imap.search(
            search_criteria, charset=self._service.encoding
        )

        if status != "OK":
            return []

        if not data[0]:
            return []

        email_ids = data[0].split()
        email_ids = email_ids[::-1]
        messages = []
        for e_id_str in email_ids:
            message = await self.get_message_by_id(e_id_str.decode(self._service.encoding))

            if since and message.date < since:
                continue

            if sender_regex and not re.search(sender_regex, message.sender, re.IGNORECASE):
                continue

            messages.append(message)

        return messages

    async def get_message_by_id(self, id) -> EmailMessage:
        typ, msg_data = await self._imap.fetch(id, "(RFC822)")
        if typ == "OK":
            email_bytes = bytes(msg_data[1])
            email_message = message_from_bytes(email_bytes)
            email_sender = email_message.get("from")
            email_receiver = email_message.get("to")
            subject = email_message.get("subject")
            email_date = parsedate_to_datetime(email_message.get("date"))

            if email_date.tzinfo is None:
                email_date = pytz.utc.localize(email_date)
            elif email_date.tzinfo != pytz.utc:
                email_date = email_date.astimezone(pytz.utc)

            message_text = extract_email_text(email_message)
            return EmailMessage(
                text=message_text,
                date=email_date,
                sender=email_sender,
                receiver=email_receiver,
                subject=subject,
            )

    async def search_matches(
        self,
        folders: Sequence[str] = None,
        *,
        search_criteria: Literal["ALL", "UNSEEN"] = "ALL",
        since: datetime = None,
        hours_offset: int = 24,
        allowed_senders: Sequence[str] = None,
        allowed_receivers: Sequence[str] = None,
        sender_regex: str | re.Pattern[str] = None,
        regex: str | re.Pattern[str],
    ) -> list[str]:
        await self._connect()

        if since is None:
            since = datetime.now(pytz.utc) - timedelta(hours=hours_offset)

        folders = folders or self._service.folders

        matches = []

        for folder in folders:
            messages = await self.fetch_messages(
                folder,
                since=since,
                search_criteria=search_criteria,
                allowed_senders=allowed_senders,
                allowed_receivers=allowed_receivers,
                sender_regex=sender_regex,
            )

            for message in messages:
                matches = re.findall(regex, message.text)
                if match := matches[0]:
                    matches.append((message, match))

        return matches

    async def search_match(self, *args, **kwargs) -> str | None:
        matches = await self.search_matches(*args, **kwargs)
        return max(matches, key=lambda x: x[0].date)[1] if matches else None

    async def search_with_retry(
        self,
        regex_pattern: str | re.Pattern[str],
        sender_email: str | re.Pattern[str] = None,
        sender_email_regex: str | re.Pattern[str] = None,
        receiver: str | None = None,
        start_date: datetime = None,
        return_latest_match=True,
        interval: int = 5,
        timeout: int = 90,
        **kwargs,
    ) -> any | list[any] | None:
        end_time = asyncio.get_event_loop().time() + timeout
        if start_date is None:
            start_date = datetime.now(pytz.utc) - timedelta(seconds=15)

        while asyncio.get_event_loop().time() < end_time:
            match = await self.search_match(
                regex=regex_pattern,
                sender=sender_email,
                sender_regex=sender_email_regex,
                receiver=receiver,
                start_date=start_date,
                limit=5,
                return_latest_match=return_latest_match,
                **kwargs,
            )

            if match:
                return match

            await asyncio.sleep(interval)

        raise IMAPSearchTimeout(f"No email received within {timeout} seconds")
