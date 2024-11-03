import asyncio
from datetime import datetime, timedelta
from typing import Literal, Sequence
from email import message_from_bytes
from email.utils import parsedate_to_datetime
import re

import pytz
from better_imap.utils import get_service_by_email_address
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
        address: str,
        password: str,
        *,
        service: Service = None,
        proxy: Proxy = None,
        timeout: float = 10,
    ):
        if not service:
            service = get_service_by_email_address(address)

        if service.host == "imap.rambler.ru" and "%" in password:
            raise ValueError(
                f"IMAP password contains '%' character. Change your password."
                f" It's a specific rambler.ru error"
            )


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
        await self.login()
        return self

    async def __aexit__(self, *args):
        await self.logout()

    async def logout(self):
        await self._imap.logout()

    async def login(self):
        if self._connected:
            return

        await self._imap.wait_hello_from_server()
        await self._imap.login(self._address, self._password)
        if self._imap.get_state() == "NONAUTH":
            raise IMAPLoginFailed()
        self._connected = True

    async def _select(self, folder: str):
        return await self._imap.select(mailbox=folder)

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
        await self.login()

        await self._select(folder)

        if since:
            date_filter = since.strftime("%d-%b-%Y")
            search_criteria += f" SINCE {date_filter}"

        if allowed_senders:
            senders_criteria = " ".join(
                [f'FROM "{sender}"' for sender in allowed_senders]
            )
            search_criteria += f" {senders_criteria}"

        if allowed_receivers:
            receivers_criteria = " ".join(
                [f'TO "{receiver}"' for receiver in allowed_receivers]
            )
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
            message = await self.get_message_by_id(
                e_id_str.decode(self._service.encoding)
            )

            if since and message.date < since:
                continue

            if sender_regex and not re.search(
                sender_regex, message.sender, re.IGNORECASE
            ):
                continue

            messages.append(message)

        return messages

    async def search_matches(
        self,
        regex: str | re.Pattern[str],
        folders: Sequence[str] = None,
        *,
        search_criteria: Literal["ALL", "UNSEEN"] = "ALL",
        since: datetime = None,
        hours_offset: int = 24,
        allowed_senders: Sequence[str] = None,
        allowed_receivers: Sequence[str] = None,
        sender_regex: str | re.Pattern[str] = None,
    ) -> list[tuple[EmailMessage, str]]:
        await self.login()

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
                if found := re.findall(regex, message.text):
                    matches.append((message, found[0]))

        return matches

    async def search_match(
        self,
        regex: str | re.Pattern[str],
        folders: Sequence[str] = None,
        *,
        search_criteria: Literal["ALL", "UNSEEN"] = "ALL",
        since: datetime = None,
        hours_offset: int = 24,
        allowed_senders: Sequence[str] = None,
        allowed_receivers: Sequence[str] = None,
        sender_regex: str | re.Pattern[str] = None,
    ) -> str | None:
        matches = await self.search_matches(
            regex,
            folders,
            search_criteria=search_criteria,
            since=since,
            hours_offset=hours_offset,
            allowed_senders=allowed_senders,
            allowed_receivers=allowed_receivers,
            sender_regex=sender_regex,
        )
        return max(matches, key=lambda x: x[0].date)[1] if matches else None

    async def search_with_retry(
        self,
        regex: str | re.Pattern[str],
        folders: Sequence[str] = None,
        *,
        allowed_senders: Sequence[str] = None,
        allowed_receivers: Sequence[str] = None,
        sender_email_regex: str | re.Pattern[str] = None,
        since: datetime = None,
        interval: int = 5,
        timeout: int = 90,
    ) -> list[any] | None:
        end_time = asyncio.get_event_loop().time() + timeout
        if since is None:
            since = datetime.now(pytz.utc) - timedelta(seconds=15)

        while asyncio.get_event_loop().time() < end_time:
            match = await self.search_match(
                regex,
                folders,
                allowed_senders=allowed_senders,
                sender_regex=sender_email_regex,
                allowed_receivers=allowed_receivers,
                since=since,
            )

            if match:
                return match

            await asyncio.sleep(interval)

        raise IMAPSearchTimeout(f"No email received within {timeout} seconds")
