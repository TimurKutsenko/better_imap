from __future__ import annotations

from email import message_from_bytes
from email.utils import parsedate_to_datetime
from typing import Literal

import pytz
from better_proxy import Proxy

from better_imap.domains import determine_email_domain, EmailEncoding, EmailDomain
from .exceptions import (
    EmailConnectionError,
    EmailFolderSelectionError,
    EmailSearchTimeout,
    EmailLoginFailed,
)
from datetime import datetime, timedelta
from .imap_client import ImapProxyClient
import re
import asyncio
from aioimaplib import Abort as EmailAbortError, Error as EmailError

from .models import EmailMessage


class MailBox:
    FOLDER_NAMES = ["INBOX", "Junk", "Spam"]

    def __init__(
        self,
        email_address: str,
        password: str,
        proxy: Proxy | None = None,
        imap_host: str | None = None,
        domain: EmailDomain | None = None,
        folder_names: list[str] = None,
        timeout: float = 30,
        encoding=EmailEncoding.UTF8,
    ):
        self._email_address = email_address
        self._password = password
        self.domain = domain or determine_email_domain(email_address)
        self.imap_host, self.encoding = self.domain.imap_server_info()

        if not imap_host and not self.imap_host and not domain:
            raise EmailConnectionError(
                "Host or domain not provided and domain can not be determined from email"
            )

        self.imap_host = imap_host or self.imap_host
        self.encoding = encoding or self.encoding

        self._verify_data()

        self.folder_names = folder_names or self.FOLDER_NAMES

        self.email_client = ImapProxyClient(
            host=self.imap_host,
            timeout=timeout,
            proxy=proxy,
        )
        self.connected = False

    async def __aenter__(self):
        await self._connect_to_mail()
        return self

    async def __aexit__(self, *args):
        await self._close_connection()

    async def check_email(self):
        await self._connect_to_mail()

        for mailbox in self.folder_names:
            await self._select_mailbox(mailbox)

        await self._close_connection()

    async def fetch_messages(
        self,
        folder: Literal["INBOX", "Junk", "Spam"] = "INBOX",
        search_criteria: Literal["ALL", "UNSEEN"] = "ALL",
        receiver: str | None = None,
        sender_email: str = None,
        sender_email_regex: str | re.Pattern[str] = None,
        n_latest_messages: int | None = None,
        since_date: datetime = None,
    ) -> list[EmailMessage]:
        await self._connect_to_mail()
        await self._select_mailbox(folder)
        return await self._fetch_messages(
            search_criteria=search_criteria,
            sender_email=sender_email,
            sender_email_regex=sender_email_regex,
            receiver=receiver,
            n_latest_messages=n_latest_messages,
            since_date=since_date,
        )

    async def _fetch_messages(
        self,
        search_criteria: Literal["ALL", "UNSEEN"] = "ALL",
        sender_email: str = None,
        sender_email_regex: str | re.Pattern[str] = None,
        receiver: str | None = None,
        n_latest_messages: int | None = None,
        since_date: datetime = None,
    ) -> list[EmailMessage]:

        if since_date:
            date_filter = since_date.strftime("%d-%b-%Y")
            search_criteria += f" SINCE {date_filter}"

        if sender_email:
            search_criteria += f' FROM "{sender_email}"'

        status, data = await self.email_client.search(
            search_criteria, charset=self.encoding
        )
        if status != "OK":
            return []
            # raise EmailConnectionError(
            #     f"Failed to search for emails: {data}, status {status}"
            # )

        if not data[0]:
            return []
        email_ids = data[0].split()
        if n_latest_messages:
            email_ids = email_ids[-n_latest_messages:]
        email_ids = email_ids[::-1]
        messages = []
        for e_id_str in email_ids:
            email_message = await self._get_email(e_id_str.decode(self.encoding))

            if since_date and email_message.date < since_date:
                continue

            if sender_email_regex and not re.search(
                sender_email_regex, email_message.sender, re.IGNORECASE
            ):
                continue

            if receiver and receiver.lower() not in email_message.receiver.lower():
                continue

            messages.append(email_message)

        return messages

    async def search_match(
        self,
        regex_pattern: str | re.Pattern[str],
        sender_email: str | None = None,
        sender_email_regex: str | re.Pattern[str] = None,
        receiver: str | None = None,
        latest_messages: int = 10,
        start_date: datetime = None,
        hours_offset=24,
        return_latest_match=True,
    ) -> any | list[any] | None:
        if not regex_pattern:
            raise ValueError("Regex pattern must be provided to search for a match")

        if start_date is None:
            start_date = datetime.now(pytz.utc) - timedelta(hours=hours_offset)

        await self._connect_to_mail()

        matches = []

        for mailbox in self.folder_names:
            messages = await self.fetch_messages(
                folder=mailbox,
                search_criteria="ALL",
                sender_email=sender_email,
                sender_email_regex=sender_email_regex,
                receiver=receiver,
                n_latest_messages=latest_messages,
                since_date=start_date,
            )

            for message in messages:
                match = self.match_email_content(message.text, regex_pattern)

                if match:
                    matches.append((message, match))

        await self._close_connection()

        if not matches:
            return None

        if return_latest_match:
            return max(matches, key=lambda x: x[0].date)[1] if matches else None
        else:
            return matches

    async def search_with_retry(
        self,
        regex_pattern: str | re.Pattern[str],
        sender_email: str | re.Pattern[str] = None,
        sender_email_regex: str | re.Pattern[str] = None,
        receiver: str | None = None,
        start_date: datetime = None,
        return_latest_match=True,
        interval=5,
        timeout=90,
        **kwargs,
    ) -> any | list[any] | None:
        end_time = asyncio.get_event_loop().time() + timeout
        if start_date is None:
            start_date = datetime.now(pytz.utc) - timedelta(seconds=15)

        while asyncio.get_event_loop().time() < end_time:
            match = await self.search_match(
                regex_pattern=regex_pattern,
                sender_email=sender_email,
                sender_email_regex=sender_email_regex,
                receiver=receiver,
                start_date=start_date,
                latest_messages=5,
                return_latest_match=return_latest_match,
                **kwargs,
            )
            if match:
                return match
            await asyncio.sleep(interval)
        raise EmailSearchTimeout(f"No email received within {timeout} seconds")

    async def _get_email(self, email_id) -> EmailMessage:
        typ, msg_data = await self.email_client.fetch(email_id, "(RFC822)")
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

            message_text = self.extract_email_text(email_message)
            return EmailMessage(
                text=message_text,
                date=email_date,
                sender=email_sender,
                receiver=email_receiver,
                subject=subject,
            )

    def _verify_data(self):
        if self.imap_host == "imap.rambler.ru" and "%" in self._password:
            raise Exception(
                f"IMAP password contains '%' character. Change your password"
            )

    async def _connect_to_mail(self, mailbox="INBOX"):
        if self.connected:
            return

        try:
            await self.email_client.wait_hello_from_server()
        except EmailError as e:
            raise EmailConnectionError(f"Email connection failed: {e}")
        try:
            await self.email_client.login(self._email_address, self._password)
            await self.email_client.select(mailbox=mailbox)
        except EmailAbortError as e:
            if "command SELECT illegal in state NONAUTH" in str(e):
                raise EmailLoginFailed(
                    f"Email account banned or login/password incorrect or IMAP not enabled: {e}"
                )

            raise EmailLoginFailed(f"Can not login to mail: {e}")

        self.connected = True

    @staticmethod
    def match_email_content(message_text: str, regex_pattern: str | re.Pattern[str]):
        matches = re.findall(regex_pattern, message_text)
        if matches:
            return matches[0]
        return None

    @staticmethod
    def extract_email_text(email_message):
        if email_message.is_multipart():
            for part in email_message.walk():
                if part.get_content_type() == "text/plain":
                    return part.get_payload(decode=True).decode("utf-8")
        msg = email_message.get_payload(decode=True)
        if msg is None:
            return ""
        return msg.decode("utf-8")

    async def _select_mailbox(self, mailbox: str):
        try:
            await self.email_client.select(mailbox=mailbox)
            if self.email_client.get_state() == "AUTH":
                raise EmailFolderSelectionError(
                    "Mail does not give access to the folder, likely IMAP is not enabled"
                )

        except TimeoutError:
            raise EmailFolderSelectionError(
                "Mail does not give access to the folder, timeout"
            )

    async def _close_connection(self):
        try:
            await self.email_client.logout()
        except Exception:
            pass
