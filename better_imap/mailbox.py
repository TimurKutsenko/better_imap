from __future__ import annotations

from email import message_from_bytes
from email.utils import parsedate_to_datetime

import pytz
from better_proxy import Proxy

from better_imap.domains import determine_email_domain, EmailEncoding
from .email_exceptions import (
    EmailLoginError,
    EmailConnectionError,
    EmailFolderSelectionError,
)
from datetime import datetime, timedelta
from .imap_client import ImapProxyClient
import re
import asyncio


class MailBox:
    FOLDER_NAMES = ["INBOX", "Junk", "Spam"]

    def __init__(
        self,
        email_address: str,
        password: str,
        proxy: Proxy | None = None,
        imap_host: str | None = None,
        folder_names: list[str] = None,
        timeout: float = 30,
        encoding=EmailEncoding.UTF8,
    ):
        self._email_address = email_address
        self._password = password
        self.domain = determine_email_domain(email_address)
        self.imap_host, self.encoding = self.domain.imap_server_info()
        if not imap_host and not self.imap_host:
            raise EmailConnectionError(
                "Host not provided and domain does not have predefined imap server info"
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

    def __enter__(self):
        self._connect_to_mail()
        return self

    def __exit__(self, *args):
        self._close_connection()

    def _verify_data(self):
        if self.imap_host == "imap.rambler.ru" and "%" in self._password:
            raise Exception(
                f"IMAP password contains '%' character. Change your password"
            )

    async def _connect_to_mail(self, mailbox="INBOX"):
        try:
            await self.email_client.wait_hello_from_server()
        except Exception as e:
            raise EmailConnectionError(f"Email connection failed: {e}")
        try:
            await self.email_client.login(self._email_address, self._password)
            await self.email_client.select(mailbox=mailbox)
        except Exception as e:
            if "command SELECT illegal in state NONAUTH" in str(e):
                raise EmailLoginError(
                    f"Email account banned or login/password incorrect or IMAP not enabled: {e}"
                )

            raise EmailLoginError(f"Can not login to mail: {e}")

    async def check_email(self):
        await self._connect_to_mail()

        for mailbox in self.folder_names:
            await self._select_mailbox(mailbox)

        await self._close_connection()

    async def search_match(
        self,
        regex_pattern: str,
        from_email: str = None,
        hours_offset: int = 2,
        latest_messages: int = 10,
        start_date: datetime = None,
    ):
        if not regex_pattern:
            raise ValueError("Regex pattern must be provided to search for a match")

        if start_date is None:
            start_date = datetime.now(pytz.utc) - timedelta(hours=hours_offset)

        await self._connect_to_mail()

        matches = []

        for mailbox in self.folder_names:
            await self.email_client.select(mailbox=mailbox)
            match = await self._search_match(
                regex_pattern,
                "ALL",
                latest_messages,
                from_email,
                start_date,
            )
            if match:
                matches.append(match)

        await self._close_connection()
        return max(matches, key=lambda x: x[1])[0].strip() if matches else None

    async def search_with_retry(
        self,
        regex_pattern: str,
        from_email: str = None,
        start_date: datetime = None,
        timeout=90,
        interval=5,
        **kwargs,
    ):
        end_time = asyncio.get_event_loop().time() + timeout
        if start_date is None:
            start_date = datetime.now(pytz.utc) - timedelta(seconds=10)

        while asyncio.get_event_loop().time() < end_time:
            match = await self.search_match(
                regex_pattern=regex_pattern,
                from_email=from_email,
                start_date=start_date,
                latest_messages=5,
                **kwargs,
            )
            if match:
                return match
            await asyncio.sleep(interval)
        raise TimeoutError(f"No email received within {timeout} seconds")

    async def _search_match(
        self,
        regex_pattern: str,
        search_criteria="UNSEEN",
        latest_messages=10,
        from_email=None,
        start_date=None,
    ):

        if start_date is not None:
            date_filter = start_date.strftime("%d-%b-%Y")
            search_criteria += f" SINCE {date_filter}"

        if from_email:
            search_criteria += f' FROM "{from_email}"'

        status, data = await self.email_client.search(
            search_criteria, charset=self.encoding
        )
        if status != "OK" or not data[0]:
            return None

        email_ids = data[0].split()[-latest_messages:][::-1]
        for e_id_str in email_ids:
            email_data, message_text = await self._get_email(
                e_id_str.decode(self.encoding)
            )
            if not email_data:
                continue

            if start_date and email_data < start_date:
                continue

            if regex_pattern:
                match = self._find_first_match(regex_pattern, message_text)
                if match:
                    return match, email_data

    async def _get_email(self, email_id):
        typ, msg_data = await self.email_client.fetch(email_id, "(RFC822)")
        if typ == "OK":
            email_bytes = bytes(msg_data[1])
            email_message = message_from_bytes(email_bytes)
            email_date = parsedate_to_datetime(email_message.get("date"))

            if email_date.tzinfo is None:
                email_date = pytz.utc.localize(email_date)
            elif email_date.tzinfo != pytz.utc:
                email_date = email_date.astimezone(pytz.utc)

            message_text = self.extract_email_text(email_message)
            return email_date, message_text

    def _find_first_match(self, regex_pattern, message_text):
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
