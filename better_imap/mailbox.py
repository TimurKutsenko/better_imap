import asyncio
import ssl
import re

from email import message_from_bytes
from email.utils import parsedate_to_datetime
from datetime import datetime, timedelta
from typing import Literal, Sequence, Callable
from bs4 import BeautifulSoup

import pytz
import aioimaplib

from .models import EmailMessage
from .errors import (
    IMAPSearchTimeout,
    IMAPLoginFailed,
)

from aioimaplib import IMAP4ClientProtocol, IMAP4_SSL
from python_socks.async_.asyncio import Proxy as ProxyClient
from python_socks import ProxyType
from better_proxy import Proxy


class IMAP4_PROXY_SSL(aioimaplib.IMAP4_SSL):
    def __init__(
        self,
        host: str = '127.0.0.1',
        port: int = 993,
        *,
        timeout: float = IMAP4_SSL.TIMEOUT_SECONDS,
        ssl_context: ssl.SSLContext = None,
        proxy: Proxy = None,
    ):
        self._proxy = proxy
        self._loop = asyncio.get_running_loop()

        if not ssl_context:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        super().__init__(host=host, port=port, timeout=timeout, ssl_context=ssl_context)

    def create_client(
        self,
        host: str,
        port: int,
        loop: asyncio.AbstractEventLoop,
        conn_lost_cb: Callable[[Exception | None], None] = None,
        ssl_context: ssl.SSLContext = None,
    ):
        self.protocol = IMAP4ClientProtocol(self._loop, conn_lost_cb)

        if ssl_context is None:
            ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

        if self._proxy:
            self._loop.create_task(
                self._proxy_connect(
                    loop or self._loop, lambda: self.protocol, ssl_context
                )
            )
        else:
            self._loop.create_task(
                self._loop.create_connection(
                    lambda: self.protocol, host, port, ssl=ssl_context
                )
            )

    async def _proxy_connect(
        self,
        loop: asyncio.AbstractEventLoop,
        protocol_factory,
        ssl_context: ssl.SSLContext | None = None,
    ):
        proxy_type_mapping = {
            "HTTP": ProxyType.HTTP,
            "SOCKS4": ProxyType.SOCKS4,
            "SOCKS5": ProxyType.SOCKS5,
        }
        proxy_type = proxy_type_mapping.get(self._proxy.protocol, ProxyType.HTTP)

        proxy_client = ProxyClient.create(
            proxy_type=proxy_type,
            host=self._proxy.host,
            port=self._proxy.port,
            username=self._proxy.login,
            password=self._proxy.password,
            loop=loop,
        )
        sock = await proxy_client.connect(
            self.host, self.port, timeout=self.timeout
        )
        await loop.create_connection(
            protocol_factory,
            sock=sock,
            ssl=ssl_context,
            server_hostname=self.host if ssl_context else None,
        )


class MailBox:
    def __init__(
        self,
        address: str,
        password: str,
        *,
        host: str,
        timeout: float = 30,
        encoding: str = "UTF-8",
        proxy: Proxy | str = None,
    ):
        self._address = address
        self._password = password
        self.encoding = encoding

        if host == "imap.rambler.ru" and "%" in self._password:
            raise IMAPLoginFailed(f"IMAP password contains '%' character. Change your password."
                                  f"It's a specific rambler.ru error")

        self.connected = False
        self.imap = IMAP4_PROXY_SSL(
            host=host,
            timeout=timeout,
            proxy=proxy,
        )

    async def __aenter__(self):
        await self._connect_to_mail()
        return self

    async def __aexit__(self, *args):
        await self.imap.logout()

    async def check_email(self, folders: Sequence[str]):
        await self._connect_to_mail()

        for mailbox in folders:
            await self.imap.select(mailbox=mailbox)

        await self.imap.logout()

    async def fetch_messages(
        self,
        folder: str,
        search_criteria: Literal["ALL", "UNSEEN"] = "ALL",
        receiver: str | None = None,
        sender_email: str = None,
        sender_email_regex: str | re.Pattern[str] = None,
        limit: int | None = None,
        since: datetime = None,
    ) -> list[EmailMessage]:
        await self._connect_to_mail()
        await self.imap.select(mailbox=folder)
        return await self._fetch_messages(
            search_criteria=search_criteria,
            sender_email=sender_email,
            sender_email_regex=sender_email_regex,
            receiver=receiver,
            limit=limit,
            since=since,
        )

    async def _fetch_messages(
        self,
        search_criteria: Literal["ALL", "UNSEEN"] = "ALL",
        sender_email: str = None,
        sender_email_regex: str | re.Pattern[str] = None,
        receiver: str | None = None,
        limit: int | None = None,
        since: datetime = None,
    ) -> list[EmailMessage]:

        if since:
            date_filter = since.strftime("%d-%b-%Y")
            search_criteria += f" SINCE {date_filter}"

        if sender_email:
            search_criteria += f' FROM "{sender_email}"'

        status, data = await self.imap.search(
            search_criteria, charset=self.encoding
        )

        if status != "OK":
            return []

        if not data[0]:
            return []

        email_ids = data[0].split()
        if limit:
            email_ids = email_ids[-limit:]

        email_ids = email_ids[::-1]
        messages = []
        for e_id_str in email_ids:
            email_message = await self._get_email(e_id_str.decode(self.encoding))

            if since and email_message.date < since:
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
        regex: str | re.Pattern[str],
        sender_email: str | None = None,
        sender_email_regex: str | re.Pattern[str] = None,
        receiver: str | None = None,
        limit: int = 10,
        start_date: datetime = None,
        hours_offset=24,
        return_latest_match=True,
        folders: Sequence[str] = ("INBOX", "Spam"),
    ) -> any | list[any] | None:
        if start_date is None:
            start_date = datetime.now(pytz.utc) - timedelta(hours=hours_offset)

        await self._connect_to_mail()

        matches = []

        for folder in folders:
            messages = await self.fetch_messages(
                folder=folder,
                search_criteria="ALL",
                sender_email=sender_email,
                sender_email_regex=sender_email_regex,
                receiver=receiver,
                limit=limit,
                since=start_date,
            )

            for message in messages:
                match = self.match_email_content(message.text, regex)

                if match:
                    matches.append((message, match))

        await self.imap.logout()

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
                sender_email=sender_email,
                sender_email_regex=sender_email_regex,
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

    async def _get_email(self, email_id) -> EmailMessage:
        typ, msg_data = await self.imap.fetch(email_id, "(RFC822)")
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

    async def _connect_to_mail(self, mailbox="INBOX"):
        if self.connected:
            return

        await self.imap.wait_hello_from_server()

        try:
            await self.imap.login(self._address, self._password)
            self.connected = True
        except aioimaplib.Abort as exc:
            if "command SELECT illegal in state NONAUTH" in str(exc):
                raise IMAPLoginFailed(
                    f"Email account banned or login/password incorrect or IMAP not enabled: {exc}"
                )

            raise IMAPLoginFailed(f"IMAP login failed: {exc}")

    @staticmethod
    def match_email_content(message_text: str, regex_pattern: str | re.Pattern[str]):
        matches = re.findall(regex_pattern, message_text)
        if matches:
            return matches[0]
        return None

    @staticmethod
    def extract_email_text(email_message):
        text_content = None
        html_content = None

        if email_message.is_multipart():
            for part in email_message.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))

                if "attachment" in content_disposition:
                    continue

                if content_type == "text/plain":
                    charset = part.get_content_charset() or "utf-8"
                    text_content = part.get_payload(decode=True).decode(
                        charset, errors="replace"
                    )
                elif content_type == "text/html":
                    charset = part.get_content_charset() or "utf-8"
                    html_content = part.get_payload(decode=True).decode(
                        charset, errors="replace"
                    )
        else:
            content_type = email_message.get_content_type()
            charset = email_message.get_content_charset() or "utf-8"

            if content_type == "text/plain":
                text_content = email_message.get_payload(decode=True).decode(
                    charset, errors="replace"
                )
            elif content_type == "text/html":
                html_content = email_message.get_payload(decode=True).decode(
                    charset, errors="replace"
                )

        if text_content and text_content.strip():
            cleaned_text = MailBox.clean_text(text_content)
            return cleaned_text
        elif html_content:
            soup = BeautifulSoup(html_content, "html.parser")
            text = soup.get_text()
            cleaned_text = MailBox.clean_text(text)
            return cleaned_text
        else:
            return ""

    @staticmethod
    def clean_text(text):
        text = text.strip()
        text = re.sub(r"\n\s*\n", "\n", text)
        lines = text.split("\n")
        lines = [line.strip() for line in lines if line.strip()]
        cleaned_text = "\n".join(lines)
        return cleaned_text
