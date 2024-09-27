from __future__ import annotations

import ssl

from aioimaplib import IMAP4ClientProtocol, IMAP4_SSL
import asyncio

from .email_exceptions import EmailConnectionError
from python_socks.async_.asyncio import Proxy as ProxyClient
from python_socks._errors import (
    ProxyConnectionError as SocksProxyConnectionError,
    ProxyError,
    ProxyTimeoutError,
)
from python_socks import ProxyType
from typing import Optional, Callable
from better_proxy import Proxy


class ImapProxyClient(IMAP4_SSL):
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 993,
        timeout: float = IMAP4_SSL.TIMEOUT_SECONDS,
        ssl_context: ssl.SSLContext = None,
        proxy: Optional[Proxy] = None,
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
        conn_lost_cb: Callable[[Optional[Exception]], None] = None,
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
        try:
            sock = await proxy_client.connect(
                self.host, self.port, timeout=self.timeout
            )
            await loop.create_connection(
                protocol_factory,
                sock=sock,
                ssl=ssl_context,
                server_hostname=self.host if ssl_context else None,
            )
        except (ProxyError, SocksProxyConnectionError, ProxyTimeoutError) as e:
            raise EmailConnectionError("Proxy connection error", str(e))
