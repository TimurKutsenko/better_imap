from typing import Callable, Optional
import asyncio
import ssl

from better_proxy import Proxy
from aioimaplib import IMAP4_SSL, IMAP4ClientProtocol, get_running_loop
from python_socks.async_.asyncio import Proxy as AsyncProxy


class IMAP4_SSL_PROXY(IMAP4_SSL):
    def __init__(self, *args, proxy: Proxy = None, **kwargs):
        self._proxy = proxy
        super().__init__(*args, **kwargs)

    def create_client(
        self,
        host: str,
        port: int,
        loop: asyncio.AbstractEventLoop,
        conn_lost_cb: Callable[[Optional[Exception]], None] = None,
        ssl_context: ssl.SSLContext = None,
    ):
        local_loop = loop if loop is not None else get_running_loop()

        if ssl_context is None:
            ssl_context = ssl.create_default_context()

            # В Украине нет доступа к Рамблеру без этих настроек
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        if not self._proxy:
            super().create_client(host, port, local_loop, conn_lost_cb, ssl_context)
            return

        async def create_connection():
            proxy = AsyncProxy.from_url(self._proxy.as_url)
            sock = await proxy.connect(dest_host=host, dest_port=port)
            await local_loop.create_connection(
                lambda: self.protocol, sock=sock, ssl=ssl_context, server_hostname=host
            )

        self.protocol = IMAP4ClientProtocol(local_loop, conn_lost_cb)
        local_loop.create_task(create_connection())
