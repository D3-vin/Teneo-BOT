"""
Модуль с низкоуровневыми классами для работы с IMAP через прокси.
"""
import os
import ssl
import socket
from typing import Optional, Union
from imap_tools import MailBox
from imaplib import IMAP4, IMAP4_SSL
from better_proxy import Proxy
from python_socks.sync import Proxy as SyncProxy
# YAML config used for IMAP decisions in higher-level code; no direct import here


os.environ['SSLKEYLOGFILE'] = ''


class IMAP4Proxy(IMAP4):
    def __init__(
            self,
            host: str,
            proxy: str,
            *,
            port: int = 993,
            rdns: bool = True,
            timeout: float = None,
    ):
        self._host = host
        self._port = port
        self._proxy = proxy
        self._pysocks_proxy = SyncProxy.from_url(self._proxy, rdns=rdns)
        super().__init__(host, port, timeout)

    def _create_socket(self, timeout):
        return self._pysocks_proxy.connect(self._host, self._port, timeout)


class IMAP4SSlProxy(IMAP4Proxy):
    def __init__(
            self,
            host: str,
            proxy: str,
            *,
            port: int = 993,
            rdns: bool = True,
            ssl_context=None,
            timeout: float = None,
    ):
        self.ssl_context = ssl_context or ssl._create_unverified_context()
        super().__init__(host, proxy, port=port, rdns=rdns, timeout=timeout)

    def _create_socket(self, timeout):
        sock = super()._create_socket(timeout)
        server_hostname = self.host if ssl.HAS_SNI else None
        return self.ssl_context.wrap_socket(sock, server_hostname=server_hostname)


class MailBoxClient(MailBox):
    def __init__(
            self,
            host: str,
            *,
            proxy: Optional[str] = None,
            port: int = 993,
            timeout: float = None,
            rdns: bool = True,
            ssl_context=None,
            use_proxy: bool = None,
    ):
        self._proxy = proxy if use_proxy else None
        self._rdns = rdns
        super().__init__(host=host, port=port, timeout=timeout, ssl_context=ssl_context)

    def _get_mailbox_client(self):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        if self._proxy:
            return IMAP4SSlProxy(
                self._host,
                self._proxy,
                port=self._port,
                rdns=self._rdns,
                timeout=self._timeout,
                ssl_context=ssl_context,
            )
        else:
            return IMAP4_SSL(
                self._host,
                port=self._port,
                timeout=self._timeout,
                ssl_context=ssl_context,
            )