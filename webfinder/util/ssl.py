# Source
# https://yzlin.medium.com/python-requests-ssl-ip-binding-6df25a9a8f6a

import ssl

import requests
from requests.adapters import HTTPAdapter


class HostSSLContext(ssl.SSLContext):
    """
    A SSL Context for wrapping socket with specific hostname for requesting certificate.
    """

    def __new__(cls, hostname):
        self = super(HostSSLContext, cls).__new__(cls, protocol=ssl.PROTOCOL_TLS_CLIENT)
        self.check_hostname = False
        self.options |= 0x4  # => Enable UNSAFE LEGACY RENEGOTIATION
        return self

    def __init__(self, hostname):
        super(HostSSLContext, self).__init__()
        self._hostname = hostname
        self.check_hostname = False
        self.options |= 0x4  # => Enable UNSAFE LEGACY RENEGOTIATION

        # Disable SSLv2 & SSLv3
        # Refer to https://docs.python.org/2/library/ssl.html#security-considerations
        # for more details.
        #self.options |= ssl.OP_NO_SSLv2
        #self.options |= ssl.OP_NO_SSLv3

    def change_server_hostname(self, hostname):
        self._hostname = hostname

    def wrap_socket(self, *args, **kwargs):
        kwargs['server_hostname'] = self._hostname
        return super(HostSSLContext, self).wrap_socket(*args, **kwargs)


class HostHeaderSSLAdapter(HTTPAdapter):
    """
    A HTTPS Adapter for Python Requests that sets the hostname for certificate
    verification based on the Host header.
    This allows requesting the IP address directly via HTTPS without getting
    a "hostname doesn't match" exception.
    Example usage:
        >>> s.mount('https://', HostHeaderSSLAdapter())
        >>> s.get("https://93.184.216.34", headers={"Host": "example.org"})
    """

    _hostname = None

    def send(self, request, **kwargs):
        # HTTP headers are case-insensitive (RFC 7230)
        hostname = None
        for header in request.headers:
            if header.lower() == 'host':
                hostname = request.headers[header]
                break

        if hostname and self._hostname != hostname:
            self._hostname = hostname
            context = HostSSLContext(hostname)
            self.init_poolmanager(self._pool_connections, self._pool_maxsize, block=self._pool_block,
                                  ssl_context=context)

        connection_pool_kwargs = self.poolmanager.connection_pool_kw

        if hostname:
            connection_pool_kwargs['assert_hostname'] = hostname
        elif 'assert_hostname' in connection_pool_kwargs:
            # cleanup previous SSL host binding
            connection_pool_kwargs.pop('assert_hostname', None)
            if self._hostname:
                self._hostname = None
                self.init_poolmanager(self._pool_connections, self._pool_maxsize, block=self._pool_block)

        return super(HostHeaderSSLAdapter, self).send(request, **kwargs)