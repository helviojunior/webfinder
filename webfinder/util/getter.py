#!/usr/bin/python3
# -*- coding: UTF-8 -*-
import datetime
from typing import Optional

from requests import Response

from ..util.tools import Tools

import os, subprocess, socket, re, requests, queue, threading, sys, operator, time, json

import os, re, sys, getopt, random
import sys, struct
import base64, string
import socket
import hashlib
from collections import defaultdict
from OpenSSL import SSL
from OpenSSL.crypto import dump_certificate, dump_publickey, FILETYPE_ASN1, FILETYPE_PEM

from urllib.parse import urlparse

from ..config import Configuration
from ..util.logger import Logger
from ..util.ssl import HostHeaderSSLAdapter


class Getter:

    '''Static variables'''
    path_found = []
    check_himself = False
    dir_not_found = 404
    not_found_lenght = -1
    checked = 0
    total = 0
    ingore_until = ''
    error_count = 0
    deep_links = []


    '''Local non-static variables'''
    q = queue.Queue()
    iplist = []
    base_url = ''
    last = {}
    running=True
    proxy={}
    paused=False

    def __init__(self, ip_list, check_himself = True):
        self.iplist = ip_list
        Getter.check_himself = check_himself
        Getter.checked = 0
        Getter.total = 0
        Getter.ingore_until = ''
        Getter.running=True

        requests.packages.urllib3.disable_warnings()
        requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'ALL:@SECLEVEL=1'

        Getter.proxy={}
        if Configuration.proxy != '':
            Getter.proxy = {
              'http': Configuration.proxy,
              'https': Configuration.proxy,
            }
        

        pass

    def pause(self):
        Getter.paused=True

    def add_checked(self):
        if Getter.checked < Getter.total:
            Getter.checked += 1

    def stop(self):
        Getter.running=False

    def run(self, base_url):
        Getter.paused = False
        Getter.running=True
        Getter.path_found = []
        Getter.base_url = base_url

        if Getter.base_url.endswith('/'):
            Getter.base_url = Getter.base_url [:-1]

        for i in range(Configuration.tasks):
            self.last[i] = ''
            t = threading.Thread(target=self.worker, kwargs=dict(index=i))
            t.daemon = True
            t.start()

        insert = True
        if self.ingore_until != '':
            insert = False

        with self.q.mutex:
            self.q.queue.clear()

        Getter.total = len(self.iplist)
        for item in self.iplist:
            if Getter.running and item.strip() != '':
                if not insert and item == self.ingore_until:
                    insert = True

                if insert:
                    self.q.put(item)
                else:
                    self.add_checked()

        self.q.join()  # block until all tasks are done

        while Getter.running:
            if len(self.q.queue) > 0:

                if Configuration.verbose > 5:
                    Logger.pl('{?} {G}Queue len: {O}%s{W}' % len(self.q.queue))

                time.sleep(0.3)
            else:
                Getter.running=False

        Tools.clear_line()

        return Getter.path_found

    @staticmethod
    def general_request(url, proxy=None, force_method=None):

        headers = Configuration.user_headers
        if Configuration.user_agent:
            headers['User-Agent'] = Configuration.user_agent

        # Always define host header
        headers['Host'] = Configuration.host
        headers['If-Modified-Since'] = (
                datetime.datetime.utcnow() - datetime.timedelta(hours=43800, minutes=50)).strftime("%c")

        method = Configuration.request_method.upper()
        if force_method is not None:
            method = force_method.upper()

        url_p = urlparse(url)

        s = requests.Session()

        if url_p.scheme.lower() == "https":
            s.mount('https://', HostHeaderSSLAdapter())

        if method == "POST":
            return s.post(url, verify=False, timeout=30, data={}, headers=headers, allow_redirects=True,
                          proxies=(proxy if proxy is not None else Getter.proxy))
        elif method == "PUT":
            return s.put(url, verify=False, timeout=30, data={}, headers=headers, allow_redirects=True,
                         proxies=(proxy if proxy is not None else Getter.proxy))
        elif method == "OPTIONS":
            return s.options(url, verify=False, timeout=30, headers=headers, allow_redirects=True,
                             proxies=(proxy if proxy is not None else Getter.proxy))
        else:
            return s.get(url, verify=False, timeout=30, headers=headers, allow_redirects=True,
                         proxies=(proxy if proxy is not None else Getter.proxy))

    def worker(self, index):
        try:
            while Getter.running:

                while Getter.paused:
                    time.sleep(1)
                    if not Getter.running:
                        return

                item = self.q.get()
                try:
                    ret_ok = self.do_work(item)
                    if ret_ok:
                        self.last[index] = item
                        Getter.error_count = 0
                    else:
                        Getter.error_count += 1
                except KeyboardInterrupt as e:
                    raise e
                finally:
                    self.q.task_done()

        except KeyboardInterrupt as e:
            raise e

    def do_work(self, ip):

        self.add_checked()

        if Configuration.verbose > 4:
            Logger.pl('{?} {G}Starting worker to: {O}%s{W}' % ip)

        uri = Configuration.base_target.replace('{ip}', ip)
        ret_ok = self.get_uri(uri)
        if Configuration.check_both:
            if 'https://' in uri.lower():
                self.get_uri(uri.replace('https://', 'http://'))
            else:
                self.get_uri(uri.replace('http://', 'https://'))

        return ret_ok

    def get_uri(self, url):

        if Getter.paused or not Getter.running:
            return

        ret_ok = False
        if Configuration.verbose > 4:
            Tools.clear_line()
            Logger.pl('{?} {G}Testing [%d/%d]: {O}%s{W}' % (Getter.checked, Getter.total, url))

        if not Configuration.full_log:
            Tools.clear_line()
            txt = url
            try:
                tmp = urlparse(url)
                txt = tmp.scheme.ljust(5, ' ') + ' ' + tmp.netloc
            except:
                pass

            print(("Testing [%d/%d]: %s" % (Getter.checked, Getter.total, txt)), end='\r', flush=True)
        
        try_cnt = 0
        while try_cnt < 5:
            try:

                r = Getter.general_request(url)
                if r is not None and r.status_code > 0:
                    ret_ok = True

                if Configuration.full_log or Configuration.verbose > 4:
                    self.log_url(url, r.status_code, len(r.text))

                self.check_if_rise(url, r.status_code, len(r.text), r)

                if Configuration.verbose > 5:
                    ht = '\r\n'.join([
                        f"  {k}: {v}"
                        for k, v in r.headers.items()
                        if k is not None and k.strip != ''
                    ])
                    Logger.pl('{*} Response header: \r\n{W}%s{W}\r\n\r\n' % ht)

                try_cnt = 4
            except Exception as e:

                Tools.clear_line()
                if Configuration.verbose > 1:
                    Logger.pl('{*} {O}Error loading %s: %s{W}' % (url, e))
                elif Configuration.verbose > 0:
                    Logger.pl('{*} {O}Error loading %s{W}' % url)
                pass

            if try_cnt >= 3:
                time.sleep(0.2 * (try_cnt+1))
            try_cnt = try_cnt+1

            return ret_ok

    def check_if_rise(self, url, status_code, size, response=None):

        if status_code not in Configuration.static_result:
            return

        is_valid = next(iter([
            i.is_valid_response(response)
            for i in Configuration.static_result[status_code]
        ]), False)

        if is_valid:

            server = Tools.get_host(url)
            pad = " " * (15 - len(server))
            scheme = str(urlparse(url).scheme).lower()

            waf = self.get_waf(url, response)
            if waf is not None:
                waf = '{R}* %s{W}' % waf
            else:
                waf = ''

            Tools.clear_line()
            Logger.pl('{W}Found: {O}%s{W} %s (SCHEME:%s|CODE:%d|SIZE:%d) %s' % (
                server, pad, scheme, status_code, size, waf))

            if Configuration.proxy_report_to != '':
                try:

                    proxy = {
                        'http': Configuration.proxy_report_to,
                        'https': Configuration.proxy_report_to,
                    }

                    Getter.general_request(url, proxy)

                except Exception as e:
                    pass

    @classmethod
    def log_url(cls, url, status, size):

        Logger.pl('+ %s (CODE:%d|SIZE:%d) ' % (
            url, status, size))

    @classmethod
    def get_waf(cls, url, response) -> Optional[str]:
        ht = ''
        try:
            if isinstance(response, Response):
                ht = '    \r\n'.join([
                    str(f"{k}: {v}").lower()
                    for k, v in response.headers.items()
                    if k is not None and k.strip != ''
                    and k.lower() != 'content-security-policy'
                ])
        except:
            return None

        try:
            for ws in Configuration.waf_list_short:
                if ws in ht:
                    waf = next(iter([
                        k
                        for k, v in Configuration.waf_list.items()
                        for n in v
                        if ws in n
                    ]), None)
                    if waf is not None:
                        return waf
        except:
            pass

        # Get by DNS
        try:
            host = Tools.get_host(url)
            ht = '\n'.join(socket.getnameinfo((host, 0), 0))
            for ws in Configuration.waf_list_short:
                if ws in ht:
                    waf = next(iter([
                        k
                        for k, v in Configuration.waf_list.items()
                        for n in v
                        if ws in n
                    ]), None)
                    if waf is not None:
                        return waf
        except:
            pass

        # Get by Standard Cert
        try:
            cert_data = ''
            host = Tools.get_host(url)
            uri = urlparse(url)
            port = 443
            if uri.scheme.lower() == 'https':

                try:
                    if ':' in uri.netloc:
                        port = int(uri.netloc.split(':')[1])
                except:
                    pass

                context = SSL.Context(method=SSL.TLS_CLIENT_METHOD)
                context.check_hostname = False

                conn = SSL.Connection(context, socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM))
                conn.settimeout(5)
                conn.connect((host, port))
                conn.setblocking(1)
                conn.do_handshake()
                conn.set_tlsext_host_name(host.encode())
                for (idx, cert) in enumerate(conn.get_peer_cert_chain()):
                    cert_data += f'{cls.get_509_name_str(cert.get_issuer())}\n'
                    cert_data += f'{cls.get_509_name_str(cert.get_subject())}\n'

                    san = cls.get_certificate_san(cert)
                    cert_data += f'{san}\n'

                conn.close()

                for ws in Configuration.waf_list_short:
                    if ws in cert_data:
                        waf = next(iter([
                            k
                            for k, v in Configuration.waf_list.items()
                            for n in v
                            if ws in n
                        ]), None)
                        if waf is not None:
                            return waf
        except:
            pass

        return None

    @classmethod
    def get_certificate_san(cls, x509cert):
        san = ''
        ext_count = x509cert.get_extension_count()
        for i in range(0, ext_count):
            ext = x509cert.get_extension(i)
            if 'subjectAltName' in str(ext.get_short_name()):
                san = ext.__str__()
        return san.lower()

    @classmethod
    def get_509_name_str(cls, name):
        try:
            return "".join("/{:s}={:s}".format(name.decode(), value.decode()) for name, value in name.get_components())
        except:
            return str(name)