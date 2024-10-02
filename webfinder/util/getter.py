#!/usr/bin/python3
# -*- coding: UTF-8 -*-

from ..util.tools import Tools

import os, subprocess, socket, re, requests, queue, threading, sys, operator, time, json

from bs4 import BeautifulSoup
from urllib.parse import urlparse

from ..config import Configuration
from ..util.logger import Logger
from ..util.ssl import HostSSLContext, HostHeaderSSLAdapter

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

        while(Getter.running):
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

        headers = {}

        headers = Configuration.user_headers
        if Configuration.user_agent:
            headers['User-Agent'] = Configuration.user_agent

        # Always define host header
        headers['Host'] = Configuration.host
        
        method=Configuration.request_method.upper()
        if force_method is not None:
            method = force_method.upper()

        url_p = urlparse(url)

        s = requests.Session()

        if url_p.scheme.lower() == "https":
            s.mount('https://', HostHeaderSSLAdapter())

        if method == "POST":
            return s.post(url, verify=False, timeout=30, data={}, headers=headers, allow_redirects=False, proxies=(proxy if proxy!=None else Getter.proxy))
        elif method == "PUT":
            return s.put(url, verify=False, timeout=30, data={}, headers=headers, allow_redirects=False, proxies=(proxy if proxy!=None else Getter.proxy))
        elif method == "OPTIONS":
            return s.options(url, verify=False, timeout=30, headers=headers, allow_redirects=False, proxies=(proxy if proxy!=None else Getter.proxy))
        else:
            return s.get(url, verify=False, timeout=30, headers=headers, allow_redirects=False, proxies=(proxy if proxy!=None else Getter.proxy))


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

        ret_ok = False
        uri = Configuration.base_target.replace('{ip}',ip)
        ret_ok = self.get_uri(uri)
        if Configuration.check_both:
            if 'https://' in uri.lower():
                self.get_uri(uri.replace('https://', 'http://'))
            else:
                self.get_uri(uri.replace('http://', 'https://'))


    def get_uri(self, url):

        if Getter.paused or not Getter.running:
            return

        ret_ok = False
        if Configuration.verbose > 4:
            Tools.clear_line()
            Logger.pl('{?} {G}Testing [%d/%d]: {O}%s{W}' % (Getter.checked,Getter.total,url))

        if not Configuration.full_log:
            Tools.clear_line()
            print(("Testing [%d/%d]: %s" % (Getter.checked,Getter.total,url)), end='\r', flush=True)
            pass
        
        try_cnt = 0
        while try_cnt < 5:
            try:

                r = Getter.general_request(url)
                if r is not None and r.status_code > 0:
                    ret_ok = True

                if Configuration.full_log or Configuration.verbose > 4:
                    self.raise_url(url, r.status_code, len(r.text))
                else:
                    self.chech_if_rise(url, r.status_code, len(r.text))

                try_cnt = 4
            except Exception as e:

                Tools.clear_line()
                if Configuration.verbose > 1:
                    Logger.pl('{*} {O}Error loading %s: %s{W}' % (url, e))
                    sys.exit(0)
                elif Configuration.verbose > 0:
                    Logger.pl('{*} {O}Error loading %s{W}' % url)
                pass

            if try_cnt >= 3:
                time.sleep( 0.2 * (try_cnt+1))
            try_cnt = try_cnt+1

            return ret_ok

    def chech_if_rise(self, url, status_code, size):

        if status_code == Configuration.main_code \
                and Configuration.main_min_length <= size <= Configuration.main_max_length:
            self.raise_url(url, status_code, size)

    def raise_url(self, url, status, len):

        Logger.pl('+ %s (CODE:%d|SIZE:%d) ' % (
            url, status, len))

        if Configuration.proxy_report_to != '':
            try:
                proxy={}

                proxy = {
                  'http': Configuration.proxy_report_to,
                  'https': Configuration.proxy_report_to,
                }
                
                Getter.general_request(url, proxy)

            except Exception as e:
                pass
