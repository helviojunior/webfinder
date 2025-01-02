#!/usr/bin/python3
# -*- coding: UTF-8 -*-

from ..util.tools import Tools

import os, subprocess, socket, re, queue, threading, sys, time, json, hashlib

from ..config import Configuration
from ..util.logger import Logger
from ..util.getter import Getter

class PathGetter:

    words = []
    q = queue.Queue()
    added = []
    last_start = []
    ignore_until = ''
    current_getter = None
    current_uri = ''
    running=True
    duplicated=0
    last_item=""
    paused=True
    skip_current=False

    def __init__(self):
        pass

    def load_iplist(self):

        if Configuration.threads_data is not None:
            try:
                for i in Configuration.threads_data:
                    self.last_start.append(Configuration.threads_data[i])
            except:
                pass

        if Configuration.nmap_file != '':
            import xml.etree.ElementTree as xml
            tree = xml.parse(Configuration.nmap_file)
            root = tree.getroot()
            for h in root.iter('host'):
                dict_item = {
                    'valid': False,
                    'ports': []
                }
                if h.tag == 'host':
                    for c in h:
                        if c.tag == 'address':
                            if c.attrib['addr'] and c.attrib['addrtype'] == 'ipv4':
                                dict_item['ip'] = c.attrib['addr']

                        elif c.tag == 'hostnames':
                            for names in list(c):
                                if names.attrib['name']:
                                    dict_item['hostname'] = names.attrib['name']

                        elif c.tag == 'ports':
                            for port in list(c):
                                if port.tag == 'port' and port.attrib.get('protocol', '').lower() == "tcp":
                                    pi = int(port.attrib['portid'])
                                    for p in list(port):
                                        if p.tag == 'state' and p.attrib.get('state', '').lower() == "open":
                                            if pi not in dict_item['ports']:
                                                dict_item['ports'].append(pi)
                                        elif p.tag == 'service':
                                            if p.attrib['name'] == 'https' or p.attrib['name'] == 'http':
                                                dict_item['valid'] = True
                                            else:
                                                servicefp = p.attrib.get('servicefp', '')
                                                if 'HTTP/' in servicefp or 'SSL' in servicefp:
                                                    dict_item['valid'] = True

                if dict_item.get('valid', False) is False:
                    continue

                if dict_item.get('ip', '') == '' and dict_item.get('hostname', '') != '':
                    dict_item['ip'] = dict_item['hostname']

                if dict_item.get('ip', '') == '':
                    continue

                ip = dict_item['ip']
                for pi in dict_item['ports']:
                    line = f'{ip}:{pi}'

                    if self.ignore_until == '' and line in self.last_start:
                        self.ignore_until = line

                    if line not in Configuration.ipaddresses:
                        Configuration.ipaddresses.append(line.strip('\r\n\t').strip())
                        self.last_item = line

        else:
            with open(Configuration.ip_list, 'r', encoding="ascii", errors="surrogateescape") as f:
                line = f.readline()
                while line:
                    if line.endswith('\n'):
                        line = line[:-1]
                    if line.endswith('\r'):
                        line = line[:-1]

                    line = ''.join(filter(Tools.permited_char, line)).strip()

                    if self.ignore_until == '' and line in self.last_start:
                        self.ignore_until = line

                    if line not in Configuration.ipaddresses:
                        Configuration.ipaddresses.append(line.strip('\r\n\t').strip())
                        self.last_item = line
                    #else:
                    #    self.duplicated+=1

                    try:
                        line = f.readline()
                    except:
                        pass

    def len(self):
        return len(Configuration.ipaddresses)

    def run(self):

        t = threading.Thread(target=self.worker)
        t.daemon = True
        t.start()

        t_status = threading.Thread(target=self.status_worker)
        t_status.daemon = True
        t_status.start()

        count = 0
        with self.q.mutex:
            self.q.queue.clear()

        count += 1
        self.q.put(Configuration.target)

        #if len(list(self.q.queue)) > 0:
        if count > 0:
            self.paused = False

            self.q.join()  # block until all tasks are done
            sys.stdout.write("\033[K")  # Clear to the end of line

    def worker(self):
        try:
            while self.running:

                while self.paused:
                    time.sleep(0.3)

                item = self.q.get()

                self.current_uri = item
                self.current_getter = Getter(Configuration.ipaddresses, False)
                self.current_getter.ignore_until = self.ignore_until
                self.current_getter.run(item)

                if Configuration.verbose > 3:
                    Logger.pl('\n{*} {W}Finishing %s{W}' % item)

                self.ignore_until = ''
                self.q.task_done()
        except KeyboardInterrupt as e:
            raise e

    def testing_base(self):
        return self.current_uri == Configuration.target

    def pause(self):
        self.paused = True
        self.running = False
        self.save_status()
        self.current_getter.pause()

    def skip(self):
        self.ignore_until = ''
        self.save_status(True)
        self.running = False
        self.paused = False
        self.current_getter.stop()
        with self.q.mutex:
            self.q.queue.clear()

    def save_status(self, skip_current=False):
        paths_found = self.current_getter.path_found

        for u in paths_found:
            if u.endswith('/'):
                u = u[:-1]
            if u not in self.added:
                self.added.append(u)
                self.q.put(u)

        dt = {
            "command": Configuration.cmd_line,
            "current_path": self.current_uri,
            "skip_current": skip_current,
            "paths": self.added,
            "deep_links": Getter.deep_links,
            "threads": self.current_getter.last
         }

        with open("webfinder.restore", "w") as text_file:
            text_file.write(json.dumps(dt))

    def status_worker(self):
        try:
            while self.running:
                try:
                    if self.current_getter is None:
                        time.sleep(1)
                        continue

                    if self.paused:
                        time.sleep(1)
                        continue

                    self.save_status()

                except:
                    raise
                time.sleep(10)
        except KeyboardInterrupt:
            pass
            

