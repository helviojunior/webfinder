#!/usr/bin/python3
# -*- coding: UTF-8 -*-

import os, subprocess, socket, re, requests, errno, sys, time, json, signal, base64, hashlib, random
from pathlib import Path
from urllib.parse import urlparse

from webfinder.result_pattern import ResultPattern
from .args import Arguments
from .util.color import Color
from .util.logger import Logger
from .util.database import Database
from .__meta__ import __version__, __description__, __url__


class Configuration(object):
    ''' Stores configuration variables and functions for Turbo Search. '''
    version = '0.0.0'

    initialized = False  # Flag indicating config has been initialized
    verbose = 0
    target = ''
    ip_list = ''
    out_file = ''
    full_log = False
    cmd_line = ''
    restore = ''
    restored_uri = ''
    restored_paths = []
    threads_data = {}
    proxy = ''
    host = ''
    proxy_report_to = ''
    request_method = 'GET'
    user_agent = ''
    user_headers = {}
    ipaddresses = []
    skip_current = False
    db = None
    statsdb = False
    check_both = False
    base_target = False
    waf_list = {}
    waf_list_short = []
    static_result = {}
    no_content_type = False
    no_entropy = False

    @staticmethod
    def initialize():
        '''
            Sets up default initial configuration values.
            Also sets config values based on command-line arguments.
        '''

        # Only initialize this class once
        if Configuration.initialized:
            return

        Configuration.initialized = True

        Configuration.verbose = 0  # Verbosity level.
        Configuration.print_stack_traces = True

        # Overwrite config values with arguments (if defined)
        Configuration.load_from_arguments()

    @staticmethod
    def load_from_arguments():
        ''' Sets configuration values based on Argument.args object '''
        from .args import Arguments

        config_check = 0

        sys.argv[0] = 'webfinder'

        force_restore = any(['-R' == word for word in sys.argv])
        show_help = any(['-h' == word for word in sys.argv])

        if show_help:
            args = Arguments().args
        else:

            Configuration.cmd_line = ' '.join([
                a if ' ' not in a else f"\"{a}\""
                for a in sys.argv
                if a != "-I"
            ])

            if not force_restore and os.path.exists("webfinder.restore"):
                ignore = any(['-I' in word for word in sys.argv])
                if not ignore:
                    Color.pl('{!} {W}Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./webfinder.restore')
                    time.sleep(10)
                os.remove("webfinder.restore")

            args = {}
            if os.path.exists("webfinder.restore"):
                try:
                    with open("webfinder.restore", 'r') as f:
                        restore_data = json.load(f)
                        Configuration.cmd_line = restore_data["command"]
                        Configuration.threads_data = restore_data["threads"]

                except Exception as e:
                    Color.pl('{!} {R}error: invalid restore file\r\n')
                    raise

                args = Arguments(Configuration.cmd_line).args

            else:
                args = Arguments().args

        Color.pl('{+} {W}Startup parameters')

        Logger.pl('     {C}command line:{O} %s{W}' % Configuration.cmd_line)

        if args.target:
            from .util.tools import Tools

            Configuration.target = args.target
            if Configuration.target.endswith('/'):
                Configuration.target = Configuration.target[:-1]

            #rUri = urlparse(Configuration.target)
            #Configuration.host = rUri.netloc
            #if ':' in Configuration.host:
            #    Configuration.host = Configuration.host.split(':')[0]
            Configuration.host = Tools.get_host(Configuration.target)
            Configuration.base_target = Configuration.target.replace(Configuration.host, '{ip}')

        if args.tasks:
            Configuration.tasks = args.tasks

        if args.ip_list:
            Configuration.ip_list = args.ip_list

        if args.verbose:
            Configuration.verbose = args.verbose

        if args.out_file:
            Configuration.out_file = args.out_file

        if args.check_both:
            Configuration.check_both = args.check_both

        if args.tasks:
            Configuration.tasks = args.tasks

        if Configuration.tasks < 1:
            Configuration.tasks = 1

        if Configuration.tasks > 256:
            Configuration.tasks = 256

        if Configuration.target == '':
            config_check = 1

        if Configuration.ip_list == '':
            config_check = 1

        if config_check == 1:
            Configuration.mandatory()

        if args.full_log:
            Configuration.full_log = args.full_log

        if args.proxy:
            Configuration.proxy = args.proxy

        if args.report_to:
            Configuration.proxy_report_to = args.report_to

        if args.no_content_type:
            Configuration.no_content_type = args.no_content_type

        if args.no_entropy:
            Configuration.no_entropy = args.no_entropy

        if args.request_method.upper() == "POST":
            Configuration.request_method = "POST"
        elif args.request_method.upper() == "PUT":
            Configuration.request_method = "PUT"
        elif args.request_method.upper() == "OPTIONS":
            Configuration.request_method = "OPTIONS"
        else:
            Configuration.request_method = "GET"

        if args.random_agent:
            try:
                
                with open(str(Path(__file__).parent) + "/resources/user_agents.txt", 'r') as f:
                    # file opened for writing. write to it here
                    line = next(f)
                    for num, aline in enumerate(f, 2):
                        if random.randrange(num):
                            continue
                        if aline.strip("\r\n").strip() == '':
                            continue
                        Configuration.user_agent = aline.strip("\r\n").strip()
                    
            except IOError as x:
                if x.errno == errno.EACCES:
                    Color.pl('{!} {R}error: could not open ./resources/user_agents.txt {O}permission denied{R}{W}\r\n')
                    Configuration.exit_gracefully(0)
                elif x.errno == errno.EISDIR:
                    Color.pl('{!} {R}error: could not open ./resources/user_agents.txt {O}it is an directory{R}{W}\r\n')
                    Configuration.exit_gracefully(0)
                else:
                    Color.pl('{!} {R}error: could not open ./resources/user_agents.txt{W}\r\n')
                    Configuration.exit_gracefully(0)

        # get list of WAF
        try:

            with open(str(Path(__file__).parent) + "/resources/waf_headers.json", 'r') as f:
                tmp_waf_list = json.loads(f.read())

                if not isinstance(tmp_waf_list, dict):
                    raise Exception("Invalid dictionary!")

                Configuration.waf_list = {
                    k: [
                        str(n).lower()
                        for n in v
                    ]
                    for k, v in tmp_waf_list.items()
                }
                Configuration.waf_list_short = [
                    str(v).lower()
                    for k, vl in tmp_waf_list.items()
                    for v in vl
                ]

        except IOError as x:
            if x.errno == errno.EACCES:
                Color.pl('{!} {R}error: could not open ./resources/waf_headers.json {O}permission denied{R}{W}\r\n')
                Configuration.exit_gracefully(0)
            elif x.errno == errno.EISDIR:
                Color.pl('{!} {R}error: could not open ./resources/waf_headers.json {O}it is an directory{R}{W}\r\n')
                Configuration.exit_gracefully(0)
            else:
                Color.pl('{!} {R}error: could not open ./resources/waf_headers.json{W}\r\n')
                Configuration.exit_gracefully(0)
        except Exception as e:
            Color.pl('{!} {R}error: could not parse ./resources/waf_headers.json {O}%s{W}\r\n' % str(e))
            Configuration.exit_gracefully(0)

        if args.header != '':
            jData = {}
            try:
                jData=json.loads(args.header)
            except:
                Logger.pl('{!} {R}error: could not convert header value {O}%s{R} from an JSON object {W}\r\n' % (args.header))
                Configuration.exit_gracefully(0)

            Configuration.user_headers = {}
            try:
                for k in jData:
                    if isinstance(k, str):
                        if isinstance(jData[k], str):
                            if k.lower().find("user-agent") != -1:
                                Configuration.user_agent = jData[k]
                            elif k.lower().find("host") != -1:
                                pass
                            elif k.lower().find("connection") != -1:
                                pass
                            elif k.lower().find("accept") != -1:
                                pass
                            elif k.lower().find("accept-encoding") != -1:
                                pass
                            else:
                                Configuration.user_headers[k] = jData[k]
                        else:
                            raise Exception("The value of %s id not an String" % k)
                    else:
                        raise Exception("%s id not an String" % k)
            except Exception as e:
                Logger.pl('{!} {R}error: could parse header data: {R}%s{W}\r\n' % (str(e)))
                Configuration.exit_gracefully(0)

        regex = re.compile(
            r'^(?:http|ftp)s?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)

        if re.match(regex, Configuration.target) is None:
            Color.pl('{!} {R}error: invalid target {O}%s{R}{W}\r\n' % Configuration.target)
            Configuration.exit_gracefully(0)

        if Configuration.proxy != '' and re.match(regex, Configuration.proxy) is None:
            Color.pl('{!} {R}error: invalid proxy {O}%s{R}{W}\r\n' % Configuration.proxy)
            Configuration.exit_gracefully(0)

        if Configuration.proxy_report_to != '' and re.match(regex, Configuration.proxy_report_to) is None:
            Color.pl('{!} {R}error: invalid report to proxy {O}%s{R}{W}\r\n' % Configuration.proxy_report_to)
            Configuration.exit_gracefully(0)

        if not os.path.isfile(Configuration.ip_list):
            Color.pl('{!} {R}error: word list file not found {O}%s{R}{W}\r\n' % Configuration.ip_list)
            Configuration.exit_gracefully(0)

        if Configuration.out_file != '':
            try:
                with open(Configuration.out_file, 'a') as f:
                    # file opened for writing. write to it here
                    Logger.out_file = Configuration.out_file
                    f.write(Color.sc(Configuration.get_banner()) + '\n')
                    f.write(Color.sc('{+} {W}Startup parameters') + '\n')
                    pass
            except IOError as x:
                if x.errno == errno.EACCES:
                    Color.pl('{!} {R}error: could not open output file to write {O}permission denied{R}{W}\r\n')
                    Configuration.exit_gracefully(0)
                elif x.errno == errno.EISDIR:
                    Color.pl('{!} {R}error: could not open output file to write {O}it is an directory{R}{W}\r\n')
                    Configuration.exit_gracefully(0)
                else:
                    Color.pl('{!} {R}error: could not open output file to write{W}\r\n')
                    Configuration.exit_gracefully(0)

        try:
            with open(Configuration.ip_list, 'r') as f:
                # file opened for writing. write to it here
                pass
        except IOError as x:
            if x.errno == errno.EACCES:
                Logger.pl('{!} {R}error: could not open word list file {O}permission denied{R}{W}\r\n')
                Configuration.exit_gracefully(0)
            elif x.errno == errno.EISDIR:
                Logger.pl('{!} {R}error: could not open word list file {O}it is an directory{R}{W}\r\n')
                Configuration.exit_gracefully(0)
            else:
                Logger.pl('{!} {R}error: could not open word list file {W}\r\n')
                Configuration.exit_gracefully(0)

        if args.static is not None and args.static != '':
            static_list = args.static.split(",")
            for static_line in static_list:

                static_line = static_line.strip()
                if ':' in static_line:
                    i_result, i_size = static_line.split(":")
                    size = 0
                    res = 0
                    try:
                        res = int(i_result)
                    except:
                        Logger.pl(
                            '{!} {R}error: could not convert {O}%s{R} from {O}%s{R} to an integer value {W}\r\n' % (
                                i_result, static_line))
                        Configuration.exit_gracefully(0)

                    try:
                        size = int(i_size)
                    except:
                        Logger.pl(
                            '{!} {R}error: could not convert {O}%s{R} from {O}%s{R} to an integer value {W}\r\n' % (
                                i_size, static_line))
                        Configuration.exit_gracefully(0)

                    if res not in Configuration.static_result:
                        Configuration.static_result[res] = []
                    Configuration.static_result[res].append(ResultPattern(status_code=res, length=size))

                else:
                    res = 0
                    try:
                        res = int(static_line)
                    except:
                        Logger.pl(
                            '{!} {R}error: could not convert {O}%s{R} to an integer value {W}\r\n' % static_line)
                        Configuration.exit_gracefully(0)

                    if res not in Configuration.static_result:
                        Configuration.static_result[res] = []
                    Configuration.static_result[res].append(ResultPattern(status_code=res))

        Logger.pl('     {C}target:{O} %s{W}' % Configuration.target)
        Logger.pl('     {C}host:{O} %s{W}' % Configuration.host)

        if Configuration.proxy != '':
            Logger.pl('     {C}Proxy:{O} %s{W}' % Configuration.proxy)

        Logger.pl('     {C}tasks:{O} %s{W}' % Configuration.tasks)

        if args.verbose:
            Logger.pl('     {C}option:{O} verbosity level %d{W}' % Configuration.verbose)

        Logger.pl('     {C}request method: {O}%s{W}' % Configuration.request_method)

        if Configuration.user_agent:
            Logger.pl('     {C}user agent: {O}%s{W}' % Configuration.user_agent)

        Logger.pl('     {C}ip address list:{O} %s{W}' % Configuration.ip_list)

        if Configuration.out_file != '':
            Logger.pl('     {C}output file:{O} %s{W}' % Configuration.out_file)

        Logger.pl('     {C}content-type checker:{O} %s{W}' %
                  ('Disabled' if Configuration.no_content_type else 'Enabled'))

        Logger.pl('     {C}entropy checker:{O} %s{W}' %
                  ('Disabled' if Configuration.no_entropy else 'Enabled'))

    @staticmethod
    def get_banner():
        """ Displays ASCII art of the highest caliber.  """

        Configuration.version = str(__version__)

        return '''\
    {W}{D}
     _       __     __       _______           __         
    | |     / /__  / /_     / ____(_)___  ____/ /__  _____
    | | /| / / _ \\/ __ \\   / /_  / / __ \\/ __  / _ \\/ ___/
    | |/ |/ /  __/ /_/ /  / __/ / / / / / /_/ /  __/ /    
    |__/|__/\\___/_.___/  / /   /_/_/ /_/\\__,_/\\___/_/     
                        /_/    {G}{D}v%s{W}{G} by M4v3r1ck{W}                                           

    {W}{D}%s{W}
    {C}{D}%s{W}

    ''' % (Configuration.version, __description__, __url__)

    @staticmethod
    def mandatory():
        Color.pl('{!} {R}error: missing a mandatory option ({O}-t and -ip{R}){G}, use -h help{W}\r\n')
        Configuration.exit_gracefully(0)

    @staticmethod
    def exit_gracefully(code=0):
        ''' Deletes temp and exist with the given code '''

        exit(code)


    @staticmethod
    def kill(code=0):
        ''' Deletes temp and exist with the given code '''

        os.kill(os.getpid(),signal.SIGTERM)


    @staticmethod
    def dump():
        ''' (Colorful) string representation of the configuration '''
        from .util.color import Color

        max_len = 20
        for key in Configuration.__dict__.keys():
            max_len = max(max_len, len(key))

        result  = Color.s('{W}%s  Value{W}\n' % 'Configuration Key'.ljust(max_len))
        result += Color.s('{W}%s------------------{W}\n' % ('-' * max_len))

        for (key,val) in sorted(Configuration.__dict__.items()):
            if key.startswith('__') or type(val) == staticmethod or val is None:
                continue
            result += Color.s("{G}%s {W} {C}%s{W}\n" % (key.ljust(max_len),val))
        return result


if __name__ == '__main__':
    Configuration.initialize()
    print(Configuration.dump())
