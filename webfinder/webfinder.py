#!/usr/bin/python3
# -*- coding: UTF-8 -*-

try:
    from .config import Configuration
except (ValueError, ImportError) as e:
    raise Exception('You may need to run WebFinder from the root directory (which includes README.md)', e)


import sys, datetime, time, os, requests, socket
from .util.color import Color
from .util.logger import Logger
from .util.process import Process
from .util.pathgetter import PathGetter
from .util.tools import Tools
from .util.getter import Getter


class WebFinder(object):

    def main(self):
        ''' Either performs action based on arguments, or starts attack scanning '''

        self.dependency_check()

        Configuration.initialize()

        self.run()

    def dependency_check(self):
        ''' Check that required programs are installed '''
        required_apps = []
        optional_apps = []
        missing_required = False
        missing_optional = False

        for app in required_apps:
            if not Process.exists(app):
                missing_required = True
                Color.pl('{!} {R}error: required app {O}%s{R} was not found' % app)

        for app in optional_apps:
            if not Process.exists(app):
                missing_optional = True
                Color.pl('{!} {O}warning: recommended app {R}%s{O} was not found' % app)

        if missing_required:
            Color.pl('{!} {R}required app(s) were not found, exiting.{W}')
            sys.exit(-1)

        if missing_optional:
            Color.pl('{!} {O}recommended app(s) were not found')
            Color.pl('{!} {O}WebFinder may not work as expected{W}')

    def run(self):
        '''
            Main program.
            1) Scans for targets, asks user to select targets
            2) Attacks each target
        '''

        get = PathGetter()
        try:
            get.load_iplist()

            now = time.time()
            ts = int(now)
            timestamp = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
            Logger.pl('     {C}start time {O}%s{W}' % timestamp)
            if get.duplicated > 0:
                Logger.pl('     {C}duplicate {O}%d{C} ip addresses, duplicates ignored {O}%d{C} ips{W}' % (get.len(), get.duplicated))
            else:
                Logger.pl('     {C}duplicate {O}%d{C} ip addresse{W}' % get.len())
            Logger.pl(' ')

            Logger.pl('{+} {W}Connectivity checker{W}')
            ip = None
            try:

                proxy = {}
                if Configuration.proxy != '':
                    proxy = {
                      'http': Configuration.proxy,
                      'https': Configuration.proxy,
                    }

                ip = socket.gethostbyname(Configuration.host)
                r = Getter.general_request(Configuration.base_target.replace('{ip}', ip), proxy=proxy)

                Configuration.main_code = r.status_code
                Configuration.main_length = len(r.text)
                Configuration.main_min_length = float(Configuration.main_length) * 0.93
                Configuration.main_max_length = float(Configuration.main_length) * 1.07

                Logger.pl('{+} {W}Connection test against {C}%s{W} OK! (IP:%s|CODE:%d|SIZE:%d) ' %
                          (Configuration.target, ip, r.status_code, Configuration.main_length))

            except Exception as e:
                if Configuration.proxy != '':
                    Logger.pl('{!} {R}Error connecting to url {O}%s{R} using proxy {O}%s{W}' % (Configuration.target, Configuration.proxy))
                else:
                    Logger.pl('{!} {R}Error connecting to url {O}%s{R} without proxy{W}' % (Configuration.target))
                
                raise e

            if Configuration.proxy_report_to != '':
                try:
                    proxy = {
                      'http': Configuration.proxy_report_to,
                      'https': Configuration.proxy_report_to,
                    }
                    
                    headers = Configuration.user_headers
                    if Configuration.user_agent:
                        headers['User-Agent'] = Configuration.user_agent

                    r = Getter.general_request(Configuration.base_target.replace('{ip}', ip), proxy=proxy)

                    Logger.pl('{+} {W}Connection test against using report to proxy {C}%s{W} OK! (CODE:%d|SIZE:%d) ' %
                              (Configuration.target, r.status_code, len(r.text)))

                except Exception as e:
                    Logger.pl('{!} {R}Error connecting to url {O}%s{R} using {G}report to{R} proxy {O}%s{W}' %
                              (Configuration.target, Configuration.proxy_report_to))
                    raise e

            Logger.pl('{*} {W}Scanning IP address for {C}%s{W} ' % Configuration.target)

            Logger.pl('     ')

        except Exception as e:
            Color.pl("\n{!} {R}Error: {O}%s" % str(e))
            if Configuration.verbose > 1:
                Color.pl('\n{!} {O}Full stack trace below')
                from traceback import format_exc
                Color.p('\n{!}    ')
                err = format_exc().strip()
                err = err.replace('\n', '\n{W}{!} {W}   ')
                err = err.replace('  File', '{W}{D}File')
                err = err.replace('  Exception: ', '{R}Exception: {O}')
                Color.pl(err)
            Configuration.exit_gracefully(1)

        testing = True
        while testing:
            try:
                get.run()
                Logger.pl('     ')

                if os.path.exists("webfinder.restore"):
                    os.remove("webfinder.restore")

                testing = False
            except Exception as e:
                Color.pl("\n{!} {R}Error: {O}%s" % str(e))
                if Configuration.verbose > 0 or True:
                    Color.pl('\n{!} {O}Full stack trace below')
                    from traceback import format_exc
                    Color.p('\n{!}    ')
                    err = format_exc().strip()
                    err = err.replace('\n', '\n{W}{!} {W}   ')
                    err = err.replace('  File', '{W}{D}File')
                    err = err.replace('  Exception: ', '{R}Exception: {O}')
                    Color.pl(err)
                    testing = False
            except KeyboardInterrupt:
                #Color.pl('\n{!} {O}interrupted{W}\n')
                get.pause() # save status and pause the test

                Tools.clear_line()
                print(" ")

                Color.pl('\n{!} {O}interrupted{W}\n')
                testing = False

        now = time.time()
        ts = int(now)
        timestamp = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        Logger.pl('{+} {C}End time {O}%s{W}' % timestamp)

        Logger.pl("{+} Finished tests against {C}%s{W}, exiting" % Configuration.target)

        #Configuration.delete_temp()

    def print_banner(self):
        """ Displays ASCII art of the highest caliber.  """
        Color.pl(Configuration.get_banner())


def run():
    requests.packages.urllib3.disable_warnings()

    o = WebFinder()
    o.print_banner()

    try:
        o.main()

    except Exception as e:
        Color.pl('\n{!} {R}Error:{O} %s{W}' % str(e))

        if Configuration.verbose > 0 or True:
            Color.pl('\n{!} {O}Full stack trace below')
            from traceback import format_exc
            Color.p('\n{!}    ')
            err = format_exc().strip()
            err = err.replace('\n', '\n{W}{!} {W}   ')
            err = err.replace('  File', '{W}{D}File')
            err = err.replace('  Exception: ', '{R}Exception: {O}')
            Color.pl(err)

        Color.pl('\n{!} {R}Exiting{W}\n')

    except KeyboardInterrupt:
        Color.pl('\n{!} {O}interrupted, shutting down...{W}')

    Configuration.exit_gracefully(0)


if __name__ == '__main__':
    run()
