#!/usr/bin/python3
# -*- coding: UTF-8 -*-

from .util.color import Color

import argparse, sys, os

class Arguments(object):
    ''' Holds arguments used by the Turbo Search '''
    restore = False

    def __init__(self, custom_args=''):
        self.verbose = any(['-v' in word for word in sys.argv])
        self.restore = any(['-R' in word for word in sys.argv])
        self.args = self.get_arguments(custom_args)

    def _verbose(self, msg):
        if self.verbose:
            return Color.s(msg)
        else:
            return argparse.SUPPRESS

    def get_arguments(self, custom_args=''):
        ''' Returns parser.args() containing all program arguments '''

        parser = argparse.ArgumentParser(usage=argparse.SUPPRESS,
                formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=80, width=130))

        glob = parser.add_argument_group('General Setting')
        self._add_global_args(glob)

        custom_group = parser.add_argument_group('Custom Settings')
        self._add_custom_args(custom_group)


        if self.restore and not custom_args == "":
            targs = custom_args.split()
            targs.pop(0) # remove o path do arquivo python, mantendo somente os parametros
            return parser.parse_args(targs)
        else:
            return parser.parse_args()

    def _add_global_args(self, glob):
        glob.add_argument('-t',
            action='store',
            dest='target',
            metavar='[target url]',
            type=str,
            help=Color.s('target url (ex: {G}http://10.10.10.10/path{W})'))

        glob.add_argument('-ip',
            action='store',
            dest='ip_list',
            metavar='[ip address list]',
            type=str,
            help=Color.s('list of IP address to be tested'))

        glob.add_argument('-T',
            action='store',
            dest='tasks',
            default=16,
            metavar='[tasks]',
            type=int,
            help=Color.s('number of connects in parallel (per host, default: {G}16{W})'))

        glob.add_argument('-o',
            action='store',
            dest='out_file',
            metavar='[output file]',
            type=str,
            help=Color.s('save output to disk (default: {G}none{W})'))

    def _add_custom_args(self, custom):
        custom.add_argument('-R',
            '--restore',
            action='store_true',
            default=False,
            dest='restore',
            help=Color.s('restore a previous aborted/crashed session'))

        custom.add_argument('-I',
            action='store_true',
            default=False,
            dest='ignore',
            help=Color.s('ignore an existing restore file (don\'t wait 10 seconds)'))

        custom.add_argument('--static',
            action='store',
            dest='static',
            metavar='[expected result]',
            type=str,
            help=Color.s('force result by result code or/and size (ex1: 200 or ex2: 200:47)'))

        custom.add_argument('--proxy',
            action='store',
            dest='proxy',
            metavar='[target proxy]',
            type=str,
            help=Color.s('target proxy URL (ex: {G}http://127.0.0.1:8080{W})'))

        custom.add_argument('--report-to',
            action='store',
            dest='report_to',
            metavar='[target proxy]',
            type=str,
            help=Color.s('target proxy URL to report only successful requests (ex: {G}http://127.0.0.1:8080{W})'))

        custom.add_argument('-v',
            '--verbose',
            action='count',
            default=0,
            dest='verbose',
            help=Color.s('Shows more options ({C}-h -v{W}). Prints commands and outputs. (default: {G}quiet{W})'))

        custom.add_argument('--full-log',
            action='store_true',
            dest='full_log',
            help=Color.s('Print full requested URLs (default: {G}no{W})'))

        custom.add_argument('--check-both',
            action='store_true',
            dest='check_both',
            default=False,
            help=Color.s('Check Both Schemes (HTTP and HTTPS) (default: {G}no{W})'))

        custom.add_argument('--method',
            action='store',
            dest='request_method',
            metavar='[http method]',
            default='GET',
            type=str,
            help=Color.s('Specify request method (default: {G}GET{W}). Available methods: {G}GET{W}, {G}POST{W}, {G}PUT{W}, {G}OPTIONS{W}'))

        custom.add_argument('--random-agent',
            action='store_true',
            default=False,
            dest='random_agent',
            help=Color.s('Use randomly selected HTTP User-Agent header value (default: {G}no{W})'))
        
        custom.add_argument('--header',
            action='store',
            dest='header',
            metavar='[text to find]',
            default='',
            type=str,
            help=Color.s('JSON-formatted header key/value'))

        custom.add_argument('--no-content-type',
                            action='store_true',
                            default=False,
                            dest='no_content_type',
                            help=Color.s('Disable content-type checker (default: {G}no{W})'))

        custom.add_argument('--no-entropy',
                            action='store_true',
                            default=False,
                            dest='no_entropy',
                            help=Color.s('Disable entropy checker (default: {G}no{W})'))