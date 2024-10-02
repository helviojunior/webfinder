#!/usr/bin/python3
# -*- coding: UTF-8 -*-

import string, random, sys, re
from urllib.parse import urlparse

class Tools:

    def __init__(self):
        pass

    @staticmethod
    def random_generator(size=6, chars=string.ascii_uppercase + string.digits):
        return ''.join(random.choice(chars) for x in range(size))


    @staticmethod
    def clear_line():
        sys.stdout.write("\033[K")  # Clear to the end of line

    @staticmethod     
    def permited_char(s):
        if s.isalpha():
            return True
        elif bool(re.match("^[A-Za-z0-9:]*$", s)):
            return True
        elif s == ".":
            return True
        else:
            return False

    @staticmethod
    def get_host(url):
        rUri = urlparse(url)
        host = rUri.netloc.strip(': ')
        if ':' in host:
            host = host.split(':')[0]
        return host
