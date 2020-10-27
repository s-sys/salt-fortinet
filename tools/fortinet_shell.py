#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pylint: disable=wrong-import-position,W1699
'''
Interactive shell to access the Fortinet API
'''

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../salt/salt/_modules/python')))

from IPython.terminal.embed import InteractiveShellEmbed

import fortiapi


USER = ''
PASS = ''
HOST = ''
PORT = ''


if __name__ == '__main__':
    os.environ['no_proxy'] = '*'

    with fortiapi.FortiAPI(USER, PASS, HOST, PORT) as fortinet:
        InteractiveShellEmbed()()
