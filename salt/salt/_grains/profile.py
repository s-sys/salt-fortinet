#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Salt grain to get the minion's profile
'''

from __future__ import absolute_import

import salt.utils.platform
import salt.utils.files


def __virtual__():
    '''
    Executes only in Linux
    '''
    if salt.utils.platform.is_linux():
        return True
    return False


def read_profile():
    '''
    Read the profile from /etc/profile
    '''
    grains = {'profile': 'profile1'}

    try:
        with salt.utils.files.fopen('/etc/profile', 'r') as file:
            grains['profile'] = file.readline().strip()
    except:  # pylint: disable=bare-except
        pass

    return grains


if __name__ == '__main__':
    print(read_profile())
