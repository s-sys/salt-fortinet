#!py
# -*- coding: utf-8 -*-
# pylint: disable=W1699
'''
Salt script to insert or update a minion profile in an Oracle Database
'''

import os
import sys
import logging

import cx_Oracle

import salt.utils.platform  # pylint: disable=wrong-import-order


log = logging.getLogger(__name__)


def __virtual__():
    '''
    Executes only in Linux
    '''
    if salt.utils.platform.is_linux():
        return True
    return False


def run():
    '''
    Update a minion profile
    '''
    fortinet_debug = False
    success = False
    changes = False
    comment = []

    try:
        oracle = __opts__['oracle']
        fortinet_debug = __opts__['fortinet'].get('debug', False)

        data = dict(pillar['event_data'])  # pylint: disable=undefined-variable
        mac_address = data['mac_address']
        profile = data['profile']

        minion_id = pillar['minion_id']  # pylint: disable=undefined-variable
        data['key'] = minion_id

        try:
            if 'store' not in data or not int(data['store']):
                from vv_info2 import populate_vv_grains  # pylint: disable=import-outside-toplevel
                data['store'] = int(populate_vv_grains(data['ip'])['num_store'])
        except:  # pylint: disable=bare-except
            pass

    except:  # pylint: disable=bare-except
        message = 'Failed to register minion profile: {0}'
        message = message.format(format_exc())
        comment = [{'comment': message}] if fortinet_debug else []
        log.info(message)
        return {
            'update_profile': {
                'test.configurable_test_state': [{"result": success}, {"changes": changes}, *comment],
            },
        }

    try:
        log.info('Registering minion %s (%s) with profile %s', minion_id, mac_address, profile)

        if 'service' in oracle:
            dsn = cx_Oracle.makedsn(oracle['host'], oracle['port'], service_name=oracle['service'])
        else:
            dsn = cx_Oracle.makedsn(oracle['host'], oracle['port'], sid=oracle['sid'])
        with cx_Oracle.connect(oracle['user'], oracle['pass'], dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(('delete from minion_profile where key = :key'), (minion_id,))
                cursor.execute(('delete from minion_profile where mac_address = :mac_address'), (mac_address,))
                cursor.execute(('insert into minion_profile '
                                '(key, ip, mac_address, hostname, store, profile, processed) '
                                'values (:key, :ip, :mac_address, :hostname, :store, :profile, 0)'), data)
            connection.commit()
        changes = True

        message = 'Successfully registered minion {0} ({1}) with profile {2}'
        message = message.format(minion_id, mac_address, profile)
        comment = [{'comment': message}] if fortinet_debug else []
        log.info(message)

        success = True

    except:  # pylint: disable=bare-except
        message = 'Failed to register minion {0} ({1}) with profile {2}: {3}'
        message = message.format(minion_id, mac_address, profile, format_exc())
        comment = [{'comment': message}] if fortinet_debug else []
        log.info(message)

    return {
        'update_profile': {
            'test.configurable_test_state': [{"result": success}, {"changes": changes}, *comment],
        },
    }


def format_exc(full=True):
    '''
    Format a short description of an exception
    '''
    exc_type, exc_obj, exc_tb = sys.exc_info()
    exc_file = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
    exc_line = exc_tb.tb_lineno
    exc_type = exc_type.__name__
    exc_value = str(exc_obj)
    prefix = '{0}:{1}: '.format(exc_file, exc_line) if full else ''
    if exc_value:
        return '{0}{1}: {2}'.format(prefix, exc_type, exc_value)
    return '{0}{1}'.format(prefix, exc_type)
