#!py
# -*- coding: utf-8 -*-
# pylint: disable=W1699
'''
Salt script to update Fortinet objects for stores in a ServiceNow order
'''

import os
import sys
import re
import logging

import cx_Oracle

import salt.utils.platform  # pylint: disable=wrong-import-order


log = logging.getLogger(__name__)

# ServiceNow status
SERVICENOW_STATUS_PENDING = 0
SERVICENOW_STATUS_UPDATING = 1
SERVICENOW_STATUS_UPDATED = 2
SERVICENOW_STATUS_UPDATED_WITH_ERRORS = 3
SERVICENOW_STATUS_FAILED = 4

RE_PYTHON_FORMAT = re.compile(r'(?:[^\{]|^)\{[^\{\}]*?\}(?:[^\}]|$)')


def __virtual__():
    '''
    Executes only in Linux
    '''
    if salt.utils.platform.is_linux():
        return True
    return False


def run():
    '''
    Load the necessary data and update the Fortinet objects for stores
    '''
    # pylint: disable=too-many-statements,too-many-locals
    fortinet_debug = False
    success = False
    changes = False
    comment = []

    try:
        # Avoid proxy errors
        os.environ['no_proxy'] = '*'

        # Make sure we can import our custom libraries from '/salt/_modules/python/'
        for module_dir in __opts__['module_dirs']:
            sys.path.insert(0, os.path.join(module_dir, 'python/'))

        import fortiapi  # pylint: disable=import-outside-toplevel

        oracle = __opts__['oracle']
        fortinet_debug = __opts__['fortinet'].get('debug', False)
        fortinet_username = __opts__['fortinet']['username']
        fortinet_password = __opts__['fortinet']['password']

        data = dict(pillar['event_data'])  # pylint: disable=undefined-variable
        order = data['order']
        store = data['store']

    except:  # pylint: disable=bare-except
        message = 'Failed to update store for ServiceNow order in Fortinet: {0}'
        message = message.format(format_exc())
        comment = [{'comment': message}] if fortinet_debug else []
        log.info(message)
        return {
            'update_fortinet': {
                'test.configurable_test_state': [{"result": success}, {"changes": changes}, *comment],
            },
        }

    try:
        log.info('Updating store #%s for ServiceNow order %s in Fortinet', store, order)

        settings = load_settings_from_oracle(oracle, store)
        if not settings['citrix']:
            message = ('Store #{0} for ServiceNow order {1} does not use Citrix so it does not '
                       'need to be created in Fortinet')
            message = message.format(store, order)
            comment = [{'comment': message}] if fortinet_debug else []
            log.info(message)
            success = True
            return {
                'update_fortinet': {
                    'test.configurable_test_state': [{"result": success}, {"changes": changes}, *comment],
                },
            }

        with fortiapi.FortiAPI(fortinet_username, fortinet_password,
                               settings['host'], settings['port']) as fortinet:
            update_store_in_fortinet(fortinet, settings)
        changes = True

        message = 'Successfully updated store #{0} for ServiceNow order {1} in Fortinet'
        message = message.format(store, order)
        comment = [{'comment': message}] if fortinet_debug else []
        log.info(message)
        success = True

    except:  # pylint: disable=bare-except
        message = 'Failed to update store #{0} for ServiceNow order {1} in Fortinet: {2}'
        message = message.format(store, order, format_exc())
        comment = [{'comment': message}] if fortinet_debug else []
        log.info(message)

    try:
        status = SERVICENOW_STATUS_UPDATED if success else SERVICENOW_STATUS_PENDING
        update_order_in_oracle(oracle, order, store, status)
        changes = True
        log.info('Successfully updated store #%s for ServiceNow order %s in Oracle', store, order)
    except:  # pylint: disable=bare-except
        message = 'Failed to update store #{0} for ServiceNow order {1} in Oracle: {2}'
        message = message.format(store, order, format_exc())
        comment = [{'comment': message}] if fortinet_debug else []
        log.info(message)
        success = False

    return {
        'update_fortinet': {
            'test.configurable_test_state': [{"result": success}, {"changes": changes}, *comment],
        },
    }


def load_settings_from_oracle(oracle, store):
    '''
    Load settings for a store from an Oracle Database
    '''
    # pylint: disable=too-many-branches,too-many-statements,too-many-locals
    def get_results(connection, query, keys, values=tuple()):
        with connection.cursor() as cursor:
            cursor.execute(query.format(keys=', '.join(keys)), values)
            keys = [key.strip(' \'"').replace('_', '-') for key in keys]
            return [
                {key: value for key, value in dict(zip(keys, result)).items() if value is not None}
                for result in cursor
            ]

    settings = {}

    if 'service' in oracle:
        dsn = cx_Oracle.makedsn(oracle['host'], oracle['port'], service_name=oracle['service'])
    else:
        dsn = cx_Oracle.makedsn(oracle['host'], oracle['port'], sid=oracle['sid'])
    with cx_Oracle.connect(oracle['user'], oracle['pass'], dsn) as connection:
        # Load Fortinet data
        keys = ['fortinet_ip', 'fortinet_port', 'citrix']
        values = (store,)
        query = 'select {keys} from fortinet_store where store = :bstore'
        try:
            result = get_results(connection, query, keys, values)[0]
            settings['host'] = result['fortinet-ip']
            settings['port'] = result['fortinet-port']
            settings['citrix'] = bool(int(result['citrix']))
        except IndexError:
            raise KeyError('Fortinet IP not found in database for store #{0}'.format(store))  # pylint: disable=raise-missing-from
        if not settings['citrix']:
            return settings

        # Load profile policies
        keys = ['policy']
        values = (store,)
        query = 'select {keys} from fortinet_profile where store = :bstore'
        results = get_results(connection, query, keys, values)
        profile_policies = {result['policy'] for result in results}

        # Load policies
        settings['policies'] = []
        for name in profile_policies:
            keys = ['name', 'policyid', 'comments', 'action', 'status', 'schedule', 'utm_status',
                    'logtraffic', 'av_profile', 'webfilter_profile', 'dnsfilter_profile',
                    'dlp_sensor', 'ips_sensor', 'application_list', 'ssl_ssh_profile', 'position',
                    'neighbor', 'changed']
            values = (store, name)
            query = ('select {keys} from fortinet_policy '
                     'where store = :bstore and name = :bname')
            settings['policies'].extend(get_results(connection, query, keys, values))

        # Load policy members
        for policy in settings['policies']:
            keys = ['interface']
            values = (store, policy['name'])
            query = ('select {keys} from fortinet_policy_srcintf '
                     'where store = :bstore and policy = :bpolicy and changed in (0, 1)')
            results = get_results(connection, query, keys, values)
            policy['srcintf'] = [result['interface'] for result in results]

            keys = ['interface']
            values = (store, policy['name'])
            query = ('select {keys} from fortinet_policy_dstintf '
                     'where store = :bstore and policy = :bpolicy and changed in (0, 1)')
            results = get_results(connection, query, keys, values)
            policy['dstintf'] = [result['interface'] for result in results]

            keys = ['addressgroup']
            values = (store, policy['name'])
            query = ('select {keys} from fortinet_policy_srcaddr '
                     'where store = :bstore and policy = :bpolicy and changed in (0, 1)')
            results = get_results(connection, query, keys, values)
            policy['srcaddr'] = [result['addressgroup'] if 'addressgroup' in result else 'all'
                                 for result in results]

            keys = ['addressgroup']
            values = (store, policy['name'])
            query = ('select {keys} from fortinet_policy_dstaddr '
                     'where store = :bstore and policy = :bpolicy and changed in (0, 1)')
            results = get_results(connection, query, keys, values)
            policy['dstaddr'] = [result['addressgroup'] if 'addressgroup' in result else 'all'
                                 for result in results]

            keys = ['servicegroup']
            values = (store, policy['name'])
            query = ('select {keys} from fortinet_policy_service '
                     'where store = :bstore and policy = :bpolicy and changed in (0, 1)')
            results = get_results(connection, query, keys, values)
            policy['service'] = [result['servicegroup'] if 'servicegroup' in result else 'ALL'
                                 for result in results]

        # Load service groups
        settings['servicegroups'] = []
        servicegroups = {member for group in settings['policies'] for member in group['service']}
        for name in servicegroups:
            if name.lower() == 'all':
                continue
            keys = ['name', '"comment"', 'changed']
            values = (store, name)
            query = ('select {keys} from fortinet_servicegroup '
                     'where store = :bstore and name = :bname')
            settings['servicegroups'].extend(get_results(connection, query, keys, values))

        # Load service group members
        for servicegroup in settings['servicegroups']:
            keys = ['service']
            values = (store, servicegroup['name'])
            query = ('select {keys} from fortinet_servicegroup_member '
                     'where store = :bstore and servicegroup = :bservicegroup and changed in (0, 1)')
            results = get_results(connection, query, keys, values)
            servicegroup['member'] = [result['service'] for result in results]

        # Load services
        settings['services'] = []
        services = {member for group in settings['servicegroups'] for member in group['member']}
        for name in services:
            keys = ['name', '"comment"', 'category', 'protocol', 'tcp_portrange',
                    'udp_portrange', 'sctp_portrange', 'icmptype', 'icmpcode',
                    'changed']
            values = (store, name)
            query = 'select {keys} from fortinet_service where store = :bstore and name = :bname'
            settings['services'].extend(get_results(connection, query, keys, values))

        # Load address groups
        settings['addressgroups'] = []
        addressgroups = {
            *{member for group in settings['policies'] for member in group['srcaddr']},
            *{member for group in settings['policies'] for member in group['dstaddr']},
            'GRP_SRV_PCI',
        }
        for name in addressgroups:
            if name.lower() == 'all':
                continue
            keys = ['name', '"comment"', 'changed']
            values = (store, name)
            query = ('select {keys} from fortinet_addressgroup '
                     'where store = :bstore and name = :bname')
            settings['addressgroups'].extend(get_results(connection, query, keys, values))

        # Load address group members
        for addressgroup in settings['addressgroups']:
            keys = ['address']
            values = (store, addressgroup['name'])
            query = ('select {keys} from fortinet_addressgroup_member '
                     'where store = :bstore and addressgroup = :baddressgroup and changed in (0, 1)')
            results = get_results(connection, query, keys, values)
            addressgroup['member'] = [result['address'] for result in results]

        # Load addresses
        settings['addresses'] = []
        addresses = {member for group in settings['addressgroups'] for member in group['member']}
        for name in addresses:
            keys = ['name', '"comment"', 'subnet', 'changed']
            values = (store, name)
            query = 'select {keys} from fortinet_address where store = :bstore and name = :bname'
            settings['addresses'].extend(get_results(connection, query, keys, values))

        # Load server addresses
        keys = ['name', '"comment"', 'subnet', 'changed']
        query = 'select {keys} from fortinet_server_address'
        results = get_results(connection, query, keys)
        settings['addresses'].extend(results)
        server_addresses = [result['name'] for result in results]

        for addressgroup in settings['addressgroups']:
            if addressgroup['name'] == 'GRP_SRV_PCI':
                addressgroup['member'] = server_addresses

    return settings


def update_store_in_fortinet(fortinet, settings):
    '''
    Update objects in Fortinet for a store
    '''
    # pylint: disable=too-many-locals,too-many-statements,too-many-branches

    addresses = settings.get('addresses', [])
    addressgroups = settings.get('addressgroups', [])
    services = settings.get('services', [])
    servicegroups = settings.get('servicegroups', [])
    policies = settings.get('policies', [])

    for addressgroup in addressgroups:
        addressgroup['member'] = [{'name': member} for member in addressgroup.get('member', [])]
    for servicegroup in servicegroups:
        servicegroup['member'] = [{'name': member} for member in servicegroup.get('member', [])]
    for policy in policies:
        policy['srcintf'] = [{'name': member} for member in policy.get('srcintf', [])]
        policy['dstintf'] = [{'name': member} for member in policy.get('dstintf', [])]
        policy['srcaddr'] = [{'name': member} for member in policy.get('srcaddr', [])]
        policy['dstaddr'] = [{'name': member} for member in policy.get('dstaddr', [])]
        policy['service'] = [{'name': member} for member in policy.get('service', [])]

    # Update or create the address objects if necessary
    for address in addresses:
        if has_python_format(address):
            continue
        try:
            found = fortinet.get_address(address['name'])
        except fortinet.Error:
            found = False
        if found and address['changed'] == 2:
            log.debug('Fortinet: Deleting address %s', address['name'])
            fortinet.delete_address(address['name'])
        elif found:
            whitelist = ['name', 'comment', 'subnet']
            patch = generate_data_patch(found, clear_data(address), whitelist)
            if patch:
                log.debug('Fortinet: Updating address %s with data %s', address['name'], patch)
                fortinet.update_address(address['name'], data=patch)
        else:
            log.debug('Fortinet: Creating address %s with data %s', address['name'], clear_data(address))
            fortinet.create_address(address['name'], data=clear_data(address))

    # Update or create the address group objects if necessary
    for addressgroup in addressgroups:
        if has_python_format(addressgroup):
            continue
        try:
            found = fortinet.get_address_group(addressgroup['name'])
        except fortinet.Error:
            found = False
        if found and (addressgroup['changed'] == 2 or not addressgroup['member']):
            log.debug('Fortinet: Deleting address group %s', addressgroup['name'])
            fortinet.delete_address_group(addressgroup['name'])
        elif found:
            members = merge_members(found['member'], addressgroup['member'])
            whitelist = ['name', 'comment']
            patch = generate_data_patch(found, clear_data(addressgroup), whitelist)
            if 'member' in patch:
                del patch['member']
            if not equal_ignoring_list_order(found['member'], members):
                patch['member'] = members
            if patch:
                log.debug('Fortinet: Updating address group %s with data %s', addressgroup['name'], patch)
                fortinet.update_address_group(addressgroup['name'], data=patch)
        elif addressgroup['member']:
            log.debug('Fortinet: Creating address group %s with data %s',
                      addressgroup['name'], clear_data(addressgroup))
            fortinet.create_address_group(addressgroup['name'], data=clear_data(addressgroup))

    # Update or create the service objects if necessary
    for service in services:
        if has_python_format(service):
            continue
        try:
            found = fortinet.get_service(service['name'])
        except fortinet.Error:
            found = False
        if found and service['changed'] == 2:
            log.debug('Fortinet: Deleting service %s', service['name'])
            fortinet.delete_service(service['name'])
        elif found:
            whitelist = ['name', 'comment', 'category', 'protocol', 'tcp-portrange',
                         'udp-portrange', 'sctp-portrange', 'icmptype', 'icmpcode']
            optional = ['protocol']
            patch = generate_data_patch(found, clear_data(service), whitelist, optional)
            if patch:
                log.debug('Fortinet: Updating service %s with data %s', service['name'], patch)
                fortinet.update_service(service['name'], data=patch)
        else:
            log.debug('Fortinet: Creating service %s with data %s', service['name'], clear_data(service))
            fortinet.create_service(service['name'], data=clear_data(service))

    # Create the service group objects if necessary
    for servicegroup in servicegroups:
        if has_python_format(servicegroup):
            continue
        try:
            found = fortinet.get_service_group(servicegroup['name'])
        except fortinet.Error:
            found = False
        if found and (servicegroup['changed'] == 2 or not servicegroup['member']):
            log.debug('Fortinet: Deleting service group %s', servicegroup['name'])
            fortinet.delete_service_group(servicegroup['name'])
        elif found:
            members = merge_members(found['member'], servicegroup['member'])
            whitelist = ['name', 'comment']
            patch = generate_data_patch(found, clear_data(servicegroup), whitelist)
            if 'member' in patch:
                del patch['member']
            if not equal_ignoring_list_order(found['member'], members):
                patch['member'] = members
            if patch:
                log.debug('Fortinet: Updating service group %s with data %s', servicegroup['name'], patch)
                fortinet.update_service_group(servicegroup['name'], data=patch)
        elif servicegroup['member']:
            log.debug('Fortinet: Creating service group %s with data %s',
                      servicegroup['name'], clear_data(servicegroup))
            fortinet.create_service_group(servicegroup['name'], data=clear_data(servicegroup))

    # Create the policy objects if necessary
    policy_dependency = {}
    policy_positions = {}
    for policy in policies:
        if has_python_format(policy):
            continue
        position = neighbor = None
        if 'position' in policy:
            position = policy['position']
            del policy['position']
        if 'neighbor' in policy:
            neighbor = policy['neighbor']
            del policy['neighbor']

        policy_exists = False
        try:
            found = fortinet.get_policy(policy['name'])
        except fortinet.Error:
            found = False
        has_all_members = (policy['srcintf'] and policy['dstintf'] and
                           policy['srcaddr'] and policy['dstaddr'] and
                           policy['service'])
        if found and (policy['changed'] == 2 or not has_all_members):
            log.debug('Fortinet: Deleting policy %s', found['name'])
            fortinet.delete_policy(found['name'])
        elif found:
            srcintfs = merge_members(found['srcintf'], policy['srcintf'])
            dstintfs = merge_members(found['dstintf'], policy['dstintf'])
            srcaddrs = merge_members(found['srcaddr'], policy['srcaddr'])
            dstaddrs = merge_members(found['dstaddr'], policy['dstaddr'])
            services = merge_members(found['service'], policy['service'])
            whitelist = ['name', 'policyid', 'comments', 'action', 'status', 'schedule',
                         'utm-status', 'logtraffic', 'av-profile', 'webfilter-profile',
                         'dnsfilter-profile', 'dlp-sensor', 'ips-sensor',
                         'application-list', 'ssl-ssh-profile']
            optional = ['action', 'status', 'utm-status', 'logtraffic']
            patch = generate_data_patch(found, clear_data(policy), whitelist, optional)
            if 'policyid' in patch:
                del patch['policyid']
            if 'srcintf' in patch:
                del patch['srcintf']
            if not equal_ignoring_list_order(found['srcintf'], srcintfs):
                patch['srcintf'] = srcintfs
            if 'dstintf' in patch:
                del patch['dstintf']
            if not equal_ignoring_list_order(found['dstintf'], dstintfs):
                patch['dstintf'] = dstintfs
            if 'srcaddr' in patch:
                del patch['srcaddr']
            if not equal_ignoring_list_order(found['srcaddr'], srcaddrs):
                patch['srcaddr'] = srcaddrs
            if 'dstaddr' in patch:
                del patch['dstaddr']
            if not equal_ignoring_list_order(found['dstaddr'], dstaddrs):
                patch['dstaddr'] = dstaddrs
            if 'service' in patch:
                del patch['service']
            if not equal_ignoring_list_order(found['service'], services):
                patch['service'] = services
            if patch:
                log.debug('Fortinet: Updating policy %s with data %s', found['name'], patch)
                fortinet.update_policy(found['policyid'], data=patch)
            policy_exists = True
        elif has_all_members:
            log.debug('Fortinet: Creating policy %s with data %s', policy['name'], clear_data(policy))
            policy['policyid'] = policy.get('policyid', 0)
            fortinet.create_policy(policy['policyid'], data=clear_data(policy))
            policy_exists = True

        if policy_exists and position and neighbor:
            found = fortinet.get_policy(policy['name'])
            policy_dependency.setdefault(policy['name'], []).append(neighbor)
            policy_positions[policy['name']] = {
                'policyid': found['policyid'],
                'neighbor': neighbor,
                'position': position,
            }

    # Move policies to their correct order
    for name in topological_sort(policy_dependency):
        if name in policy_positions:
            policy = policy_positions[name]
            try:
                neighbor = fortinet.get_policy(policy['neighbor'])
                log.debug('Fortinet: Moving policy %s %s policy %s',
                          policy['policyid'], policy['position'], neighbor['policyid'])
                fortinet.move_policy(policy['policyid'], neighbor['policyid'], policy['position'])
            except fortinet.Error:
                pass


def update_order_in_oracle(oracle, order, store, status):
    '''
    Update the ServiceNow order in the Oracle Database
    '''
    # pylint: disable=too-many-statements

    if 'service' in oracle:
        dsn = cx_Oracle.makedsn(oracle['host'], oracle['port'], service_name=oracle['service'])
    else:
        dsn = cx_Oracle.makedsn(oracle['host'], oracle['port'], sid=oracle['sid'])
    with cx_Oracle.connect(oracle['user'], oracle['pass'], dsn) as connection:
        with connection.cursor() as cursor:
            if status != SERVICENOW_STATUS_FAILED:
                try:
                    cursor.execute(('update fortinet_policy_service set changed = 0 '
                                    'where store = :bstore and changed = 1'), (store,))
                    cursor.execute(('update fortinet_policy_dstaddr set changed = 0 '
                                    'where store = :bstore and changed = 1'), (store,))
                    cursor.execute(('update fortinet_policy_srcaddr set changed = 0 '
                                    'where store = :bstore and changed = 1'), (store,))
                    cursor.execute(('update fortinet_policy_dstintf set changed = 0 '
                                    'where store = :bstore and changed = 1'), (store,))
                    cursor.execute(('update fortinet_policy_srcintf set changed = 0 '
                                    'where store = :bstore and changed = 1'), (store,))
                    cursor.execute(('update fortinet_policy set changed = 0 '
                                    'where store = :bstore and changed = 1'), (store,))
                    cursor.execute(('update fortinet_servicegroup_member set changed = 0 '
                                    'where store = :bstore and changed = 1'), (store,))
                    cursor.execute(('update fortinet_servicegroup set changed = 0 '
                                    'where store = :bstore and changed = 1'), (store,))
                    cursor.execute(('update fortinet_service set changed = 0 '
                                    'where store = :bstore and changed = 1'), (store,))
                    cursor.execute(('update fortinet_addressgroup_member set changed = 0 '
                                    'where store = :bstore and changed = 1'), (store,))
                    cursor.execute(('update fortinet_addressgroup set changed = 0 '
                                    'where store = :bstore and changed = 1'), (store,))
                    cursor.execute(('update fortinet_address set changed = 0 '
                                    'where store = :bstore and changed = 1'), (store,))

                    cursor.execute(('delete from fortinet_policy_service '
                                    'where store = :bstore and changed = 2'), (store,))
                    cursor.execute(('delete from fortinet_policy_dstaddr '
                                    'where store = :bstore and changed = 2'), (store,))
                    cursor.execute(('delete from fortinet_policy_srcaddr '
                                    'where store = :bstore and changed = 2'), (store,))
                    cursor.execute(('delete from fortinet_policy_dstintf '
                                    'where store = :bstore and changed = 2'), (store,))
                    cursor.execute(('delete from fortinet_policy_srcintf '
                                    'where store = :bstore and changed = 2'), (store,))
                    cursor.execute(('delete from fortinet_policy '
                                    'where store = :bstore and changed = 2'), (store,))
                    cursor.execute(('delete from fortinet_servicegroup_member '
                                    'where store = :bstore and changed = 2'), (store,))
                    cursor.execute(('delete from fortinet_servicegroup '
                                    'where store = :bstore and changed = 2'), (store,))
                    cursor.execute(('delete from fortinet_service '
                                    'where store = :bstore and changed = 2'), (store,))
                    cursor.execute(('delete from fortinet_addressgroup_member '
                                    'where store = :bstore and changed = 2'), (store,))
                    cursor.execute(('delete from fortinet_addressgroup '
                                    'where store = :bstore and changed = 2'), (store,))
                    cursor.execute(('delete from fortinet_address '
                                    'where store = :bstore and changed = 2'), (store,))

                    connection.commit()

                except:  # pylint: disable=bare-except
                    status = SERVICENOW_STATUS_FAILED
                    connection.cancel()

            cursor.execute(('update fortinet_servicenow_store set status = :bstatus '
                            'where "order" = :border and store = :bstore'), (status, order, store))
            connection.commit()

            cursor.execute(('select status from fortinet_servicenow_store '
                            'where "order" = :border'), (order,))

            status_list = [row[0] for row in cursor]
            status = None
            if SERVICENOW_STATUS_PENDING in status_list:
                status = SERVICENOW_STATUS_PENDING
            elif SERVICENOW_STATUS_UPDATING not in status_list:
                status = SERVICENOW_STATUS_UPDATED
                if SERVICENOW_STATUS_FAILED in status_list:
                    status = SERVICENOW_STATUS_FAILED
                    if SERVICENOW_STATUS_UPDATED in status_list:
                        status = SERVICENOW_STATUS_UPDATED_WITH_ERRORS
            if status is not None:
                if SERVICENOW_STATUS_UPDATING not in status_list:
                    cursor.execute(('update fortinet_server_address set changed = 0 '
                                    'where changed = 1'))
                    cursor.execute('delete from fortinet_server_address where changed = 2')
                cursor.execute(('update fortinet_servicenow set status = :bstatus '
                                'where "order" = :border'), (status, order))

            connection.commit()


def generate_data_patch(before, after, whitelist=None, optional=None):
    '''
    Generate a patch between two dicts, containing only the changes to be applied between them
    '''
    patch = {}
    for key in {*before.keys(), *after.keys()}:
        if isinstance(whitelist, list) and key not in whitelist:
            continue
        value_before = before.get(key)
        value_before = None if value_before == '' else value_before
        value_after = after.get(key)
        value_after = None if value_after == '' else value_after
        if isinstance(value_before, dict) and isinstance(value_after, dict):
            member_patch = generate_data_patch(value_before, value_after)
            if member_patch:
                patch[key] = member_patch
        elif not equal_ignoring_list_order(value_before, value_after):
            patch[key] = value_after
    if isinstance(optional, list):
        for field in optional:
            if field in patch and after.get(field) is None:
                del patch[field]
    return patch


def clear_data(data):
    '''
    Remove fields that should not be included in Fortinet requests
    '''
    blacklist = ['id', 'changed']
    for item in blacklist:
        if item in data:
            del data[item]
    return data


def merge_members(list1, list2):
    '''
    Merge two lists of members into a single list, without removed members
    '''
    names = {member['name'] if isinstance(member, dict) else member for member in [*list1, *list2]
             if not (isinstance(member, dict) and member.get('changed', 0) == 2)}
    return [{'name': name} for name in names]


def equal_ignoring_list_order(value1, value2):
    '''
    Compare two values, ignoring the order of elements if the values are lists
    '''
    if not isinstance(value1, list) or not isinstance(value2, list):
        return value1 == value2
    unmatched = {member['name'] if isinstance(member, dict) else member for member in value1}
    attempt_match = {member['name'] if isinstance(member, dict) else member for member in value2}
    for element in attempt_match:
        try:
            unmatched.remove(element)
        except KeyError:
            return False
    return not unmatched


def has_python_format(value):
    '''
    Recursively check if a value contains a string with a Python format syntax
    '''
    if isinstance(value, list):
        for subvalue in value:
            if has_python_format(subvalue):
                return True
    elif isinstance(value, dict):
        for key, subvalue in value.items():
            if has_python_format(key) or has_python_format(subvalue):
                return True
    elif isinstance(value, str):
        return bool(RE_PYTHON_FORMAT.search(value))
    return False


def topological_sort(graph):
    '''
    Sort a graph of dependencies topologically
    '''
    # Calculate valid and used nodes
    used_nodes = list(graph.keys())
    nodes = {adjacent for node in graph.values() for adjacent in node}
    for node in nodes:
        if node not in graph:
            graph[node] = []

    # Calculate degree of each node
    node_degree = {node: 0 for node in graph}
    for node in graph:
        for adjacent in graph[node]:
            node_degree[adjacent] += 1

    # Collect nodes with a degree of zero
    result = []
    queue = [node for node, degree in node_degree.items() if degree == 0]
    while queue:
        node = queue.pop()
        result.append(node)
        # Update degrees for all nodes adjacent to the collected node
        for adjacent in graph[node]:
            node_degree[adjacent] -= 1
            if node_degree[adjacent] == 0:
                queue.append(adjacent)

    result.reverse()
    return [node for node in result if node in used_nodes]


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
