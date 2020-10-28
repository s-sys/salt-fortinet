#!py
# -*- coding: utf-8 -*-
# pylint: disable=W1699
'''
Salt script to create Fortinet objects for a minion
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
    Load the necessary data and create the Fortinet objects for a minion
    '''
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
        minion_ip = data['ip']

    except:  # pylint: disable=bare-except
        message = 'Failed to create minion in Fortinet: {0}'
        message = message.format(format_exc())
        comment = [{'comment': message}] if fortinet_debug else []
        log.info(message)
        return {
            'create_fortinet_minion': {
                'test.configurable_test_state': [{"result": success}, {"changes": changes}, *comment],
            },
        }

    try:
        log.info('Updating minion with IP %s in Fortinet', minion_ip)

        settings = load_settings_from_oracle(oracle, minion_ip)
        if settings['minion']['processed']:
            message = 'Minion with IP {0} was already processed and does not need to be created in Fortinet'
            message = message.format(minion_ip)
            comment = [{'comment': message}] if fortinet_debug else []
            log.info(message)
            success = True
            return {
                'create_fortinet_minion': {
                    'test.configurable_test_state': [{"result": success}, {"changes": changes}, *comment],
                },
            }

        if not settings['citrix']:
            message = 'Minion with IP {0} does not use Citrix so it does not need to be created in Fortinet'
            message = message.format(minion_ip)
            comment = [{'comment': message}] if fortinet_debug else []
            log.info(message)
            success = True
            return {
                'create_fortinet_minion': {
                    'test.configurable_test_state': [{"result": success}, {"changes": changes}, *comment],
                },
            }

        with fortiapi.FortiAPI(fortinet_username, fortinet_password,
                               settings['host'], settings['port']) as fortinet:
            create_minion_in_fortinet(fortinet, settings)
        changes = True

        update_minion_in_oracle(oracle, minion_ip)

        message = 'Successfully created minion with IP {0} in Fortinet'
        message = message.format(minion_ip)
        comment = [{'comment': message}] if fortinet_debug else []
        log.info(message)
        success = True

    except:  # pylint: disable=bare-except
        message = 'Failed to create minion with IP {0} in Fortinet: {1}'
        message = message.format(minion_ip, format_exc())
        comment = [{'comment': message}] if fortinet_debug else []
        log.info(message)

    return {
        'create_fortinet_minion': {
            'test.configurable_test_state': [{"result": success}, {"changes": changes}, *comment],
        },
    }


def load_settings_from_oracle(oracle, minion_ip):
    '''
    Load settings from an Oracle Database
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
        # Load minion data
        keys = ['key', 'ip', 'mac_address', 'hostname', 'store', 'profile', 'processed']
        values = (minion_ip,)
        query = 'select {keys} from minion_profile where ip = :bip'
        try:
            settings['minion'] = get_results(connection, query, keys, values)[0]
            settings['minion']['processed'] = bool(int(settings['minion']['processed']))
        except IndexError:
            raise KeyError('Minion profile not found in database for IP {0}'.format(minion_ip))  # pylint: disable=raise-missing-from
        if settings['minion']['processed']:
            return settings

        minion_store = settings['minion']['store']
        minion_profile = settings['minion']['profile']

        # Load Fortinet data
        keys = ['fortinet_ip', 'fortinet_port', 'citrix']
        values = (minion_store,)
        query = 'select {keys} from fortinet_store where store = :bstore'
        try:
            result = get_results(connection, query, keys, values)[0]
            settings['host'] = result['fortinet-ip']
            settings['port'] = result['fortinet-port']
            settings['citrix'] = bool(int(result['citrix']))
        except IndexError:
            raise KeyError('Fortinet IP not found in database for store #{0}'.format(minion_store))  # pylint: disable=raise-missing-from
        if not settings['citrix']:
            return settings

        # Load profile policies
        keys = ['policy']
        values = (minion_store, minion_profile)
        query = ('select {keys} from fortinet_profile '
                 'where store = :bstore and profile = :bprofile')
        results = get_results(connection, query, keys, values)
        profile_policies = {result['policy'] for result in results}

        # Load policies
        settings['policies'] = []
        for name in profile_policies:
            keys = ['name', 'policyid', 'comments', 'action', 'status', 'schedule',
                    'utm_status', 'logtraffic', 'av_profile', 'webfilter_profile',
                    'dnsfilter_profile', 'dlp_sensor', 'ips_sensor',
                    'application_list', 'ssl_ssh_profile', 'position', 'neighbor']
            values = (minion_store, name)
            query = ('select {keys} from fortinet_policy '
                     'where store = :bstore and name = :bname and changed in (0, 1)')
            settings['policies'].extend(get_results(connection, query, keys, values))

        # Load policy members
        for policy in settings['policies']:
            keys = ['interface']
            values = (minion_store, policy['name'])
            query = ('select {keys} from fortinet_policy_srcintf '
                     'where store = :bstore and policy = :bpolicy and changed in (0, 1)')
            results = get_results(connection, query, keys, values)
            policy['srcintf'] = [result['interface'] for result in results]

            keys = ['interface']
            values = (minion_store, policy['name'])
            query = ('select {keys} from fortinet_policy_dstintf '
                     'where store = :bstore and policy = :bpolicy and changed in (0, 1)')
            results = get_results(connection, query, keys, values)
            policy['dstintf'] = [result['interface'] for result in results]

            keys = ['addressgroup']
            values = (minion_store, policy['name'])
            query = ('select {keys} from fortinet_policy_srcaddr '
                     'where store = :bstore and policy = :bpolicy and changed in (0, 1)')
            results = get_results(connection, query, keys, values)
            policy['srcaddr'] = [result['addressgroup'] if 'addressgroup' in result else 'all'
                                 for result in results]

            keys = ['addressgroup']
            values = (minion_store, policy['name'])
            query = ('select {keys} from fortinet_policy_dstaddr '
                     'where store = :bstore and policy = :bpolicy and changed in (0, 1)')
            results = get_results(connection, query, keys, values)
            policy['dstaddr'] = [result['addressgroup'] if 'addressgroup' in result else 'all'
                                 for result in results]

            keys = ['servicegroup']
            values = (minion_store, policy['name'])
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
            keys = ['name', '"comment"']
            values = (minion_store, name)
            query = ('select {keys} from fortinet_servicegroup '
                     'where store = :bstore and name = :bname and changed in (0, 1)')
            settings['servicegroups'].extend(get_results(connection, query, keys, values))

        # Load service group members
        for servicegroup in settings['servicegroups']:
            keys = ['service']
            values = (minion_store, servicegroup['name'])
            query = ('select {keys} from fortinet_servicegroup_member '
                     'where store = :bstore and servicegroup = :bservicegroup and changed in (0, 1)')
            results = get_results(connection, query, keys, values)
            servicegroup['member'] = [result['service'] for result in results]

        # Load services
        settings['services'] = []
        services = {member for group in settings['servicegroups'] for member in group['member']}
        for name in services:
            keys = ['name', '"comment"', 'category', 'protocol', 'tcp_portrange',
                    'udp_portrange', 'sctp_portrange', 'icmptype', 'icmpcode']
            values = (minion_store, name)
            query = ('select {keys} from fortinet_service '
                     'where store = :bstore and name = :bname and changed in (0, 1)')
            settings['services'].extend(get_results(connection, query, keys, values))

        # Load address groups
        settings['addressgroups'] = []
        addressgroups = {
            *{member for group in settings['policies'] for member in group['srcaddr']},
            *{member for group in settings['policies'] for member in group['dstaddr']},
            'GRP_SRV',
        }
        for name in addressgroups:
            if name.lower() == 'all':
                continue
            keys = ['name', '"comment"']
            values = (minion_store, name)
            query = ('select {keys} from fortinet_addressgroup '
                     'where store = :bstore and name = :bname and changed in (0, 1)')
            settings['addressgroups'].extend(get_results(connection, query, keys, values))

        # Load address group members
        for addressgroup in settings['addressgroups']:
            keys = ['address']
            values = (minion_store, addressgroup['name'])
            query = ('select {keys} from fortinet_addressgroup_member '
                     'where store = :bstore and addressgroup = :baddressgroup and changed in (0, 1)')
            results = get_results(connection, query, keys, values)
            addressgroup['member'] = [result['address'] for result in results]

        # Load addresses
        keys = ['name', '"comment"', 'subnet']
        values = (minion_store,)
        query = 'select {keys} from fortinet_address where store = :bstore and changed in (0, 1)'
        settings['addresses'] = get_results(connection, query, keys, values)

        # Load server addresses
        keys = ['name', '"comment"', 'subnet']
        query = 'select {keys} from fortinet_server_address where changed in (0, 1)'
        results = get_results(connection, query, keys)
        settings['addresses'].extend(results)
        server_addresses = [result['name'] for result in results]

        for addressgroup in settings['addressgroups']:
            if addressgroup['name'] == 'GRP_SRV':
                addressgroup['member'] = server_addresses

    return settings


def create_minion_in_fortinet(fortinet, settings):
    '''
    Create objects in Fortinet for a minion
    '''
    # pylint: disable=too-many-locals,too-many-statements,too-many-branches
    format_settings_with_minion_data(settings, settings['minion'])

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
        try:
            found = fortinet.get_address(address['name'])
        except fortinet.Error:
            found = False
        if found:
            # Update the address with a patch
            whitelist = ['name', 'comment', 'subnet']
            patch = generate_data_patch(found, clear_data(address), whitelist)
            if patch:
                log.debug('Fortinet: Updating address %s with data %s', address['name'], patch)
                fortinet.update_address(address['name'], data=patch)
            # Generate a list of groups where the address should be contained in
            contained_in = set()
            for addressgroup in addressgroups:
                if group_contains_member(addressgroup['member'], address['name']):
                    contained_in.add(addressgroup['name'])
            # Remove the address from any old groups that might contain it but shouldn't
            for addressgroup in fortinet.get_address_groups_with_address(address['name']):
                if addressgroup['name'] not in contained_in:
                    log.debug('Fortinet: Removing address %s from address group %s',
                              address['name'], addressgroup['name'])
                    fortinet.remove_address_from_address_group(addressgroup['name'], address['name'])
            # Update existing address groups that should contain the address to include it if necessary
            for addressgroup_name in contained_in:
                try:
                    addressgroup = fortinet.get_address_group(addressgroup_name)
                except fortinet.Error:
                    addressgroup = False
                if addressgroup and not group_contains_member(addressgroup['member'], address['name']):
                    log.debug('Fortinet: Adding address %s to address group %s',
                              address['name'], addressgroup['name'])
                    fortinet.add_address_to_address_group(addressgroup['name'], address['name'])
        else:
            log.debug('Fortinet: Creating address %s with data %s', address['name'], clear_data(address))
            fortinet.create_address(address['name'], data=clear_data(address))

    # Update or create the address group objects if necessary
    for addressgroup in addressgroups:
        try:
            found = fortinet.get_address_group(addressgroup['name'])
        except fortinet.Error:
            found = False
        if not found and addressgroup['member']:
            log.debug('Fortinet: Creating address group %s with data %s', addressgroup['name'],
                      clear_data(addressgroup))
            fortinet.create_address_group(addressgroup['name'], data=clear_data(addressgroup))

    # Update or create the service objects if necessary
    for service in services:
        try:
            found = fortinet.get_service(service['name'])
        except fortinet.Error:
            found = False
        if not found:
            log.debug('Fortinet: Creating service %s with data %s', service['name'], clear_data(service))
            fortinet.create_service(service['name'], data=clear_data(service))

    # Create the service group objects if necessary
    for servicegroup in servicegroups:
        try:
            found = fortinet.get_service_group(servicegroup['name'])
        except fortinet.Error:
            found = False
        if not found and servicegroup['member']:
            log.debug('Fortinet: Creating service group %s with data %s', servicegroup['name'],
                      clear_data(servicegroup))
            fortinet.create_service_group(servicegroup['name'], data=clear_data(servicegroup))

    # Create the policy objects if necessary
    policy_dependency = {}
    policy_positions = {}
    for policy in policies:
        position = neighbor = None
        if 'position' in policy:
            position = policy['position']
            del policy['position']
        if 'neighbor' in policy:
            neighbor = policy['neighbor']
            del policy['neighbor']

        try:
            found = fortinet.get_policy(policy['name'])
        except fortinet.Error:
            found = False
        has_all_members = (policy['srcintf'] and policy['dstintf'] and
                           policy['srcaddr'] and policy['dstaddr'] and
                           policy['service'])
        if not found and has_all_members:
            log.debug('Fortinet: Creating policy %s with data %s', policy['name'], clear_data(policy))
            policy['policyid'] = policy.get('policyid', 0)
            fortinet.create_policy(policy['policyid'], data=clear_data(policy))
            if position and neighbor:
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


def update_minion_in_oracle(oracle, minion_ip):
    '''
    Update the minion in the Oracle Database
    '''
    if 'service' in oracle:
        dsn = cx_Oracle.makedsn(oracle['host'], oracle['port'], service_name=oracle['service'])
    else:
        dsn = cx_Oracle.makedsn(oracle['host'], oracle['port'], sid=oracle['sid'])

    with cx_Oracle.connect(oracle['user'], oracle['pass'], dsn) as connection:
        with connection.cursor() as cursor:
            cursor.execute('update minion_profile set processed = 1 where ip = :bip', (minion_ip,))
        connection.commit()


def format_settings_with_minion_data(data, minion):
    '''
    Format all fields in Fortinet settings with minion data
    '''
    # pylint: disable=invalid-name
    if isinstance(data, list):
        for index, value in enumerate(data):
            data[index] = format_settings_with_minion_data(value, minion)
    if isinstance(data, dict):
        for key, value in data.items():
            if key != 'minion':
                data[key] = format_settings_with_minion_data(value, minion)
    if isinstance(data, str):
        data = data.format(**minion)
    return data


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


def group_contains_member(group, member):
    '''
    Check if a member is included in a list of members for a group
    '''
    for member2 in group:
        if (isinstance(member2, dict) and member == member2['name']) or member == member2:
            return True
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
