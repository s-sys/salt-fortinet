#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pylint: disable=W1699
'''
Flask API to manage Fortinet data
'''

import os
import sys
import json
import logging
import datetime
import dateutil.parser

import cx_Oracle

from pepper.libpepper import Pepper

from flask import Flask, request, jsonify


LOG_FILE = '/var/log/fortinet/fortinet.log'
logging.basicConfig(filename=LOG_FILE, level=logging.INFO)
log = logging.getLogger('Fortinet')

app = Flask('Fortinet')  # pylint: disable=invalid-name

# ServiceNow status
SERVICENOW_STATUS_PENDING = 0
SERVICENOW_STATUS_UPDATING = 1
SERVICENOW_STATUS_UPDATED = 2
SERVICENOW_STATUS_UPDATED_WITH_ERRORS = 3
SERVICENOW_STATUS_FAILED = 4

SERVICENOW_LABEL_STATUS = {
    SERVICENOW_STATUS_PENDING: 'pending',
    SERVICENOW_STATUS_UPDATING: 'updating',
    SERVICENOW_STATUS_UPDATED: 'updated',
    SERVICENOW_STATUS_UPDATED_WITH_ERRORS: 'updated-with-errors',
    SERVICENOW_STATUS_FAILED: 'failed',
}

# Oracle connection settings
ORACLE_AUTH = {
    'username': os.getenv('ORACLE_USERNAME', 'SYSDB'),
    'password': os.getenv('ORACLE_PASSWORD', ''),
    'host': os.getenv('ORACLE_HOST', '127.0.0.1'),
    'port': int(os.getenv('ORACLE_PORT', '1521')),
    'sid': os.getenv('ORACLE_SID', 'XE'),
    'service': os.getenv('ORACLE_SERVICE', ''),
}

# Oracle whitelisted tables
ORACLE_TABLE_WHITELIST = [
    'fortinet_server_address',
    'fortinet_address',
    'fortinet_addressgroup',
    'fortinet_addressgroup_member',
    'fortinet_service',
    'fortinet_servicegroup',
    'fortinet_servicegroup_member',
    'fortinet_policy',
    'fortinet_policy_srcintf',
    'fortinet_policy_dstintf',
    'fortinet_policy_srcaddr',
    'fortinet_policy_dstaddr',
    'fortinet_policy_service',
    'fortinet_profile',
    'fortinet_service_template',
    'fortinet_policy_template',
    'fortinet_policy_template_srcintf',
    'fortinet_policy_template_dstintf',
    'fortinet_policy_template_srcaddr',
    'fortinet_policy_template_dstaddr',
    'fortinet_policy_template_service',
]

# Oracle tables with a 'store' column
ORACLE_TABLES_WITH_STORE = [
    'fortinet_address',
    'fortinet_addressgroup',
    'fortinet_addressgroup_member',
    'fortinet_service',
    'fortinet_servicegroup',
    'fortinet_servicegroup_member',
    'fortinet_policy',
    'fortinet_policy_srcintf',
    'fortinet_policy_dstintf',
    'fortinet_policy_srcaddr',
    'fortinet_policy_dstaddr',
    'fortinet_policy_service',
    'fortinet_profile',
]

# Oracle tables with a 'changed' flag
ORACLE_TABLES_WITH_CHANGED = [
    'fortinet_server_address',
    'fortinet_address',
    'fortinet_addressgroup',
    'fortinet_addressgroup_member',
    'fortinet_service',
    'fortinet_servicegroup',
    'fortinet_servicegroup_member',
    'fortinet_policy',
    'fortinet_policy_srcintf',
    'fortinet_policy_dstintf',
    'fortinet_policy_srcaddr',
    'fortinet_policy_dstaddr',
    'fortinet_policy_service',
]

# Salt connection settings
SALT_URL = os.getenv('SALT_URL', 'http://127.0.0.1')
SALT_USERNAME = os.getenv('SALT_USERNAME', 'salt')
SALT_PASSWORD = os.getenv('SALT_PASSWORD', 'salt')
SALT_EAUTH = os.getenv('SALT_EAUTH', 'pam')

# Complementary Fortinet template data to be formatted and inserted into Oracle
ORACLE_TEMPLATE_HEAD = [
    # {
    #     'table': 'fortinet_store',
    #     'fields': ['store', 'flag', 'city', 'state', 'region', 'fortinet_ip',
    #                'fortinet_port', 'citrix'],
    #     'values': [
    #         ('{store}', '{flag}', '{city}', '{state}', '{region}', '{fortinet_ip}',
    #          '{fortinet_port}', '{citrix}'),
    #     ],
    # }, {
    #     'table': 'fortinet_address',
    #     'fields': ['store', 'name', '"comment"', 'subnet'],
    #     'values': [
    #         ('{store}', 'GRP_SRC_{{ip}}', 'HOST_{{ip}}', '{{ip}} 255.255.255.255'),
    #     ],
    # }, {
    #     'table': 'fortinet_addressgroup',
    #     'fields': ['store', 'name', '"comment"'],
    #     'values': [
    #         ('{store}', 'GRP_SRV', 'Server Group'),
    #         ('{store}', 'GRP_SRC_{store:04d}', 'Source Group'),
    #     ],
    # }, {
    #     'table': 'fortinet_addressgroup_member',
    #     'fields': ['store', 'addressgroup', 'address'],
    #     'values': [
    #         ('{store}', 'GRP_SRC_{store:04d}', 'GRP_SRC_{{ip}}'),
    #     ],
    # },
]

ORACLE_TEMPLATE_TAIL = [
    # {
    #     'table': 'fortinet_profile',
    #     'fields': ['store', 'profile', 'policy'],
    #     'values': [
    #         ('{store}', 'profile1', 'PCI_IN_PROFILE1'),
    #         ('{store}', 'profile1', 'PCI_OUT_PROFILE1'),
    #         ('{store}', 'profile2', 'PCI_IN_PROFILE2'),
    #         ('{store}', 'profile2', 'PCI_OUT_PROFILE2'),
    #     ],
    # },
]

# Procedures to delete Fortinet data of a store from Oracle
ORACLE_DELETE_STORE = [
    {'table': 'fortinet_profile', 'filters': {'store': '{store}'}},
    {'table': 'fortinet_policy_service', 'filters': {'store': '{store}'}},
    {'table': 'fortinet_policy_dstaddr', 'filters': {'store': '{store}'}},
    {'table': 'fortinet_policy_srcaddr', 'filters': {'store': '{store}'}},
    {'table': 'fortinet_policy_dstintf', 'filters': {'store': '{store}'}},
    {'table': 'fortinet_policy_srcintf', 'filters': {'store': '{store}'}},
    {'table': 'fortinet_policy', 'filters': {'store': '{store}'}},
    {'table': 'fortinet_servicegroup_member', 'filters': {'store': '{store}'}},
    {'table': 'fortinet_servicegroup', 'filters': {'store': '{store}'}},
    {'table': 'fortinet_service', 'filters': {'store': '{store}'}},
    {'table': 'fortinet_addressgroup_member', 'filters': {'store': '{store}'}},
    {'table': 'fortinet_addressgroup', 'filters': {'store': '{store}'}},
    {'table': 'fortinet_address', 'filters': {'store': '{store}'}},
    {'table': 'fortinet_store', 'filters': {'store': '{store}'}},
]


@app.route('/fortinet/store/get', methods=['POST'])
def get_store():
    '''Get Fortinet data for stores from the database with filters'''
    try:
        data = json.loads(request.get_data().decode('unicode_escape'))
        with FortinetDatabase(**ORACLE_AUTH) as db:
            # Read context
            context = data.get('context')
            # Read list of fields to select
            fields = data.get('fields', ['*'])
            # Read filters
            filters = data.get('filters', {})
            if not filters:
                filters = None
            stores = db.select('fortinet_store', fields, filters, context)
            if len(fields) >= 1 and fields[0] != '*':
                stores = [dict(zip(fields, row)) for row in stores]
        return jsonify({'success': True, 'stores': list(stores)})
    except:  # pylint: disable=bare-except
        log.error('POST /fortinet/store/get', exc_info=True)
        return jsonify({'success': False, 'error': format_exc()})


@app.route('/fortinet/store', methods=['POST'])
def create_store():
    '''Create Fortinet data for new stores in the database, based on template data'''
    try:
        stores = json.loads(request.get_data().decode('unicode_escape'))
        if not isinstance(stores, list):
            stores = [stores]
        created, failed = set(), {}
        with FortinetDatabase(**ORACLE_AUTH) as db:
            template = db.generate_template(ORACLE_TEMPLATE_HEAD, ORACLE_TEMPLATE_TAIL)
            for store in stores:
                store_id = int(store['store'])
                try:
                    context = {
                        'store': store_id,
                        'flag': store['flag'],
                        'city': store['city'],
                        'state': store['state'],
                        'region': int(store['region']),
                        'fortinet_ip': store['fortinet_ip'],
                        'fortinet_port': int(store['fortinet_port']),
                        'citrix': str(int(store['citrix'])),
                    }
                    db.insert(template, context)
                    created.add(store_id)
                    db.commit()
                except:  # pylint: disable=bare-except
                    db.rollback()
                    log.error('Error while trying to create store #%s', store_id, exc_info=True)
                    failed[store_id] = format_exc()
        return jsonify({'success': True, 'created': list(created), 'failed': failed})
    except:  # pylint: disable=bare-except
        log.error('POST /fortinet/store', exc_info=True)
        return jsonify({'success': False, 'error': format_exc()})


@app.route('/fortinet/store', methods=['DELETE'])
def delete_store():
    '''Delete Fortinet data for stores from the database'''
    try:
        stores = json.loads(request.get_data().decode('unicode_escape'))
        if not isinstance(stores, list):
            stores = [stores]
        deleted, failed = set(), {}
        with FortinetDatabase(**ORACLE_AUTH) as db:
            for store in stores:
                store_id = int(store)
                try:
                    context = {
                        'store': store_id,
                    }
                    db.delete(ORACLE_DELETE_STORE, context)
                    deleted.add(store_id)
                    db.commit()
                except:  # pylint: disable=bare-except
                    db.rollback()
                    log.error('Error while trying to delete store #%s', store_id, exc_info=True)
                    failed[store_id] = format_exc()
        return jsonify({'success': True, 'deleted': list(deleted), 'failed': failed})
    except:  # pylint: disable=bare-except
        log.error('DELETE /fortinet/store', exc_info=True)
        return jsonify({'success': False, 'error': format_exc()})


@app.route('/fortinet/minion/<minion_ip>', methods=['POST'])
def create_minion(minion_ip):
    '''Request Salt to create Fortinet objects with current data for a specific minion'''
    try:
        with FortinetDatabase(**ORACLE_AUTH) as db:
            minions = db.select('minion_profile', ['ip'], {'ip': minion_ip})
        jobs, failed = salt_create_fortinet_minions([row[0] for row in minions])
        return jsonify({'success': True, 'jobs': jobs, 'failed': failed})
    except:  # pylint: disable=bare-except
        log.error('POST /fortinet/minion', exc_info=True)
        return jsonify({'success': False, 'error': format_exc()})


@app.route('/fortinet/minion/unprocessed', methods=['POST'])
def create_unprocessed_minions():
    '''Request Salt to create Fortinet objects with current data for all unprocessed minions'''
    try:
        with FortinetDatabase(**ORACLE_AUTH) as db:
            minions = db.select('minion_profile', ['ip'], {'processed': 0})
        jobs, failed = salt_create_fortinet_minions([row[0] for row in minions])
        return jsonify({'success': True, 'jobs': jobs, 'failed': failed})
    except:  # pylint: disable=bare-except
        log.error('POST /fortinet/minion/unprocessed', exc_info=True)
        return jsonify({'success': False, 'error': format_exc()})


@app.route('/fortinet/minion/all', methods=['POST'])
def create_all_minions():
    '''Request Salt to create Fortinet objects with current data for all minions'''
    try:
        with FortinetDatabase(**ORACLE_AUTH) as db:
            minions = db.select('minion_profile', ['ip'])
        jobs, failed = salt_create_fortinet_minions([row[0] for row in minions])
        return jsonify({'success': True, 'jobs': jobs, 'failed': failed})
    except:  # pylint: disable=bare-except
        log.error('POST /fortinet/minion/all', exc_info=True)
        return jsonify({'success': False, 'error': format_exc()})


@app.route('/fortinet/object/get', methods=['POST'])
def get_object():
    '''Get data for a Fortinet object from the database'''
    def sanitize(row):
        return tuple(value.hex().upper() if isinstance(value, bytes) else value for value in row)

    try:
        data = json.loads(request.get_data().decode('unicode_escape'))
        # Read table and check if it is whitelisted
        table = data['table']
        if table not in ORACLE_TABLE_WHITELIST:
            raise ValueError('Permission denied')
        # Read context
        context = data.get('context')
        # Read list of fields to select
        fields = data.get('fields', ['*'])
        # Read filters
        filters = data.get('filters', {})
        if table in ORACLE_TABLES_WITH_STORE:
            filters['store'] = data['store']
        if table in ORACLE_TABLES_WITH_CHANGED:
            filters['changed__!='] = 2
        if 'id' in data:
            filters['id'] = data['id']
        if not filters:
            filters = None
        objs = []
        with FortinetDatabase(**ORACLE_AUTH) as db:
            # Select from database
            objs = db.select(table, fields, filters, context)
        objs = [sanitize(row) for row in objs]
        if len(fields) >= 1 and fields[0] != '*':
            objs = [dict(zip(fields, row)) for row in objs]
        return jsonify({'success': True, 'objects': objs})
    except:  # pylint: disable=bare-except
        log.error('POST /fortinet/object/get', exc_info=True)
        return jsonify({'success': False, 'error': format_exc()})


@app.route('/fortinet/object/merge', methods=['POST'])
def merge_object():
    '''Merge data for Fortinet objects from the database'''
    def sanitize(values):
        if isinstance(values, list):
            return [sanitize(value) for value in values]
        return values.hex().upper() if isinstance(values, bytes) else values

    try:
        data = json.loads(request.get_data().decode('unicode_escape'))
        # Read table and check if it is whitelisted
        table = data['table']
        if table not in ORACLE_TABLE_WHITELIST:
            raise ValueError('Permission denied')
        # Read context
        context = data.get('context')
        # Read list of fields to select
        fields = data['fields']
        # Read list of fields to group
        group_fields = data.get('group', ['id'])
        if not isinstance(group_fields, list):
            group_fields = [group_fields]
        # Read filters
        filters = data.get('filters', {})
        if table in ORACLE_TABLES_WITH_STORE:
            filters['store'] = data['store']
        if table in ORACLE_TABLES_WITH_CHANGED:
            filters['changed__!='] = 2
        if not filters:
            filters = None
        with FortinetDatabase(**ORACLE_AUTH) as db:
            # Merge from database
            merged = sanitize(db.merge(table, fields, group_fields, filters, context))
        if len(fields) >= 1 and fields[0] != '*':
            merged = dict(zip(fields, merged))
        return jsonify({'success': True, 'merged': merged})
    except:  # pylint: disable=bare-except
        log.error('POST /fortinet/object/merge', exc_info=True)
        return jsonify({'success': False, 'error': format_exc()})


@app.route('/fortinet/object/group', methods=['POST'])
def group_object():
    '''Group data for Fortinet objects from the database'''
    def sanitize(values):
        if isinstance(values, list):
            return [sanitize(value) for value in values]
        return values.hex().upper() if isinstance(values, bytes) else values

    try:
        data = json.loads(request.get_data().decode('unicode_escape'))
        # Read table and check if it is whitelisted
        table = data['table']
        if table not in ORACLE_TABLE_WHITELIST:
            raise ValueError('Permission denied')
        # Read context
        context = data.get('context')
        # Read list of fields to merge
        merge_fields = data['merge']
        if not isinstance(merge_fields, list):
            merge_fields = [merge_fields]
        # Read list of fields to group
        group_fields = data.get('group', ['id'])
        if not isinstance(group_fields, list):
            group_fields = [group_fields]
        # Read filters
        filters = data.get('filters', {})
        if table in ORACLE_TABLES_WITH_STORE:
            filters['store'] = data['store']
        if table in ORACLE_TABLES_WITH_CHANGED:
            filters['changed__!='] = 2
        if not filters:
            filters = None
        groups = []
        with FortinetDatabase(**ORACLE_AUTH) as db:
            # Group from database
            groups = db.group(table, merge_fields, group_fields, filters, context)
        groups = [{field: sanitize(values) for field, values in group.items()} for group in groups]
        return jsonify({'success': True, 'groups': groups})
    except:  # pylint: disable=bare-except
        log.error('POST /fortinet/object/group', exc_info=True)
        return jsonify({'success': False, 'error': format_exc()})


@app.route('/fortinet/object/post', methods=['POST'])
def create_object():
    '''Create new Fortinet objects in the database'''
    try:
        data = json.loads(request.get_data().decode('unicode_escape'))
        return jsonify(execute_generic_queries(data, 'insert', 'created'))
    except:  # pylint: disable=bare-except
        log.error('POST /fortinet/object/post', exc_info=True)
        return jsonify({'success': False, 'error': format_exc()})


@app.route('/fortinet/object/upsert', methods=['POST'])
def upsert_object():
    '''Update Fortinet objects in the database'''
    try:
        data = json.loads(request.get_data().decode('unicode_escape'))
        return jsonify(execute_generic_queries(data, 'upsert', 'upserted'))
    except:  # pylint: disable=bare-except
        log.error('POST /fortinet/object/upsert', exc_info=True)
        return jsonify({'success': False, 'error': format_exc()})


@app.route('/fortinet/object/put', methods=['POST'])
def update_object():
    '''Update Fortinet objects in the database'''
    try:
        data = json.loads(request.get_data().decode('unicode_escape'))
        return jsonify(execute_generic_queries(data, 'update', 'updated'))
    except:  # pylint: disable=bare-except
        log.error('POST /fortinet/object/put', exc_info=True)
        return jsonify({'success': False, 'error': format_exc()})


@app.route('/fortinet/object/delete', methods=['POST'])
def delete_object():
    '''Delete Fortinet objects from the database'''
    try:
        data = json.loads(request.get_data().decode('unicode_escape'))
        return jsonify(execute_generic_queries(data, 'delete', 'deleted'))
    except:  # pylint: disable=bare-except
        log.error('POST /fortinet/object/delete', exc_info=True)
        return jsonify({'success': False, 'error': format_exc()})


@app.route('/fortinet/servicenow', methods=['POST'])
def servicenow_order():
    '''Request execution of a Fortinet order'''
    try:
        data = json.loads(request.get_data().decode('unicode_escape'))
        return jsonify(execute_servicenow_order(data))
    except:  # pylint: disable=bare-except
        log.error('POST /fortinet/servicenow', exc_info=True)
        return jsonify({'success': False, 'error': format_exc()})


@app.route('/fortinet/order/status', methods=['POST'])
def servicenow_order_status():
    '''Request status of a ServiceNow order'''
    try:
        def status_label(status):
            try:
                return SERVICENOW_LABEL_STATUS[status]
            except KeyError:
                return status
        data = json.loads(request.get_data().decode('unicode_escape'))
        with FortinetDatabase(**ORACLE_AUTH) as db:
            filters = {'"order"': data.get('order')}
            # Get order status
            fields = ['status', 'created', 'deadline']
            result = db.select('fortinet_servicenow', fields, filters)
            if not result:
                return jsonify({'success': False, 'error': 'ServiceNow order not found'})
            status, created, deadline = result[0]
            status = status_label(status)
            created = created.isoformat()
            deadline = deadline.isoformat()
            # Get stores status
            fields = ['store', 'status']
            result = db.select('fortinet_servicenow_store', fields, filters)
            stores = {item[0]: status_label(item[1]) for item in result}
        return jsonify({'success': True, 'status': status, 'created': created,
                        'deadline': deadline, 'stores': stores})
    except:  # pylint: disable=bare-except
        log.error('POST /fortinet/order/status', exc_info=True)
        return jsonify({'success': False, 'error': format_exc()})


@app.route('/fortinet/update', methods=['POST'])
def update_fortinet():
    '''Request Salt to update Fortinet stores with open ServiceNow orders'''
    try:
        with FortinetDatabase(**ORACLE_AUTH) as db:
            # Select the IDs of all pending ServiceNow orders
            select_kwargs = {
                'table': 'fortinet_servicenow',
                'fields': ['"order"'],
                'filters': {
                    'status': SERVICENOW_STATUS_PENDING,
                    'deadline__>': datetime.datetime.now(),
                },
            }
            orders = {}
            for order in [row[0] for row in db.select(**select_kwargs)]:
                select_kwargs = {
                    'table': 'fortinet_servicenow_store',
                    'fields': ['store'],
                    'filters': {
                        '"order"': order,
                        'status': SERVICENOW_STATUS_PENDING,
                    },
                }
                orders[order] = [row[0] for row in db.select(**select_kwargs)]

            # Update all ServiceNow request status
            update_queries = [
                {
                    'table': 'fortinet_servicenow',
                    'values': {'status': SERVICENOW_STATUS_UPDATING},
                    'filters': {'"order"': order},
                }
                for order in orders
            ]
            for order, stores in orders.items():
                update_queries.extend([
                    {
                        'table': 'fortinet_servicenow_store',
                        'values': {'status': SERVICENOW_STATUS_UPDATING},
                        'filters': {'"order"': order, 'store': store},
                    }
                    for store in stores
                ])
            db.update(update_queries)

        # Request Salt to update Fortinet
        jobs, failed = salt_update_fortinet(orders)

        return jsonify({'success': True, 'jobs': jobs, 'failed': failed})
    except:  # pylint: disable=bare-except
        log.error('POST /fortinet/update', exc_info=True)
        return jsonify({'success': False, 'error': format_exc()})


def execute_generic_queries(queries, operation, success_label):
    '''Execute operation-agnostic queries for a ServiceNow order'''
    queries = json.loads(request.get_data().decode('unicode_escape'))
    if not isinstance(queries, list):
        queries = [queries]

    orders = {}
    for i, query in enumerate(queries):
        index = i + 1
        order_id = query['order_servicenow']
        order = orders.setdefault(order_id, {
            'order_servicenow': order_id,
            'deadline_servicenow': query['deadline_servicenow'],
            'query_indexes': {'order': order_id},
            'queries_servicenow': [],
        })
        order['queries_servicenow'].append({
            'operation': operation,
            **{key: value for key, value in query.items()
               if key in ['table', 'store', 'id', 'values', 'fields', 'filters', 'context']},
        })
        index_inside_order = len(order['queries_servicenow'])
        order['query_indexes'][index_inside_order] = index

    success, succeeded, failed = False, [], {}
    for order in orders.values():
        result = execute_servicenow_order(order)
        if result['success']:
            success = True
            succeeded.extend([order['query_indexes'][index] for index in result['executed']])
        if 'failed' in result:
            failed.update({order['query_indexes'][index]: message for index, message in result['failed'].items()})

    return {'success': success, success_label: succeeded, 'failed': failed}


def execute_servicenow_order(order):
    '''Execute a ServiceNow order in the database'''
    # pylint: disable=too-many-branches,too-many-statements,too-many-locals
    order_id = order['order_servicenow']
    expire = dateutil.parser.parse(order['deadline_servicenow'])
    queries = order['queries_servicenow']
    all_stores, stores, executed, failed = False, set(), set(), {}
    with FortinetDatabase(**ORACLE_AUTH) as db:
        for i, query in enumerate(queries):
            index = i + 1
            try:
                # Read operation type
                operation = query['operation']
                if operation not in ['insert', 'upsert', 'update', 'delete']:
                    raise ValueError('Invalid operation \'{0}\''.format(str(operation)))
                # Read table and check if it is whitelisted
                table = query['table']
                if table not in ORACLE_TABLE_WHITELIST:
                    raise ValueError('Permission denied')
                # Read store
                store = None
                if table in ORACLE_TABLES_WITH_STORE:
                    store = query['store']
                    if isinstance(store, list):
                        stores.update(store)
                    else:
                        stores.add(store)
                elif not all_stores:
                    stores.update({store['store'] for store in db.select('fortinet_store', ['store'])})
                    # The flag 'all_stores' helps us know if we already updated
                    # 'stores' with all stores. We only need to do this once.
                    all_stores = True
                # Read context
                context = query.get('context')

                if operation == 'insert':
                    # Read fields
                    fields = []
                    if table in ORACLE_TABLES_WITH_STORE:
                        fields.append('store')
                    if table in ORACLE_TABLES_WITH_CHANGED:
                        fields.append('changed')
                    fields.extend(query['fields'])
                    # Read values
                    values = query['values']
                    if not isinstance(values, list):
                        values = [values]
                    # Insert changed field
                    if table in ORACLE_TABLES_WITH_CHANGED:
                        values = [(1, *row) for row in values]
                    # Insert store field
                    if table in ORACLE_TABLES_WITH_STORE:
                        if isinstance(store, list):
                            values = [(item, *row) for item in store for row in values]
                        else:
                            values = [(store, *row) for row in values]
                    # Insert into database
                    template = [{'table': table, 'fields': fields, 'values': values}]
                    db.insert(template, context)
                    executed.add(index)

                elif operation == 'upsert':
                    # Read values
                    values = query['values']
                    if table in ORACLE_TABLES_WITH_CHANGED:
                        values['changed'] = 1
                    # Read filters
                    filters = query['filters']
                    if not isinstance(filters, dict) or not filters:
                        raise ValueError('A filter must be specified')
                    if table in ORACLE_TABLES_WITH_STORE:
                        if isinstance(store, list):
                            template = [{'table': table, 'values': values, 'filters': {'store': item, **filters}}
                                        for item in store]
                            template2 = [{'table': table, 'filters': {'changed': 2, 'store': item, **filters}}
                                         for item in store]
                        else:
                            template = [{'table': table, 'values': values, 'filters': {'store': store, **filters}}]
                            template2 = [{'table': table, 'filters': {'changed': 2, 'store': store, **filters}}]
                    else:
                        template = [{'table': table, 'values': values, 'filters': filters}]
                        template2 = [{'table': table, 'filters': {'changed': 2, **filters}}]
                    # Delete objects flagged for deletion before upserting
                    if table in ORACLE_TABLES_WITH_CHANGED:
                        db.delete(template2, context)
                    # Upsert into database
                    db.upsert(template, context)
                    executed.add(index)

                elif operation == 'update':
                    # Read object ID
                    object_id = query.get('id')
                    filters = query.get('filters', {})
                    if object_id is None and not filters:
                        raise KeyError('id')
                    # Read values
                    values = query['values']
                    if table in ORACLE_TABLES_WITH_CHANGED:
                        values['changed'] = 1
                    # Read filters
                    if object_id is not None:
                        filters = {
                            **filters,
                            'id': object_id,
                        }
                    if table in ORACLE_TABLES_WITH_STORE:
                        filters['store'] = store
                    # Update in database
                    template = [{'table': table, 'values': values, 'filters': filters}]
                    db.update(template, context)
                    executed.add(index)

                elif operation == 'delete' and table in ORACLE_TABLES_WITH_CHANGED:
                    # Read object ID
                    object_id = query.get('id')
                    filters = query.get('filters', {})
                    if object_id is None and not filters:
                        raise KeyError('id')
                    # Read filters
                    if object_id is not None:
                        filters = {
                            **filters,
                            'id': object_id,
                        }
                    if table in ORACLE_TABLES_WITH_STORE:
                        filters['store'] = store
                    # Delete objects by updating the 'changed' flag in database
                    template = [{'table': table, 'values': {'changed': 2}, 'filters': filters}]
                    db.update(template, context)
                    executed.add(index)

                elif operation == 'delete':
                    # Read object ID
                    object_id = query.get('id')
                    filters = query.get('filters', {})
                    if object_id is None and not filters:
                        raise KeyError('id')
                    # Read filters
                    if object_id is not None:
                        filters = {
                            **filters,
                            'id': object_id,
                        }
                    if table in ORACLE_TABLES_WITH_STORE:
                        filters['store'] = store
                    # Delete objects from database
                    template = [{'table': table, 'filters': filters}]
                    db.delete(template, context)
                    executed.add(index)

            except:  # pylint: disable=bare-except
                log.error('Error while trying to execute query #%s', index, exc_info=True)
                failed[index] = format_exc()

        if failed:
            db.rollback()

        try:
            status_failed = SERVICENOW_STATUS_FAILED
            status_pending = SERVICENOW_STATUS_PENDING
            status = status_failed if failed else status_pending
            template = [
                {
                    'table': 'fortinet_servicenow',
                    'filters': {'"order"': order_id},
                    'values': {'contents': json.dumps(queries), 'status': status, 'deadline': expire},
                    'merge': {
                        'contents': lambda x, y: json.dumps(json.loads(str(x)) + json.loads(y)),
                        'status': lambda x, y: status_failed if status_failed in (x, y) else status_pending,
                    },
                },
                *[{
                    'table': 'fortinet_servicenow_store',
                    'filters': {'"order"': order_id, 'store': store},
                    'values': {'status': status},
                    'merge': {
                        'status': lambda x, y: status_failed if status_failed in (x, y) else status_pending,
                    },
                } for store in stores],
            ]
            db.upsert(template, context)
        except:  # pylint: disable=bare-except
            log.error('Error while trying to save ServiceNow order %s in Oracle', order_id, exc_info=True)
            failed['order'] = format_exc()

        if failed:
            db.rollback()
            return {'success': False, 'changed': [], 'executed': list(executed), 'failed': failed}

    return {'success': True, 'changed': list(stores), 'executed': list(executed), 'failed': failed}


class FortinetDatabase:
    '''Allow access to generalized operations inside an Oracle Database storing Fortinet data'''
    # pylint: disable=too-many-instance-attributes
    def __init__(self, username, password, host='127.0.0.1', port=1521, sid='XE', service=None):
        # pylint: disable=too-many-arguments
        self.username = username
        self.password = password
        self.host = host
        self.port = port
        self.sid = sid
        self.service = service
        self._changed = False
        self._connection = None

    def __enter__(self):
        self._connection = cx_Oracle.connect(self.username, self.password, self._make_dsn())
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        if self._changed and exc_type is None:
            self.commit()
        elif self._changed:
            self.rollback()
        self._connection.close()

    def commit(self):
        '''Commit changes to the database'''
        self._connection.commit()
        self._changed = False

    def rollback(self):
        '''Cancel changes to the database'''
        self._connection.rollback()
        self._changed = False

    def generate_template(self, head=None, tail=None):
        '''Generate template data from a head, database and tail template settings'''
        template = list(head or [])

        # Read 'fortinet_service', 'fortinet_servicegroup' and 'fortinet_servicegroup_member'
        # from 'fortinet_service_template'
        services = []
        servicegroups = []
        servicegroup_members = []
        service_names = set()
        servicegroup_names = set()
        fields = ['group_name', 'name', '"comment"', 'category', 'protocol',
                  'tcp_portrange', 'udp_portrange', 'sctp_portrange',
                  'icmptype', 'icmpcode']
        for row in self.select('fortinet_service_template', fields):
            # A service with the same name may be defined twice but in a different group, we don't
            # want to add it to the list twice or we risk violating the unique constraint
            if row[1] not in service_names:
                services.append(('{store}', *row[1:]))
                service_names.add(row[1])
            servicegroup_members.append(('{store}', row[0], row[1]))
            servicegroup_names.add(row[0])
        servicegroups = [('{store}', name) for name in servicegroup_names]
        template.append({
            'table': 'fortinet_service',
            'fields': ['store', *fields[1:]],
            'values': services,
        })
        template.append({
            'table': 'fortinet_servicegroup',
            'fields': ['store', 'name'],
            'values': servicegroups,
        })
        template.append({
            'table': 'fortinet_servicegroup_member',
            'fields': ['store', 'servicegroup', 'service'],
            'values': servicegroup_members,
        })

        # Read 'fortinet_policy' from 'fortinet_policy_template'
        fields = ['name', 'policyid', 'comments', 'action', 'status', 'schedule', 'utm_status',
                  'logtraffic', 'av_profile', 'webfilter_profile', 'dnsfilter_profile',
                  'dlp_sensor', 'ips_sensor', 'application_list', 'ssl_ssh_profile', 'position',
                  'neighbor']
        rows = self.select('fortinet_policy_template', fields)
        template.append({
            'table': 'fortinet_policy',
            'fields': ['store', *fields],
            'values': [('{store}', *row) for row in rows],
        })

        # Read 'fortinet_policy_srcintf' from 'fortinet_policy_template_srcintf'
        fields = ['policy', 'interface']
        rows = self.select('fortinet_policy_template_srcintf', fields)
        template.append({
            'table': 'fortinet_policy_srcintf',
            'fields': ['store', *fields],
            'values': [('{store}', *row) for row in rows],
        })

        # Read 'fortinet_policy_dstintf' from 'fortinet_policy_template_dstintf'
        fields = ['policy', 'interface']
        rows = self.select('fortinet_policy_template_dstintf', fields)
        template.append({
            'table': 'fortinet_policy_dstintf',
            'fields': ['store', *fields],
            'values': [('{store}', *row) for row in rows],
        })

        # Read 'fortinet_policy_srcaddr' from 'fortinet_policy_template_srcaddr'
        fields = ['policy', 'addressgroup']
        rows = self.select('fortinet_policy_template_srcaddr', fields)
        template.append({
            'table': 'fortinet_policy_srcaddr',
            'fields': ['store', *fields],
            'values': [('{store}', *row) for row in rows],
        })

        # Read 'fortinet_policy_dstaddr' from 'fortinet_policy_template_dstaddr'
        fields = ['policy', 'addressgroup']
        rows = self.select('fortinet_policy_template_dstaddr', fields)
        template.append({
            'table': 'fortinet_policy_dstaddr',
            'fields': ['store', *fields],
            'values': [('{store}', *row) for row in rows],
        })

        # Read 'fortinet_policy_service' from 'fortinet_policy_template_service'
        fields = ['policy', 'servicegroup']
        rows = self.select('fortinet_policy_template_service', fields)
        template.append({
            'table': 'fortinet_policy_service',
            'fields': ['store', *fields],
            'values': [('{store}', *row) for row in rows],
        })

        if isinstance(tail, list):
            template.extend(tail)

        return template

    def select(self, table, fields=None, filters=None, context=None):
        '''Return the result of a select query'''
        values = tuple()
        if isinstance(filters, dict):
            values = tuple(filters.values())
        values = self._format_values(values, context)
        query = self._format_select(table, fields or ['*'], filters)
        with self._connection.cursor() as cursor:
            return list(cursor.execute(query, values))

    def merge(self, table, fields=None, group_fields=None, filters=None, context=None):
        '''Return the merged result of a select query'''
        # pylint: disable=too-many-arguments
        values = tuple()
        if isinstance(filters, dict):
            values = tuple(filters.values())
        values = self._format_values(values, context)
        query = self._format_select(table, fields, filters)
        with self._connection.cursor() as cursor:
            objs = list(cursor.execute(query, values))
        # Merge object fields
        merged = []
        for index, field in enumerate(fields):
            options = {obj[index] for obj in objs}
            if field in group_fields:
                merged.append(list(options))
            elif len(options) == 1:
                merged.append(options.pop())
            else:
                merged.append(None)
        return merged

    def group(self, table, merge_fields=None, group_fields=None, filters=None, context=None):
        '''Return the grouped result of a select query'''
        # pylint: disable=too-many-arguments,too-many-locals
        fields = [*merge_fields, *group_fields]
        values = tuple()
        if isinstance(filters, dict):
            values = tuple(filters.values())
        values = self._format_values(values, context)
        query = self._format_select(table, fields, filters)
        with self._connection.cursor() as cursor:
            objs = list(cursor.execute(query, values))
        objs = [dict(zip(fields, row)) for row in objs]
        # Group objects with identical merge fields
        groups = []
        for obj in objs:
            found = None
            for group in groups:
                match_all = True
                for field in merge_fields:
                    if obj[field] != group[field]:
                        match_all = False
                        break
                if match_all:
                    found = group
                    break
            if found is not None:
                for field in group_fields:
                    found[field].append(obj[field])
                continue
            groups.append({
                **{field: obj[field] for field in merge_fields},
                **{field: [obj[field]] for field in group_fields},
            })
        return groups

    def insert(self, data, context=None):
        '''Execute insert queries in bulk'''
        self._changed = True
        for table in data:
            query = self._format_insert(table['table'], table['fields'])
            data = [self._format_values(row, context) for row in table['values']]
            with self._connection.cursor() as cursor:
                cursor.executemany(query, data)

    def upsert(self, data, context=None):
        '''Execute upsert queries in bulk'''
        self._changed = True
        for table in data:
            fields = [*table['filters'].keys(), *table['values'].keys()]
            try:
                found = dict(zip(fields, self.select(table['table'], fields, table['filters'], context)[0]))
            except IndexError:
                found = None
            if found:
                values = table['values']
                for key, func in table.get('merge', {}).items():
                    values[key] = func(found[key], values[key])
                template = [{'table': table['table'], 'values': values, 'filters': table['filters']}]
                self.update(template, context)
            else:
                filter_values = tuple(table['filters'].values())
                field_values = tuple(table['values'].values())
                template = [{'table': table['table'], 'fields': fields, 'values': [(*filter_values, *field_values)]}]
                self.insert(template, context)

    def update(self, data, context=None):
        '''Execute update queries in bulk'''
        self._changed = True
        for table in data:
            field_values = tuple(table['values'].values())
            fields = list(table['values'].keys())
            filter_values = tuple()
            filters = None
            if isinstance(table.get('filters'), dict):
                filter_values = tuple(table['filters'].values())
                filters = table['filters']
            values = self._format_values((*field_values, *filter_values), context)
            query = self._format_update(table['table'], fields, filters)
            with self._connection.cursor() as cursor:
                cursor.execute(query, values)

    def delete(self, data, context=None):
        '''Execute delete queries in bulk'''
        self._changed = True
        for table in data:
            values = tuple()
            filters = None
            if isinstance(table.get('filters'), dict):
                values = tuple(table['filters'].values())
                filters = table['filters']
            values = self._format_values(values, context)
            query = self._format_delete(table['table'], filters)
            with self._connection.cursor() as cursor:
                cursor.execute(query, values)

    def _format_select(self, table, fields, filters=None):
        '''Format a select query'''
        # pylint: disable=no-self-use
        context = {
            'table': table,
            'fields': ', '.join(fields),
        }
        if filters is None:
            return 'select {fields} from {table}'.format(**context)
        context['filters'] = self._format_filters(filters)
        return 'select {fields} from {table} where {filters}'.format(**context)

    def _format_insert(self, table, fields):
        '''Format an insert query'''
        # pylint: disable=no-self-use
        context = {
            'table': table,
            'fields': ', '.join(fields),
            'values': ', '.join([self._format_bind(field) for field in fields]),
        }
        return 'insert into {table} ({fields}) values ({values})'.format(**context)

    def _format_update(self, table, fields, filters=None):
        '''Format an update query'''
        # pylint: disable=no-self-use
        context = {
            'table': table,
            'values': ', '.join(['{0} = {1}'.format(field, self._format_bind(field)) for field in fields]),
        }
        if filters is None:
            return 'update {table} set {values}'.format(**context)
        context['filters'] = self._format_filters(filters)
        return 'update {table} set {values} where {filters}'.format(**context)

    def _format_delete(self, table, filters=None):
        '''Format a delete query'''
        # pylint: disable=no-self-use
        context = {
            'table': table,
        }
        if filters is None:
            return 'delete from {table}'.format(**context)
        context['filters'] = self._format_filters(filters)
        return 'delete from {table} where {filters}'.format(**context)

    def _format_values(self, values, context):
        '''Format all values in a tuple'''
        # pylint: disable=no-self-use
        def flatten(value):
            return [item for sub in value for item in flatten(sub)] if isinstance(value, (list, tuple)) else [value]
        values = flatten(values)
        if context is None:
            return values
        return tuple(value.format(**context) if isinstance(value, str) else value for value in values)

    def _format_filters(self, filters):
        '''Format filter operators'''
        # pylint: disable=no-self-use
        formatted_filters = []
        for key, value in filters.items():
            parts = key.rsplit('__', 1)
            if len(parts) >= 2:
                field, operator = parts
                if operator not in ['=', '!=', '^=', '<>', '>', '<', '>=', '<=', 'in']:
                    raise ValueError('Invalid operator')
            elif isinstance(value, list):
                field, operator = key, 'in'
            else:
                field, operator = key, '='
            if isinstance(value, list):
                bind = self._format_bind(field, len(value))
            else:
                bind = self._format_bind(field)
            formatted_filters.append('{0} {1} {2}'.format(field, operator, bind))
        return ' and '.join(formatted_filters)

    def _format_bind(self, field, num_binds=None):
        '''Format bind variables'''
        # pylint: disable=no-self-use
        if num_binds is None:
            return ':b{0}'.format(field.strip(' "'))
        binds = [':b{0}{1}'.format(field.strip(' "'), num) for num in range(num_binds)]
        return '({0})'.format(', '.join(binds))

    def _make_dsn(self):
        '''Make the DSN to be used in the Oracle Database connection'''
        if self.service:
            return cx_Oracle.makedsn(self.host, self.port, service_name=self.service)
        return cx_Oracle.makedsn(self.host, self.port, sid=self.sid)


def salt_create_fortinet_minions(minions):
    '''Request Salt to create Fortinet objects for a list of minions'''
    api = Pepper(SALT_URL)
    api.login(SALT_USERNAME, SALT_PASSWORD, SALT_EAUTH)
    jobs, failed = {}, {}
    for minion in minions:
        try:
            job = {
                'client': 'runner_async',
                'pillar': {
                    'event_data': {
                        'ip': minion,
                    },
                },
            }
            result = api.runner('state.orchestrate', 'orchestrations.create_fortinet_minion', **job)
            jobs[minion] = result['return'][0]['jid']
        except:  # pylint: disable=bare-except
            log.error('Error while trying to create minion with IP %s', minion, exc_info=True)
            failed[minion] = format_exc()
    return jobs, failed


def salt_update_fortinet(orders):
    '''Request Salt to update Fortinet stores included in ServiceNow requests'''
    api = Pepper(SALT_URL)
    api.login(SALT_USERNAME, SALT_PASSWORD, SALT_EAUTH)
    jobs, failed = [], []
    for order, stores in orders.items():
        for store in stores:
            try:
                job = {
                    'client': 'runner_async',
                    'pillar': {
                        'event_data': {
                            'order': order,
                            'store': store,
                        },
                    },
                }
                result = api.runner('state.orchestrate', 'orchestrations.update_fortinet', **job)
                jobs.append({
                    'order': order,
                    'store': store,
                    'job': result['return'][0]['jid'],
                })
            except:  # pylint: disable=bare-except
                log.error('Error while trying to update Fortinet for ServiceNow request with ID %s', order,
                          exc_info=True)
                failed.append({
                    'order': order,
                    'store': store,
                    'error': format_exc(),
                })
    return jobs, failed


def format_exc(full=False):
    '''Format a short description of an exception'''
    exc_type, exc_obj, exc_tb = sys.exc_info()
    exc_file = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
    exc_line = exc_tb.tb_lineno
    exc_type = exc_type.__name__
    exc_value = str(exc_obj)
    prefix = '{0}:{1}: '.format(exc_file, exc_line) if full else ''
    if exc_value:
        return '{0}{1}: {2}'.format(prefix, exc_type, exc_value)
    return '{0}{1}'.format(prefix, exc_type)


if __name__ == '__main__':
    app.run(debug=True)
