# -*- coding: utf-8 -*-
# pylint: disable=W1699
'''
Wrapper for pyfortiapi with sanitized methods, arguments and error handling
'''

import json
import urllib.parse
import requests.exceptions

import pyfortiapi


class _FortiGateWrapper(pyfortiapi.FortiGate):
    '''Wrapper around pyfortiapi.FortiGate to cache the session, avoiding multiple logins'''
    def __init__(self, ipaddr, username, password, timeout=10, vdom="root", port="443"):
        # pylint: disable=too-many-arguments
        super().__init__(ipaddr, username, password, timeout, vdom, port)
        self.session = None

    def login(self):
        '''Override the login method to cache the session'''
        if self.session is None:
            self.session = super().login()
        return self.session

    def logout(self, session=None):
        '''Override the logout method to use the cached session'''
        if not session and self.session:
            super().logout(self.session)


class FortiAPI:
    '''Fortinet API'''
    # pylint: disable=too-many-public-methods

    def __init__(self, username, password, host, port='443', **kwargs):
        self.api = _FortiGateWrapper(host, username, password, port=port, **kwargs)

    def __enter__(self):
        self.api.login()
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        try:
            self.api.logout()
        except:  # pylint: disable=bare-except
            pass

    ############################################################################
    # Address
    ############################################################################
    def get_address_list(self, filters=False, pretty=False):
        '''Get a list of address objects'''
        return self._api_call(self.api.get_firewall_address, filters=filters, pretty=pretty)

    def get_address(self, name, pretty=False):
        '''Get an address object'''
        return self._api_call_get_first(self.api.get_firewall_address, name, pretty=pretty)

    def create_address(self, name=False, data=False, **kwargs):
        '''Create a new address object'''
        payload = self._gen_payload({'name': name}, data, kwargs)
        return self._api_call(self.api.create_firewall_address, payload['name'], payload)

    def delete_address(self, name):
        '''Delete an address object'''
        for address_group in self.get_address_group_list():
            if name in self._get_member_names(address_group['member']):
                self.remove_address_from_address_group(address_group['name'], name)
        for policy in self.get_policy_list():
            if name in self._get_member_names(policy['srcaddr']):
                self.remove_srcaddr_from_policy(policy['policyid'], name)
        for policy in self.get_policy_list():
            if name in self._get_member_names(policy['dstaddr']):
                self.remove_dstaddr_from_policy(policy['policyid'], name)
        return self._api_call(self.api.delete_firewall_address, name)

    def update_address(self, name=False, data=False, **kwargs):
        '''Update an address object'''
        payload = self._gen_payload({'name': name}, data, kwargs)
        return self._api_call(self.api.update_firewall_address, payload['name'], payload)

    ############################################################################
    # Address Group
    ############################################################################
    def get_address_group_list(self, filters=False, pretty=False):
        '''Get a list of address group objects'''
        return self._api_call(self.api.get_address_group, filters=filters, pretty=pretty)

    def get_address_group(self, name, pretty=False):
        '''Get an address group object'''
        return self._api_call_get_first(self.api.get_address_group, name, pretty=pretty)

    def create_address_group(self, name=False, member=False, data=False, **kwargs):
        '''Create a new address group object'''
        payload = self._gen_payload({'name': name, 'member': member}, data, kwargs)
        self._clear_members(payload, 'member')
        return self._api_call(self.api.create_address_group, payload['name'], payload)

    def delete_address_group(self, name):
        '''Delete an address group object'''
        for policy in self.get_policy_list():
            if name in self._get_member_names(policy['srcaddr']):
                self.remove_srcaddr_from_policy(policy['policyid'], name)
        for policy in self.get_policy_list():
            if name in self._get_member_names(policy['dstaddr']):
                self.remove_dstaddr_from_policy(policy['policyid'], name)
        return self._api_call(self.api.delete_address_group, name)

    def update_address_group(self, name=False, member=False, data=False, **kwargs):
        '''Update an address group object'''
        payload = self._gen_payload({'name': name, 'member': member}, data, kwargs)
        self._clear_members(payload, 'member')
        return self._api_call(self.api.update_address_group, payload['name'], payload)

    def is_address_in_address_group(self, name, address):
        '''Check if an address object is in an address group object'''
        try:
            address_group = self.get_address_group(name)
        except FortiAPI.Error:
            return False
        return address in self._get_member_names(address_group['member'])

    def get_address_groups_with_address(self, address):
        '''Get a list of address group objects containing an address object'''
        address_groups = []
        for address_group in self.get_address_group_list():
            if address in self._get_member_names(address_group['member']):
                address_groups.append(address_group)
        return address_groups

    def add_address_to_address_group(self, name, new_members):
        '''Add an address object to an address group object'''
        members = self.get_address_group(name)['member']
        payload = {'member': self._include_members(members, new_members)}
        return self._api_call(self.api.update_address_group, name, payload)

    def remove_address_from_address_group(self, name, old_members):
        '''Remove an address object from an address group object'''
        # pylint: disable=invalid-name
        members = self._exclude_members(self.get_address_group(name)['member'], old_members)
        if not members:
            return self.delete_address_group(name)
        return self._api_call(self.api.update_address_group, name, {'member': members})

    ############################################################################
    # Service
    ############################################################################
    def get_service_list(self, filters=False, pretty=False):
        '''Get a list of service objects'''
        return self._api_call(self.api.get_firewall_service, filters=filters, pretty=pretty)

    def get_service(self, name, pretty=False):
        '''Get a service object'''
        return self._api_call_get_first(self.api.get_firewall_service, name, pretty=pretty)

    def create_service(self, name=False, data=False, **kwargs):
        '''Create a new service object'''
        payload = self._gen_payload({'name': name}, data, kwargs)
        return self._api_call(self.api.create_firewall_service, payload['name'], payload)

    def delete_service(self, name):
        '''Delete a service object'''
        for service_group in self.get_service_group_list():
            if name in self._get_member_names(service_group['member']):
                self.remove_service_from_service_group(service_group['name'], name)
        for policy in self.get_policy_list():
            if name in self._get_member_names(policy['service']):
                self.remove_service_from_policy(policy['policyid'], name)
        return self._api_call(self.api.delete_firewall_service, name)

    def update_service(self, name=False, data=False, **kwargs):
        '''Update a service object'''
        payload = self._gen_payload({'name': name}, data, kwargs)
        return self._api_call(self.api.update_firewall_service, payload['name'], payload)

    ############################################################################
    # Service Group
    ############################################################################
    def get_service_group_list(self, filters=False, pretty=False):
        '''Get a list of service group objects'''
        return self._api_call(self.api.get_service_group, filters=filters, pretty=pretty)

    def get_service_group(self, name, pretty=False):
        '''Get a service group object'''
        return self._api_call_get_first(self.api.get_service_group, name, pretty=pretty)

    def create_service_group(self, name=False, member=False, data=False, **kwargs):
        '''Create a new service group object'''
        payload = self._gen_payload({'name': name, 'member': member}, data, kwargs)
        self._clear_members(payload, 'member')
        return self._api_call(self.api.create_service_group, payload['name'], payload)

    def delete_service_group(self, name):
        '''Delete a service group object'''
        for policy in self.get_policy_list():
            if name in self._get_member_names(policy['service']):
                self.remove_service_from_policy(policy['policyid'], name)
        return self._api_call(self.api.delete_service_group, name)

    def update_service_group(self, name=False, member=False, data=False, **kwargs):
        '''Update a service group object'''
        payload = self._gen_payload({'name': name, 'member': member}, data, kwargs)
        self._clear_members(payload, 'member')
        return self._api_call(self.api.update_service_group, payload['name'], payload)

    def is_service_in_service_group(self, name, service):
        '''Check if a service object is in a service group object'''
        try:
            service_group = self.get_service_group(name)
        except FortiAPI.Error:
            return False
        return service in self._get_member_names(service_group['member'])

    def get_service_groups_with_service(self, service):
        '''Get a list of service group objects containing a service object'''
        service_groups = []
        for service_group in self.get_service_group_list():
            if service in self._get_member_names(service_group['member']):
                service_groups.append(service_group)
        return service_groups

    def add_service_to_service_group(self, name, new_members):
        '''Add a service object to a service group object'''
        members = self.get_service_group(name)['member']
        payload = {'member': self._include_members(members, new_members)}
        return self._api_call(self.api.update_service_group, name, payload)

    def remove_service_from_service_group(self, name, old_members):
        '''Remove a service object from a service group object'''
        # pylint: disable=invalid-name
        members = self._exclude_members(self.get_service_group(name)['member'], old_members)
        if not members:
            return self.delete_service_group(name)
        return self._api_call(self.api.update_service_group, name, {'member': members})

    ############################################################################
    # Policy
    ############################################################################
    def get_policy_list(self, filters=False, pretty=False):
        '''Get a list of policy objects'''
        return self._api_call(self.api.get_firewall_policy, filters=filters, pretty=pretty)

    def get_policy(self, policyid, pretty=False):
        '''Get a policy object'''
        return self._api_call_get_first(self.api.get_firewall_policy, policyid, pretty=pretty)

    def create_policy(self, policyid=0, data=False, **kwargs):
        '''Create a new policy object'''
        payload = self._gen_payload({'policyid': policyid}, data, kwargs)
        if payload['policyid'] == 0:
            del payload['policyid']
        self._clear_members(payload, 'srcintf')
        self._clear_members(payload, 'dstintf')
        self._clear_members(payload, 'srcaddr')
        self._clear_members(payload, 'dstaddr')
        self._clear_members(payload, 'service')
        return self._api_call(self.api.create_firewall_policy, payload.get('policyid', 0), payload)

    def delete_policy(self, policyid):
        '''Delete a policy object'''
        return self._api_call(self.api.delete_firewall_policy, policyid)

    def update_policy(self, policyid=False, data=False, **kwargs):
        '''Update a policy object'''
        payload = self._gen_payload({'policyid': policyid}, data, kwargs)
        self._clear_members(payload, 'srcintf')
        self._clear_members(payload, 'dstintf')
        self._clear_members(payload, 'srcaddr')
        self._clear_members(payload, 'dstaddr')
        self._clear_members(payload, 'service')
        return self._api_call(self.api.update_firewall_policy, payload['policyid'], payload)

    def move_policy(self, policyid, neighbor, position='before'):
        '''Move a policy object'''
        payload = {
            'base': self.api.urlbase,
            'policy': str(policyid),
            'neighbor': str(neighbor),
            'position': position,
        }
        url = '{base}api/v2/cmdb/firewall/policy/{policy}?action=move&{position}={neighbor}'
        try:
            result = self.api.put(url.format(**payload), '{}')
        except requests.exceptions.HTTPError as exc:
            result = exc.response.status_code
        return self._handle_result(result)

    def is_srcaddr_in_policy(self, policyid, srcaddr):
        '''Check if a source address object is in a policy object'''
        try:
            policy = self.get_policy(policyid)
        except FortiAPI.Error:
            return False
        return srcaddr in self._get_member_names(policy['srcaddr'])

    def get_policies_with_srcaddr(self, srcaddr):
        '''Get a list of policy objects containing a source address object'''
        policies = []
        for policy in self.get_policy_list():
            if srcaddr in self._get_member_names(policy['srcaddr']):
                policies.append(policy)
        return policies

    def add_srcaddr_to_policy(self, policyid, new_members):
        '''Add a source address object to a policy object'''
        members = self.get_policy(policyid)['srcaddr']
        payload = {'srcaddr': self._include_members(members, new_members)}
        return self._api_call(self.api.update_firewall_policy, policyid, payload)

    def remove_srcaddr_from_policy(self, policyid, old_members):
        '''Remove a source address object from a policy object'''
        members = self._exclude_members(self.get_policy(policyid)['srcaddr'], old_members)
        if not members:
            return self.delete_policy(policyid)
        return self._api_call(self.api.update_firewall_policy, policyid, {'srcaddr': members})

    def is_dstaddr_in_policy(self, policyid, dstaddr):
        '''Check if a destination address object is in a policy object'''
        try:
            policy = self.get_policy(policyid)
        except FortiAPI.Error:
            return False
        return dstaddr in self._get_member_names(policy['dstaddr'])

    def get_policies_with_dstaddr(self, dstaddr):
        '''Get a list of policy objects containing a destination address object'''
        policies = []
        for policy in self.get_policy_list():
            if dstaddr in self._get_member_names(policy['dstaddr']):
                policies.append(policy)
        return policies

    def add_dstaddr_to_policy(self, policyid, new_members):
        '''Add a destination address object to a policy object'''
        members = self.get_policy(policyid)['dstaddr']
        payload = {'dstaddr': self._include_members(members, new_members)}
        return self._api_call(self.api.update_firewall_policy, policyid, payload)

    def remove_dstaddr_from_policy(self, policyid, old_members):
        '''Remove a destination address object from a policy object'''
        members = self._exclude_members(self.get_policy(policyid)['dstaddr'], old_members)
        if not members:
            return self.delete_policy(policyid)
        return self._api_call(self.api.update_firewall_policy, policyid, {'dstaddr': members})

    def is_service_in_policy(self, policyid, service):
        '''Check if a service object is in a policy object'''
        try:
            policy = self.get_policy(policyid)
        except FortiAPI.Error:
            return False
        return service in self._get_member_names(policy['service'])

    def get_policies_with_service(self, service):
        '''Get a list of policy objects containing a service object'''
        policies = []
        for policy in self.get_policy_list():
            if service in self._get_member_names(policy['service']):
                policies.append(policy)
        return policies

    def add_service_to_policy(self, policyid, new_members):
        '''Add a service object to a policy object'''
        members = self.get_policy(policyid)['service']
        payload = {'service': self._include_members(members, new_members)}
        return self._api_call(self.api.update_firewall_policy, policyid, payload)

    def remove_service_from_policy(self, policyid, old_members):
        '''Remove a service object from a policy object'''
        members = self._exclude_members(self.get_policy(policyid)['service'], old_members)
        if not members:
            return self.delete_policy(policyid)
        return self._api_call(self.api.update_firewall_policy, policyid, {'service': members})

    ############################################################################
    # Utils
    ############################################################################
    def _get_member_names(self, members):
        '''Generic function to get a list of member names from a list of members'''
        # pylint: disable=no-self-use
        return list({member['name'] for member in members})

    def _gen_payload(self, *args, **kwargs):
        '''Generic function to merge multiple sources of data into a valid payload'''
        # pylint: disable=no-self-use
        payload = {}
        for arg in args:
            if isinstance(arg, dict):
                payload.update(arg)
        payload.update(kwargs)
        return payload

    def _gen_members(self, members):
        '''Generic function to generate a valid list of members'''
        # pylint: disable=no-self-use
        if isinstance(members, list):
            names = {member['name'] if isinstance(member, dict) else member for member in members}
        elif isinstance(members, dict):
            names = {members['name']}
        elif isinstance(members, str):
            names = {members}
        else:
            return []
        members = [{'name': name} for name in names]
        return sorted(members, key=lambda member: member['name'])

    def _include_members(self, members, new_members):
        '''Generic function to include a list of new members into a list of members'''
        if not isinstance(members, list):
            members = [members]
        if not isinstance(new_members, list):
            new_members = [new_members]
        return self._gen_members([*members, *new_members])

    def _exclude_members(self, members, old_members):
        '''Generic function to exclude a list of old members from a list of members'''
        if not isinstance(members, list):
            members = [members]
        if not isinstance(old_members, list):
            old_members = [old_members]
        members = self._gen_members(members)
        old_names = self._get_member_names(self._gen_members(old_members))
        return [member for member in members if member['name'] not in old_names]

    def _clear_members(self, payload, key):
        '''Generic function to clear a list of members in a payload'''
        try:
            members = self._gen_members(payload[key])
            if isinstance(members, list) and len(members) > 0:
                payload[key] = members
            else:
                del payload[key]
        except KeyError:
            pass

    ############################################################################
    # Error Handling
    ############################################################################
    def _api_call(self, api_method, *args, pretty=False, **kwargs):
        '''Generic function to call an API method'''
        args = list(args)
        if len(args) > 0 and isinstance(args[0], str):
            args[0] = urllib.parse.quote(str(args[0]), safe='')
        for index, arg in enumerate(args):
            if isinstance(arg, (list, dict)):
                args[index] = json.dumps(arg)
        try:
            result = api_method(*args, **kwargs)
        except requests.exceptions.HTTPError as exc:
            result = exc.response.status_code
        return self._handle_result(result, pretty)

    def _api_call_get_first(self, api_method, *args, pretty=False, **kwargs):
        '''Generic function to call an API method and return the first element in the result'''
        args = list(args)
        if len(args) > 0 and isinstance(args[0], str):
            args[0] = urllib.parse.quote(str(args[0]), safe='')
        for index, arg in enumerate(args):
            if isinstance(arg, (list, dict)):
                args[index] = json.dumps(arg)
        try:
            result = api_method(*args, **kwargs)
            if isinstance(result, list):
                result = result[0]
        except requests.exceptions.HTTPError as exc:
            result = exc.response.status_code
        except IndexError:
            result = 404
        return self._handle_result(result, pretty)

    def _handle_result(self, result, pretty=False):
        '''Handle HTTP error codes from pyfortiapi as exceptions'''
        # pylint: disable=no-self-use
        if isinstance(result, int):
            if result == 200:
                return True
            if result == 401:
                raise FortiAPI.AuthenticationError('Fortinet authentication failed')
            if result == 404:
                raise FortiAPI.NotFoundError('Fortinet object not found')
            if result in [400, 424, 500]:
                raise FortiAPI.InvalidRequestError('Invalid Fortinet API request')
            raise FortiAPI.UnknownError('Unknown error during Fortinet API request')
        if pretty:
            return json.dumps(result, indent=4)
        return result

    class Error(Exception):
        '''Generic error'''

    class AuthenticationError(Error):
        '''Authentication error'''

    class NotFoundError(Error):
        '''Object not found error'''

    class InvalidRequestError(Error):
        '''Invalid request error'''

    class UnknownError(Error):
        '''Unknown error'''
