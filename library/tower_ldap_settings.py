#!/usr/bin/python
# coding: utf-8 -*-

# (c) 2017, Stanley Karunditu <skarundi@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: tower_ldap_settings
author: "Stanley Karunditu (@linuxsimba)"
short_description: Set Ansible Tower LDAP Credentials
description:
    - Set Ansible Tower LDAP Credentials. These actions can
      only be performed by a Tower superuser. See
      U(https://www.ansible.com/tower) for details.
options:
    ldap_server_protocol:
        description:
            - LDAP connection protocol
        required: False
        default: ldaps
    ldap_server_name:
        description:
            - LDAP Server FQDN
        required: False
    ldap_server_port:
        description:
            - LDAP Server Connection Port
        default: 636
        required: False
    ldap_bind_dn:
        description:
            - LDAP Bind User DN
        required: False
    ldap_bind_password:
        description:
            - LDAP Bind User password. If set, this module will never be idempotent
            - because bind password is encrypted and difficult to confirm if the password
            - has changed.
        required: False
    ldap_start_tls:
        description:
            - Set  LDAP Start TLS
        default: false
        required: False
    ldap_user_search:
        description:
            - List of DNs to search through to find users. Performs recursive LDAP search
        required: False
    ldap_group_search:
        description:
            - single group DN to find User Groups. Performs recursive LDAP search.
            - Multiple DNs cannot be specified
        required: False
    ldap_group_type:
        description:
            - Specify the type of LDAP database to be used.
            - The C(active_directory) option will set the I(AUTH_LDAP_GROUP_TYPE) Tower setting attribute to I(NestedActiveDirectoryGroupType)
            - The  C(open_ldap) option will set the I(AUTH_LDAP_GROUP_TYPE) Tower setting attribute to  I(NestedGroupOfNamesType)
            - The default setting is C(active_directory)
        choices: ['"active_directory"', "open_ldap"]
        default: "active_directory"
        required: False
    ldap_superuser:
        description:
            - Specify DN that can have superuser privileges on Tower. Could be a Group or User.
            - Multiple DNs cannot be specified
        required: False
    ldap_organization_map:
        description:
            - Provide a list  of Tower organization maps dictionaries.
            - Each dictionary contains the following
            - C(organization) - Tower Organization name. This value is case sensitive.
            - C(users) -  List of DNs associated with the organization
            - C(admins) list - List of DNs that have admin organization privileges
        required: False
    ldap_team_map:
        description:
            -  Provide a list of Tower teams map directories
            - Each directory contains the following
            - C(organization) - Tower organization the team belongs to. This value is case sensitive.
            - C(team) - Tower team name
            - C(users) - List of User LDAP DNs that should belong to the team.
        required: False
    state:
        description:
            - When set to absent all LDAP configuration is removed.
        required: True
        default: "present"
        choices: ["present", "absent"]
extends_documentation_fragment: tower
'''


EXAMPLES = '''
- name:  Remove all LDAP configuration
  tower_ldap_settings:
  state: absent
  tower_host: tower.example.com
  tower_username: "{{ vault_tower_user }}"
  tower_password: "{{ vault_tower_pass }}"


- name: |
    Update Ldap org and team map with a dbapp org and admin team. Previously only
    defined a webapp organization and webapp-admin team
  tower_ldap_settings:
    state: present
    ldap_organization_map:
        - organization: webapp
          users: "cn=webapp,ou=groups,dc=example,dc=local"
          admins: "cn=webadmins,ou=groups,dc=example,dc=local"
        - organization: dbapp
          users: "cn=dbapp,ou=groups,dc=example,dc=local"
          admins: "cn=dbadmins,ou=groups,dc=example,dc=local"
    ldap_team_map:
        - team: webapp_admins
          organization: webapp
          users: "cn=webadmins,ou=groups,dc=example,dc=local"
        - team: dbapp_admins
          organization: dbapp
          users: "cn=dbadmins, ou=groups,dc=example,dc=local"
    tower_host: tower.example.com
    tower_username: "{{ vault_tower_user }}"
    tower_password: "{{ vault_tower_pass }}"

- name: | use multiple user search DNs to find users. Modify existing settings.
  tower_ldap_settings:
    state: present
    ldap_user_search:
      - "ou=hrdept,ou=users,dc=example,dc=local"
      - "ou=engdept,ou=users,dc=example,dc=local"
    tower_host: tower.example.com
    tower_username: "{{ vault_tower_user }}"
    tower_password: "{{ vault_tower_pass }}"

- name: |
    set all available tower ldap module settings.
    NOTE - it is not idempotent because ldap_bind_password is defined
  tower_ldap_settings:
    state: present
    ldap_server_name: adserver.example.local
    ldap_bind_dn: "cn=towerbinduser,ou=users,dc=example,dc=local"
    ldap_bind_password: "{{ vault_bind_password }}"
    ldap_user_search:
        - "ou=users,dc=example,dc=local"
    ldap_group_search: "ou=groups,dc=example,dc=local"
    ldap_superuser:
        - cn=toweradmins, ou=groups,dc=example,dc=local
    ldap_organization_map:
        - organization: webapp
          users: "cn=webapp,ou=groups,dc=example,dc=local"
          admins: "cn=webadmins,ou=groups,dc=example,dc=local"
    ldap_team_map:
        - team: webapp_admins
          organization: webapp
          users: "cn=webadmins,ou=groups,dc=example,dc=local"
    tower_host: tower.example.com
    tower_username: "{{ vault_tower_user }}"
    tower_password: "{{ vault_tower_pass }}"

'''

from ansible.module_utils.ansible_tower import tower_argument_spec, tower_auth_config, tower_check_mode,HAS_TOWER_CLI

try:
    import tower_cli
    import tower_cli.utils.exceptions as exc
    import json
    from tower_cli.conf import settings
    import re
except ImportError:
    pass


class FixBoolValuesEncoder(json.JSONEncoder):
    def change_bool_to_str(self, obj):
        """
        the Python AST parser has a bug where it
        interprets the key-pair value of "true" as a literal
        instead of converting it to "True" the boolean
        This recursive function is a workaround until the
        AST parser tower-cli depends on is fixed.
        """
        if isinstance(obj, bool):
            return str(obj)
        elif isinstance(obj, dict):
            for _key, _value in obj.items():
                obj[_key] = self.change_bool_to_str(_value)
        return obj

    def iterencode(self, obj, _one_shot=True):
        obj = self.change_bool_to_str(obj)
        return json.JSONEncoder.iterencode(self, obj)

def empty_module_params(module):
    """
    define settings to clear out all LDAP settings.
    """
    module.params = {
        'ldap_server_name': '',
        'ldap_bind_dn': '',
        'ldap_bind_password': '',
        'ldap_start_tls': False,
        'ldap_user_search': [],
        'ldap_group_search': [],
        'ldap_organization_map': [],
        'ldap_team_map': [],
        'ldap_group_type': '',
        'ldap_user_attr_map': {},
        'ldap_superuser': '',
        'state': 'absent'
    }



def clear_all_ldap_config(module, check_mode=False):
    """
    Clear all LDAP configuration
    """
    empty_module_params(module)
    modify_ldap_config(module, check_mode)

def modify_ldap_config(module, check_mode=False):
    """
    Modified LDAP configuration or checks LDAP configuration
    Args:
        module: AnsibleModule instance
        check_mode: True if no modifications should occur. Default: false.
    """
    module.changed_values = []
    modified_server_uri = False
    for _ldap_attr, _value in module.current_settings.items():
        if _ldap_attr == 'ldap_server_uri' or _ldap_attr == 'ldap_user_attr_map':
            continue
        elif _ldap_attr == 'ldap_bind_password':
            module.changed_values.append(_ldap_attr)
            module.tower_settings.modify('AUTH_LDAP_BIND_PASSWORD',
                                                                module.params.get('ldap_bind_password'))
        elif _value != module.params.get(_ldap_attr):
            if _ldap_attr == 'ldap_bind_dn':
                if not check_mode:
                    module.tower_settings.modify('AUTH_LDAP_BIND_DN',
                                                                        module.params.get(_ldap_attr))
                module.changed_values.append(_ldap_attr)
            elif _ldap_attr == 'ldap_start_tls':
                if not check_mode:
                    module.tower_settings.modify('AUTH_LDAP_START_TLS',
                                                                        str(module.params.get(_ldap_attr)))
            elif _ldap_attr == 'ldap_server_name' or _ldap_attr == 'ldap_server_port' or \
                    _ldap_attr == 'ldap_server_protocol':
                if modified_server_uri == False:
                    if not check_mode:
                        module.tower_settings.modify('AUTH_LDAP_SERVER_URI',
                            transform_ldap_server_uri(
                                ldap_server_name=module.params.get('ldap_server_name'),
                                ldap_server_port=module.params.get('ldap_server_port'),
                                ldap_server_protocol=module.params.get('ldap_server_protocol')).get('ldap_server_uri'))
                    modified_server_uri = True
                    module.changed_values = module.changed_values + [
                            'ldap_server_name', 'ldap_server_protocol',
                            'ldap_server_port', 'ldap_server_uri']
                    del module.current_settings['ldap_server_name']
                    del module.current_settings['ldap_server_protocol']
                    del module.current_settings['ldap_server_uri']
                    del module.current_settings['ldap_server_port']
            elif _ldap_attr == 'ldap_superuser':
                if not check_mode:
                    module.tower_settings.modify('AUTH_LDAP_USER_FLAGS_BY_GROUP',
                        json.dumps(transform_ldap_user_flags_by_group(module.params.get(_ldap_attr)),
                                            cls=FixBoolValuesEncoder))
                module.changed_values.append(_ldap_attr)
            elif _ldap_attr == 'ldap_user_search':
                if not check_mode:
                    module.tower_settings.modify('AUTH_LDAP_USER_SEARCH',
                        json.dumps(transform_ldap_user_search(
                            module.params.get(_ldap_attr),
                            module.params.get('ldap_group_type')
                        ), cls=FixBoolValuesEncoder))
                module.changed_values.append(_ldap_attr)
            else:
                real_ldap_attr = "AUTH_%s" % _ldap_attr.upper()
                if not check_mode:
                    _value = globals()["transform_%s" % (_ldap_attr)](module.params.get(_ldap_attr))
                    if isinstance(_value, str) or isinstance(_value, bool):
                        _value = str(_value)
                    else:
                        _value = json.dumps(_value, cls=FixBoolValuesEncoder)
                    module.tower_settings.modify(real_ldap_attr, _value)
                module.changed_values.append(_ldap_attr)


def get_ldap_values(module):
    """
    Get LDAP values used by this module.
    Arguments: AnsibleModule instance
    Return: Nothing modifies the ansible module instance.
    """
    tower_settings = tower_cli.get_resource('setting')
    current_settings = {
        'ldap_server_protocol': None,
        'ldap_server_name': None,
        'ldap_server_port': None
    }

    current_ldap_server_uri = tower_settings.get('AUTH_LDAP_SERVER_URI').get('value')
    ldap_server_uri_settings = transform_ldap_server_uri(ldap_server_uri=current_ldap_server_uri)
    for _key, _value in ldap_server_uri_settings.items():
        current_settings[_key] = _value

    if module.params.get('ldap_bind_password'):
        current_settings['ldap_bind_password'] = tower_settings.get('AUTH_LDAP_BIND_PASSWORD').get('value')
    current_settings['ldap_bind_dn'] = tower_settings.get('AUTH_LDAP_BIND_DN').get('value')
    current_settings['ldap_start_tls'] = tower_settings.get('AUTH_LDAP_START_TLS').get('value')
    current_settings['ldap_user_attr_map'] = tower_settings.get('AUTH_LDAP_USER_ATTR_MAP').get('value')

    group_search = tower_settings.get('AUTH_LDAP_GROUP_SEARCH').get('value')
    current_settings['ldap_group_search'] = transform_ldap_group_search(group_search)

    group_type_from_tower = tower_settings.get('AUTH_LDAP_GROUP_TYPE').get('value')
    group_type = transform_ldap_group_type(group_type_from_tower)
    current_settings['ldap_group_type'] = group_type


    user_search = tower_settings.get('AUTH_LDAP_USER_SEARCH').get('value')
    current_settings['ldap_user_search'] = transform_ldap_user_search(user_search, group_type)
    ldap_user_flags = tower_settings.get('AUTH_LDAP_USER_FLAGS_BY_GROUP').get('value')
    current_settings['ldap_superuser']= transform_ldap_user_flags_by_group(ldap_user_flags)

    org_map = tower_settings.get('AUTH_LDAP_ORGANIZATION_MAP').get('value')
    current_settings['ldap_organization_map'] = transform_ldap_organization_map(org_map)


    team_map = tower_settings.get('AUTH_LDAP_TEAM_MAP').get('value')
    current_settings['ldap_team_map'] = transform_ldap_team_map(team_map)

    current_settings['ldap_user_attr_map'] = tower_settings.get('AUTH_LDAP_USER_ATTR_MAP').get('value')

    module.tower_settings = tower_settings
    module.current_settings = current_settings

def transform_ldap_user_attr_map(_value=None):
    """
    Define the default user attribute mappings for active directory and OpenLDAP
    These defaults have worked for me so far. If need be it can be added as module
    parameters if writing in defaults doesn't work for most people
    """
    attr_map_assignment = {
          "first_name": "givenName",
          "last_name": "sn",
          "email": "mail"
    }
    return attr_map_assignment

def transform_ldap_server_uri(**kwargs):
    """
    Given kwargs that match the following attributes
        * ldap_server_uri
        * ldap_server_protocol
        * ldap_server_name
        * ldap_server_port
    Return a hash matching the kwargs.
    """
    server_protocol = kwargs.get('ldap_server_protocol')
    server_name = kwargs.get('ldap_server_name')
    server_port = kwargs.get('ldap_server_port')
    server_uri = kwargs.get('ldap_server_uri')

    if server_uri:
        uri_match =  re.match('(\w+)://(.+):(\d+)', server_uri)
        if uri_match:
                server_protocol =  uri_match.group(1)
                server_name =  uri_match.group(2)
                server_port =  int(uri_match.group(3))
    else:
        server_uri = ''
        if server_protocol and \
            server_name and \
            server_port:
            server_uri =  "%s://%s:%s" % (server_protocol, server_name, server_port)
    result = {
        'ldap_server_protocol': server_protocol,
        'ldap_server_name': server_name,
        'ldap_server_port': server_port,
        'ldap_server_uri': server_uri
    }
    return result


def transform_ldap_group_type(group_type):
    """
    This transformation function takes a group type name. If the group type name matches this module group_type
    options then it outputs the Tower API equivalent output. And the reverse is true.
    """
    transformed_group_type = ''
    # Converting from Tower API to module format
    if group_type  == 'NestedActiveDirectoryGroupType':
        transformed_group_type = 'active_directory'
    # TODO: Find out what RHT Identity manager recommends for the group type setting since it
    # uses a form of OpenLDAP
    elif group_type == 'NestedGroupOfNamesType':
        transformed_group_type = 'open_ldap'
    # Converting from module format to Tower API
    elif group_type == 'active_directory':
        transformed_group_type = 'NestedActiveDirectoryGroupType'
    elif group_type == 'open_ldap':
        transformed_group_type = "NestedGroupOfNamesType"
    else:
        transformed_group_type = 'MemberDNGroupType'
    return transformed_group_type

def transform_ldap_group_search(group_search):
    results = []
    if isinstance(group_search, list):
        # From Tower API -> module data model
        if len(group_search) == 3:
            return group_search[0]
        # From module data model -> Tower API
    else:
        for _entry in group_search:
            results = [
                group_search,
                "SCOPE_SUBTREE",
                '(objectClass=group)'
            ]
    return results

def transform_ldap_user_search(users_search_list, ldap_server_type='active_directory'):
    """
    Transform list of this module's user_search model format to the Tower API user_search format and
    visa-versa.
    """
    results = []
    if isinstance(users_search_list, list):
        # From Tower API -> module data model
        if len(users_search_list) > 0 and isinstance(users_search_list[0], list):
            for _entry in users_search_list:
                results.append(_entry[0])
        # From module data model -> Tower API
        else:
            user_search_str = ""
            if ldap_server_type == 'active_directory':
                user_search_str = '(sAMAccountname=%(user)s)'
            elif ldap_server_type == 'open_ldap':
                user_search_str = '(cn=%(user)s)'
            for _entry in users_search_list:
                results.append(
                [
                    _entry,
                    "SCOPE_SUBTREE",
                    user_search_str
                ])
    return results

def transform_ldap_organization_map(org_map):
    """
    Convert Tower formatted org map to this module's Org format
    """
    results = None
    if isinstance(org_map, dict):
        results = []
        for _key, _value in org_map.items():
            results.append({
                "organization": _key,
                "users":  _value.get('users'),
                "admins": _value.get('admins')
            })
    elif isinstance(org_map, list):
        results = {}
        for _entry in org_map:
            results[_entry.get('organization')] = {
                "admins": _entry.get('admins'),
                "users": _entry.get("users"),
                "remove_users": True,
                "remove_admins": True
            }
    return results

def transform_ldap_user_flags_by_group(ldap_user_flags_by_group):
    """
    If a dict is feed to it, it will attempt to extract the superuser info and return that string
    else if the output is a string then assume it is a dn and create a API value structure that
    complies with the AUTH_LDAP_USER_FLAGS_BY_GROUP settings attribute
    """
    result = {}
    if isinstance(ldap_user_flags_by_group, dict):
        result = ''
        superuser_dn = ldap_user_flags_by_group.get('is_superuser')
        if superuser_dn:
            result =   superuser_dn

    elif isinstance(ldap_user_flags_by_group, str):
        if ldap_user_flags_by_group:
            result = {
                'is_superuser': ldap_user_flags_by_group
            }
    return result

def transform_ldap_team_map(team_map):
    """
    Convert team map settings between the API compliant format, or this module's team
    map dict structure. It autodetects if the _team_map argument is a dict or list, and returns
    either an API compliant format or this module compliant format
    """
    result = None
    if not team_map:
        return {}
    if isinstance(team_map, dict):
        result = []
        for _key, _value in team_map.items():
            result.append({
                "team": _key,
                "organization": _value.get('organization'),
                "users": _value.get('users')
            })
    else:
        result = {}
        for _entry in team_map:
            result[_entry.get('team')] = {
                "organization": _entry.get('organization'),
                "users": _entry.get('users'),
                "remove": True
            }
    return result


def main():
    argument_spec = tower_argument_spec()
    argument_spec.update(dict(
        ldap_server_protocol=dict(type='str', default='ldaps' ),
        ldap_server_name=dict(type='str'),
        ldap_server_port=dict(type='int', default=636),
        ldap_bind_dn=dict(type='str'),
        ldap_bind_password=dict(type='str', no_log=True),
        ldap_start_tls=dict(type='bool', default=False),
        ldap_user_search=dict(type='list'),
        ldap_group_search=dict(type='str'),
        ldap_group_type=dict(type='str', choices=['active_directory', 'open_ldap'],
                             default='active_directory'),
        ldap_superuser=dict(type='str'),
        ldap_organization_map=dict(type='list'),
        ldap_team_map=dict(type='list'),
        state=dict(type='str', choices=['present','absent'], default='present'),
        ldap_user_attr_map = transform_ldap_user_attr_map()
    ))
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    if not HAS_TOWER_CLI:
        module.fail_json(msg="ansible-tower-cli required for this module")
    tower_auth = tower_auth_config(module)
    with settings.runtime_values(**tower_auth):
        state = module.params.get('state')
        json_output = {}
        get_ldap_values(module)
        if state == 'absent':
            clear_all_ldap_config(module, module.check_mode)
            if module.changed_values:
                json_output['changed'] = True
                json_output['msg'] = ('The following LDAP settings were cleared %s' % module.changed_values)
            else:
                json_output['changed'] = False
                json_output['msg'] = 'LDAP settings already cleared'
        else:
            modify_ldap_config(module, module.check_mode)
            if module.changed_values:
                json_output['changed'] = True
                json_output['msg'] = ('The following LDAP settings were changed %s' % module.changed_values)
            else:
                json_output['changed'] = False

        module.exit_json(**json_output)

from ansible.module_utils.basic import AnsibleModule
if __name__ == '__main__':
    main()
