ansible-tower-ldap-settings
=========
Sets Ansible Tower LDAP settings. This role is a wrapper for the ``tower_ldap_settings`` Ansible module that is included in this role.

Requirements
------------

* [ansible-tower-cli](https://github.com/ansible/tower-cli) >= 3.1. Install using the``pip install ansible-tower-cli`` command on the Ansible server.

Role Variables
--------------

* ``server_name:``: LDAP server name
* ``bind_dn``: LDAP Bind DN
* ``bind_password``: LDAP Bind DN password
* ``user_search``: List of LDAP user search filters. Must be a list
* ``group_search``: Single LDAP group search filter.  Must be a string
* ``superuser``: Group or User DN defining users with superuser Tower privileges.
* ``organization_map``: List of dictionaries that map Tower organizations to User or Group LDAP DNs. Each directory has the following structure:
    - _organization_: name of the organization
    -  _users_: Users in this Group DN will be placed in this organization
    - _admins_: Users in this Group DN have admin rights within the Tower organization.
* ``team_map``: List of dictionaries that map Tower teams  to User or Group LDAP DNs. Each directory has the following structure:
   - _team_: team name
   - _organization_: name of the organization the  team belongs to
   -  _users_: Users in this Group DN will be placed in this team
* ``ldap_state``: when set to ``absent`` all LDAP configuration is deleted. Defaults to ``present``.
* ``host``: Tower hostname
* ``username``: Tower username. This username must have superuser privileges in order to modify LDAP settings.
* ``password``: Tower user password.

Example Playbook
----------------

```
- hosts: localhost
  connection: local
  roles:
    - role: tower_ldap_settings
      ldap_state: present
      server_name: ldapserver.example.local
      bind_dn: "cn=binduser, OU=Users, DC=example,DC=local"
      bind_password: "{{ vault_bind_pass }}"
      user_search:
        - "ou=users,dc=example,dc=local"
      group_search: "ou=groups,ou=example, dc=local"
      superuser: "cn=toweruser, ou=users,dc=example,dc=local"
      organization_map:
        - organization: webapp
          users: "cn=webapp, ou=groups,dc=example,dc=local"
          admins: "ou=webadmins,ou=groups,dc=example,dc=local"
      team_map:
        - team: webapp_admins
          organization: webapp
          users: "cn=webadmins,ou=groups,dc=example,dc=local"
      host: tower.example.local
      username: "{{ vault_tower_user }}"
      password: "{{ vault_tower_pass }}"
```


License
-------

MIT

Author Information
------------------

Twitter: @linuxsimba
