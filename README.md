# Fortinet Automation with Salt

`flask/` contains a Flask REST API built to facilitate communication between ServiceNow, Salt, and the Oracle Database.

`oracle/` contains the schema for the database.

`salt/etc/` contains the configuration files needed by the Salt master, including credentials.

`salt/salt/_grains/` contains the custom grain responsible for reading the profile from `/etc/profile`.

`salt/salt/_modules/` contains a wrapper built on top of PyFortiAPI to adapt it to our particular use case.

`salt/salt/bootstrapping/` contains all states related to changing the profile of a minion, as well as an installation script that can be used to make that change.

`salt/salt/reactors/` contains the reactor state responsible for listening for new minion events and firing up the orchestrations.

`salt/salt/orchestrations/` contains the orchestration states responsible for acessing and configuring data in the database and in the FortiGate firewalls.

`salt/salt/profileN/` contains states specific for each profile, including the state responsible for changing `/etc/profile`.
