{%- set profile = salt['grains.get']('profile') %}
{%- set current_profile = salt['pillar.get']('profile') %}

# These grains are not included in this repository
{%- set store = salt['grains.get']('store') %}
{%- set network = salt['grains.get']('network') %}

{%- if current_profile != profile %}
send_new_minion_event:
  event.send:
    - name: salt/register/new_minion
    - data:
        store: {{ store }}
        profile: {{ profile }}
        ip: {{ network['ip'] }}
        mac_address: {{ network['mac'] }}
        hostname: {{ network['hostname'] }}
{%- endif %}
