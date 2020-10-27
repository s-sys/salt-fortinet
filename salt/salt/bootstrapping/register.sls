# {%- from "maps/defs.jinja" import with context %}
# {%- from "maps/network.jinja" import with context %}
{%- set store = salt['grains.get']('num_store', False) %}

send_new_minion_event:
  event.send:
    - name: salt/register/new_minion
    - data:
        ip: {{ net_info['ip'] }}
        mac_address: {{ net_info['mac'] }}
        hostname: {{ net_info['hostname'] }}
        store: {{ store }}
        profile: {{ bootstrap }}
