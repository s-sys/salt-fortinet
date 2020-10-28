{%- set profile = "profile2" %}

{{ profile }}_set_profile_file:
  file.managed:
    - name: /etc/profile
    - contents: {{ profile }}
    - mode: "0644"
    - user: root
    - group: root

{{ profile }}_set_profile_grains:
  module.run:
    - name: grains.set
    - key: profile
    - val: {{ profile }}
    - force: True
    - require:
      - id: {{ profile }}_set_profile_file
    - watch:
      - id: {{ profile }}_set_profile_file

{{ profile }}_clear_profile_cache:
  module.run:
    - name: saltutil.clear_cache
    - require:
      - id: {{ profile }}_set_profile_grains
    - watch_any:
      - id: {{ profile }}_set_profile_grains
