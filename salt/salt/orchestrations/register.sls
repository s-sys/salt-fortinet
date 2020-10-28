update_minion_profile_in_database:
  salt.runner:
    - name: state.orchestrate
    - kwarg:
        mods: orchestrations.update_profile
        pillar: {{ pillar|json }}

create_minion_profile_in_fortinet:
  salt.runner:
    - name: state.orchestrate
    - kwarg:
        mods: orchestrations.create_fortinet_minion
        pillar: {{ pillar|json }}
