update_minion_profile_in_database:
  salt.runner:
    - name: state.orchestrate
    - kwarg:
        mods: orchestrations.update_profile
        pillar: {{ pillar|json }}

finish_bootstrapping:
  salt.state:
    - tgt: {{ pillar.minion_id }}
    - sls: bootstrapping.finish
    - require:
      - id: update_minion_profile_in_database

create_minion_profile_in_fortinet:
  salt.runner:
    - name: state.orchestrate
    - kwarg:
        mods: orchestrations.create_fortinet_minion
        pillar: {{ pillar|json }}
    - require:
      - id: finish_bootstrapping

kill_all_jobs:
  salt.function:
    - tgt: {{ pillar.minion_id }}
    - name: saltutil.kill_all_jobs
    - require:
      - id: finish_bootstrapping

run_highstate:
  salt.state:
    - tgt: {{ pillar.minion_id }}
    - highstate: True
    - require:
      - id: kill_all_jobs
