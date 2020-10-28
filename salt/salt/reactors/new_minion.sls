react_to_new_minion_event:
  runner.state.orchestrate:
    - args:
      - mods: orchestrations.register
      - pillar:
          minion_id: {{ data.id }}
          event_data: {{ data.data|json }}
