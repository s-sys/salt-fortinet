install_register_script:
  file.managed:
    - name: /usr/bin/register
    - source: salt://bootstrapping/files/register.sh
    - user: root
    - group: root
    - mode: "0750"
