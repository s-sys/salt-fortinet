create table minion_profile (
  key varchar2(64) not null primary key,
  ip varchar2(45) not null,
  mac_address varchar2(20) not null,
  hostname varchar2(256) not null,
  store number(4) not null,
  profile varchar2(64) not null,
  processed number(1) default 0 not null,
  last_sync date default sysdate not null,
  constraint minion_profile_ip_unique unique (ip),
  constraint minion_profile_mac_address_unique unique (mac_address),
  constraint minion_profile_processed check (processed in (0, 1))
);
create index minion_profile_store_idx on minion_profile (store);
create index minion_profile_profile_idx on minion_profile (profile);
create index minion_profile_processed_idx on minion_profile (processed);

create table fortinet_store (
  store number(4) not null primary key,
  flag varchar2(2) not null,
  city varchar2(64) not null,
  state varchar2(2) not null,
  region number(4) not null,
  fortinet_ip varchar2(45) not null,
  fortinet_port number(5) default 11443 not null,
  citrix number(1) default 0 not null,
  constraint fortinet_store_citrix check (citrix in (0, 1))
);
create index fortinet_store_flag_idx on fortinet_store (flag);
create index fortinet_store_city_idx on fortinet_store (city);
create index fortinet_store_state_idx on fortinet_store (state);
create index fortinet_store_region_idx on fortinet_store (region);
create index fortinet_store_citrix_idx on fortinet_store (citrix);

create table fortinet_servicenow (
  "order" varchar2(64) not null primary key,
  contents clob not null,
  status number(1) not null,
  created date default sysdate not null,
  deadline date not null
);
create index fortinet_servicenow_status_idx on fortinet_servicenow (status);

create table fortinet_servicenow_store (
  "order" varchar2(64) not null,
  store number(4) not null,
  status number(1) not null,
  constraint fortinet_servicenow_store_pk primary key ("order", store),
  constraint fortinet_servicenow_store_order_fk foreign key ("order") references fortinet_servicenow ("order"),
  constraint fortinet_servicenow_store_store_fk foreign key (store) references fortinet_store (store)
);
create index fortinet_servicenow_store_order_idx on fortinet_servicenow_store ("order");
create index fortinet_servicenow_store_store_idx on fortinet_servicenow_store (store);
create index fortinet_servicenow_store_status_idx on fortinet_servicenow_store (status);

create table fortinet_server_address (
  id raw(16) default sys_guid(),
  name varchar2(64) not null primary key,
  "comment" varchar2(255),
  subnet varchar2(92) not null,
  changed number(1) default 0 not null,
  constraint fortinet_server_address_id_unique unique (id),
  constraint fortinet_server_address_changed check (changed in (0, 1, 2))
);
create index fortinet_server_address_changed_idx on fortinet_server_address (changed);

create table fortinet_address (
  id raw(16) default sys_guid(),
  store number(4) not null,
  name varchar2(64) not null,
  "comment" varchar2(255),
  subnet varchar2(92) not null,
  changed number(1) default 0 not null,
  constraint fortinet_address_pk primary key (store, name),
  constraint fortinet_address_id_unique unique (id),
  constraint fortinet_address_changed check (changed in (0, 1, 2))
);
create index fortinet_address_store_idx on fortinet_address (store);
create index fortinet_address_changed_idx on fortinet_address (changed);

create table fortinet_addressgroup (
  id raw(16) default sys_guid(),
  store number(4) not null,
  name varchar2(64) not null,
  "comment" varchar2(255),
  changed number(1) default 0 not null,
  constraint fortinet_addressgroup_pk primary key (store, name),
  constraint fortinet_addressgroup_id_unique unique (id),
  constraint fortinet_addressgroup_changed check (changed in (0, 1, 2))
);
create index fortinet_addressgroup_store_idx on fortinet_addressgroup (store);
create index fortinet_addressgroup_changed_idx on fortinet_addressgroup (changed);

create table fortinet_addressgroup_member (
  id raw(16) default sys_guid(),
  store number(4) not null,
  addressgroup varchar2(64) not null,
  address varchar2(64) not null,
  changed number(1) default 0 not null,
  constraint fortinet_addressgroup_member_pk primary key (store, addressgroup, address),
  constraint fortinet_addressgroup_member_id_unique unique (id),
  constraint fortinet_addressgroup_member_addressgroup_fk foreign key (store, addressgroup) references fortinet_addressgroup (store, name),
  constraint fortinet_addressgroup_member_address_fk foreign key (store, address) references fortinet_address (store, name),
  constraint fortinet_addressgroup_member_changed check (changed in (0, 1, 2))
);
create index fortinet_addressgroup_member_store_idx on fortinet_addressgroup_member (store);
create index fortinet_addressgroup_member_addressgroup_idx on fortinet_addressgroup_member (store, addressgroup);
create index fortinet_addressgroup_member_changed_idx on fortinet_addressgroup_member (changed);

create table fortinet_service (
  id raw(16) default sys_guid(),
  store number(4) not null,
  name varchar2(64) not null,
  "comment" varchar2(255),
  category varchar2(64),
  protocol varchar2(64),
  tcp_portrange varchar2(255),
  udp_portrange varchar2(255),
  sctp_portrange varchar2(255),
  icmptype number(10),
  icmpcode number(3),
  changed number(1) default 0 not null,
  constraint fortinet_service_pk primary key (store, name),
  constraint fortinet_service_id_unique unique (id),
  constraint fortinet_service_protocol check (protocol in ('TCP/UDP/SCTP', 'ICMP', 'ICMP6', 'IP', 'HTTP', 'FTP', 'CONNECT', 'SOCKS-TCP', 'SOCKS-UDP', 'ALL')),
  constraint fortinet_service_changed check (changed in (0, 1, 2))
);
create index fortinet_service_store_idx on fortinet_service (store);
create index fortinet_service_changed_idx on fortinet_service (changed);

create table fortinet_servicegroup (
  id raw(16) default sys_guid(),
  store number(4) not null,
  name varchar2(64) not null,
  "comment" varchar2(255),
  changed number(1) default 0 not null,
  constraint fortinet_servicegroup_pk primary key (store, name),
  constraint fortinet_servicegroup_id_unique unique (id),
  constraint fortinet_servicegroup_changed check (changed in (0, 1, 2))
);
create index fortinet_servicegroup_store_idx on fortinet_servicegroup (store);
create index fortinet_servicegroup_changed_idx on fortinet_servicegroup (changed);

create table fortinet_servicegroup_member (
  id raw(16) default sys_guid(),
  store number(4) not null,
  servicegroup varchar2(64) not null,
  service varchar2(64) not null,
  changed number(1) default 0 not null,
  constraint fortinet_servicegroup_member_pk primary key (store, servicegroup, service),
  constraint fortinet_servicegroup_member_id_unique unique (id),
  constraint fortinet_servicegroup_member_servicegroup_fk foreign key (store, servicegroup) references fortinet_servicegroup (store, name),
  constraint fortinet_servicegroup_member_service_fk foreign key (store, service) references fortinet_service (store, name),
  constraint fortinet_servicegroup_member_changed check (changed in (0, 1, 2))
);
create index fortinet_servicegroup_member_store_idx on fortinet_servicegroup_member (store);
create index fortinet_servicegroup_member_servicegroup_idx on fortinet_servicegroup_member (store, servicegroup);
create index fortinet_servicegroup_member_changed_idx on fortinet_servicegroup_member (changed);

create table fortinet_policy (
  id raw(16) default sys_guid(),
  store number(4) not null,
  name varchar2(64) not null,
  policyid number(10),
  comments varchar2(1023),
  action varchar2(10),
  status varchar2(10),
  schedule varchar2(64),
  utm_status varchar2(10),
  logtraffic varchar2(10),
  av_profile varchar2(64),
  webfilter_profile varchar2(64),
  dnsfilter_profile varchar2(64),
  dlp_sensor varchar2(64),
  ips_sensor varchar2(64),
  application_list varchar2(64),
  ssl_ssh_profile varchar2(64),
  position varchar2(6) default 'before' not null,
  neighbor varchar2(64),
  changed number(1) default 0 not null,
  constraint fortinet_policy_pk primary key (store, name),
  constraint fortinet_policy_id_unique unique (id),
  constraint fortinet_policy_action check (action in ('accept', 'deny', 'ipsec')),
  constraint fortinet_policy_status check (status in ('enable', 'disable')),
  constraint fortinet_policy_utm_status check (utm_status in ('enable', 'disable')),
  constraint fortinet_policy_logtraffic check (logtraffic in ('all', 'utm', 'disable')),
  constraint fortinet_policy_position check (position in ('before', 'after')),
  constraint fortinet_policy_changed check (changed in (0, 1, 2))
);
create index fortinet_policy_store_idx on fortinet_policy (store);
create index fortinet_policy_changed_idx on fortinet_policy (changed);

create table fortinet_policy_srcintf (
  id raw(16) default sys_guid() primary key,
  store number(4) not null,
  policy varchar2(64) not null,
  interface varchar2(64) not null,
  changed number(1) default 0 not null,
  constraint fortinet_policy_srcintf_unique unique (store, policy, interface),
  constraint fortinet_policy_srcintf_policy_fk foreign key (store, policy) references fortinet_policy (store, name),
  constraint fortinet_policy_srcintf_changed check (changed in (0, 1, 2))
);
create index fortinet_policy_srcintf_store_idx on fortinet_policy_srcintf (store);
create index fortinet_policy_srcintf_policy_idx on fortinet_policy_srcintf (store, policy);
create index fortinet_policy_srcintf_changed_idx on fortinet_policy_srcintf (changed);

create table fortinet_policy_dstintf (
  id raw(16) default sys_guid() primary key,
  store number(4) not null,
  policy varchar2(64) not null,
  interface varchar2(64) not null,
  changed number(1) default 0 not null,
  constraint fortinet_policy_dstintf_unique unique (store, policy, interface),
  constraint fortinet_policy_dstintf_policy_fk foreign key (store, policy) references fortinet_policy (store, name),
  constraint fortinet_policy_dstintf_changed check (changed in (0, 1, 2))
);
create index fortinet_policy_dstintf_store_idx on fortinet_policy_dstintf (store);
create index fortinet_policy_dstintf_policy_idx on fortinet_policy_dstintf (store, policy);
create index fortinet_policy_dstintf_changed_idx on fortinet_policy_dstintf (changed);

create table fortinet_policy_srcaddr (
  id raw(16) default sys_guid() primary key,
  store number(4) not null,
  policy varchar2(64) not null,
  addressgroup varchar2(64),
  changed number(1) default 0 not null,
  constraint fortinet_policy_srcaddr_unique unique (store, policy, addressgroup),
  constraint fortinet_policy_srcaddr_policy_fk foreign key (store, policy) references fortinet_policy (store, name),
  constraint fortinet_policy_srcaddr_addressgroup_fk foreign key (store, addressgroup) references fortinet_addressgroup (store, name),
  constraint fortinet_policy_srcaddr_changed check (changed in (0, 1, 2))
);
create index fortinet_policy_srcaddr_store_idx on fortinet_policy_srcaddr (store);
create index fortinet_policy_srcaddr_policy_idx on fortinet_policy_srcaddr (store, policy);
create index fortinet_policy_srcaddr_changed_idx on fortinet_policy_srcaddr (changed);

create table fortinet_policy_dstaddr (
  id raw(16) default sys_guid() primary key,
  store number(4) not null,
  policy varchar2(64) not null,
  addressgroup varchar2(64),
  changed number(1) default 0 not null,
  constraint fortinet_policy_dstaddr_unique unique (store, policy, addressgroup),
  constraint fortinet_policy_dstaddr_policy_fk foreign key (store, policy) references fortinet_policy (store, name),
  constraint fortinet_policy_dstaddr_addressgroup_fk foreign key (store, addressgroup) references fortinet_addressgroup (store, name),
  constraint fortinet_policy_dstaddr_changed check (changed in (0, 1, 2))
);
create index fortinet_policy_dstaddr_store_idx on fortinet_policy_dstaddr (store);
create index fortinet_policy_dstaddr_policy_idx on fortinet_policy_dstaddr (store, policy);
create index fortinet_policy_dstaddr_changed_idx on fortinet_policy_dstaddr (changed);

create table fortinet_policy_service (
  id raw(16) default sys_guid() primary key,
  store number(4) not null,
  policy varchar2(64) not null,
  servicegroup varchar2(64),
  changed number(1) default 0 not null,
  constraint fortinet_policy_service_unique unique (store, policy, servicegroup),
  constraint fortinet_policy_service_policy_fk foreign key (store, policy) references fortinet_policy (store, name),
  constraint fortinet_policy_service_servicegroup_fk foreign key (store, servicegroup) references fortinet_servicegroup (store, name),
  constraint fortinet_policy_service_changed check (changed in (0, 1, 2))
);
create index fortinet_policy_service_store_idx on fortinet_policy_service (store);
create index fortinet_policy_service_policy_idx on fortinet_policy_service (store, policy);
create index fortinet_policy_service_changed_idx on fortinet_policy_service (changed);

create table fortinet_profile (
  id raw(16) default sys_guid(),
  store number(4) not null,
  profile varchar2(64) not null,
  policy varchar2(64) not null,
  constraint fortinet_profile_pk primary key (store, profile, policy),
  constraint fortinet_profile_id_unique unique (id),
  constraint fortinet_profile_policy_fk foreign key (store, policy) references fortinet_policy (store, name)
);
create index fortinet_profile_store_idx on fortinet_profile (store);

create table fortinet_service_template (
  id raw(16) default sys_guid(),
  group_name varchar2(64) not null,
  name varchar2(64) not null,
  "comment" varchar2(255),
  category varchar2(64),
  protocol varchar2(64),
  tcp_portrange varchar2(255),
  udp_portrange varchar2(255),
  sctp_portrange varchar2(255),
  icmptype number(10),
  icmpcode number(3),
  constraint fortinet_service_template_pk primary key (group_name, name),
  constraint fortinet_service_template_id_unique unique (id),
  constraint fortinet_service_template_protocol check (protocol in ('TCP/UDP/SCTP', 'ICMP', 'ICMP6', 'IP', 'HTTP', 'FTP', 'CONNECT', 'SOCKS-TCP', 'SOCKS-UDP', 'ALL'))
);
create index fortinet_service_template_group_name_idx on fortinet_service_template (group_name);

create table fortinet_policy_template (
  id raw(16) default sys_guid(),
  name varchar2(64) not null primary key,
  policyid number(10),
  comments varchar2(1023),
  action varchar2(10),
  status varchar2(10),
  schedule varchar2(64),
  utm_status varchar2(10),
  logtraffic varchar2(10),
  av_profile varchar2(64),
  webfilter_profile varchar2(64),
  dnsfilter_profile varchar2(64),
  dlp_sensor varchar2(64),
  ips_sensor varchar2(64),
  application_list varchar2(64),
  ssl_ssh_profile varchar2(64),
  position varchar2(6) default 'before' not null,
  neighbor varchar2(64),
  constraint fortinet_policy_template_id_unique unique (id),
  constraint fortinet_policy_template_action check (action in ('accept', 'deny', 'ipsec')),
  constraint fortinet_policy_template_status check (status in ('enable', 'disable')),
  constraint fortinet_policy_template_utm_status check (utm_status in ('enable', 'disable')),
  constraint fortinet_policy_template_logtraffic check (logtraffic in ('all', 'utm', 'disable')),
  constraint fortinet_policy_template_position check (position in ('before', 'after'))
);

create table fortinet_policy_template_srcintf (
  id raw(16) default sys_guid() primary key,
  policy varchar2(64) not null,
  interface varchar2(64) not null,
  constraint fortinet_policy_template_srcintf_unique unique (policy, interface),
  constraint fortinet_policy_template_srcintf_policy_fk foreign key (policy) references fortinet_policy_template (name)
);
create index fortinet_policy_template_srcintf_policy_idx on fortinet_policy_template_srcintf (policy);

create table fortinet_policy_template_dstintf (
  id raw(16) default sys_guid() primary key,
  policy varchar2(64) not null,
  interface varchar2(64) not null,
  constraint fortinet_policy_template_dstintf_unique unique (policy, interface),
  constraint fortinet_policy_template_dstintf_policy_fk foreign key (policy) references fortinet_policy_template (name)
);
create index fortinet_policy_template_dstintf_policy_idx on fortinet_policy_template_dstintf (policy);

create table fortinet_policy_template_srcaddr (
  id raw(16) default sys_guid() primary key,
  policy varchar2(64) not null,
  addressgroup varchar2(64),
  constraint fortinet_policy_template_srcaddr_unique unique (policy, addressgroup),
  constraint fortinet_policy_template_srcaddr_policy_fk foreign key (policy) references fortinet_policy_template (name)
);
create index fortinet_policy_template_srcaddr_policy_idx on fortinet_policy_template_srcaddr (policy);

create table fortinet_policy_template_dstaddr (
  id raw(16) default sys_guid() primary key,
  policy varchar2(64) not null,
  addressgroup varchar2(64),
  constraint fortinet_policy_template_dstaddr_unique unique (policy, addressgroup),
  constraint fortinet_policy_template_dstaddr_policy_fk foreign key (policy) references fortinet_policy_template (name)
);
create index fortinet_policy_template_dstaddr_policy_idx on fortinet_policy_template_dstaddr (policy);

create table fortinet_policy_template_service (
  id raw(16) default sys_guid() primary key,
  policy varchar2(64) not null,
  servicegroup varchar2(64),
  constraint fortinet_policy_template_service_unique unique (policy, servicegroup),
  constraint fortinet_policy_template_service_policy_fk foreign key (policy) references fortinet_policy_template (name)
);
create index fortinet_policy_template_service_policy_idx on fortinet_policy_template_service (policy);
