Exec { logoutput => true, path => ['/usr/bin', '/usr/sbin', '/sbin', '/bin'] }

stage {'openstack-custom-repo': before => Stage['main']}
$mirror_type="default"
class { 'openstack::mirantis_repos': stage => 'openstack-custom-repo', type=>$mirror_type }


$deployment_id = '99'


### GENERAL CONFIG ###
# This section sets main parameters such as hostnames and IP addresses of different nodes

# This is the name of the public interface. The public network provides address space for Floating IPs, as well as public IP accessibility to the API endpoints.
$public_interface = "bond0"
$public_br           = 'br-ex'

# This is the name of the internal interface. It will be attached to the management network, where data exchange between components of the OpenStack cluster will happen.
$internal_interface = "vlan2"
$internal_br         = 'br-mgmt'

# This is the name of the private interface. All traffic within OpenStack tenants' networks will go through this interface.
#$private_interface = "eth2"

# Public and Internal VIPs. These virtual addresses are required by HA topology and will be managed by keepalived.
$internal_virtual_ip = "10.0.1.15"
# Change this IP to IP routable from your 'public' network,
# e. g. Internet or your office LAN, in which your public 
# interface resides
$public_virtual_ip = "89.108.113.200"
#$private_virtual_ip = "10.10.11.205"
#
# Example file for building out a multi-node environment
#
# This example creates nodes of the following roles:
#   swift_storage - nodes that host storage servers
#   swift_proxy - nodes that serve as a swift proxy
#   swift_ringbuilder - nodes that are responsible for
#     rebalancing the rings
#
# This example assumes a few things:
#   * the multi-node scenario requires a puppetmaster
#   * it assumes that networking is correctly configured
#
# These nodes need to be brought up in a certain order
#
# 1. storage nodes
# 2. ringbuilder
# 3. run the storage nodes again (to synchronize the ring db)
# 4. run the proxy
# 5. test that everything works!!
# this site manifest serves as an example of how to
# deploy various swift environments

$nodes_harr = [
  {
    'name' => 'unknown-7416',
    'role' => 'primary-swift-proxy',
    'internal_address' => '10.0.1.10',
    'public_address'   => '89.108.113.202',
  }, 
  {
    'name' => 'unknown-7415',
    'role' => 'swift-proxy',
    'internal_address' => '10.0.1.11',
    'public_address'   => '89.108.113.204',
  },
  {
    'name' => 'unknown-7418',
    'role' => 'swift-proxy',
    'internal_address' => '10.0.1.12',
    'public_address'   => '9.108.113.203',
  },  
  {
    'name' => 'st-unknown-7416',
    'role' => 'storage',
    'internal_address' => '10.0.1.10',
    'public_address'   => '89.108.113.202',
    'swift_zone'       => 1,
    'mountpoints'=> "sda1 1\n sdb1 1\n sdc1 1\n sde1 1\n sdd1 1\n sdf1 1\n sdh1 1\n sdi1 1\n sdg1 1",
    'storage_local_net_ip' => '10.0.1.10',
  },
  {
    'name' => 'st-unknown-7415',
    'role' => 'storage',
    'internal_address' => '10.0.1.11',
    'public_address'   => '89.108.113.204',
    'swift_zone'       => 2,
    'mountpoints'=> "sdc1 1\n sdb1 1\n sdf1 1\n sde1 1\n sdh1 1\n sdd1 1\n sdg1 1\n sdi1 1\n sdk1 1",
    'storage_local_net_ip' => '10.0.1.11',
  },
  {
    'name' => 'st-unknown-7418',
    'role' => 'storage',
    'internal_address' => '10.0.1.12',
    'public_address'   => '89.108.113.203',
    'swift_zone'       => 3,
    'mountpoints'=> "sdc1 1\n sdd1 1\n sde1 1\n sdb1 1\n sdg1 1\n sdf1 1\n sdh1 1\n sdi1 1\n sdj1 1",
    'storage_local_net_ip' => '10.0.1.12',
  },
  { 'name' => 'u7394',
    'role' => 'nagios-server',
    'internal_address' => '10.0.1.13',
    'public_address'   => '89.108.113.201',
  }
]

$nodes = $nodes_harr

$internal_netmask = '255.255.255.0'
$public_netmask = '255.255.255.0'

$default_gateway = "192.168.122.100"

# Specify nameservers here.
# Need points to cobbler node IP, or to special prepared nameservers if you known what you do.
$dns_nameservers = ["8.8.8.8","8.8.4.4"]
stage {'openstack-firewall': before => Stage['main']} 
class { '::openstack::firewall':
   stage => 'openstack-firewall'
}

$ntp_servers = ['pool.ntp.org']

class {'openstack::clocksync': ntp_servers=>$ntp_servers}

if !defined(Class['selinux']) and ($::osfamily == 'RedHat') {
  class { 'selinux':
    mode=>"disabled",
    stage=>"openstack-custom-repo"
  }
}


if $::operatingsystem == 'Ubuntu' {
  class { 'openstack::apparmor::disable': stage => 'openstack-custom-repo' }
}

$master_swift_proxy_nodes = filter_nodes($nodes,'role','primary-swift-proxy')
$master_swift_proxy_ip = $master_swift_proxy_nodes[0]['internal_address']

$node = filter_nodes($nodes,'name',$::hostname)
if empty($node) {
  fail("Node $::hostname is not defined in the hash structure")
}
$internal_address = $node[0]['internal_address']
$public_address = $node[0]['public_address']

$swift_local_net_ip      = $internal_address

if $node[0]['role'] == 'primary-swift-proxy' {
  $primary_proxy = true
} else {
  $primary_proxy = false
}

$swift_proxy_nodes = merge_arrays(filter_nodes($nodes,'role','primary-swift-proxy'),filter_nodes($nodes,'role','swift-proxy'))
$swift_proxies = nodes_to_hash($swift_proxy_nodes,'name','internal_address')
$swift_internal_addresses = $swift_proxies
$swift_public_addresses = nodes_to_hash($swift_proxy_nodes,'name','public_address')
$swift_proxy_hostnames = keys($swift_internal_addresses)


$nv_physical_volume     = ['vdb','vdc'] 
$swift_loopback = false
$swift_user_password     = 'swift'

$verbose                = true
$admin_email          = 'dan@example_company.com'

$keystone_db_user        = 'keystone'
$keystone_db_dbname      = 'keystone'

$keystone_db_password = 'sdkf93i451'

$keystone_admin_token = 'JJ9sa3rkswd'
$admin_user           = 'admin'
$admin_password       = 'sdf09sdfa'

$nagios_master = 'u7394'
$proj_name = "LG_S3_cloud"

node u7394 {
  class {'nagios::master':
    proj_name       => $proj_name,
    rabbitmq        => false,
    nginx           => true,
    mysql_pass      => 'kofar0aw3r2',
    rabbit_user     => 'nova',
    rabbit_pass     => 'nova',
    rabbit_port     => '5673',
    templatehost    => {'name' => 'default-host', 'check_interval' => '10'},
    templateservice => {'name' => 'default-service', 'check_interval'=>'10'},
    hostgroups      => ['swift-storage', 'swift-proxy'],
    contactgroups   => {'group' => 'admins', 'alias' => 'Admins'},
    contacts        => {'user' => 'hotkey', 'alias' => 'Dennis Hoppe',
                 'email' => 'sergey.sapunov@lge.com',
                 'group' => 'admins'},
  }    
}

node keystone {
      #set up mysql server
#  class { 'mysql::server':
#    config_hash => {
#      # the priv grant fails on precise if I set a root password
#      # TODO I should make sure that this works
#      'root_password' => $mysql_root_password,
 #     'bind_address'  => $public_address
 #   }
 #}
  # set up all openstack databases, users, grants
#  class { 'keystone::db::mysql':
#   password => $keystone_db_password,
#}


  # install and configure the keystone service
  class { 'keystone':
    admin_token  => $keystone_admin_token,
    # we are binding keystone on all interfaces
    # the end user may want to be more restrictive
    bind_host    => $internal_address,
    verbose  => $verbose,
    debug    => $verbose,
    catalog_type => 'mysql',
    sql_connection => "mysql://${keystone_db_user}:${keystone_db_password}@${internal_virtual_ip}/${keystone_db_dbname}",
  }

  # set up keystone database
  # set up the keystone config for mysql
  class { 'openstack::db::mysql':
    keystone_db_password => $keystone_db_password,
    nova_db_password => $keystone_db_password,
    mysql_root_password => $keystone_db_password,
    cinder_db_password => $keystone_db_password,
    glance_db_password => $keystone_db_password,
    quantum_db_password => $keystone_db_password,
    mysql_bind_address => $internal_address,
    allowed_hosts => '%',
    custom_setup_class => 'galera',
    enabled                  => true,
    galera_node_address => $internal_address,
    galera_nodes => $swift_proxy_hostnames,
    primary_controller => $primary_proxy,
    galera_cluster_name => 'openstack',
  }
  # set up keystone admin users
  class { 'keystone::roles::admin':
    email    => $admin_email,
    password => $admin_password,
  }
  # configure the keystone service user and endpoint
  class { 'swift::keystone::auth':
    password => $swift_user_password,
    address  => $public_virtual_ip,
  }
}



# The following specifies 3 swift storage nodes
node /st-unknown-[\d+]/ {

    class {'nagios':
	proj_name       => $proj_name,
        services        => [
    	    'host-alive', 'swift-account', 'swift-container', 'swift-object',
        ],
        whitelist       => ['127.0.0.1', $nagios_master],
        hostgroup       => 'swift-storage',
    }

  include stdlib
  class { 'operatingsystem::checksupported':
      stage => 'setup'
  }

  $swift_zone = $node[0]['swift_zone']
  notice("swift zone is: ${swift_zone}")
  class { 'openstack::swift::storage_node':
#    storage_type           => $swift_loopback,
    swift_zone             => $swift_zone,
    swift_local_net_ip     => $swift_local_net_ip,
    master_swift_proxy_ip  => $master_swift_proxy_ip,
#    nv_physical_volume     => $nv_physical_volume,
#    storage_devices    => $nv_physical_volume,
    storage_base_dir     => '/srv/node/',
    db_host                => $internal_virtual_ip,
    service_endpoint       => $internal_virtual_ip,
    cinder       => false,
    workers      => "10",
  }

}

node /unknown-[\d+]/ inherits keystone {
  
  include stdlib
  class { 'operatingsystem::checksupported':
      stage => 'setup'
  }
  
    class {'nagios':
        proj_name       => $proj_name,
        services        => ['host-alive', 'swift-proxy','keystone','haproxy','mysql'],
        whitelist       => ['127.0.0.1', $nagios_master],
        hostgroup       => 'swift-proxy',
    }
  
  if $primary_proxy {
    ring_devices {'all':
      storages => filter_nodes($nodes, 'role', 'storage')
    }
  }

  class { 'openstack::swift::proxy':
    swift_user_password     => $swift_user_password,
    swift_proxies           => $swift_proxies,
    primary_proxy           => $primary_proxy,
    controller_node_address => $internal_virtual_ip,
    swift_local_net_ip      => $internal_address,
    master_swift_proxy_ip   => $master_swift_proxy_ip,
  }
  
  


    # haproxy
    include haproxy::params

    Haproxy_service {
      balancers => $swift_proxies
    }

    file { '/etc/rsyslog.d/haproxy.conf':
      ensure => present,
      content => 'local0.* -/var/log/haproxy.log'
    }
#    Class['keepalived'] -> Class ['nova::rabbitmq']

    haproxy_service { 'keystone-1': order => 20, port => 35357, virtual_ips => [$public_virtual_ip, $internal_virtual_ip]  }
    haproxy_service { 'keystone-2': order => 30, port => 5000, virtual_ips => [$public_virtual_ip, $internal_virtual_ip]  }
    haproxy_service { 'rabbitmq-epmd':    order => 91, port => 4369, virtual_ips => [$internal_virtual_ip], define_backend => true }
#    haproxy_service { 'rabbitmq-openstack':    order => 92, port => 5672, virtual_ips => [$internal_virtual_ip], define_backend => true }
    haproxy_service { 'mysqld': order => 95, port => 3306, virtual_ips => [$internal_virtual_ip], define_backend => true }
    haproxy_service { 'swift': order => 96, port => 8080, virtual_ips => [$public_virtual_ip,$internal_virtual_ip], balancers => $swift_proxies }
   

    exec { 'up-public-interface':
      command => "ifconfig ${public_interface} up",
      path    => ['/usr/bin', '/usr/sbin', '/sbin', '/bin'],
    }
    exec { 'up-internal-interface':
      command => "ifconfig ${internal_interface} up",
      path    => ['/usr/bin', '/usr/sbin', '/sbin', '/bin'],
    }
#    exec { 'up-private-interface':
#      command => "ifconfig ${private_interface} up",
#      path    => ['/usr/bin', '/usr/sbin', '/sbin', '/bin'],
 #   }

 #   if $primary_controller {
      exec { 'create-public-virtual-ip':
        command => "ip addr add ${public_virtual_ip} dev ${public_interface} label ${public_interface}:ka",
        unless  => "ip addr show dev ${public_interface} | grep -w ${public_virtual_ip}",
        path    => ['/usr/bin', '/usr/sbin', '/sbin', '/bin'],
        before  => Service['keepalived'],
        require => Exec['up-public-interface'],
      }
 #   }

    keepalived_dhcp_hook {$public_interface:interface=>$public_interface}
    if $internal_interface != $public_interface {
      keepalived_dhcp_hook {$internal_interface:interface=>$internal_interface}
    }

    Keepalived_dhcp_hook<| |> {before =>Service['keepalived']}

 #   if $primary_controller {
      exec { 'create-internal-virtual-ip':
        command => "ip addr add ${internal_virtual_ip} dev ${internal_interface} label ${internal_interface}:ka",
        unless  => "ip addr show dev ${internal_interface} | grep -w ${internal_virtual_ip}",
        path    => ['/usr/bin', '/usr/sbin', '/sbin', '/bin'],
        before  => Service['keepalived'],
        require => Exec['up-internal-interface'],
      }
#    }
    sysctl::value { 'net.ipv4.ip_nonlocal_bind': value => '1' }
    sysctl::value { 'net.netfilter.nf_conntrack_max': value => '1548576' }
    sysctl::value { 'net.netfilter.nf_conntrack_tcp_timeout_fin_wait': value => '5' }
    sysctl::value { 'net.netfilter.nf_conntrack_tcp_timeout_close_wait':  value => '5' }
    sysctl::value { 'net.netfilter.nf_conntrack_tcp_timeout_time_wait':  value => '5' }
    sysctl::value { 'net.core.rmem_max':  value => '16777216' }
    sysctl::value { 'net.core.wmem_max': value => '16777216' }
    sysctl::value { 'net.ipv4.tcp_rmem': value => '4096 87380 16777216' }
    sysctl::value { 'net.ipv4.tcp_wmem': value => '4096 87380 16777216' }
    sysctl::value { 'net.core.netdev_max_backlog':  value => '30000' }
    sysctl::value { 'net.ipv4.tcp_congestion_control': value => 'htcp' }
    sysctl::value { 'net.ipv4.tcp_mtu_probing': value => '1' }
    sysctl::value { 'net.ipv4.tcp_timestamps': value => '1' }
    sysctl::value { 'net.ipv4.tcp_sack': value => '1' }

    package { 'socat': ensure => present }
    exec { 'wait-for-haproxy-mysql-backend':
      command   => "echo show stat | socat unix-connect:///var/lib/haproxy/stats stdio | grep -q '^mysqld,BACKEND,.*,UP,'",
      path      => ['/usr/bin', '/usr/sbin', '/sbin', '/bin'],
      require   => [Service['haproxy'], Package['socat']],
      try_sleep => 5,
      tries     => 60,
    }

    Exec<| title == 'wait-for-synced-state' |> -> Exec['wait-for-haproxy-mysql-backend']
    Exec['wait-for-haproxy-mysql-backend'] -> Exec<| title == 'initial-db-sync' |>
    Exec['wait-for-haproxy-mysql-backend'] -> Exec<| title == 'keystone-manage db_sync' |>

    class { 'haproxy':
      enable => true,
      global_options   => merge($::haproxy::params::global_options, {'log' => "/dev/log local0"}),
      defaults_options => merge($::haproxy::params::defaults_options, {'mode' => 'http'}),
      require => Sysctl::Value['net.ipv4.ip_nonlocal_bind'],
    }
    
    
    # keepalived
    $public_vrid   = $::deployment_id
    $internal_vrid = $::deployment_id + 1

    class { 'keepalived':
      require => Class['haproxy'] ,
    }

    keepalived::instance { $public_vrid:
      interface => $public_interface,
      virtual_ips => [$public_virtual_ip],
      state    => $primary_controller ? { true => 'MASTER', default => 'BACKUP' },
      priority => $primary_controller ? { true => 101,      default => 100      },
    }
    keepalived::instance { $internal_vrid:
      interface => $internal_interface,
      virtual_ips => [$internal_virtual_ip],
      state    => $primary_controller ? { true => 'MASTER', default => 'BACKUP' },
      priority => $primary_controller ? { true => 101,      default => 100      },
    }


   Class['haproxy'] -> Class['galera']
  
  
 } 

########## define HA sevices ###########
  
define haproxy_service($order, $balancers, $virtual_ips, $port, $define_cookies = false, $define_backend = false) {

  case $name {
    "mysqld": {
      $haproxy_config_options = { 'option' => ['mysql-check user cluster_watcher', 'tcplog','clitcpka','srvtcpka'], 'balance' => 'roundrobin', 'mode' => 'tcp', 'timeout server' => '28801s', 'timeout client' => '28801s' }
      $balancermember_options = 'check inter 15s fastinter 2s downinter 1s rise 5 fall 3'
      $balancer_port = 3307
    }

    "rabbitmq-epmd": {
      $haproxy_config_options = { 'option' => ['clitcpka'], 'balance' => 'roundrobin', 'mode' => 'tcp'}
      $balancermember_options = 'check inter 5000 rise 2 fall 3'
      $balancer_port = 4369
    }
#    "rabbitmq-openstack": {
#      $haproxy_config_options = { 'option' => ['tcpka'], 'timeout client' => '48h', 'timeout server' => '48h', 'balance' => 'roundrobin', 'mode' => 'tcp'}
#      $balancermember_options = 'check inter 5000 rise 2 fall 3'
#      $balancer_port = 5673
#    }

    default: {
      $haproxy_config_options = { 'option' => ['httplog'], 'balance' => 'roundrobin' }
      $balancermember_options = 'check'
      $balancer_port = $port
    }
  }
  
  add_haproxy_service { $name : 
    order                    => $order, 
    balancers                => $balancers, 
    virtual_ips              => $virtual_ips, 
    port                     => $port, 
    haproxy_config_options   => $haproxy_config_options, 
    balancer_port            => $balancer_port, 
    balancermember_options   => $balancermember_options, 
    define_cookies           => $define_cookies, 
    define_backend           => $define_backend,
  }
}

# add_haproxy_service moved to separate define to allow adding custom sections 
# to haproxy config without any default config options, except only required ones.
define add_haproxy_service (
    $order, 
    $balancers, 
    $virtual_ips, 
    $port, 
    $haproxy_config_options, 
    $balancer_port, 
    $balancermember_options,
    $mode = 'tcp',
    $define_cookies = false, 
    $define_backend = false, 
    $collect_exported = false
    ) {
    haproxy::listen { $name:
      order            => $order - 1,
      ipaddress        => $virtual_ips,
      ports            => $port,
      options          => $haproxy_config_options,
      collect_exported => $collect_exported,
      mode             => $mode,
    }
    @haproxy::balancermember { "${name}":
      order                  => $order,
      listening_service      => $name,
      balancers              => $balancers,
      balancer_port          => $balancer_port,
      balancermember_options => $balancermember_options,
      define_cookies         => $define_cookies,
      define_backend        =>  $define_backend,
    }
}

define keepalived_dhcp_hook($interface)
{
    $down_hook="ip addr show dev $interface | grep -w $interface:ka | awk '{print \$2}' > /tmp/keepalived_${interface}_ip\n"
    $up_hook="cat /tmp/keepalived_${interface}_ip |  while read ip; do  ip addr add \$ip dev $interface label $interface:ka; done\n"
    file {"/etc/dhcp/dhclient-${interface}-down-hooks": content=>$down_hook, mode => 744 }
    file {"/etc/dhcp/dhclient-${interface}-up-hooks": content=>$up_hook, mode => 744 }
}



################### end define HA sevices #################################

