# Sophos XG API

Sophos XG API is a PHP library for requesting Sophos XG firewalls. This library can :

* Retrieve data from the firewall
* Set data on the firewall
* Remove data from the firewall

You can find all supported entities' names on [Sophos website](https://docs.sophos.com/nsg/sophos-firewall/18.0/API/index.html).

## Table of contents

<!--ts-->
   * [Getting started](#getting-started)
   * [Documentation](#documentation)
      * [Config class](#config-class)
      * [XGAPI class](#xgapi-class)
         * [get()](#get)
         * [set()](#set)
         * [remove()](#remove)
<!--te-->

## Getting started

1. Get [Composer](http://getcomposer.org/).
2. Install the library using composer `composer require benclerc/sophosxg-api`.
3. Add the following to your application's main PHP file `require 'vendor/autoload.php';`.
4. Instanciate the Config class with the firewall's hostname, username and password `$configFirewall = new \Sophos\Config('123.123.123.123', 'admin', 'password');`.
5. Use the Config object previously created to instanciate the XGAPI object `$firewall = new \Sophos\APIXG($configFirewall);`.
6. Start using the library `$hosts = $firewall->get(['IPHost']);`.

## Documentation

You can find a full documentation [here](https://benclerc.github.io/SophosXGAPI/).

### Config class

This Config class is used to prepare the mandatory configuration information to instanciate and use the XGAPI class. In the constructor you must pass :

1. The firewall's hostname (FQDN)
2. A valid user's username
3. The valid user's password

Optional parameters :

* CURL timeout : 10000ms. Use `setCurlTimeout()` to change.
* CURL SSL verify peer option : TRUE. Use `setCurlSSLVerifyPeer()` to change.
* CURL SSL verify host option : TRUE. Use `setCurlSSLVerifyHost()` to change.

Example :

```php
// Basic configuration
$configFirewall = new \Sophos\Config('123.123.123.123', 'admin', 'password');

// Configuration for very slow firewalls/long requests
$configFirewall = new \Sophos\Config('123.123.123.123', 'admin', 'password');
$configFirewall->setCurlTimeout(20000);

// Unsecure configuration
$configFirewall = new \Sophos\Config('123.123.123.123', 'admin', 'password');
$configFirewall->setCurlSSLVerifyPeer(FALSE)->setCurlSSLVerifyHost(FALSE);

$firewall = new \Sophos\APIXG($configFirewall);
```


### XGAPI class

#### get()

This method is used to retrieve data from the firewall. You must set which entity/entities you want to retrieve and you can set a filter for each one. Be careful, if you set several filters for the same entity they add up like a 'OR' not an 'AND'. Be careful not all attributes are filterable, see Sophos documentation. Available criterias for filtering :

1. =
2. like
3. !=

Examples :

```php
// All IPHost
$entities = ['IPHost'];
// IPHost named 'IP_TEST'
$entities = [
	'IPHost'=>[
		['Name', '=', 'IP_TEST']
	]
];
// All IPHost with 'IP_' in the name OR of type 'Network' 
$entities = [
	'IPHost'=>[
		['Name', 'like', 'IP_'],
		['HostType', '=', 'Network']
	]
];
// All IPHost and network interface named LAN
$entities = [
	'IPHost',
	'Interface'=>[
		['Name', '=', 'LAN']
	]
];

try {
	$result = $firewall->get($entites);
} catch (Exception $e) {
	echo('Handle error : '.$e->getMessage());
}
```

#### set()

This method is used to set data on the firewall. You must set all mandatory attributes for each entities you want to add.

Examples :

```php
// Add 1 IPv4 hosts
$entities = [
	'IPHost'=> [
		[
			'Name'=>'IP_TEST',
			'IPFamily'=>'IPv4',
			'HostType'=>'IP',
			'HostGroupList'=>[
				'HostGroup'=>'IP-GRP_TEST'
			],
			'IPAddress'=>'10.11.12.13',
			'Subnet'=>'255.255.255.0'
		]
	]
];
// Add 2 IPv4 hosts
$entities = [
	'IPHost'=> [
		[
			'Name'=>'IP_TEST',
			'IPFamily'=>'IPv4',
			'HostType'=>'IP',
			'HostGroupList'=>[
				'HostGroup'=>'IP-GRP_TEST'
			],
			'IPAddress'=>'10.11.12.13',
			'Subnet'=>'255.255.255.0'
		],
		[
			'Name'=>'IP_TEST2',
			'IPFamily'=>'IPv4',
			'HostType'=>'IP',
			'HostGroupList'=>[
				'HostGroup'=>'IP-GRP_TEST'
			],
			'IPAddress'=>'10.11.12.14',
			'Subnet'=>'255.255.255.0'
		]
	]
];
// Add 2 IPv4 hosts and 1 QOS policy
$entities = [
	'IPHost'=> [
		[
			'Name'=>'IP_TEST',
			'IPFamily'=>'IPv4',
			'HostType'=>'IP',
			'HostGroupList'=>[
				'HostGroup'=>'IP-GRP_TEST'
			],
			'IPAddress'=>'10.11.12.13',
			'Subnet'=>'255.255.255.0'
		],
		[
			'Name'=>'IP_TEST2',
			'IPFamily'=>'IPv4',
			'HostType'=>'IP',
			'HostGroupList'=>[
				'HostGroup'=>'IP-GRP_TEST'
			],
			'IPAddress'=>'10.11.12.14',
			'Subnet'=>'255.255.255.0'
		]
	],
	'QoSPolicy'=>[
		[
		'Name'=>'QOS_TEST',
		'PolicyBasedOn'=>'FirewallRule',
		'BandwidthUsageType'=>'Shared',
		'ImplementationOn'=>'Total',
		'PolicyType'=>'Strict',
		'Priority'=>'Normal4',
		'TotalBandwidth'=>'6875'
		]
	]
];

try {
	$result = $firewall->set($entites);
} catch (Exception $e) {
	echo('Handle error : '.$e->getMessage());
}
```

#### remove()

This method is used to remove data from the firewall. You must set the entities you want to delete as well as the name of the objects you want to delete, you cannot delete on anything else than the object's name.

Examples :

```php
// Remove the IPv4 host 'IP_TEST'
$entities = [
	'IPHost'=> [
		'IP_TEST'
	]
];
// Remove the IPv4 hosts 'IP_TEST' and 'IP_TEST2'
$entities = [
	'IPHost'=> [
		'IP_TEST',
		'IP_TEST2'
	]
];
// Remove the IPv4 hosts 'IP_TEST' and 'IP_TEST2' and QOS policy 'QOS_TEST'
$entities = [
	'IPHost'=> [
		'IP_TEST',
		'IP_TEST2'
	],
	'QoSPolicy'=> [
		'QOS_TEST'
	]
];

try {
	$result = $firewall->remove($entites);
} catch (Exception $e) {
	echo('Handle error : '.$e->getMessage());
}
```




