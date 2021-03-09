<?php

/**
* 	Library used for interacting with Sophos XG firewall API.
*	@author Benjamin Clerc <contact@benjamin-clerc.com>
*	@copyright Copyright (c) 2021, Benjamin Clerc.
*	@license MIT
*	@link https://github.com/benclerc/Sophos-XGAPI
*/

namespace Sophos;

use Exception;

/**
* 	XGAPI's configuration class
*/
class Config {
	private string $hostname;
	private string $username;
	private string $password;
	private int $timeout = 10000;
	private bool $SSLVerifyPeer = TRUE;
	private int $SSLVerifyHost = 2;


	/**
	*	@param string $hostname Firewall's FQDN
	*	@param string $username API autorized user
	*	@param string $password API autorized user's password
	*	@return Config Config object to be passed on a new instance of XGAPI object.
	*/
	public function __construct(string $hostname, string $username, string $password) {
		// Check and register firewall's hostname
		if (filter_var($hostname, FILTER_VALIDATE_DOMAIN)) {
			$this->hostname = $hostname;
		} else {
			throw new Exception('__construct() : Invalid hostname provided.');
		}
		// Register username and password
		$this->username = $username;
		$this->password = $password;
	}


	/**
	*	Getter for firewall's FQDN.
	*	@return string Firewall's FQDN.
	*/
	public function getHostname() {
		return $this->hostname;
	}


	/**
	*	Getter for API autorized user.
	*	@return string API autorized user.
	*/
	public function getUsername() {
		return $this->username;
	}


	/**
	*	Getter for API autorized user's password.
	*	@return string API autorized user's password.
	*/
	public function getPassword() {
		return $this->password;
	}


	/**
	*	Setter for curl's timeout in ms.
	*	@param int $timeout Curl's timeout in ms.
	*	@return Config Config object to be passed on a new instance of XGAPI object.
	*/
	public function setTimeout(int $timeout) {
		$this->timeout = $timeout;
		return $this;
	}


	/**
	*	Getter for curl's timeout in ms.
	*	@return int Curl's timeout in ms.
	*/
	public function getTimeout() {
		return $this->timeout;
	}


	/**
	*	Setter for curl's option to verify SSL peer.
	*	@param int $verifySSLPeer Curl's option to verify SSL peer.
	*	@return Config Config object to be passed on a new instance of XGAPI object.
	*/
	public function setSSLVerifyPeer(bool $verifySSLPeer) {
		$this->SSLVerifyPeer = $verifySSLPeer;
		return $this;
	}


	/**
	*	Getter for curl's option to verify SSL peer.
	*	@return bool Curl's option to verify SSL peer.
	*/
	public function getSSLVerifyPeer() {
		return $this->SSLVerifyPeer;
	}


	/**
	*	Setter for curl's option to verify SSL peer.
	*	@param bool $verifySSLHost Curl's option to verify SSL host.
	*	@return Config Config object to be passed on a new instance of XGAPI object.
	*/
	public function setSSLVerifyHost(bool $verifySSLHost) {
		$this->SSLVerifyHost = ($verifySSLHost) ? 2 : 0;
		return $this;
	}


	/**
	*	Getter for curl's option to verify SSL peer.
	*	@return bool Curl's option to verify SSL host.
	*/
	public function getSSLVerifyHost() {
		return $this->SSLVerifyHost;
	}

}
