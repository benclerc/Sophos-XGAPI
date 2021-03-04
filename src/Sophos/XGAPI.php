<?php

/**
* 	Library used for interacting with Sophos XG firewall API.
*	@author Benjamin Clerc <contact@benjamin-clerc.com>
*	@copyright Copyright (c) 2021, Benjamin Clerc.
*	@license MIT
*	@link https://github.com/benclerc/SophosXGAPI
*/

namespace Sophos;

use Exception;
use DOMDocument;
use SimpleXMLElement;

/**
* 	Sophos XG API
*	@property Config $config Config object with all needed information.
*	@link https://docs.sophos.com/nsg/sophos-firewall/18.0/API/index.html Sophos API documentation with all entities name, etc ...
*/
class XGAPI {
	private Config $config;


	/**
	*	Constructor takes care of checking and registering firewall's configuration information.
	*	@param Config $config Object containing all necessary configuration.
	*/
	public function __construct(Config $config) {
		$this->config = $config;
	}


	/**
	*	Method to request the firewall's API using curl library.
	*	@param DOMDocument $xml DOMDocument object containing the request core without login information. The document first element must be "Get", "Set" or "Remove".
	*	@return array Firewall's raw XML response as a PHP array.
	*/
	private function curlRequest(\DOMDocument $xml) : array {
		// Create an empty document
		$reqxml = new DOMDocument();
		// Create the "Request" entity
		$xml_request = $reqxml->createElement('Request');

		// Create login element
		$xml_login = $reqxml->createElement('Login');
		$xml_username = $reqxml->createElement('Username', $this->config->getUsername());
		$xml_pass = $reqxml->createElement('Password', $this->config->getPassword());
		// Append username and pass in the login element
		$xml_login->appendChild($xml_username);
		$xml_login->appendChild($xml_pass);
		// Append login element in request element
		$xml_request->appendChild($xml_login);

		// Append request element in the document
		$reqxml->appendChild($xml_request);
		// Append to the request element in the main document the Get, Set or Remove element from document passed in argument
		$reqxml->documentElement->appendChild(
			$reqxml->importNode($xml->documentElement, TRUE)
		);

		// Create XML url encoded string from the document
		$strxml = urlencode($reqxml->saveXML());

		// Init CURL
		$ch = curl_init();
		// Set CURL options (URL, do not check SSL, return response in variable and quite long timeout cause firewall's might take long time to answer)
		curl_setopt($ch, CURLOPT_URL, 'https://'.$this->config->getHostname().':4444/webconsole/APIController?reqxml='.$strxml);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $this->config->getCurlSSLVerifyPeer());
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $this->config->getCurlSSLVerifyHost());
		curl_setopt($ch, CURLOPT_TIMEOUT_MS, $this->config->getCurlTimeout());

		// Execute CURL
		$result = curl_exec($ch);

		// Check if there is a CURL error
		if (curl_errno($ch)) {
		    throw new Exception('curlRequest() called by '.debug_backtrace()[1]['function'].'() : Curl error : '.curl_error($ch));
		}
		// Close CURL
		curl_close ($ch);

		// Try to parse XML, if not parsable throw error because the firewall always answer an XML element
		try {
			$resXML = new SimpleXMLElement($result);
		} catch (Exception $e) {
			throw new Exception('curlRequest() called by '.debug_backtrace()[1]['function'].'() : Request returned not parsable XML.');
		}

		// Transform XML answer in PHP array (not cleanest way of doing it but it works)
		$resPHP = json_decode(json_encode((array) simplexml_load_string($result)), 1);

		// Return firewall's respsonse in a PHP array
		return $resPHP;
	}


	/**
	*	Method to retrieve data from the firewall.
	*	@param array $entities One or several Sophos XG firewall entities. See API documentation. Those entities can be the key of an array of filter, if it is only a string then there is no filter on this entity. Each filter is an array where the first element must be the name of the element on which we filter, second element is the type of comparison ('=', '!=' or 'like'), third element is the value of the filter. E.g. ['entity1' => [['Name', '=', 'First entity'], ['IPv4', '!=', '172.20.1.1']], 'entity2' => [['Name', 'like', 'Second entity']]]
	*	@return array PHP array of entities containing array of results.
	*/
	public function get(array $entities) : array {
		// Create an empty XML document and the "Get" element for our request
		$xml = new DOMDocument();
		$get = $xml->createElement('Get');

		// Create request with or without filter
		foreach ($entities as $key => $value) {
			// If $value is not an array, it means there is no filter
			if (!is_array($value)) {
				// Create node with no sub-node
				$get->appendChild($xml->createElement($value));
			} else {
				// Create node with subnodes and attributes
				$xml_entity = $xml->createElement($key);
				$xml_filter = $xml->createElement('Filter');
				foreach ($value as $key2 => $value2) {
					$xml_key = $xml->createElement('Key', $value2[2]);
					$xml_key->setAttribute('name', $value2[0]);
					$xml_key->setAttribute('criteria', $value2[1]);
				}
				$xml_filter->appendChild($xml_key);
				$xml_entity->appendChild($xml_filter);
				// Append the filter created into the document
				$get->appendChild($xml_entity);
			}
			$xml->appendChild($get);
		}

		// Execute request
		$res = $this->curlRequest($xml);

		// Declare callback functions used to remove "@attributes" element in array created from the firewall's response
		function rmMiscXSEObjects($a) {
			if (isset($a['@attributes'])) { unset($a['@attributes']); }
			return $a;
		}

		// Analyze result : if one of the entities does not return a correct result or does not return the wanted entity then throw an error, else fill a return element (allows us to return only wanted information, without request status related information)
		foreach ($entities as $key => $value) {
			// If $value is an array, it means that a filter is set so we use $key for entity name, if it is not an array then we use $value for the entity name
			$entity = (!is_array($value)) ? $value : $key;

			if (empty($res[$entity])) {
				throw new Exception('get() called by '.debug_backtrace()[1]['function'].'() : Request did not return the wanted entity.');
			} else {
				if (count($res[$entity]) == 2 && !empty($res[$entity]['Status'])) {
					throw new Exception('get() called by '.debug_backtrace()[1]['function'].'() : Request returned "'.$res[$entity]['Status'].'" for "'.$entity.'" entity.');
				} else {
					// This if statement check (using the position of the array element "@attributes") if there is one or several element in the response. If there is only one result, then put in an array in order to keep the same structure if there are one or more results in the response
					if (isset($res[$entity]['@attributes'])) {
						$return[$entity] = array_map('Sophos\rmMiscXSEObjects', [$res[$entity]]);
					} else {
						$return[$entity] = array_map('Sophos\rmMiscXSEObjects', $res[$entity]);
					}
				}
			}
		}

		return $return;
	}


	/**
	*	Method to set data on the firewall.
	*	@param array $entities One or several Sophos XG firewall entities. See API documentation. Each entities is an array of the entity's properties to declare e.g. ['IPHost'=> [['Name'=>'IP_TEST', 'IPFamily'=>'IPv4', 'HostType'=>'IP', 'HostGroupList'=>['HostGroup'=>'GBL_IP-GRP_SIE'], 'IPAddress'=>'172.20.1.230', 'Subnet'=>'255.255.255.0'], ['Name'=>'IP_TEST2', 'IPFamily'=>'IPv4', 'HostType'=>'IP', 'HostGroupList'=>['HostGroup'=>'GBL_IP-GRP_SIE'], 'IPAddress'=>'172.20.1.231', 'Subnet'=>'255.255.255.0'] ], 'QoSPolicy'=>[['Name'=>'QOS_TEST', 'PolicyBasedOn'=>'FirewallRule', 'BandwidthUsageType'=>'Shared', 'ImplementationOn'=>'Total', 'PolicyType'=>'Strict', 'Priority'=>'Normal4', 'TotalBandwidth'=>'6875'] ] ]
	*	@return bool Request status.
	*/
	public function set(array $entities) : bool {
		// Create an empty XML document and the "Set" element for our request
		$xml = new DOMDocument();
		$set = $xml->createElement('Set');

		// Function used to add properties to the document no matter how many levels there are
		function addRecursiveProperties($document, $propertyName, $propertyValue) {
			if (is_array($propertyValue)) {
				$element = $document->createElement($propertyName);
				foreach ($propertyValue as $key => $value) {
					$element->appendChild(addRecursiveProperties($document, $key, $value));
				}
				return $element;
			} else {
				return $document->createElement($propertyName, $propertyValue);
			}
		}

		// Create request with or without filter
		foreach ($entities as $key => $value) {
			// Here we use a foreach because even if we have several times the same entity it must be redeclared each time
			foreach ($value as $key2 => $value2) {
				// Create the entity node
				$xml_entity = $xml->createElement($key);
				// Go through all properties and add them to the entity node
				foreach ($value2 as $key3 => $value3) {
					$xml_entity->appendChild(addRecursiveProperties($xml, $key3, $value3));
				}
				// Append the entity created into the Set node
				$set->appendChild($xml_entity);
			}
			// Append to the document
			$xml->appendChild($set);
		}

		// Execute request
		$res = $this->curlRequest($xml);

		// Analyze result : if one of the entities does not return a correct result or does not return the wanted status then throw an error, else return true
		foreach ($entities as $key => $value) {
			if (empty($res[$key])) {
				throw new Exception('set() called by '.debug_backtrace()[1]['function'].'() : Request did not return the wanted entity.');
			}
			// If there was only one record for this entity, then the status element is one level lower
			if (count($entities[$key]) == 1) {
				if ($res[$key]['Status'] != 'Configuration applied successfully.') {
					throw new Exception('set() called by '.debug_backtrace()[1]['function'].'() : Request returned "'.$res[$key]['Status'].'" for "'.$key.'" entity.');
				}
			} else {
				foreach ($value as $key2 => $value2) {
					if ($res[$key][$key2]['Status'] != 'Configuration applied successfully.') {
						throw new Exception('set() called by '.debug_backtrace()[1]['function'].'() : Request returned "'.$res[$key][$key2]['Status'].'" for "'.$key.'" entity.');
					}
				}
			}
		}

		return TRUE;
	}


	/**
	*	Method to remove data on the firewall.
	*	@param array $entities One or several Sophos XG firewall entities. See API documentation. Each entities is an array of the entity's name to remove e.g. ['IPHost'=>['OBJ_TEST', 'OBJ_TEST2'], 'QoSPolicy'=>['SHP_TST']]
	*	@return bool Request status.
	*/
	public function remove(array $entities) : bool {
		// Create an empty XML document and the "Remove" element for our request
		$xml = new DOMDocument();
		$set = $xml->createElement('Remove');

		// Create request with all wanted entities
		foreach ($entities as $key => $value) {
			// Create the entity node
			$xml_entity = $xml->createElement($key);
			// Add every name entities we want to remove
			foreach ($value as $key2 => $value2) {
				$xml_entity->appendChild($xml->createElement('Name', $value2));
				// Append the entity created into the Set node
			}
			$set->appendChild($xml_entity);
			// Append to the document
			$xml->appendChild($set);
		}

		// Execute request
		$res = $this->curlRequest($xml);

		// Analyze result : if one of the entities does not return a correct result or does not return the wanted status then throw an error else, return true
		foreach ($entities as $key => $value) {
			if (empty($res[$key])) {
				throw new Exception('set() called by '.debug_backtrace()[1]['function'].'() : Request did not return the wanted entity.');
			} else {
				if ($res[$key]['Status'] != 'Configuration applied successfully.') {
					throw new Exception('set() called by '.debug_backtrace()[1]['function'].'() : Request returned "'.$res[$key]['Status'].'" for "'.$key.'" entity.');
				}
			}
		}

		return TRUE;
	}

}