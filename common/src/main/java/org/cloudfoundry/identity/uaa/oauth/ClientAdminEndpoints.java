/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */
package org.cloudfoundry.identity.uaa.oauth;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Controller for listing and manipulating OAUth2 clients.
 * 
 * @author Dave Syer
 */
@Controller
public class ClientAdminEndpoints {

	private ClientRegistrationService clientRegistrationService;

	private ClientDetailsService clientDetailsService;
	
	/**
	 * @param clientRegistrationService the clientRegistrationService to set
	 */
	public void setClientRegistrationService(ClientRegistrationService clientRegistrationService) {
		this.clientRegistrationService = clientRegistrationService;
	}
	
	/**
	 * @param clientDetailsService the clientDetailsService to set
	 */
	public void setClientDetailsService(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

	@RequestMapping(value="/oauth/clients/{client}", method=RequestMethod.GET)
	@ResponseBody
	public ClientDetails getClientDetails(@PathVariable String client) throws Exception {
		try {
			return removeSecret(clientDetailsService.loadClientByClientId(client));
		}
		catch (InvalidClientException e) {
			throw new NoSuchClientException("No such client: " + client);
		}
	}

	@RequestMapping(value="/oauth/clients", method=RequestMethod.POST)
	public ResponseEntity<Void> createClientDetails(@RequestBody BaseClientDetails details) throws Exception {
		clientRegistrationService.addClientDetails(details);
		return new ResponseEntity<Void>(HttpStatus.CREATED);
	}

	@RequestMapping(value="/oauth/clients/{client}", method=RequestMethod.PUT)
	public ResponseEntity<Void> updateClientDetails(@RequestBody BaseClientDetails details, @PathVariable String client) throws Exception {
		Assert.state(client.equals(details.getClientId()), String.format("The client id (%s) does not match the URL (%s)", details.getClientId(), client));
		clientRegistrationService.updateClientDetails(details);
		return new ResponseEntity<Void>(HttpStatus.NO_CONTENT);
	}

	@RequestMapping(value="/oauth/clients/{client}", method=RequestMethod.DELETE)
	public ResponseEntity<Void> removeClientDetails(@PathVariable String client) throws Exception {
		ClientDetails details = clientDetailsService.loadClientByClientId(client);
		clientRegistrationService.removeClientDetails(details);
		return new ResponseEntity<Void>(HttpStatus.NO_CONTENT);
	}
	
	@ExceptionHandler(NoSuchClientException.class)
	public ResponseEntity<Void> handleNoSuchClient(NoSuchClientException e) {
		return new ResponseEntity<Void>(HttpStatus.NOT_FOUND);
	}

	@ExceptionHandler(ClientAlreadyExistsException.class)
	public ResponseEntity<Void> handleClientAlreadyExists(ClientAlreadyExistsException e) {
		return new ResponseEntity<Void>(HttpStatus.CONFLICT);
	}

	private ClientDetails removeSecret(ClientDetails client) {
		BaseClientDetails details = new BaseClientDetails();
		details.setClientId(client.getClientId());
		details.setScope(client.getScope());
		details.setResourceIds(client.getResourceIds());
		details.setAuthorizedGrantTypes(client.getAuthorizedGrantTypes());
		details.setRegisteredRedirectUri(client.getRegisteredRedirectUri());
		details.setAuthorities(client.getAuthorities());
		details.setAccessTokenValiditySeconds(client.getAccessTokenValiditySeconds());
		return details;
	}

}
