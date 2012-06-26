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

import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.security.DefaultSecurityContextAccessor;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jmx.export.annotation.ManagedMetric;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.jmx.support.MetricType;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Controller for listing and manipulating OAuth2 clients.
 * 
 * @author Dave Syer
 */
@Controller
@ManagedResource
public class ClientAdminEndpoints implements InitializingBean {

	private final Log logger = LogFactory.getLog(getClass());

	private static final Set<String> ADMIN_VALID_GRANTS = new HashSet<String>(Arrays.asList("implicit", "password",
			"client_credentials", "authorization_code", "refresh_token"));

	private static final Set<String> NON_ADMIN_VALID_GRANTS = new HashSet<String>(Arrays.asList("implicit",
			"authorization_code", "refresh_token"));

	private ClientRegistrationService clientRegistrationService;

	private ClientDetailsService clientDetailsService;

	private SecurityContextAccessor securityContextAccessor = new DefaultSecurityContextAccessor();

	private final Map<String, AtomicInteger> errorCounts = new ConcurrentHashMap<String, AtomicInteger>();

	private AtomicInteger clientUpdates = new AtomicInteger();

	private AtomicInteger clientDeletes = new AtomicInteger();

	private AtomicInteger clientSecretChanges = new AtomicInteger();

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

	void setSecurityContextAccessor(SecurityContextAccessor securityContextAccessor) {
		this.securityContextAccessor = securityContextAccessor;
	}

	@ManagedMetric(metricType = MetricType.COUNTER, displayName = "Client Registration Count")
	public int getTotalClients() {
		return clientRegistrationService.listClientDetails().size();
	}

	@ManagedMetric(metricType = MetricType.COUNTER, displayName = "Client Update Count (Since Startup)")
	public int getClientUpdates() {
		return clientUpdates.get();
	}

	@ManagedMetric(metricType = MetricType.COUNTER, displayName = "Client Delete Count (Since Startup)")
	public int getClientDeletes() {
		return clientDeletes.get();
	}

	@ManagedMetric(metricType = MetricType.COUNTER, displayName = "Client Secret Change Count (Since Startup)")
	public int getClientSecretChanges() {
		return clientSecretChanges.get();
	}

	@ManagedMetric(displayName = "Errors Since Startup")
	public Map<String, AtomicInteger> getErrorCounts() {
		return errorCounts;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.state(clientRegistrationService != null, "A ClientRegistrationService must be provided");
		Assert.state(clientDetailsService != null, "A ClientDetailsService must be provided");
	}

	@RequestMapping(value = "/oauth/clients/{client}", method = RequestMethod.GET)
	@ResponseBody
	public ClientDetails getClientDetails(@PathVariable String client) throws Exception {
		try {
			return removeSecret(clientDetailsService.loadClientByClientId(client));
		}
		catch (InvalidClientException e) {
			throw new NoSuchClientException("No such client: " + client);
		}
	}

	@RequestMapping(value = "/oauth/clients", method = RequestMethod.POST)
	public ResponseEntity<Void> createClientDetails(@RequestBody BaseClientDetails details) throws Exception {
		validateClient(details, true);
		clientRegistrationService.addClientDetails(details);
		return new ResponseEntity<Void>(HttpStatus.CREATED);
	}

	@RequestMapping(value = "/oauth/clients/{client}", method = RequestMethod.PUT)
	public ResponseEntity<Void> updateClientDetails(@RequestBody BaseClientDetails details, @PathVariable String client)
			throws Exception {
		validateClient(details, false);
		Assert.state(client.equals(details.getClientId()),
				String.format("The client id (%s) does not match the URL (%s)", details.getClientId(), client));
		try {
			ClientDetails existingClientConfig = getClientDetails(client);
			details = syncWithExisting(existingClientConfig, details);
		}
		catch (Exception e) {
			logger.warn("Couldn't fetch client config for client_id: " + client, e);
		}
		clientRegistrationService.updateClientDetails(details);
		clientUpdates.incrementAndGet();
		return new ResponseEntity<Void>(HttpStatus.NO_CONTENT);
	}

	@RequestMapping(value = "/oauth/clients/{client}", method = RequestMethod.DELETE)
	public ResponseEntity<Void> removeClientDetails(@PathVariable String client) throws Exception {
		clientRegistrationService.removeClientDetails(client);
		clientDeletes.incrementAndGet();
		return new ResponseEntity<Void>(HttpStatus.NO_CONTENT);
	}

	@RequestMapping(value = "/oauth/clients", method = RequestMethod.GET)
	public ResponseEntity<Map<String, ClientDetails>> listClientDetails() throws Exception {
		List<ClientDetails> details = clientRegistrationService.listClientDetails();
		Map<String, ClientDetails> map = new LinkedHashMap<String, ClientDetails>();
		for (ClientDetails client : details) {
			map.put(client.getClientId(), removeSecret(client));
		}
		return new ResponseEntity<Map<String, ClientDetails>>(map, HttpStatus.OK);
	}

	@RequestMapping(value = "/oauth/clients/{client}/secret", method = RequestMethod.PUT)
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void changeSecret(@PathVariable String client, @RequestBody SecretChangeRequest change) {

		ClientDetails clientDetails;
		try {
			clientDetails = clientDetailsService.loadClientByClientId(client);
		}
		catch (InvalidClientException e) {
			throw new NoSuchClientException("No such client: " + client);
		}

		checkPasswordChangeIsAllowed(clientDetails, change.getOldSecret());

		clientRegistrationService.updateClientSecret(client, change.getSecret());

		clientSecretChanges.incrementAndGet();
	}

	@ExceptionHandler(InvalidClientDetailsException.class)
	public ResponseEntity<InvalidClientDetailsException> handleInvalidClientDetails(InvalidClientDetailsException e) {
		incrementErrorCounts(e);
		return new ResponseEntity<InvalidClientDetailsException>(e, HttpStatus.BAD_REQUEST);
	}

	@ExceptionHandler(NoSuchClientException.class)
	public ResponseEntity<Void> handleNoSuchClient(NoSuchClientException e) {
		incrementErrorCounts(e);
		return new ResponseEntity<Void>(HttpStatus.NOT_FOUND);
	}

	@ExceptionHandler(ClientAlreadyExistsException.class)
	public ResponseEntity<Void> handleClientAlreadyExists(ClientAlreadyExistsException e) {
		incrementErrorCounts(e);
		return new ResponseEntity<Void>(HttpStatus.CONFLICT);
	}

	private void incrementErrorCounts(Exception e) {
		String series = UaaStringUtils.getErrorName(e);
		AtomicInteger value = errorCounts.get(series);
		if (value == null) {
			synchronized (errorCounts) {
				value = errorCounts.get(series);
				if (value == null) {
					value = new AtomicInteger();
					errorCounts.put(series, value);
				}
			}
		}
		value.incrementAndGet();
	}

	private void validateClient(ClientDetails client, boolean create) {

		Set<String> requestedGrantTypes = client.getAuthorizedGrantTypes();

		Set<String> validGrants = NON_ADMIN_VALID_GRANTS;
		if (securityContextAccessor.isAdmin()) {
			validGrants = ADMIN_VALID_GRANTS;
		}
		else {

			// Not admin, so be strict with grant types and scopes
			if (requestedGrantTypes.contains("implicit")
					&& (requestedGrantTypes.contains("authorization_code") || requestedGrantTypes
							.contains("refresh_token"))) {
				throw new InvalidClientDetailsException(
						"Not allowed: implicit grant type is not allowed together with authorization_code or refresh_token");
			}

			String callerId = securityContextAccessor.getClientId();
			if (callerId != null) {

				ClientDetails caller = clientDetailsService.loadClientByClientId(callerId);
				Set<String> validScope = caller.getScope();
				for (String scope : client.getScope()) {
					if (!validScope.contains(scope)) {
						throw new InvalidClientDetailsException(scope + " is not an allowed scope. Must be one of: "
								+ validScope.toString());
					}
				}

				Set<String> validAuthorities = AuthorityUtils.authorityListToSet(caller.getAuthorities());
				for (String authority : AuthorityUtils.authorityListToSet(client.getAuthorities())) {
					if (!validAuthorities.contains(authority)) {
						throw new InvalidClientDetailsException(authority
								+ " is not an allowed authority. Must be one of: " + validAuthorities.toString());
					}
				}

			}

		}

		for (String grant : requestedGrantTypes) {
			if (!validGrants.contains(grant)) {
				throw new InvalidClientDetailsException(grant + " is not an allowed grant type. Must be one of: "
						+ validGrants.toString());
			}
		}

		if (create) {
			// Only check for missing secret if client is being created.
			if (requestedGrantTypes.size() == 1 && requestedGrantTypes.contains("implicit")) {
				if (StringUtils.hasText(client.getClientSecret())) {
					throw new InvalidClientDetailsException("implicit grant does not require a client_secret");
				}
			}
			else {
				if (!StringUtils.hasText(client.getClientSecret())) {
					throw new InvalidClientDetailsException("client_secret is required for non-implicit grant types");
				}
			}
		}

	}

	private void checkPasswordChangeIsAllowed(ClientDetails clientDetails, String oldSecret) {

		if (!securityContextAccessor.isClient()) {
			// Trusted client (not acting on behalf of user)
			throw new IllegalStateException("Only a client can change client secret");
		}

		String clientId = clientDetails.getClientId();

		// Call is by client
		String currentClientId = securityContextAccessor.getClientId();

		if (securityContextAccessor.isAdmin()) {

			// even an admin needs to provide the old value to change password
			if (clientId.equals(currentClientId) && !StringUtils.hasText(oldSecret)) {
				throw new IllegalStateException("Previous secret is required even for admin");
			}

		}
		else {

			if (!clientId.equals(currentClientId)) {
				logger.warn("Client with id " + currentClientId + " attempting to change password for client "
						+ clientId);
				// TODO: This should be audited when we have non-authentication events in the log
				throw new IllegalStateException("Bad request. Not permitted to change another client's secret");
			}

			// Client is changing their own secret, old password is required
			if (!StringUtils.hasText(oldSecret)) {
				throw new IllegalStateException("Previous secret is required");
			}

		}

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

	private BaseClientDetails syncWithExisting(ClientDetails existingClientConfig, BaseClientDetails details) {
		if (details.getAccessTokenValiditySeconds() == null) {
			details.setAccessTokenValiditySeconds(existingClientConfig.getAccessTokenValiditySeconds());
		}
		if (details.getRefreshTokenValiditySeconds() == null) {
			details.setRefreshTokenValiditySeconds(existingClientConfig.getRefreshTokenValiditySeconds());
		}
		if (details.getAuthorities() == null || details.getAuthorities().isEmpty()) {
			details.setAuthorities(existingClientConfig.getAuthorities());
		}
		if (details.getAuthorizedGrantTypes() == null || details.getAuthorizedGrantTypes().isEmpty()) {
			details.setAuthorizedGrantTypes(existingClientConfig.getAuthorizedGrantTypes());
		}
		if (details.getRegisteredRedirectUri() == null || details.getRegisteredRedirectUri().isEmpty()) {
			details.setRegisteredRedirectUri(existingClientConfig.getRegisteredRedirectUri());
		}
		if (details.getResourceIds() == null || details.getResourceIds().isEmpty()) {
			details.setResourceIds(existingClientConfig.getResourceIds());
		}
		if (details.getScope() == null || details.getScope().isEmpty()) {
			details.setScope(existingClientConfig.getScope());
		}
		return details;
	}

}
