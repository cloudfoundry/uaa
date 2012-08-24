/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.cloudfoundry.identity.uaa.oauth;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationService;

/**
 * @author Dave Syer
 * 
 */
public class ClientAdminBootstrap implements InitializingBean {

	private static Log logger = LogFactory.getLog(ClientAdminBootstrap.class);

	private Map<String, Map<String, Object>> clients = new HashMap<String, Map<String, Object>>();

	private ClientRegistrationService clientRegistrationService;

	private boolean override = false;

	private Map<String, String> authoritiesToScopes = new HashMap<String, String>();

	private Collection<String> validScopes = Arrays.asList("password.write", "openid", "cloud_controller.read",
			"cloud_controller.write", "clients.read", "clients.write", "clients.secret", "tokens.read", "tokens.write",
			"scim.read", "scim.write");

	private String domain = "cloudfoundry\\.com";

	{
		authoritiesToScopes.put("ROLE_UNTRUSTED", "uaa.none");
		authoritiesToScopes.put("ROLE_RESOURCE", "uaa.resource");
		authoritiesToScopes.put("ROLE_LOGIN", "uaa.login");
		authoritiesToScopes.put("ROLE_ADMIN", "uaa.admin");
	}

	/**
	 * The domain suffix (default "cloudfoundry.com") used to detect http redirects. If an http callback in this domain
	 * is found in a client registration and there is no corresponding value with https as well, then the https value
	 * will be added.
	 * 
	 * @param domain the domain to set
	 */
	public void setDomain(String domain) {
		this.domain = domain.replace(".", "\\.");
	}

	/**
	 * @param override the override to set
	 */
	public void setOverride(boolean override) {
		this.override = override;
	}

	/**
	 * @param clients the clients to set
	 */
	public void setClients(Map<String, Map<String, Object>> clients) {
		this.clients = clients == null ? Collections.<String, Map<String, Object>> emptyMap()
				: new HashMap<String, Map<String, Object>>(clients);
	}

	/**
	 * @param clientRegistrationService the clientRegistrationService to set
	 */
	public void setClientRegistrationService(ClientRegistrationService clientRegistrationService) {
		this.clientRegistrationService = clientRegistrationService;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		convertLegacyClients();
		addHttpsCallbacks();
		addNewClients();
	}

	/**
	 * Add https callback to clients in cloudfoundry.com if not present
	 */
	private void addHttpsCallbacks() {
		List<ClientDetails> clients = clientRegistrationService.listClientDetails();

		for (ClientDetails client : clients) {
			if (client.getClientId().startsWith("legacy_")) {
				continue;
			}
			Set<String> registeredRedirectUri = client.getRegisteredRedirectUri();
			if (registeredRedirectUri == null || registeredRedirectUri.isEmpty()) {
				continue;
			}
			Set<String> uris = new HashSet<String>(registeredRedirectUri);
			for (String uri : registeredRedirectUri) {
				if (uri.matches("^http://[^/]*\\." + domain + ".*")) {
					uris.add("https" + uri.substring("http".length()));
				}
			}
			if (uris.size() == registeredRedirectUri.size()) {
				continue;
			}
			BaseClientDetails newClient = new BaseClientDetails(client);
			newClient.setRegisteredRedirectUri(uris);
			logger.info("Adding https callback: " + newClient);
			clientRegistrationService.updateClientDetails(newClient);
		}
	}

	/**
	 * Convert legacy clients to best guess for new scopes and authorities.
	 */
	private void convertLegacyClients() {

		List<ClientDetails> clients = clientRegistrationService.listClientDetails();

		for (ClientDetails client : clients) {
			if (client.getClientId().startsWith("legacy_")) {
				continue;
			}
			if (!client.getAuthorities().toString().contains("ROLE_")) {
				logger.info("Already converted: " + client);
				continue;
			}
			logger.info("Converting: " + client);
			try {
				BaseClientDetails legacyClient = new BaseClientDetails(client);
				legacyClient.setClientId("legacy_" + client.getClientId());
				if (!clients.contains(legacyClient)) {
					clientRegistrationService.addClientDetails(legacyClient);
				}
			}
			catch (ClientAlreadyExistsException e) {
				// Should not happen
				logger.error("Error creating legacy copy of: " + client);
			}

			BaseClientDetails newClient = new BaseClientDetails(client);
			newClient.setResourceIds(Collections.singleton("none"));
			Set<String> userScopes = getUserScopes(client);
			// Use sorted set to make testing easier
			Set<String> clientScopes = new TreeSet<String>(getClientScopes(client));
			if (client.getAuthorizedGrantTypes().equals(Collections.singleton("client_credentials"))) {
				userScopes = Collections.singleton("uaa.none");
				clientScopes.addAll(getUserScopes(client));
			}
			newClient.setScope(userScopes);
			newClient.setAuthorities(AuthorityUtils.createAuthorityList(clientScopes.toArray(new String[clientScopes
					.size()])));
			Integer validity = newClient.getAccessTokenValiditySeconds();
			if (validity != null && validity == 0) {
				newClient.setAccessTokenValiditySeconds(null);
			}
			validity = newClient.getRefreshTokenValiditySeconds();
			if (validity != null && validity == 0) {
				newClient.setRefreshTokenValiditySeconds(null);
			}
			logger.info("Converted: " + newClient);
			clientRegistrationService.updateClientDetails(newClient);

		}

	}

	private Set<String> getUserScopes(ClientDetails client) {
		Set<String> result = new TreeSet<String>();
		Set<String> resourceIds = client.getResourceIds();
		Set<String> scopes = client.getScope();
		for (String scope : scopes) {
			if (scope.equals("openid")) {
				result.add(scope);
			}
			else if (scope.equals("password")) {
				if (resourceIds.contains("password")) {
					result.add("password.write");
				}
				if (resourceIds.contains("clients")) {
					result.add("clients.secret");
				}
			}
			else {
				for (String resource : resourceIds) {
					String value = resource + "." + scope;
					if (validScopes.contains(value)) {
						result.add(value);
					}
				}
			}
		}
		if (result.isEmpty()) {
			// Safety measure, just to prevent errors (empty means all scopes are allowed)
			result.add("uaa.none");
		}
		return result;
	}

	private Set<String> getClientScopes(ClientDetails client) {
		Set<String> result = new TreeSet<String>();
		Set<String> authorities = AuthorityUtils.authorityListToSet(client.getAuthorities());
		for (String authority : authorities) {
			if (authoritiesToScopes.containsKey(authority)) {
				result.add(authoritiesToScopes.get(authority));
			}
		}
		if (result.isEmpty()) {
			// Safety measure, just to prevent errors (empty means all scopes are allowed)
			result.add("uaa.none");
		}
		return result;
	}

	private void addNewClients() throws Exception {
		for (String clientId : clients.keySet()) {
			Map<String, Object> map = clients.get(clientId);
			BaseClientDetails client = new BaseClientDetails(clientId, (String) map.get("resource-ids"),
					(String) map.get("scope"), (String) map.get("authorized-grant-types"),
					(String) map.get("authorities"), (String) map.get("redirect-uri"));
			client.setClientSecret((String) map.get("secret"));
			Integer validity = (Integer) map.get("access-token-validity");
			if (validity != null) {
				client.setAccessTokenValiditySeconds(validity);
			}
			validity = (Integer) map.get("refresh-token-validity");
			if (validity != null) {
				client.setRefreshTokenValiditySeconds(validity);
			}
			try {
				clientRegistrationService.addClientDetails(client);
			}
			catch (ClientAlreadyExistsException e) {
				if (override) {
					logger.info("Overriding client details for " + clientId);
					clientRegistrationService.updateClientDetails(client);
					clientRegistrationService.updateClientSecret(clientId, client.getClientSecret());
					return;
				}
				// ignore it
				logger.debug(e.getMessage());
			}
		}
	}
}
