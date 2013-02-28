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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.util.StringUtils;

/**
 * @author Dave Syer
 *
 */
public class ClientAdminBootstrap implements InitializingBean {

	private static Log logger = LogFactory.getLog(ClientAdminBootstrap.class);

	private Map<String, Map<String, Object>> clients = new HashMap<String, Map<String, Object>>();

	private Collection<String> autoApproveClients = Collections.emptySet();

	private ClientRegistrationService clientRegistrationService;

	private String domain = "cloudfoundry\\.com";

	private boolean defaultOverride = true;

	/**
	 * Flag to indicate that client details should override existing values by default. If true and the override flag is
	 * not set in the client details input then the details will override any existing details with the same id.
	 *
	 * @param defaultOverride the default override flag to set (default true, so flag does not have to be provided
	 * explicitly)
	 */
	public void setDefaultOverride(boolean defaultOverride) {
		this.defaultOverride = defaultOverride;
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
	 * @param clients the clients to set
	 */
	public void setClients(Map<String, Map<String, Object>> clients) {
		this.clients = clients == null ? Collections.<String, Map<String, Object>> emptyMap()
				: new HashMap<String, Map<String, Object>>(clients);
	}

	/**
	 * A set of client ids that are unconditionally to be autoapproved (independent of the settings in the client
	 * details map). These clients will have <code>autoapprove=true</code> when they are inserted into the client
	 * details store.
	 *
	 * @param autoApproveClients the auto approve clients
	 */
	public void setAutoApproveClients(Collection<String> autoApproveClients) {
		this.autoApproveClients = autoApproveClients;
	}

	/**
	 * @param clientRegistrationService the clientRegistrationService to set
	 */
	public void setClientRegistrationService(ClientRegistrationService clientRegistrationService) {
		this.clientRegistrationService = clientRegistrationService;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		addHttpsCallbacks();
		addNewClients();
		updateAutoApprovClients();
	}

	/**
	 * Explicitly override autoapprove in all clients that were provided in the whitelist.
	 */
	private void updateAutoApprovClients() {

		List<ClientDetails> clients = clientRegistrationService.listClientDetails();

		for (ClientDetails client : clients) {
			if (!autoApproveClients.contains(client.getClientId())) {
				continue;
			}
			BaseClientDetails base = new BaseClientDetails(client);
			Map<String, Object> info = new HashMap<String, Object>(client.getAdditionalInformation());
			info.put("autoapprove", true);
			base.setAdditionalInformation(info);
			logger.info("Adding autoapprove flag: " + base);
			clientRegistrationService.updateClientDetails(base);
		}

	}

	/**
	 * Make sure all cloudfoundry.com callbacks are https
	 */
	private void addHttpsCallbacks() {
		List<ClientDetails> clients = clientRegistrationService.listClientDetails();

		for (ClientDetails client : clients) {
			Set<String> registeredRedirectUri = client.getRegisteredRedirectUri();
			if (registeredRedirectUri == null || registeredRedirectUri.isEmpty()) {
				continue;
			}
			Set<String> uris = new HashSet<String>(registeredRedirectUri);
			boolean newItems = false;
			for (String uri : registeredRedirectUri) {
				if (uri.matches("^http://[^/]*\\." + domain + ".*")) {
					newItems = true;
					uris.remove(uri);
					uris.add("https" + uri.substring("http".length()));
				}
			}
			if (!newItems) {
				continue;
			}
			BaseClientDetails newClient = new BaseClientDetails(client);
			newClient.setRegisteredRedirectUri(uris);
			logger.info("Adding https callback: " + newClient);
			clientRegistrationService.updateClientDetails(newClient);
		}
	}

	private void addNewClients() throws Exception {
		for (String clientId : clients.keySet()) {
			Map<String, Object> map = clients.get(clientId);
			BaseClientDetails client = new BaseClientDetails(clientId, (String) map.get("resource-ids"),
					(String) map.get("scope"), (String) map.get("authorized-grant-types"),
					(String) map.get("authorities"), (String) map.get("redirect-uri"));
			client.setClientSecret((String) map.get("secret"));
			Integer validity = (Integer) map.get("access-token-validity");
			Boolean override = (Boolean) map.get("override");
			if (override == null) {
				override = defaultOverride;
			}
			Map<String, Object> info = new HashMap<String, Object>(map);
			if (validity != null) {
				client.setAccessTokenValiditySeconds(validity);
			}
			validity = (Integer) map.get("refresh-token-validity");
			if (validity != null) {
				client.setRefreshTokenValiditySeconds(validity);
			}
			// UAA does not use the resource ids in client registrations
			client.setResourceIds(Collections.singleton("none"));
			if (client.getScope().isEmpty()) {
				client.setScope(Collections.singleton("uaa.none"));
			}
			if (client.getAuthorities().isEmpty()) {
				client.setAuthorities(Collections.singleton(UaaAuthority.UAA_NONE));
			}
			if (client.getAuthorizedGrantTypes().contains("authorization_code")) {
				client.getAuthorizedGrantTypes().add("refresh_token");
			}
			for (String key : Arrays.asList("resource-ids", "scope", "authorized-grant-types", "authorities",
					"redirect-uri", "secret", "id", "override", "access-token-validity", "refresh-token-validity")) {
				info.remove(key);
			}
			client.setAdditionalInformation(info);
			try {
				clientRegistrationService.addClientDetails(client);
			}
			catch (ClientAlreadyExistsException e) {
				if (override == null || override) {
					logger.info("Overriding client details for " + clientId);
					clientRegistrationService.updateClientDetails(client);
					if (StringUtils.hasText(client.getClientSecret())) {
						clientRegistrationService.updateClientSecret(clientId, client.getClientSecret());
					}
				} else {
					// ignore it
					logger.debug(e.getMessage());
				}
			}
		}
	}
}
