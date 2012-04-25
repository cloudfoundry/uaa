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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientRegistrationService;

/**
 * @author Dave Syer
 * 
 */
public class ClientAdminBootstrap implements InitializingBean {

	private static Log logger = LogFactory.getLog(ClientAdminBootstrap.class);

	private Map<String, Map<String, Object>> clients = new HashMap<String, Map<String, Object>>();

	private ClientRegistrationService clientRegistrationService;

	private Set<String> clientsToOverride = Collections.emptySet();

	private boolean override = false;
	
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
	 * A set of client ids to attempt an update if they already exist (overriding changes made online)
	 * 
	 * @param clientsToOverride the clients to override to set
	 */
	public void setClientsToOverride(Set<String> clientsToOverride) {
		this.clientsToOverride = clientsToOverride;
	}

	/**
	 * @param clientRegistrationService the clientRegistrationService to set
	 */
	public void setClientRegistrationService(ClientRegistrationService clientRegistrationService) {
		this.clientRegistrationService = clientRegistrationService;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		for (String clientId : clients.keySet()) {
			Map<String, Object> map = clients.get(clientId);
			BaseClientDetails client = new BaseClientDetails((String) map.get("resource-ids"),
					(String) map.get("scope"), (String) map.get("authorized-grant-types"),
					(String) map.get("authorities"), (String) map.get("redirect-uri"));
			client.setClientId(clientId);
			client.setClientSecret((String) map.get("secret"));
			Integer validity = (Integer) map.get("access-token-validity");
			if (validity != null) {
				client.setAccessTokenValiditySeconds(validity);
			}
			try {
				clientRegistrationService.addClientDetails(client);
			}
			catch (ClientAlreadyExistsException e) {
				if (clientsToOverride.contains(clientId)) {
					if (override) {
						logger.info("Overriding client details for " + clientId);
						clientRegistrationService.updateClientDetails(client);
						return;
					}
				}
				// ignore it
				logger.debug(e.getMessage());
			}
		}
	}
}
