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

package org.cloudfoundry.identity.uaa.oauth.event;

import java.security.Principal;

import org.aspectj.lang.ProceedingJoinPoint;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;

/**
 * Event publisher for client registration changes with the resulting event type varying according to the input and
 * outcome. Can be used as an aspect intercepting calls to a component that changes client details.
 * 
 * @author Dave Syer
 * 
 */
public class ClientAdminEventPublisher implements ApplicationEventPublisherAware {

	private ClientDetailsService clientDetailsService;

	private ApplicationEventPublisher publisher;

	/**
	 * @param clientDetailsService the clientDetailsService to set
	 */
	public ClientAdminEventPublisher(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher publisher) {
		this.publisher = publisher;
	}
	
	public void create(ClientDetails client) {
		publish(new ClientCreateEvent(client, getPrincipal()));		
	}
	
	public void update(ClientDetails client) {
		publish(new ClientUpdateEvent(client, getPrincipal()));
	}

	public ClientDetails delete(ProceedingJoinPoint jp, String clientId) throws Throwable {
		ClientDetails client = (ClientDetails) jp.proceed();
		publish(new ClientDeleteEvent(client, getPrincipal()));
		return client;
	}

	public void secretFailure(String clientId, Exception e) {
		ClientDetails client = getClient(clientId);
		if (client == null) {
			publish(new SecretFailureEvent(e.getMessage(), client, getPrincipal()));
		}
		else {
			publish(new SecretFailureEvent(e.getMessage(), getPrincipal()));
		}
	}

	public void secretChange(String clientId) {
		publish(new SecretChangeEvent(getClient(clientId), getPrincipal()));
	}

	private ClientDetails getClient(String clientId) {
		try {
			return clientDetailsService.loadClientByClientId(clientId);
		}
		catch (InvalidClientException e) {
			return null;
		}
	}

	private Principal getPrincipal() {
		return SecurityContextHolder.getContext().getAuthentication();
	}

	private void publish(AbstractUaaEvent event) {
		if (publisher != null) {
			publisher.publishEvent(event);
		}
	}

}
