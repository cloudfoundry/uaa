/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

package org.cloudfoundry.identity.uaa.client.event;

import org.aspectj.lang.ProceedingJoinPoint;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;

/**
 * Event publisher for client registration changes with the resulting event type
 * varying according to the input and
 * outcome. Can be used as an aspect intercepting calls to a component that
 * changes client details.
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

    public ApplicationEventPublisher getPublisher() {
        return publisher;
    }

    public void create(ClientDetails client) {
        publish(new ClientCreateEvent(client, getPrincipal()));
    }

    public void createTx(ClientDetails[] clients) {
        for (ClientDetails client : clients) {
            publish(new ClientCreateEvent(client, getPrincipal()));
        }
    }

    public void update(ClientDetails client) {
        publish(new ClientUpdateEvent(client, getPrincipal()));
    }

    public void updateTx(ClientDetails[] clients) {
        for (ClientDetails client:clients) {
            publish(new ClientUpdateEvent(client, getPrincipal()));
        }
    }

    public ClientDetails delete(ProceedingJoinPoint jp, String clientId) throws Throwable {
        ClientDetails client = (ClientDetails) jp.proceed();
        publish(new ClientDeleteEvent(client, getPrincipal()));
        return client;
    }

    public void deleteTx(ClientDetails[] clients) {
        for (ClientDetails client:clients) {
            publish(new ClientDeleteEvent(client, getPrincipal()));
        }
    }

    public void modifyTx(ClientDetailsModification[] clients) {
        for (ClientDetailsModification client:clients) {
            if (ClientDetailsModification.ADD.equals(client.getAction())) {
                publish(new ClientCreateEvent(client, getPrincipal()));
            } else if (ClientDetailsModification.UPDATE.equals(client.getAction())) {
                publish(new ClientUpdateEvent(client, getPrincipal()));
            } else if (ClientDetailsModification.DELETE.equals(client.getAction())) {
                publish(new ClientDeleteEvent(client, getPrincipal()));
            } else if (ClientDetailsModification.UPDATE_SECRET.equals(client.getAction())) {
                publish(new ClientUpdateEvent(client, getPrincipal()));
                if (client.isApprovalsDeleted()) {
                    publish(new SecretChangeEvent(client, getPrincipal()));
                    publish(new ClientApprovalsDeletedEvent(client, getPrincipal()));
                }
            } else if (ClientDetailsModification.SECRET.equals(client.getAction())) {
                if (client.isApprovalsDeleted()) {
                    publish(new SecretChangeEvent(client, getPrincipal()));
                    publish(new ClientApprovalsDeletedEvent(client, getPrincipal()));
                }
            }
        }
    }

    public void secretTx(ClientDetailsModification[] clients) {
        for (ClientDetailsModification client:clients) {
            publish(new ClientDeleteEvent(client, getPrincipal()));
            if (client.isApprovalsDeleted()) {
                publish(new ClientApprovalsDeletedEvent(client, getPrincipal()));
            }
        }
    }

    public void secretFailure(String clientId, Exception e) {
        publish(new SecretFailureEvent(e.getMessage(), getClient(clientId), getPrincipal()));
    }

    public void secretChange(String clientId) {
        publish(new SecretChangeEvent(getClient(clientId), getPrincipal()));
    }

    private ClientDetails getClient(String clientId) {
        try {
            return clientDetailsService.loadClientByClientId(clientId);
        } catch (InvalidClientException e) {
            return null;
        }
    }

    private Authentication getPrincipal() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    private void publish(AbstractUaaEvent event) {
        if (publisher != null) {
            publisher.publishEvent(event);
        }
    }

}
