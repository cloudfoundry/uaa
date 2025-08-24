package org.cloudfoundry.identity.uaa.client.event;

import org.aspectj.lang.ProceedingJoinPoint;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;

/**
 * Event publisher for client registration changes with the resulting event type
 * varying according to the input and outcome. Can be used as an aspect intercepting
 * calls to a component that changes client details.
 */
public class ClientAdminEventPublisher implements ApplicationEventPublisherAware {

    private final MultitenantClientServices clientDetailsService;
    private final IdentityZoneManager identityZoneManager;

    private ApplicationEventPublisher publisher;

    public ClientAdminEventPublisher(
            final MultitenantClientServices clientDetailsService,
            final IdentityZoneManager identityZoneManager) {
        this.clientDetailsService = clientDetailsService;
        this.identityZoneManager = identityZoneManager;
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher publisher) {
        this.publisher = publisher;
    }

    public ApplicationEventPublisher getPublisher() {
        return publisher;
    }

    public void create(ClientDetails client) {
        publish(new ClientCreateEvent(client, getPrincipal(), identityZoneManager.getCurrentIdentityZoneId()));
    }

    public void createTx(ClientDetails[] clients) {
        for (ClientDetails client : clients) {
            publish(new ClientCreateEvent(client, getPrincipal(), identityZoneManager.getCurrentIdentityZoneId()));
        }
    }

    public void update(ClientDetails client) {
        publish(new ClientUpdateEvent(client, getPrincipal(), identityZoneManager.getCurrentIdentityZoneId()));
    }

    public void updateTx(ClientDetails[] clients) {
        for (ClientDetails client : clients) {
            publish(new ClientUpdateEvent(client, getPrincipal(), identityZoneManager.getCurrentIdentityZoneId()));
        }
    }

    public ClientDetails delete(ProceedingJoinPoint jp, String clientId) throws Throwable {
        ClientDetails client = (ClientDetails) jp.proceed();
        publish(new ClientDeleteEvent(client, getPrincipal(), identityZoneManager.getCurrentIdentityZoneId()));
        return client;
    }

    public void deleteTx(ClientDetails[] clients) {
        for (ClientDetails client : clients) {
            publish(new ClientDeleteEvent(client, getPrincipal(), identityZoneManager.getCurrentIdentityZoneId()));
        }
    }

    public void modifyTx(ClientDetailsModification[] clients) {
        for (ClientDetailsModification client : clients) {
            if (ClientDetailsModification.ADD.equals(client.getAction())) {
                publish(new ClientCreateEvent(client, getPrincipal(), identityZoneManager.getCurrentIdentityZoneId()));
            } else if (ClientDetailsModification.UPDATE.equals(client.getAction())) {
                publish(new ClientUpdateEvent(client, getPrincipal(), identityZoneManager.getCurrentIdentityZoneId()));
            } else if (ClientDetailsModification.DELETE.equals(client.getAction())) {
                publish(new ClientDeleteEvent(client, getPrincipal(), identityZoneManager.getCurrentIdentityZoneId()));
            } else if (ClientDetailsModification.UPDATE_SECRET.equals(client.getAction())) {
                publish(new ClientUpdateEvent(client, getPrincipal(), identityZoneManager.getCurrentIdentityZoneId()));
                if (client.isApprovalsDeleted()) {
                    publish(new SecretChangeEvent(client, getPrincipal(), identityZoneManager.getCurrentIdentityZoneId()));
                    publish(new ClientApprovalsDeletedEvent(client, getPrincipal(), identityZoneManager.getCurrentIdentityZoneId()));
                }
            } else if (ClientDetailsModification.SECRET.equals(client.getAction())) {
                if (client.isApprovalsDeleted()) {
                    publish(new SecretChangeEvent(client, getPrincipal(), identityZoneManager.getCurrentIdentityZoneId()));
                    publish(new ClientApprovalsDeletedEvent(client, getPrincipal(), identityZoneManager.getCurrentIdentityZoneId()));
                }
            }
        }
    }

    public void secretTx(ClientDetailsModification[] clients) {
        for (ClientDetailsModification client : clients) {
            publish(new ClientDeleteEvent(client, getPrincipal(), identityZoneManager.getCurrentIdentityZoneId()));
            if (client.isApprovalsDeleted()) {
                publish(new ClientApprovalsDeletedEvent(client, getPrincipal(), identityZoneManager.getCurrentIdentityZoneId()));
            }
        }
    }

    public void secretFailure(String clientId, Exception e) {
        publish(new SecretFailureEvent(e.getMessage(), getClient(clientId), getPrincipal(), identityZoneManager.getCurrentIdentityZoneId()));
    }

    public void secretChange(String clientId) {
        publish(new SecretChangeEvent(getClient(clientId), getPrincipal(), identityZoneManager.getCurrentIdentityZoneId()));
    }

    public void clientJwtFailure(String clientId, Exception e) {
        publish(new ClientJwtFailureEvent(e.getMessage(), getClient(clientId), getPrincipal(), identityZoneManager.getCurrentIdentityZoneId()));
    }

    public void clientJwtChange(String clientId) {
        publish(new ClientJwtChangeEvent(getClient(clientId), getPrincipal(), identityZoneManager.getCurrentIdentityZoneId()));
    }

    private ClientDetails getClient(String clientId) {
        try {
            return clientDetailsService.loadClientByClientId(clientId, identityZoneManager.getCurrentIdentityZoneId());
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
