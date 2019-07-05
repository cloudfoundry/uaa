package org.cloudfoundry.identity.uaa.client.event;

import org.aspectj.lang.ProceedingJoinPoint;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.provider.ClientDetails;

/**
 * Event publisher for client registration changes with the resulting event type
 * varying according to the input and outcome. Can be used as an aspect intercepting
 * calls to a component that changes client details.
 */
public class ClientAdminEventPublisher implements ApplicationEventPublisherAware {

    private final MultitenantClientServices clientDetailsService;

    private ApplicationEventPublisher publisher;

    public ClientAdminEventPublisher(final MultitenantClientServices clientDetailsService) {
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
        publish(new ClientCreateEvent(client, getPrincipal(), IdentityZoneHolder.getCurrentZoneId()));
    }

    public void createTx(ClientDetails[] clients) {
        for (ClientDetails client : clients) {
            publish(new ClientCreateEvent(client, getPrincipal(), IdentityZoneHolder.getCurrentZoneId()));
        }
    }

    public void update(ClientDetails client) {
        publish(new ClientUpdateEvent(client, getPrincipal(), IdentityZoneHolder.getCurrentZoneId()));
    }

    public void updateTx(ClientDetails[] clients) {
        for (ClientDetails client : clients) {
            publish(new ClientUpdateEvent(client, getPrincipal(), IdentityZoneHolder.getCurrentZoneId()));
        }
    }

    public ClientDetails delete(ProceedingJoinPoint jp, String clientId) throws Throwable {
        ClientDetails client = (ClientDetails) jp.proceed();
        publish(new ClientDeleteEvent(client, getPrincipal(), IdentityZoneHolder.getCurrentZoneId()));
        return client;
    }

    public void deleteTx(ClientDetails[] clients) {
        for (ClientDetails client : clients) {
            publish(new ClientDeleteEvent(client, getPrincipal(), IdentityZoneHolder.getCurrentZoneId()));
        }
    }

    public void modifyTx(ClientDetailsModification[] clients) {
        for (ClientDetailsModification client : clients) {
            if (ClientDetailsModification.ADD.equals(client.getAction())) {
                publish(new ClientCreateEvent(client, getPrincipal(), IdentityZoneHolder.getCurrentZoneId()));
            } else if (ClientDetailsModification.UPDATE.equals(client.getAction())) {
                publish(new ClientUpdateEvent(client, getPrincipal(), IdentityZoneHolder.getCurrentZoneId()));
            } else if (ClientDetailsModification.DELETE.equals(client.getAction())) {
                publish(new ClientDeleteEvent(client, getPrincipal(), IdentityZoneHolder.getCurrentZoneId()));
            } else if (ClientDetailsModification.UPDATE_SECRET.equals(client.getAction())) {
                publish(new ClientUpdateEvent(client, getPrincipal(), IdentityZoneHolder.getCurrentZoneId()));
                if (client.isApprovalsDeleted()) {
                    publish(new SecretChangeEvent(client, getPrincipal(), IdentityZoneHolder.getCurrentZoneId()));
                    publish(new ClientApprovalsDeletedEvent(client, getPrincipal(), IdentityZoneHolder.getCurrentZoneId()));
                }
            } else if (ClientDetailsModification.SECRET.equals(client.getAction())) {
                if (client.isApprovalsDeleted()) {
                    publish(new SecretChangeEvent(client, getPrincipal(), IdentityZoneHolder.getCurrentZoneId()));
                    publish(new ClientApprovalsDeletedEvent(client, getPrincipal(), IdentityZoneHolder.getCurrentZoneId()));
                }
            }
        }
    }

    public void secretTx(ClientDetailsModification[] clients) {
        for (ClientDetailsModification client : clients) {
            publish(new ClientDeleteEvent(client, getPrincipal(), IdentityZoneHolder.getCurrentZoneId()));
            if (client.isApprovalsDeleted()) {
                publish(new ClientApprovalsDeletedEvent(client, getPrincipal(), IdentityZoneHolder.getCurrentZoneId()));
            }
        }
    }

    public void secretFailure(String clientId, Exception e) {
        publish(new SecretFailureEvent(e.getMessage(), getClient(clientId), getPrincipal(), IdentityZoneHolder.getCurrentZoneId()));
    }

    public void secretChange(String clientId) {
        publish(new SecretChangeEvent(getClient(clientId), getPrincipal(), IdentityZoneHolder.getCurrentZoneId()));
    }

    private ClientDetails getClient(String clientId) {
        try {
            return clientDetailsService.loadClientByClientId(clientId, IdentityZoneHolder.get().getId());
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
