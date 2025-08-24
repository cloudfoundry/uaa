package org.cloudfoundry.identity.uaa.zone.event;

import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.stereotype.Component;

@Component("idpEventPublisher")
public class IdentityProviderEventPublisher implements ApplicationEventPublisherAware {

    private final IdentityZoneManager identityZoneManager;

    private ApplicationEventPublisher publisher;

    public IdentityProviderEventPublisher(final IdentityZoneManager identityZoneManager) {
        this.identityZoneManager = identityZoneManager;
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.publisher = applicationEventPublisher;
    }

    public void idpCreated(IdentityProvider identityProvider) {
        publish(IdentityProviderModifiedEvent.identityProviderCreated(identityProvider, identityZoneManager.getCurrentIdentityZoneId()));
    }

    public void idpModified(IdentityProvider identityProvider) {
        publish(IdentityProviderModifiedEvent.identityProviderModified(identityProvider, identityZoneManager.getCurrentIdentityZoneId()));
    }

    public void publish(ApplicationEvent event) {
        if (publisher != null) {
            publisher.publishEvent(event);
        }
    }
}
