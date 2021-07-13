package org.cloudfoundry.identity.uaa.zone.event;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.stereotype.Component;

@Component("identityZoneEventPublisher")
public class IdentityZoneEventPublisher implements ApplicationEventPublisherAware {
    private ApplicationEventPublisher publisher;

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.publisher = applicationEventPublisher;
    }

    public void identityZoneCreated(IdentityZone identityZone) {
        publish(IdentityZoneModifiedEvent.identityZoneCreated(identityZone));
    }

    public void identityZoneModified(IdentityZone identityZone) {
        publish(IdentityZoneModifiedEvent.identityZoneModified(identityZone));
    }

    public void publish(ApplicationEvent event) {
        if (publisher != null) {
            publisher.publishEvent(event);
        }
    }
}