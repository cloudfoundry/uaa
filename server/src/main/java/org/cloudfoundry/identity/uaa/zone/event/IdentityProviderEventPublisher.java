/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.zone.event;

import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;

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
        if (publisher!=null) {
            publisher.publishEvent(event);
        }
    }
}
