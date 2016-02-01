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

import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProvider;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;

public class ServiceProviderEventPublisher implements ApplicationEventPublisherAware {
    private ApplicationEventPublisher publisher;

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.publisher = applicationEventPublisher;
    }

    public void spCreated(SamlServiceProvider serviceProvider) {
        publish(ServiceProviderModifiedEvent.serviceProviderCreated(serviceProvider));
    }

    public void spModified(SamlServiceProvider serviceProvider) {
        publish(ServiceProviderModifiedEvent.serviceProviderModified(serviceProvider));
    }

    public void publish(ApplicationEvent event) {
        if (publisher!=null) {
            publisher.publishEvent(event);
        }
    }
}