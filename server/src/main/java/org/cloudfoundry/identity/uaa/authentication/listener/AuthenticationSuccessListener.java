/*
 *  Cloud Foundry
 *  Copyright (c) [2009-2018] Pivotal Software, Inc. All Rights Reserved.
 *  <p/>
 *  This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *  You may not use this product except in compliance with the License.
 *  <p/>
 *  This product includes a number of subcomponents with
 *  separate copyright notices and license terms. Your use of these
 *  subcomponents is subject to the terms and conditions of the
 *  subcomponent's license, as noted in the LICENSE file
 */

package org.cloudfoundry.identity.uaa.authentication.listener;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.event.AbstractUaaAuthenticationEvent;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.user.UaaUser;

import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.ApplicationListener;
import org.springframework.security.core.Authentication;

public class AuthenticationSuccessListener implements ApplicationListener<AbstractUaaAuthenticationEvent>, ApplicationEventPublisherAware {

    private final ScimUserProvisioning scimUserProvisioning;
    private ApplicationEventPublisher publisher;

    public AuthenticationSuccessListener(ScimUserProvisioning scimUserProvisioning) {
        this.scimUserProvisioning = scimUserProvisioning;
    }

    @Override
    public void onApplicationEvent(AbstractUaaAuthenticationEvent event) {
        if (event instanceof UserAuthenticationSuccessEvent successEvent) {
            onApplicationEvent(successEvent, event.getIdentityZoneId());
        } else if (event instanceof IdentityProviderAuthenticationSuccessEvent passwordAuthEvent) {
            UserAuthenticationSuccessEvent userEvent = new UserAuthenticationSuccessEvent(
                    passwordAuthEvent.getUser(),
                    (Authentication) passwordAuthEvent.getSource(), IdentityZoneHolder.getCurrentZoneId()
            );
            publisher.publishEvent(userEvent);
        }
    }

    protected void onApplicationEvent(UserAuthenticationSuccessEvent event, String zoneId) {
        UaaUser user = event.getUser();
        if (user.isLegacyVerificationBehavior() && !user.isVerified()) {
            scimUserProvisioning.verifyUser(user.getId(), -1, zoneId);
        }
        UaaAuthentication authentication = (UaaAuthentication) event.getAuthentication();
        authentication.setLastLoginSuccessTime(user.getLastLogonTime());
        scimUserProvisioning.updateLastLogonTime(user.getId(), zoneId);
    }


    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.publisher = applicationEventPublisher;
    }

    public void publish(ApplicationEvent event) {
        if (publisher != null) {
            publisher.publishEvent(event);
        }
    }
}
