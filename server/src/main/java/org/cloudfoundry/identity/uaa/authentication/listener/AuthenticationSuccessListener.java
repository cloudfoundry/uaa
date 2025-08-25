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
import org.cloudfoundry.identity.uaa.authentication.event.MfaAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.mfa.MfaChecker;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;

import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.ApplicationListener;
import org.springframework.security.core.Authentication;

public class AuthenticationSuccessListener implements ApplicationListener<AbstractUaaAuthenticationEvent>, ApplicationEventPublisherAware {

    private final static Logger logger = LoggerFactory.getLogger(AuthenticationSuccessListener.class);

    private final ScimUserProvisioning scimUserProvisioning;
    private final UaaUserDatabase userDatabase;
    private final MfaChecker checker;
    private final UserAttributeChangeEventPublisher userAttributeChangeEventPublisher;
    private ApplicationEventPublisher publisher;

    public AuthenticationSuccessListener(ScimUserProvisioning scimUserProvisioning,
                                         UaaUserDatabase userDatabase,
                                         MfaChecker checker,
                                         UserAttributeChangeEventPublisher userAttributeChangeEventPublisher) {
        this.scimUserProvisioning = scimUserProvisioning;
        this.userDatabase = userDatabase;
        this.checker = checker;
        this.userAttributeChangeEventPublisher = userAttributeChangeEventPublisher;
    }

    @Override
    public void onApplicationEvent(AbstractUaaAuthenticationEvent event) {
        if (event instanceof UserAuthenticationSuccessEvent) {
            onApplicationEvent((UserAuthenticationSuccessEvent) event, event.getIdentityZoneId());
        } else if (event instanceof IdentityProviderAuthenticationSuccessEvent) {
            IdentityProviderAuthenticationSuccessEvent passwordAuthEvent = (IdentityProviderAuthenticationSuccessEvent) event;
            UserAuthenticationSuccessEvent userEvent = new UserAuthenticationSuccessEvent(
                passwordAuthEvent.getUser(),
                (Authentication) passwordAuthEvent.getSource(), IdentityZoneHolder.getCurrentZoneId()
            );
            if (!checker.isMfaEnabledForZoneId(userEvent.getIdentityZoneId())) {
                publisher.publishEvent(userEvent);
            }
        } else if (event instanceof MfaAuthenticationSuccessEvent) {
            MfaAuthenticationSuccessEvent mfaEvent = (MfaAuthenticationSuccessEvent) event;
            UserAuthenticationSuccessEvent userEvent = new UserAuthenticationSuccessEvent(
                mfaEvent.getUser(),
                (Authentication) mfaEvent.getSource(), IdentityZoneHolder.getCurrentZoneId()
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
        
        // Use previousUser from the user object if available (set by SAML flow when attributes changed)
        // This captures the state before SAML attribute modifications
        UaaUser userBeforeLastLogonUpdate = user.getPreviousUser();
        if (userBeforeLastLogonUpdate == null) {
            // For non-SAML flows or when no SAML attributes changed, use current user state
            userBeforeLastLogonUpdate = user;
        }
        
        scimUserProvisioning.updateLastLogonTime(user.getId(), zoneId);
        UaaUser userAfterLastLogonUpdate = userDatabase.retrieveUserById(user.getId());
    
        if (userAfterLastLogonUpdate != null) {
            // Now this will capture BOTH SAML attribute changes AND lastLogonTime change in a single event
            userAttributeChangeEventPublisher.publishUserAttributeChangeEventAsync(this, userBeforeLastLogonUpdate, userAfterLastLogonUpdate);
        }
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
