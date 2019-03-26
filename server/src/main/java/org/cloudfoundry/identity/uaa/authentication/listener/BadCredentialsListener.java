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
package org.cloudfoundry.identity.uaa.authentication.listener;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.event.PrincipalAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.PrincipalNotFoundEvent;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Spring {@code ApplicationListener} which picks up the listens for Spring
 * Security events and relays them.
 *
 * @author Dave Syer
 */
public class BadCredentialsListener implements ApplicationListener<AuthenticationFailureBadCredentialsEvent>,
                ApplicationEventPublisherAware {

    private ApplicationEventPublisher publisher;

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher publisher) {
        this.publisher = publisher;
    }

    @Override
    public void onApplicationEvent(AuthenticationFailureBadCredentialsEvent event) {
        AuthenticationFailureBadCredentialsEvent bce = event;
        String principal = bce.getAuthentication().getName();
        UaaAuthenticationDetails details = (UaaAuthenticationDetails) bce.getAuthentication().getDetails();
        if (bce.getException() instanceof UsernameNotFoundException) {
            publisher.publishEvent(new PrincipalNotFoundEvent(principal, details, IdentityZoneHolder.getCurrentZoneId()));
        }
        else {
            publisher.publishEvent(new PrincipalAuthenticationFailureEvent(principal, details, IdentityZoneHolder.getCurrentZoneId()));
        }
    }

}
