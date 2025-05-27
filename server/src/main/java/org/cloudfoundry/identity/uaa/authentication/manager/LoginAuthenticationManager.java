/*
 * *****************************************************************************
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
package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Map;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.NotANumber;

@Component
public class LoginAuthenticationManager implements AuthenticationManager, ApplicationEventPublisherAware {
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final IdentityZoneManager identityZoneManager;
    private final UaaUserDatabase userDatabase;

    private ApplicationEventPublisher eventPublisher;

    public LoginAuthenticationManager(IdentityZoneManager identityZoneManager, UaaUserDatabase userDatabase) {
        this.identityZoneManager = identityZoneManager;
        this.userDatabase = userDatabase;
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    @Override
    public Authentication authenticate(Authentication request) throws AuthenticationException {

        if (!(request instanceof AuthzAuthenticationRequest)) {
            logger.debug("Cannot process request of type: {}", request.getClass().getName());
            return null;
        }

        AuthzAuthenticationRequest req = (AuthzAuthenticationRequest) request;
        Map<String, String> info = req.getInfo();
        logger.debug("Processing authentication request for {}", req.getName());

        SecurityContext context = SecurityContextHolder.getContext();

        if (context.getAuthentication() instanceof OAuth2Authentication authentication && authentication.isClientOnly()) {
            UaaUser user = getUser(req, info);
            UaaAuthenticationDetails authdetails = (UaaAuthenticationDetails) req.getDetails();
            boolean addNewAccounts = authdetails != null && authdetails.isAddNew();
            try {
                if (NotANumber.equals(user.getId())) {
                    user = userDatabase.retrieveUserByName(user.getUsername(), user.getOrigin());
                } else {
                    //we should never add new accounts if we specify user_id
                    addNewAccounts = false;
                    user = userDatabase.retrieveUserById(user.getId());
                }
            } catch (UsernameNotFoundException e) {
                // Not necessarily fatal
                if (addNewAccounts) {
                    // Register new users automatically
                    publish(new NewUserAuthenticatedEvent(user));
                    try {
                        user = userDatabase.retrieveUserByName(user.getUsername(), user.getOrigin());
                    } catch (UsernameNotFoundException ex) {
                        throw new BadCredentialsException("Bad credentials");
                    }
                } else {
                    //if add_new=false then this is a bad user ID
                    throw new BadCredentialsException("Bad Credentials");
                }
            }
            Authentication success = new UaaAuthentication(new UaaPrincipal(user), user.getAuthorities(), authdetails);
            publish(new IdentityProviderAuthenticationSuccessEvent(user, success, user.getOrigin(), identityZoneManager.getCurrentIdentityZoneId()));
            return success;
        }

        logger.debug("Did not locate login credentials");
        return null;
    }

    protected void publish(ApplicationEvent event) {
        if (eventPublisher != null) {
            eventPublisher.publishEvent(event);
        }
    }

    protected UaaUser getUser(AuthzAuthenticationRequest req, Map<String, String> info) {
        if (info.get(OriginKeys.ORIGIN) != null && info.get(OriginKeys.ORIGIN).equals(OriginKeys.UAA)) {
            throw new BadCredentialsException("uaa origin not allowed for external login server");
        }

        // TODO: Verify this can be removed
        // AuthzAuthenticationRequest requires name. This condition can never happen.
        if (req.getName() == null && info.get("email") == null && info.get("user_id") == null) {
            throw new BadCredentialsException("Cannot determine username from credentials supplied");
        }

        String name = req.getName();
        return UaaUser.createWithDefaults(u ->
                u.withId(info.getOrDefault("user_id", NotANumber))
                        .withUsername(name)
                        .withEmail(info.get("email"))
                        .withGivenName(info.get("given_name"))
                        .withFamilyName(info.get("family_name"))
                        .withPassword("")
                        .withAuthorities(UaaAuthority.USER_AUTHORITIES)
                        .withOrigin(info.getOrDefault(OriginKeys.ORIGIN, OriginKeys.LOGIN_SERVER))
                        .withExternalId(name)
                        .withZoneId(identityZoneManager.getCurrentIdentityZoneId())
        );
    }
}
